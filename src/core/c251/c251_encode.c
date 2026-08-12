#include "c251_encode.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

/* ============================================================
 * M1/M2 编码表（Source Mode，对照 functional.py / stc32g 指令表 / decode_impl.inc）
 *   MOV Rm,Rn      7C rd rs
 *   MOV WRj,WRjs   7D (jd/2)4|(js/2)
 *   MOV Rm,#v      7E m0 v
 *   MOV WRj,#d16   7E (j/2)4 hi lo     (大端: hi 在前)
 *   MOV dir16,Rm   7A m3 hi lo
 *   MOV Rm,dir16   7E m3 hi lo
 *   ADD Rm,Rn      2C rd rs
 *   ADD WRj,WRk    2D (j/2)4|(k/2)
 *   ADD WRj,#imm16 2E (j/2)4 hi lo
 *   SUB WRj,WRk    9D (j/2)4|(k/2)
 *   SUB WRj,#imm16 9E (j/2)4 hi lo
 *   MUL WRj,WRk    AD (j/2)4|(k/2)     (16x16 → 32 位, 低 16 位在 WRj)
 *   CMP Rm,Rn      BC rd rs
 *   CMP WRj,WRk    BD (j/2)4|(k/2)
 *   CMP Rm,#d8     BE m0 v
 *   CMP WRj,#d16   BE (j/2)4 hi lo     (注意: 不是 BD! BD 是 reg-reg)
 *   RET            22
 *   NOP            00
 *   条件跳转/SJMP (rel8, Source Mode 裸码):
 *     SJMP 80 / JE 68 (Z) / JNE 78 (!Z) / JG 38 (!cy&&!z 无符号>) /
 *     JLE 28 (cy||z 无符号<=) / JSL 48 (n!=ov 有符号<) /
 *     JSLE 08 (有符号<=) / JSG 18 (有符号>) / JSGE 58 (有符号>=) /
 *     JC 40 (cy) / JNC 50 (!cy) / JZ 60 / JNZ 70
 * ============================================================ */

typedef struct RelFixup {
    int offset;         /* 跳转指令起始偏移（rel 字节在 offset+1） */
    char *label;        /* 目标标签名（无冒号） */
    int seq;            /* 跳转指令序号（重编码时关联降级决策） */
} RelFixup;

/* 绝对地址 fixup（LJMP/LCALL 目标符号；函数符号 value 在编码中才确定，需两遍） */
typedef struct AbsFixup {
    int offset;         /* 指令起始偏移（地址 hi/lo 在 offset+1..offset+2） */
    char *symbol;       /* 目标符号名 */
} AbsFixup;

typedef struct EncodeState {
    Section *sec;
    const ObjFile *obj;
    int pc;
    Dict *label_pos;    /* char* label(无冒号) -> List<int*> offset 列表（同名标签多函数重复） */
    List *fixups;       /* List<RelFixup*> */
    List *absfixups;    /* List<AbsFixup*> 函数符号绝对跳转 */
    List *abslabfixups; /* List<AbsFixup*> 代码内标签绝对跳转（LJMP 降级） */
    List *degraded_seqs;/* List<int*> 已降级跳转序号（跨轮次保留） */
    int jump_seq;       /* 跳转指令序号计数器（每轮重置） */
} EncodeState;

static void emit1(EncodeState *st, unsigned char b) {
    section_append_bytes(st->sec, &b, 1);
    st->pc++;
}
static void emit2(EncodeState *st, unsigned char b1, unsigned char b2) {
    unsigned char bb[2] = { b1, b2 };
    section_append_bytes(st->sec, bb, 2);
    st->pc += 2;
}
static void emit3(EncodeState *st, unsigned char b1, unsigned char b2, unsigned char b3) {
    unsigned char bb[3] = { b1, b2, b3 };
    section_append_bytes(st->sec, bb, 3);
    st->pc += 3;
}
static void emit4(EncodeState *st, unsigned char b1, unsigned char b2, unsigned char b3, unsigned char b4) {
    unsigned char bb[4] = { b1, b2, b3, b4 };
    section_append_bytes(st->sec, bb, 4);
    st->pc += 4;
}

/* R0-R15 → 0-15；A → 11 (R11, 累加器)；WR0/WR2/WR4/... → 0,2,4,...；失败返回 -1 */
static int parse_reg(const char *s, int *is_word) {
    if (!s) return -1;
    *is_word = 0;
    if (s[0] == 'A' && s[1] == '\0') return 11;  /* A = R11 (sim251 RF_ACC) */
    if (s[0] == 'R') {
        char *end; long v = strtol(s + 1, &end, 10);
        if (*end == '\0' && v >= 0 && v <= 15) return (int)v;
    }
    if (s[0] == 'W' && s[1] == 'R') {
        char *end; long v = strtol(s + 2, &end, 10);
        if (*end == '\0' && v >= 0 && v <= 30 && (v % 2) == 0) { *is_word = 1; return (int)v; }
    }
    return -1;
}

/* @WRn → WR 索引（16 位间接地址寄存器），失败返回 -1 */
static int parse_indirect_wr(const char *s) {
    if (!s || s[0] != '@' || s[1] != 'W' || s[2] != 'R') return -1;
    char *end; long v = strtol(s + 3, &end, 10);
    if (*end != '\0' || v < 0 || v > 30 || (v % 2) != 0) return -1;
    return (int)v;
}

/* @DRn → DR 索引（24 位间接地址寄存器，far 指针访问），失败返回 -1 */
static int parse_indirect_dr(const char *s) {
    if (!s || s[0] != '@' || s[1] != 'D' || s[2] != 'R') return -1;
    char *end; long v = strtol(s + 3, &end, 10);
    if (*end != '\0' || v < 0 || v > 12 || (v % 4) != 0) return -1;
    return (int)v;
}

/* #imm / #0xHH 解析；base 0 失败（如 isel 硬编码的 #FFFF 无 0x 前缀）→ base 16 重试。
 * 失败返回 0 且 *ok=0 */
static long parse_imm(const char *s, int *ok) {
    *ok = 0;
    if (!s || s[0] != '#') return 0;
    char *end; long v = strtol(s + 1, &end, 0);
    if (*end == '\0') { *ok = 1; return v; }
    v = strtol(s + 1, &end, 16);
    if (*end == '\0') { *ok = 1; return v; }
    return 0;
}

static int is_label_instr(const AsmInstr *ins) {
    return ins && ins->op && ins->op[strlen(ins->op) - 1] == ':';
}

/* 条件跳转 / SJMP 操作码表（Source Mode 裸码，对照 decode_impl.inc cmp_branch） */
static int rel_jump_opcode(const char *op) {
    if (!strcmp(op, "SJMP")) return 0x80;
    if (!strcmp(op, "JE"))   return 0x68;  /* Z */
    if (!strcmp(op, "JNE"))  return 0x78;  /* !Z */
    if (!strcmp(op, "JG"))   return 0x38;  /* !cy&&!z 无符号> */
    if (!strcmp(op, "JLE"))  return 0x28;  /* cy||z 无符号<= */
    if (!strcmp(op, "JSL"))  return 0x48;  /* n!=ov 有符号< */
    if (!strcmp(op, "JSLE")) return 0x08;  /* n!=ov||z 有符号<= */
    if (!strcmp(op, "JSG"))  return 0x18;  /* n==ov&&!z 有符号> */
    if (!strcmp(op, "JSGE")) return 0x58;  /* n==ov 有符号>= */
    if (!strcmp(op, "JC"))   return 0x40;  /* cy */
    if (!strcmp(op, "JNC"))  return 0x50;  /* !cy */
    if (!strcmp(op, "JZ"))   return 0x60;  /* A==0 */
    if (!strcmp(op, "JNZ"))  return 0x70;  /* A!=0 */
    return -1;
}

/* 条件跳转反转（用于 rel8 越界降级：反转跳转跳过 LJMP 序列）。无条件跳转返回 -1 */
static int invert_jcc(int opcode) {
    switch (opcode) {
        case 0x68: return 0x78;  /* JE <-> JNE */
        case 0x78: return 0x68;
        case 0x38: return 0x28;  /* JG <-> JLE */
        case 0x28: return 0x38;
        case 0x48: return 0x58;  /* JSL <-> JSGE */
        case 0x58: return 0x48;
        case 0x08: return 0x18;  /* JSLE <-> JSG */
        case 0x18: return 0x08;
        case 0x40: return 0x50;  /* JC <-> JNC */
        case 0x50: return 0x40;
        case 0x60: return 0x70;  /* JZ <-> JNZ */
        case 0x70: return 0x60;
    }
    return -1;  /* SJMP 等无条件跳转 */
}

/* 跳转序号是否已在降级集合中（重编码时决定发射 LJMP 序列） */
static int seq_is_degraded(List *degraded_seqs, int seq) {
    if (!degraded_seqs) return 0;
    for (Iter it = list_iter(degraded_seqs); !iter_end(it);) {
        int *sp = iter_next(&it);
        if (sp && *sp == seq) return 1;
    }
    return 0;
}

/* 符号查找（仿 c51_encode find_symbol_for_asm：带 '@' 前缀时跳过前缀再试） */
static Symbol *c251_find_symbol(const ObjFile *obj, const char *name) {
    if (!obj || !name) return NULL;
    for (Iter it = list_iter(obj->symbols); !iter_end(it);) {
        Symbol *s = iter_next(&it);
        if (s && s->name && strcmp(s->name, name) == 0) return s;
    }
    if (name[0] == '@') {
        for (Iter it = list_iter(obj->symbols); !iter_end(it);) {
            Symbol *s = iter_next(&it);
            if (s && s->name && strcmp(s->name, name + 1) == 0) return s;
        }
    }
    return NULL;
}

/* 符号地址 = sym->value（EDATA 从 0 布局，value 即地址，与 hex 输出一致） */
static unsigned symbol_addr(EncodeState *st, const char *name) {
    /* 支持 (sym + N) 地址偏移语法: 提取符号名与偏移 (0046-inits: long 低 16 位) */
    int addend = 0;
    const char *symname = name;
    if (name && name[0] == '(') {
        const char *p = name + 1;
        const char *plus = strchr(p, '+');
        if (plus) {
            int len = (int)(plus - p);
            while (len > 0 && (p[len-1] == ' ' || p[len-1] == '\t')) len--;
            char buf[128];
            if (len > 0 && len < (int)sizeof(buf)) {
                memcpy(buf, p, (size_t)len);
                buf[len] = '\0';
                symname = buf;
                addend = (int)strtol(plus + 1, NULL, 0);
            }
        }
    }
    Symbol *s = c251_find_symbol(st->obj, symname);
    if (!s || s->section < 0) {
        fprintf(stderr, "c251_encode: unknown symbol: %s\n", name);
        return 0;
    }
    if (getenv("C251_DEBUG_SYM")) {
        fprintf(stderr, "c251_encode: sym %s value=%d sec=%d kind=%d\n",
                symname, s->value, s->section, s->kind);
    }
    return (unsigned)(s->value + addend);
}

/* 判定操作数是否为符号名：非 #imm、非 R0-R7、非 WRj、非纯数字 */
static int is_symbol_arg(const char *s) {
    if (!s || s[0] == '\0' || s[0] == '#') return 0;
    if (s[0] == 'R' && s[1] >= '0' && s[1] <= '7' && s[2] == '\0') return 0;
    if (s[0] == 'W' && s[1] == 'R') return 0;
    if (s[0] == '@' && s[1] == 'W' && s[2] == 'R') return 0;  /* @WRj 间接 */
    char *end; strtol(s, &end, 0);
    if (*end == '\0' && end != s) return 0;  /* 纯数字字面量 */
    return 1;
}

static const char* arg(const AsmInstr *ins, int i) {
    if (!ins->args) return NULL;
    int n = 0;
    for (Iter it = list_iter(ins->args); !iter_end(it);) {
        const char *a = iter_next(&it);
        if (n == i) return a;
        n++;
    }
    return NULL;
}

static int encode_instr(EncodeState *st, AsmInstr *ins) {
    if (!ins || !ins->op) return 0;
    if (is_label_instr(ins)) {
        /* 记录标签位置（去尾部 ':'）。同名标签跨函数重复（L1/L2/L3 每函数重置），
         * 故 value 存 List<int*> 位置列表，resolve 时按 offset 找最近的前驱标签。 */
        size_t n = strlen(ins->op);
        char *lbl = strdup(ins->op);
        if (n > 0 && lbl[n - 1] == ':') lbl[n - 1] = '\0';
        int *pos = malloc(sizeof(int)); *pos = st->pc;
        List *positions = (List*)dict_get(st->label_pos, lbl);
        if (!positions) {
            positions = make_list();
            dict_put(st->label_pos, lbl, positions);
        }
        list_push(positions, pos);
        /* 函数标签 `_name:` → 更新函数符号 value（代码偏移，供 LJMP/LCALL fixup） */
        if (lbl[0] == '_') {
            Symbol *s = c251_find_symbol(st->obj, lbl + 1);
            if (s && s->kind == SYM_FUNC) s->value = st->pc;
        }
        return 0;
    }

    const char *op = ins->op;
    const char *a1 = arg(ins, 0), *a2 = arg(ins, 1);
    int w1 = 0, w2 = 0, ok = 0;
    long imm;

    if (!strcmp(op, "NOP"))            { emit1(st, 0x00); return 0; }
    if (!strcmp(op, "RET"))            { emit1(st, 0x22); return 0; }
    if (!strcmp(op, "RETI"))           { emit1(st, 0x32); return 0; }  /* 中断返回 */

    /* PUSH dir8 / POP dir8 (8051 兼容, 递归栈保护用; R0-R7 → 地址 0x00-0x07) */
    if (!strcmp(op, "PUSH") || !strcmp(op, "POP")) {
        int r1 = parse_reg(a1, &w1);
        if (r1 >= 0 && !w1) {
            if (r1 <= 7) {
                /* 8051 风格: PUSH Rn = C0+n / POP Rn = D0+n */
                emit2(st, !strcmp(op, "PUSH") ? 0xC0 : 0xD0, (unsigned char)r1);
            } else {
                /* 251 源模式 (WR8-14 扩展): PUSH op1 = CA (idx<<4|8) / POP = DA */
                emit2(st, !strcmp(op, "PUSH") ? 0xCA : 0xDA,
                      (unsigned char)((r1 << 4) | 8));
            }
            return 0;
        }
        /* PUSH/POP dir8 (SFR 地址, 如 PSW=0xD0) */
        {
            char *end; long dir = strtol(a1, &end, 16);
            if (a1 && *a1 != '#' && *end == '\0' && dir >= 0x80 && dir <= 0xFF) {
                emit2(st, !strcmp(op, "PUSH") ? 0xC0 : 0xD0, (unsigned char)(dir & 0xFF));
                return 0;
            }
        }
        return -1;
    }

    /* LCALL sym: 12 hi lo (Keil C251 实测用 LCALL, golden tmp_func3.src)；
     * 函数符号 value 编码中才确定 → 占位 + AbsFixup 两遍填充 */
    if (!strcmp(op, "LCALL")) {
        const char *tgt = a1;
        if (tgt && is_symbol_arg(tgt)) {
            emit3(st, 0x12, 0x00, 0x00);
            AbsFixup *fx = malloc(sizeof(AbsFixup));
            fx->offset = st->pc - 3;
            fx->symbol = strdup(tgt);
            list_push(st->absfixups, fx);
            return 0;
        }
        /* @WRj 间接调用 (0089-fptr) */
        if (tgt && tgt[0] == '@') {
            int w = parse_indirect_wr(tgt);
            if (w >= 0) {
                emit2(st, 0x99, (unsigned char)(((w / 2) << 4)));
                return 0;
            }
        }
        return -1;
    }

    /* LJMP sym: 02 hi lo (入口 stub 跳 main)；同样两遍填充 */
    if (!strcmp(op, "LJMP")) {
        const char *tgt = a1;
        if (tgt && is_symbol_arg(tgt)) {
            emit3(st, 0x02, 0x00, 0x00);
            AbsFixup *fx = malloc(sizeof(AbsFixup));
            fx->offset = st->pc - 3;
            fx->symbol = strdup(tgt);
            list_push(st->absfixups, fx);
            return 0;
        }
        return -1;
    }

    /* MOVZ WRj,Rm: 0A (j/2)4|m (字节零扩展, functional.py movz_wr_rn) */
    if (!strcmp(op, "MOVZ")) {
        int r1 = parse_reg(a1, &w1);
        int r2 = parse_reg(a2, &w2);
        if (r1 >= 0 && w1 && r2 >= 0 && !w2)
            { emit2(st, 0x0A, (unsigned char)(((r1 / 2) << 4) | r2)); return 0; }
        return -1;
    }

    /* MOVS WRj,Rm: 1A (j/2)4|m (字节符号扩展) */
    if (!strcmp(op, "MOVS")) {
        int r1 = parse_reg(a1, &w1);
        int r2 = parse_reg(a2, &w2);
        if (r1 >= 0 && w1 && r2 >= 0 && !w2)
            { emit2(st, 0x1A, (unsigned char)(((r1 / 2) << 4) | r2)); return 0; }
        return -1;
    }

    /* 条件跳转 / SJMP（rel8，第二遍 resolve_fixups 填充；越界时降级 LJMP 序列） */
    {
        int jop = rel_jump_opcode(op);
        if (jop >= 0) {
            const char *tgt = a1;
            int seq = st->jump_seq++;
            if (tgt && seq_is_degraded(st->degraded_seqs, seq)) {
                /* 降级为 LJMP 绝对跳转（重编码轮次中）:
                 *   无条件 SJMP → 02 hi lo (3 字节)
                 *   条件跳转 → 反转跳转 rel=3 (跳过 LJMP) + 02 hi lo (5 字节) */
                if (jop == 0x80) {
                    emit3(st, 0x02, 0x00, 0x00);
                    AbsFixup *fx = malloc(sizeof(AbsFixup));
                    fx->offset = st->pc - 3;
                    fx->symbol = strdup(tgt);
                    list_push(st->abslabfixups, fx);
                } else {
                    int inv = invert_jcc(jop);
                    if (inv < 0) return -1;
                    emit2(st, (unsigned char)inv, 0x03);  /* 反转跳转：目标 = LJMP 之后 (rel=3) */
                    emit3(st, 0x02, 0x00, 0x00);
                    AbsFixup *fx = malloc(sizeof(AbsFixup));
                    fx->offset = st->pc - 3;
                    fx->symbol = strdup(tgt);
                    list_push(st->abslabfixups, fx);
                }
                return 0;
            }
            emit2(st, (unsigned char)jop, 0x00);  /* rel 占位 */
            if (tgt) {
                RelFixup *fx = malloc(sizeof(RelFixup));
                fx->offset = st->pc - 2;
                fx->label = strdup(tgt);
                fx->seq = seq;
                list_push(st->fixups, fx);
            }
            return 0;
        }
    }

    if (!strcmp(op, "MOV")) {
        if (getenv("C251_DBG_MOV")) fprintf(stderr, "MOV op args: %s %s\n", a1 ? a1 : "?", a2 ? a2 : "?");
        /* M3: sfr 8 位访问 — MOV A,#imm (0x74) / MOV A,dir8 (0xE5 xx) / MOV dir8,A (0xF5 xx) */
        /* dir8 无 # 前缀: 0x80-0xFF (SFR 直接地址) */
        if (a1 && strcmp(a1, "A") == 0) {
            if (a2 && a2[0] == '#') {
                int ok = 0;
                long imm = parse_imm(a2, &ok);
                if (ok) { emit2(st, 0x74, (unsigned char)(imm & 0xFF)); return 0; }
            }
            { /* MOV A,dir8 */
                char *end; long dir = strtol(a2, &end, 16);
                if (a2 && *a2 != '#' && *end == '\0' && dir >= 0x80 && dir <= 0xFF) { emit2(st, 0xE5, (unsigned char)(dir & 0xFF)); return 0; }
            }
            int r2 = parse_reg(a2, &w2);
            if (r2 >= 0 && !w2) { emit2(st, 0xE8 | (unsigned char)r2, 0x00); return 0; }  /* MOV A,Rn (0xE8+n) */
            return -1;
        }
        if (a2 && strcmp(a2, "A") == 0) {
            { /* MOV dir8,A */
                char *end; long dir = strtol(a1, &end, 16);
                if (a1 && *a1 != '#' && *end == '\0' && dir >= 0x80 && dir <= 0xFF) { emit2(st, 0xF5, (unsigned char)(dir & 0xFF)); return 0; }
            }
            { /* MOV Rn,A (0xF8+n) */
                int r1 = parse_reg(a1, &w1);
                if (r1 >= 0 && !w1) { emit2(st, 0xF8 | (unsigned char)r1, 0x00); return 0; }
            }
        }
        /* @DRk 间接目标 (far 指针写): MOV @DRk,Rm = 7A (k/4)B (m)0;
         * MOV @DRk,WRj = 7E (k/4)1A (j/2)0 (decode inc_dec_short sel2, b1&2) */
        int indd1 = parse_indirect_dr(a1);
        if (indd1 >= 0) {
            int r2 = parse_reg(a2, &w2);
            if (r2 >= 0 && w2) {
                emit3(st, 0x7E, (unsigned char)(((indd1 / 4) << 4) | 0x1A),
                      (unsigned char)((r2 / 2) << 4));
                return 0;
            }
            if (r2 >= 0 && !w2) {
                emit3(st, 0x7A, (unsigned char)(((indd1 / 4) << 4) | 0xB),
                      (unsigned char)(r2 << 4));
                return 0;
            }
            return -1;
        }
        /* @DRk 间接源 (far 指针读): MOV Rm,@DRk = 7E (k/4)B (m)0;
         * MOV WRj,@DRk = 7E (k/4)0A (j/2)0 */
        int indd2 = parse_indirect_dr(a2);
        if (indd2 >= 0) {
            int r1b = parse_reg(a1, &w1);
            if (r1b >= 0 && w1) {
                emit3(st, 0x7E, (unsigned char)(((indd2 / 4) << 4) | 0x0A),
                      (unsigned char)((r1b / 2) << 4));
                return 0;
            }
            if (r1b >= 0 && !w1) {
                emit3(st, 0x7E, (unsigned char)(((indd2 / 4) << 4) | 0xB),
                      (unsigned char)(r1b << 4));
                return 0;
            }
            return -1;
        }
        /* @WRj 间接目标: MOV @WRk,src (7A (k/2)A (src/2)0, decode_impl.inc case 0x9/0xA) */
        int ind1 = parse_indirect_wr(a1);
        if (ind1 >= 0) {
            int r2 = parse_reg(a2, &w2);
            if (r2 >= 0 && w2) {
                emit3(st, 0x7A, (unsigned char)(((ind1 / 2) << 4) | 0xA),
                      (unsigned char)((r2 / 2) << 4));
                return 0;
            }
            if (r2 >= 0 && !w2) {
                emit3(st, 0x7A, (unsigned char)(((ind1 / 2) << 4) | 0x9),
                      (unsigned char)(r2 << 4));
                return 0;
            }
            return -1;
        }
        /* @WRj 间接源: MOV dst,@WRk。
         * 读形态 (decode case 0xA/0x9): b1 高半字节=目标, b2 高半字节=地址寄存器。
         * MOV WRj,@WRk = 7E ((j/2)4|A) ((k/2)4|0); MOV Rm,@WRk = 7E ((m)4|9) ((k/2)4|0) */
        int ind2 = parse_indirect_wr(a2);
        if (ind2 >= 0) {
            int r1b = parse_reg(a1, &w1);
            if (r1b >= 0 && w1) {
                emit3(st, 0x7E, (unsigned char)(((r1b / 2) << 4) | 0xA),
                      (unsigned char)((ind2 / 2) << 4));
                return 0;
            }
            if (r1b >= 0 && !w1) {
                /* 8 位读 (decode case 0x9: Rm,@WRj): 地址在 b1, 目标在 b2 */
                emit3(st, 0x7E, (unsigned char)(((ind2 / 2) << 4) | 0x9),
                      (unsigned char)(r1b << 4));
                return 0;
            }
            return -1;
        }
        int r1 = parse_reg(a1, &w1);
        if (r1 >= 0 && w1) { /* WRj 目标 */
            if (a2 && a2[0] == '#') {
                /* #SYM 优先：符号地址立即数（ADDR 产物物化，如 MOV WRj,#g_x）。
                 * 必须在 parse_imm 之前判定——parse_imm 的 base-16 兜底会把
                 * 符号名 "a".."f"/"1a" 等误解析为十六进制数字（0092 变量 a）。 */
                if (a2[1] != '\0' && is_symbol_arg(a2 + 1) &&
                    c251_find_symbol(st->obj, a2 + 1)) {
                    unsigned addr = symbol_addr(st, a2 + 1);
                    emit4(st, 0x7E, (unsigned char)(((r1 / 2) << 4) | 0x4),
                          (unsigned char)((addr >> 8) & 0xFF), (unsigned char)(addr & 0xFF));
                    return 0;
                }
                imm = parse_imm(a2, &ok);
                if (ok) {
                    emit4(st, 0x7E, (unsigned char)(((r1 / 2) << 4) | 0x4),
                          (unsigned char)((imm >> 8) & 0xFF), (unsigned char)(imm & 0xFF));
                    return 0;
                }
                return -1;
            }
            int r2 = parse_reg(a2, &w2);
            if (r2 >= 0 && w2) { emit2(st, 0x7D, (unsigned char)(((r1 / 2) << 4) | (r2 / 2))); return 0; }
            if (is_symbol_arg(a2)) {
                /* MOV WRj,dir16: 7E (j/2)7 hi lo (decode_impl.inc case 0x7) */
                unsigned addr = symbol_addr(st, a2);
                emit4(st, 0x7E, (unsigned char)(((r1 / 2) << 4) | 0x7),
                      (unsigned char)((addr >> 8) & 0xFF), (unsigned char)(addr & 0xFF));
                return 0;
            }
        } else if (r1 >= 0) { /* Rm 目标 */
            if (a2 && a2[0] == '#') {
                imm = parse_imm(a2, &ok);
                if (!ok) return -1;
                emit3(st, 0x7E, (unsigned char)((r1 << 4) | 0x0), (unsigned char)(imm & 0xFF));
                return 0;
            }
            int r2 = parse_reg(a2, &w2);
            if (r2 >= 0 && !w2) { emit2(st, 0x7C, (unsigned char)((r1 << 4) | r2)); return 0; }
            if (is_symbol_arg(a2)) {
                /* MOV Rm,dir16: 7E m3 hi lo (decode_impl.inc case 0x3) */
                unsigned addr = symbol_addr(st, a2);
                emit4(st, 0x7E, (unsigned char)((r1 << 4) | 0x3),
                      (unsigned char)((addr >> 8) & 0xFF), (unsigned char)(addr & 0xFF));
                return 0;
            }
        } else if (a1 && !strcmp(a1, "SP")) {
            /* MOV SP,#imm: 75 81 v (8051/251 兼容, 启动代码初始化栈用)。
             * SP 动态化: = EDATA 段末尾 + 栈余量 (栈向下增长不碰全局/spill 槽)。
             * 0041-queen: _heap[1024] 全局占 0x84-0x483, 硬编码 SP=0xDF 使栈区与
             * _heap 重叠 — calloc 清零覆盖 PUSH 保存区 → 递归结果错 (N=0)。
             * 段末尾 > 0xFF 时用 MOV DR60,#imm16 (SPX: 7E F8 hi lo)。 */
            if (a2 && a2[0] == '#') {
                unsigned sp = 0xDF;
                for (Iter sit = list_iter(st->obj->sections); !iter_end(sit);) {
                    Section *sec = iter_next(&sit);
                    if (sec && sec->kind == SEC_EDATA && sec->bytes_len > 0) {
                        sp = (unsigned)sec->bytes_len + 0x200;  /* 段末尾 + 512B 栈余量 */
                        if (sp > 0xFF00) sp = 0xFF00;
                        break;
                    }
                }
                if (sp <= 0xFF) {
                    emit3(st, 0x75, 0x81, (unsigned char)(sp & 0xFF));
                } else {
                    emit4(st, 0x7E, 0xF8, (unsigned char)((sp >> 8) & 0xFF),
                          (unsigned char)(sp & 0xFF));
                }
                return 0;
            }
        } else if (is_symbol_arg(a1)) {
            /* 目标是符号：MOV SYM,src */
            int r2 = parse_reg(a2, &w2);
            unsigned addr = symbol_addr(st, a1);
            if (r2 >= 0 && w2) {
                /* MOV dir16,WRj: 7A (j/2)7 hi lo (mov_op1_reg case 0x7) */
                emit4(st, 0x7A, (unsigned char)(((r2 / 2) << 4) | 0x7),
                      (unsigned char)((addr >> 8) & 0xFF), (unsigned char)(addr & 0xFF));
                return 0;
            }
            if (r2 >= 0 && !w2) {
                /* MOV dir16,Rm: 7A m3 hi lo (mov_op1_reg case 0x3) */
                emit4(st, 0x7A, (unsigned char)((r2 << 4) | 0x3),
                      (unsigned char)((addr >> 8) & 0xFF), (unsigned char)(addr & 0xFF));
                return 0;
            }
        }
        return -1; /* 未支持的 MOV 形态（M2 扩展） */
    }

    if (!strcmp(op, "ADD")) {
        int r1 = parse_reg(a1, &w1);
        int r2 = parse_reg(a2, &w2);
        if (r1 >= 0 && w1 && r2 >= 0 && w2)
            emit2(st, 0x2D, (unsigned char)(((r1 / 2) << 4) | (r2 / 2)));
        else if (r1 >= 0 && !w1 && r2 >= 0 && !w2)
            emit2(st, 0x2C, (unsigned char)((r1 << 4) | r2));
        else if (r1 >= 0 && w1 && a2 && a2[0] == '#') {
            /* ADD WRj,#imm16: 2E (j/2)4 hi lo (reg,op2 imm16 形态, functional.py add_wr_imm) */
            imm = parse_imm(a2, &ok);
            if (!ok) return -1;
            emit4(st, 0x2E, (unsigned char)(((r1 / 2) << 4) | 0x4),
                  (unsigned char)((imm >> 8) & 0xFF), (unsigned char)(imm & 0xFF));
        }
        else return -1;
        return 0;
    }

    if (!strcmp(op, "SUB")) {
        int r1 = parse_reg(a1, &w1);
        int r2 = parse_reg(a2, &w2);
        if (r1 >= 0 && w1 && r2 >= 0 && w2)
            emit2(st, 0x9D, (unsigned char)(((r1 / 2) << 4) | (r2 / 2)));
        else if (r1 >= 0 && w1 && a2 && a2[0] == '#') {
            /* SUB WRj,#imm16: 9E (j/2)4 hi lo (functional.py sub_wr_imm) */
            imm = parse_imm(a2, &ok);
            if (!ok) return -1;
            emit4(st, 0x9E, (unsigned char)(((r1 / 2) << 4) | 0x4),
                  (unsigned char)((imm >> 8) & 0xFF), (unsigned char)(imm & 0xFF));
        }
        else return -1;
        return 0;
    }

    if (!strcmp(op, "MUL")) {
        int r1 = parse_reg(a1, &w1);
        int r2 = parse_reg(a2, &w2);
        if (r1 >= 0 && w1 && r2 >= 0 && w2)
            emit2(st, 0xAD, (unsigned char)(((r1 / 2) << 4) | (r2 / 2)));
        else return -1;
        return 0;
    }

    if (!strcmp(op, "ANL") || !strcmp(op, "ORL") || !strcmp(op, "XRL")) {
            /* ANL/ORL/XRL WRj,WRk: 5D/4D/6D (j/2)4|(k/2) (regop2 word)
         * ANL/ORL/XRL WRj,#imm16: 5E/4E/6E (j/2)4 hi lo (regop2 generic case 0x4)
         * ANL/ORL/XRL Rm,#data: 5E/4E/6E m0 data (regop2 generic case 0x0) */
        int base = !strcmp(op, "ANL") ? 0x5D : (!strcmp(op, "ORL") ? 0x4D : 0x6D);
        int r1 = parse_reg(a1, &w1);
        int r2 = parse_reg(a2, &w2);
        if (r1 >= 0 && w1 && r2 >= 0 && w2)
            emit2(st, (unsigned char)base, (unsigned char)(((r1 / 2) << 4) | (r2 / 2)));
        else if (r1 >= 0 && !w1 && r2 >= 0 && !w2)
            emit2(st, (unsigned char)(base - 1), (unsigned char)((r1 << 4) | r2));
        else if (r1 >= 0 && w1 && a2 && a2[0] == '#') {
            imm = parse_imm(a2, &ok);
            if (!ok) return -1;
            emit4(st, (unsigned char)(base + 1), (unsigned char)(((r1 / 2) << 4) | 0x4),
                  (unsigned char)((imm >> 8) & 0xFF), (unsigned char)(imm & 0xFF));
        }
        else if (r1 >= 0 && !w1 && a2 && a2[0] == '#') {
            imm = parse_imm(a2, &ok);
            if (!ok) return -1;
            emit3(st, (unsigned char)(base + 1), (unsigned char)((r1 << 4) | 0x0), (unsigned char)(imm & 0xFF));
        }
        else return -1;
        return 0;
    }

    if (!strcmp(op, "SLL") || !strcmp(op, "SRL") || !strcmp(op, "SRA")) {
        /* 移位 1 位 (shift_single): SLL=3E SRL=1E SRA=0E (j/2)4 (lo=4 表示 WRj!)
         * 第二字节 = (j/2)<<4 | 0x4，lo=4 才是 word 移位 (lo=0 是 Rm 字节移位) */
        int r1 = parse_reg(a1, &w1);
        unsigned char code = !strcmp(op, "SLL") ? 0x3E : (!strcmp(op, "SRL") ? 0x1E : 0x0E);
        if (r1 >= 0 && w1) {
            emit2(st, code, (unsigned char)(((r1 / 2) << 4) | 0x4));
        } else if (r1 >= 0) {
            /* Rm 字节移位 (lo=0): SRL A = 0x1E B0 */
            emit2(st, code, (unsigned char)((r1 << 4) | 0x0));
        }
        else return -1;
        return 0;
    }

    if (!strcmp(op, "DIV")) {
        /* DIV WRj,WRk: 8D (j/2)4|(k/2); 商→WRj, 余数→DR 对另一侧 */
        int r1 = parse_reg(a1, &w1);
        int r2 = parse_reg(a2, &w2);
        if (r1 >= 0 && w1 && r2 >= 0 && w2)
            emit2(st, 0x8D, (unsigned char)(((r1 / 2) << 4) | (r2 / 2)));
        else return -1;
        return 0;
    }

    if (!strcmp(op, "INC")) {
        /* INC WRj,#1: 0B (j/2)4 (sel=1 word, ss=0 shortv=1; functional.py inc_wr_1) */
        int r1 = parse_reg(a1, &w1);
        if (r1 >= 0 && w1)
            emit2(st, 0x0B, (unsigned char)(((r1 / 2) << 4) | 0x4));
        else return -1;
        return 0;
    }

    if (!strcmp(op, "CMP")) {
        int r1 = parse_reg(a1, &w1);
        int r2 = parse_reg(a2, &w2);
        if (r1 >= 0 && w1 && r2 >= 0 && w2)
            emit2(st, 0xBD, (unsigned char)(((r1 / 2) << 4) | (r2 / 2)));
        else if (r1 >= 0 && !w1 && r2 >= 0 && !w2)
            emit2(st, 0xBC, (unsigned char)((r1 << 4) | r2));
        else if (r1 >= 0 && w1 && a2 && a2[0] == '#') {
            imm = parse_imm(a2, &ok);
            if (!ok) return -1;
            emit4(st, 0xBE, (unsigned char)(((r1 / 2) << 4) | 0x4),
                  (unsigned char)((imm >> 8) & 0xFF), (unsigned char)(imm & 0xFF));
        } else if (r1 >= 0 && !w1 && a2 && a2[0] == '#') {
            imm = parse_imm(a2, &ok);
            if (!ok) return -1;
            emit3(st, 0xBE, (unsigned char)((r1 << 4) | 0x0), (unsigned char)(imm & 0xFF));
        } else return -1;
        return 0;
    }

    return -1; /* 未支持指令（M2 扩展） */
}

/* 第二遍：填充条件跳转/SJMP 的 rel8 偏移（rel = 目标 - (指令起始 + 2)）。
 * 越界（超出 ±128）→ 加入 degraded_seqs，下一轮重编码降级为 LJMP 序列。 */
/* 找距 offset 最近的同名标签位置（同名标签跨函数重复；跳转目标可能是前向或后向）。
 * 对同轮编码内的前向/后向跳转都正确：取绝对距离最近的位置。 */
static int label_pos_before(EncodeState *st, const char *name, int offset, int *out) {
    List *positions = (List*)dict_get(st->label_pos, name);
    if (!positions) return 0;
    int best = -1, best_dist = 0x7FFFFFFF;
    for (Iter it = list_iter(positions); !iter_end(it);) {
        int *p = (int*)iter_next(&it);
        int d = *p > offset ? (*p - offset) : (offset - *p);
        if (d < best_dist) { best_dist = d; best = *p; }
    }
    if (best < 0) return 0;
    *out = best;
    return 1;
}

/* 释放 label_pos dict：键 strdup + 值 List<int*>（元素+节点+结构）
 * 注意：元素已手动 free，list_free 会再 free elem → 只用其释放节点 */
static void free_label_pos_entry(void *val) {
    List *positions = (List*)val;
    if (!positions) return;
    for (Iter it = list_iter(positions); !iter_end(it);) {
        int *p = (int*)iter_next(&it);
        free(p);
    }
    /* 只释放节点结构，不清 elem（已 free） */
    ListNode *node = positions->head;
    while (node) {
        ListNode *next = node->next;
        free(node);
        node = next;
    }
    free(positions);
}

static void resolve_fixups(EncodeState *st) {
    if (!st->fixups) return;
    for (Iter it = list_iter(st->fixups); !iter_end(it);) {
        RelFixup *fx = iter_next(&it);
        int lp = 0;
        if (!label_pos_before(st, fx->label, fx->offset, &lp)) {
            fprintf(stderr, "c251_encode: unknown jump label: %s\n", fx->label);
            continue;
        }
        int rel = lp - (fx->offset + 2);
        if (getenv("C251_DBG_SJMP")) {
            fprintf(stderr, "[sjmp] %s @0x%X -> 0x%X rel=%d\n", fx->label, fx->offset, lp, rel);
        }
        if (rel < -128 || rel > 127) {
            fprintf(stderr, "c251_encode: rel8 overflow for %s (rel=%d), degrading to LJMP\n", fx->label, rel);
            int *sp = malloc(sizeof(int));
            *sp = fx->seq;
            list_push(st->degraded_seqs, sp);
            continue;  /* 不填充 rel；下一轮重编码时该跳转降级为 LJMP */
        }
        st->sec->bytes[fx->offset + 1] = (unsigned char)(rel & 0xFF);
    }
}

/* 绝对地址 fixup（代码内标签）：LJMP 降级序列的 02 hi lo，
 * 目标为代码内标签（label_pos 查找，非 obj 符号） */
static void resolve_abs_label_fixups(EncodeState *st) {
    if (!st->abslabfixups) return;
    for (Iter it = list_iter(st->abslabfixups); !iter_end(it);) {
        AbsFixup *fx = iter_next(&it);
        int lp = 0;
        if (!label_pos_before(st, fx->symbol, fx->offset, &lp)) {
            fprintf(stderr, "c251_encode: unknown abs label target: %s\n", fx->symbol);
            continue;
        }
        unsigned addr = (unsigned)lp;
        st->sec->bytes[fx->offset + 1] = (unsigned char)((addr >> 8) & 0xFF);
        st->sec->bytes[fx->offset + 2] = (unsigned char)(addr & 0xFF);
    }
}

/* 绝对地址 fixup（LJMP/LCALL）：编码完成后函数符号 value 已确定，填充 hi/lo */
static void resolve_abs_fixups(EncodeState *st) {
    if (!st->absfixups) return;
    for (Iter it = list_iter(st->absfixups); !iter_end(it);) {
        AbsFixup *fx = iter_next(&it);
        Symbol *s = c251_find_symbol(st->obj, fx->symbol);
        if (!s || s->section < 0) {
            fprintf(stderr, "c251_encode: unknown abs target: %s\n", fx->symbol);
            continue;
        }
        unsigned addr = (unsigned)s->value;
        st->sec->bytes[fx->offset + 1] = (unsigned char)((addr >> 8) & 0xFF);
        st->sec->bytes[fx->offset + 2] = (unsigned char)(addr & 0xFF);
    }
}

/* 释放 fixup 列表（label/symbol strdup + 节点；list_free 只释放节点结构） */
static void free_absfixups(List *list) {
    if (!list) return;
    for (Iter it = list_iter(list); !iter_end(it);) {
        AbsFixup *fx = iter_next(&it);
        if (fx) free(fx->symbol);
    }
    list_free(list);
    free(list);
}

void c251_encode(C251GenContext* ctx, ObjFile* obj) {
    if (!obj) return;
    (void)ctx;
    for (Iter sit = list_iter(obj->sections); !iter_end(sit);) {
        Section *sec = iter_next(&sit);
        if (!sec || sec->kind != SEC_CODE || !sec->asminstrs) continue;
        /* rel8 越界降级决策（跨轮次保留）：List<int*> 跳转序号 */
        List *degraded_seqs = make_list();
        for (int round = 0; round < 20; round++) {
            EncodeState st = { sec, obj, 0, make_dict(NULL), make_list(), make_list(),
                               make_list(), degraded_seqs, 0 };
            sec->bytes_len = 0;  /* 重置代码段，重新编码 */
            for (Iter ait = list_iter(sec->asminstrs); !iter_end(ait);) {
                AsmInstr *ai = iter_next(&ait);
                if (encode_instr(&st, ai) < 0) {
                    fprintf(stderr, "c251_encode: unsupported instruction: %s\n", ai->op ? ai->op : "?");
                }
            }
            int before = list_len(degraded_seqs);
            resolve_fixups(&st);
            resolve_abs_label_fixups(&st);
            resolve_abs_fixups(&st);
            int after = list_len(degraded_seqs);
            /* 释放本轮临时结构 */
            dict_free(st.label_pos, free_label_pos_entry);
            for (Iter it = list_iter(st.fixups); !iter_end(it);) {
                RelFixup *fx = iter_next(&it);
                if (fx) free(fx->label);
            }
            list_free(st.fixups);
            free(st.fixups);
            free_absfixups(st.absfixups);
            free_absfixups(st.abslabfixups);
            if (after == before) break;  /* 无新降级，稳定 */
        }
        /* 释放降级序号集：list_free 释放 int* 元素 + 节点，再释放 List 结构 */
        list_free(degraded_seqs);
        free(degraded_seqs);
    }
}
