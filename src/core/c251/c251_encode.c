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
    Dict *label_pos;    /* char* label(无冒号) -> int* offset */
    List *fixups;       /* List<RelFixup*> */
    List *absfixups;    /* List<AbsFixup*> */
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

/* #imm / #0xHH 解析；失败返回 0 且 *ok=0 */
static long parse_imm(const char *s, int *ok) {
    *ok = 0;
    if (!s || s[0] != '#') return 0;
    char *end; long v = strtol(s + 1, &end, 0);
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
    Symbol *s = c251_find_symbol(st->obj, name);
    if (!s || s->section < 0) {
        fprintf(stderr, "c251_encode: unknown symbol: %s\n", name);
        return 0;
    }
    return (unsigned)s->value;
}

/* 判定操作数是否为符号名：非 #imm、非 R0-R7、非 WRj、非纯数字 */
static int is_symbol_arg(const char *s) {
    if (!s || s[0] == '\0' || s[0] == '#') return 0;
    if (s[0] == 'R' && s[1] >= '0' && s[1] <= '7' && s[2] == '\0') return 0;
    if (s[0] == 'W' && s[1] == 'R') return 0;
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
        /* 记录标签位置（去尾部 ':'） */
        size_t n = strlen(ins->op);
        char *lbl = strdup(ins->op);
        if (n > 0 && lbl[n - 1] == ':') lbl[n - 1] = '\0';
        int *pos = malloc(sizeof(int)); *pos = st->pc;
        dict_put(st->label_pos, lbl, pos);
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

    /* PUSH dir8 / POP dir8 (8051 兼容, 递归栈保护用; R0-R7 → 地址 0x00-0x07) */
    if (!strcmp(op, "PUSH") || !strcmp(op, "POP")) {
        int r1 = parse_reg(a1, &w1);
        if (r1 >= 0 && !w1 && r1 <= 7) {
            emit2(st, !strcmp(op, "PUSH") ? 0xC0 : 0xD0, (unsigned char)r1);
            return 0;
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

    /* 条件跳转 / SJMP（rel8，第二遍 resolve_fixups 填充） */
    {
        int jop = rel_jump_opcode(op);
        if (jop >= 0) {
            emit2(st, (unsigned char)jop, 0x00);  /* rel 占位 */
            const char *tgt = a1;
            if (tgt) {
                RelFixup *fx = malloc(sizeof(RelFixup));
                fx->offset = st->pc - 2;
                fx->label = strdup(tgt);
                list_push(st->fixups, fx);
            }
            return 0;
        }
    }

    if (!strcmp(op, "MOV")) {
        int r1 = parse_reg(a1, &w1);
        if (r1 >= 0 && w1) { /* WRj 目标 */
            if (a2 && a2[0] == '#') {
                imm = parse_imm(a2, &ok);
                if (!ok) return -1;
                emit4(st, 0x7E, (unsigned char)(((r1 / 2) << 4) | 0x4),
                      (unsigned char)((imm >> 8) & 0xFF), (unsigned char)(imm & 0xFF));
                return 0;
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

/* 第二遍：填充条件跳转/SJMP 的 rel8 偏移（rel = 目标 - (指令起始 + 2)） */
static void resolve_fixups(EncodeState *st) {
    if (!st->fixups) return;
    for (Iter it = list_iter(st->fixups); !iter_end(it);) {
        RelFixup *fx = iter_next(&it);
        int *lp = (int*)dict_get(st->label_pos, fx->label);
        if (!lp) {
            fprintf(stderr, "c251_encode: unknown jump label: %s\n", fx->label);
            continue;
        }
        int rel = *lp - (fx->offset + 2);
        if (rel < -128 || rel > 127)
            fprintf(stderr, "c251_encode: rel8 overflow for %s (rel=%d)\n", fx->label, rel);
        st->sec->bytes[fx->offset + 1] = (unsigned char)(rel & 0xFF);
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

void c251_encode(C251GenContext* ctx, ObjFile* obj) {
    if (!obj) return;
    (void)ctx;
    for (Iter sit = list_iter(obj->sections); !iter_end(sit);) {
        Section *sec = iter_next(&sit);
        if (!sec || sec->kind != SEC_CODE || !sec->asminstrs) continue;
        EncodeState st = { sec, obj, 0, make_dict(NULL), make_list(), make_list() };
        for (Iter ait = list_iter(sec->asminstrs); !iter_end(ait);) {
            AsmInstr *ai = iter_next(&ait);
            if (encode_instr(&st, ai) < 0) {
                fprintf(stderr, "c251_encode: unsupported instruction: %s\n", ai->op ? ai->op : "?");
            }
        }
        resolve_fixups(&st);
        resolve_abs_fixups(&st);
        dict_free(st.label_pos, free);
        /* 先释放 fx->label（list_free 会释放 fx 结构与节点本身） */
        for (Iter it = list_iter(st.fixups); !iter_end(it);) {
            RelFixup *fx = iter_next(&it);
            if (fx) free(fx->label);
        }
        list_free(st.fixups);
        free(st.fixups);
        for (Iter it = list_iter(st.absfixups); !iter_end(it);) {
            AbsFixup *fx = iter_next(&it);
            if (fx) free(fx->symbol);
        }
        list_free(st.absfixups);
        free(st.absfixups);
    }
}
