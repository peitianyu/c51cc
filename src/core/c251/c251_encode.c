#include "c251_encode.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

/* ============================================================
 * M1 编码表（Source Mode，对照 functional.py / stc32g 指令表）
 *   MOV Rm,Rn      7C rd rs
 *   MOV WRj,WRjs   7D (jd/2)4|(js/2)
 *   MOV Rm,#v      7E m0 v
 *   MOV WRj,#d16   7E (j/2)4 hi lo     (大端: hi 在前)
 *   MOV dir16,Rm   7A m3 hi lo
 *   MOV Rm,dir16   7E m3 hi lo
 *   ADD Rm,Rn      2C rd rs
 *   ADD WRj,WRk    2D (j/2)4|(k/2)
 *   SUB WRj,WRk    9D (j/2)4|(k/2)
 *   MUL WRj,WRk    AD (j/2)4|(k/2)     (16x16 → 32 位, 低 16 位在 WRj)
 *   RET            22
 *   SJMP rel       80 rel
 *   NOP            00
 * ============================================================ */

typedef struct EncodeState {
    Section *sec;
    int pc;
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

/* R0-R7 → 0-7；WR0/WR2/WR4/... → 0,2,4,...；失败返回 -1 */
static int parse_reg(const char *s, int *is_word) {
    if (!s) return -1;
    *is_word = 0;
    if (s[0] == 'R' && s[1] >= '0' && s[1] <= '7' && s[2] == '\0') return s[1] - '0';
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
    if (is_label_instr(ins)) return 0; /* 标签不编码，后续 reloc 处理 */

    const char *op = ins->op;
    const char *a1 = arg(ins, 0), *a2 = arg(ins, 1);
    int w1 = 0, w2 = 0, ok = 0;
    long imm;

    if (!strcmp(op, "NOP"))            { emit1(st, 0x00); return 0; }
    if (!strcmp(op, "RET"))            { emit1(st, 0x22); return 0; }

    if (!strcmp(op, "MOV")) {
        int r1 = parse_reg(a1, &w1);
        if (r1 >= 0 && w1) { /* WRj */
            if (a2 && a2[0] == '#') {
                imm = parse_imm(a2, &ok);
                if (!ok) return -1;
                emit4(st, 0x7E, (unsigned char)(((r1 / 2) << 4) | 0x4),
                      (unsigned char)((imm >> 8) & 0xFF), (unsigned char)(imm & 0xFF));
                return 0;
            }
            int r2 = parse_reg(a2, &w2);
            if (r2 >= 0 && w2) { emit2(st, 0x7D, (unsigned char)(((r1 / 2) << 4) | (r2 / 2))); return 0; }
        } else if (r1 >= 0) { /* Rm */
            if (a2 && a2[0] == '#') {
                imm = parse_imm(a2, &ok);
                if (!ok) return -1;
                emit3(st, 0x7E, (unsigned char)((r1 << 4) | 0x0), (unsigned char)(imm & 0xFF));
                return 0;
            }
            int r2 = parse_reg(a2, &w2);
            if (r2 >= 0 && !w2) { emit2(st, 0x7C, (unsigned char)((r1 << 4) | r2)); return 0; }
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
        else return -1;
        return 0;
    }

    if (!strcmp(op, "SUB")) {
        int r1 = parse_reg(a1, &w1);
        int r2 = parse_reg(a2, &w2);
        if (r1 >= 0 && w1 && r2 >= 0 && w2)
            emit2(st, 0x9D, (unsigned char)(((r1 / 2) << 4) | (r2 / 2)));
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

    if (!strcmp(op, "SJMP")) { /* M1 占位：rel 由后续 reloc 填充，先发 80 00 */
        emit2(st, 0x80, 0x00);
        return 0;
    }

    return -1; /* 未支持指令（M2 扩展） */
}

void c251_encode(C251GenContext* ctx, ObjFile* obj) {
    if (!obj) return;
    for (Iter sit = list_iter(obj->sections); !iter_end(sit);) {
        Section *sec = iter_next(&sit);
        if (!sec || sec->kind != SEC_CODE || !sec->asminstrs) continue;
        EncodeState st = { sec, 0 };
        for (Iter ait = list_iter(sec->asminstrs); !iter_end(ait);) {
            AsmInstr *ai = iter_next(&ait);
            if (encode_instr(&st, ai) < 0) {
                fprintf(stderr, "c251_encode: unsupported instruction: %s\n", ai->op ? ai->op : "?");
            }
        }
    }
}
