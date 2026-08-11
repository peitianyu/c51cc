#include "c251_isel.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void wr_name(char *buf, size_t n, int wr) {
    snprintf(buf, n, "WR%d", wr);
}

void isel_emit(ISelContext* isel, const char* op, const char* arg1, const char* arg2) {
    if (!isel || !op) return;
    AsmInstr *ai = calloc(1, sizeof(AsmInstr));
    ai->op = strdup(op);
    ai->args = make_list();
    if (arg1) list_push(ai->args, strdup(arg1));
    if (arg2) list_push(ai->args, strdup(arg2));
    list_push(isel->sec->asminstrs, ai);
}

int isel_value_reg(C251GenContext* ctx, ValueName val) {
    if (!ctx || val < 0) return -1;
    char *k = c251_key(val);
    int *r = (int*)dict_get(ctx->value_to_reg, k);
    free(k);
    return r ? *r : -1;
}

/* ============================================================
 * 简单 liveness（M2）：
 *  - global_live：跨块活值（PHI 参数 / 出现在 ≥2 块）永不释放
 *  - 块内：从当前位置 pos（含）往后无使用 → 可释放
 * ============================================================ */

typedef struct LiveInfo { int cnt; int last_block; } LiveInfo;

/* 预扫描（isel_function）：统计每个值出现的不同块数；PHI 参数强制跨块活 */
static Dict* compute_global_live(Func* func) {
    Dict *d = make_dict(NULL);
    int block_id = 0;
    for (Iter bit = list_iter(func->blocks); !iter_end(bit);) {
        Block *blk = iter_next(&bit);
        /* 块内指令 args 使用 */
        for (Iter iit = list_iter(blk->instrs); !iter_end(iit);) {
            Instr *ins = iter_next(&iit);
            if (!ins || !ins->args) continue;
            for (Iter ait = list_iter(ins->args); !iter_end(ait);) {
                ValueName *ap = iter_next(&ait);
                if (!ap || *ap < 0) continue;
                char *k = c251_key(*ap);
                LiveInfo *li = (LiveInfo*)dict_get(d, k);
                if (!li) { li = calloc(1, sizeof(LiveInfo)); dict_put(d, k, li); }
                else free(k);
                if (li->last_block != block_id) { li->last_block = block_id; li->cnt++; }
            }
            /* 块内指令 dest 定义：定义块+使用块 ≥2 → 跨块活（防跨块值被死值释放） */
            if (ins->dest >= 0) {
                char *k = c251_key(ins->dest);
                LiveInfo *li = (LiveInfo*)dict_get(d, k);
                if (!li) { li = calloc(1, sizeof(LiveInfo)); dict_put(d, k, li); }
                else free(k);
                if (li->last_block != block_id) { li->last_block = block_id; li->cnt++; }
            }
        }
        /* PHI 参数：无条件跨块活（cnt=2 哨兵） */
        for (Iter pit = list_iter(blk->phis); !iter_end(pit);) {
            Instr *phi = iter_next(&pit);
            if (!phi || !phi->args) continue;
            for (Iter ait = list_iter(phi->args); !iter_end(ait);) {
                ValueName *ap = iter_next(&ait);
                if (!ap || *ap < 0) continue;
                char *k = c251_key(*ap);
                LiveInfo *li = (LiveInfo*)dict_get(d, k);
                if (!li) { li = calloc(1, sizeof(LiveInfo)); li->cnt = 2; dict_put(d, k, li); }
                else { li->cnt = 2; free(k); }
            }
        }
        block_id++;
    }
    return d;
}

static bool is_global_live(Dict *gl, ValueName v) {
    if (!gl || v < 0) return false;
    char *k = c251_key(v);
    LiveInfo *li = (LiveInfo*)dict_get(gl, k);
    free(k);
    return li && li->cnt >= 2;
}

/* 值 v 在位置 pos（含）之后是否仍被使用 */
static bool value_still_used(ISelContext* isel, ValueName v, int pos) {
    if (v < 0) return false;
    if (is_global_live(isel->global_live, v)) return true;
    for (int i = pos; i < isel->block_instr_count; i++) {
        Instr *ins = isel->block_instrs[i];
        if (!ins || !ins->args) continue;
        for (Iter it = list_iter(ins->args); !iter_end(it);) {
            ValueName *ap = iter_next(&it);
            if (ap && *ap == v) return true;
        }
    }
    return false;
}

/* 选临时寄存器：避开 avoid1/avoid2 → 空闲 → 块内死值 → 强制溢出兜底（几乎不达） */
static int isel_temp_wr(ISelContext* isel, int avoid1, int avoid2) {
    C251GenContext *ctx = isel->ctx;
    for (int w = 0; w <= 6; w += 2) {
        if (w == avoid1 || w == avoid2) continue;
        if (isel->reg_val[w/2] < 0) return w;
    }
    for (int w = 0; w <= 6; w += 2) {
        if (w == avoid1 || w == avoid2) continue;
        ValueName rv = isel->reg_val[w/2];
        if (rv >= 0 && !value_still_used(isel, rv, isel->block_instr_pos)) return w;
    }
    /* 极端兜底：强制溢出第一个非 avoid 寄存器中的值 */
    for (int w = 0; w <= 6; w += 2) {
        if (w == avoid1 || w == avoid2) continue;
        ValueName rv = isel->reg_val[w/2];
        if (rv >= 0) {
            char *sp = c251_alloc_spill(ctx, rv);
            char wbuf[16]; wr_name(wbuf, sizeof(wbuf), w);
            isel_emit(isel, "MOV", sp, wbuf);
            char *k = c251_key(rv);
            dict_remove(ctx->value_to_reg, k);
            free(k);
            isel->reg_val[w/2] = -1;
            return w;
        }
    }
    return 0; /* 理论不可达 */
}

/* 值 → 寄存器分配：已分配复用 → 空闲 → 块内死值释放 → -1（调用方走溢出） */
int isel_alloc_wr(ISelContext* isel, ValueName val) {
    C251GenContext *ctx = isel->ctx;
    char *key = c251_key(val);
    int *exist = (int*)dict_get(ctx->value_to_reg, key);
    if (exist) { free(key); return *exist; }

    int pos = isel->block_instr_pos;
    int w = -1;
    for (int i = 0; i < 4; i++)
        if (isel->reg_val[i] < 0) { w = i * 2; break; }
    if (w < 0) {
        for (int i = 0; i < 4; i++) {
            ValueName rv = isel->reg_val[i];
            if (rv >= 0 && !value_still_used(isel, rv, pos)) { w = i * 2; break; }
        }
    }
    if (w < 0) { free(key); return -1; }

    isel->reg_val[w/2] = val;
    int *slot = malloc(sizeof(int)); *slot = w;
    dict_put(ctx->value_to_reg, key, slot);
    return w;
}

/* 把值 v 加载到寄存器 w：v 已在 w 跳过；否则按 寄存器/常量/溢出槽 顺序 */
static int load_value_to_wr(ISelContext* isel, ValueName v, int w) {
    C251GenContext *ctx = isel->ctx;
    char wbuf[16]; wr_name(wbuf, sizeof(wbuf), w);
    int r = isel_value_reg(ctx, v);
    if (r == w) return 0;
    if (r >= 0) { char rbuf[16]; wr_name(rbuf, sizeof(rbuf), r); isel_emit(isel, "MOV", wbuf, rbuf); return 0; }
    char *k = c251_key(v);
    int64_t *cv = (int64_t*)dict_get(ctx->value_to_const, k);
    free(k);
    if (cv) {
        char imm[32]; snprintf(imm, sizeof(imm), "#%lld", *cv & 0xFFFF);
        isel_emit(isel, "MOV", wbuf, imm);
        return 0;
    }
    char *sp = c251_value_spill(ctx, v);
    if (sp) { isel_emit(isel, "MOV", wbuf, sp); return 0; }
    fprintf(stderr, "c251 isel: 值 %d 无寄存器/常量/槽可加载\n", v);
    return -1;
}

/* 查 ADDR 产物指向的全局符号名（无则 NULL） */
static char* value_to_addr_lookup(C251GenContext* ctx, ValueName val) {
    if (!ctx || !ctx->value_to_addr) return NULL;
    char *k = c251_key(val);
    char *sym = (char*)dict_get(ctx->value_to_addr, k);
    free(k);
    return sym;
}

/* 从 SSA 指令取 src1/src2 值名 */
static ValueName src1_of(Instr* ins) {
    if (!ins->args || list_len(ins->args) < 1) return -1;
    return *(ValueName*)list_get(ins->args, 0);
}
static ValueName src2_of(Instr* ins) {
    if (!ins->args || list_len(ins->args) < 2) return -1;
    return *(ValueName*)list_get(ins->args, 1);
}

/* 生成内部标签名（无冒号）；发射时用 isel_emit_label */
static char* isel_new_label(ISelContext* isel, const char* prefix) {
    char buf[48];
    snprintf(buf, sizeof(buf), "%s%d", prefix, isel->label_counter++);
    return strdup(buf);
}

static void isel_emit_label(ISelContext* isel, const char* name) {
    if (!name) return;
    char *s = malloc(strlen(name) + 2);
    sprintf(s, "%s:", name);
    isel_emit(isel, s, NULL, NULL);
    free(s);
}

/* 值类型 unsigned 判断（def 时 value_type 已记录）；未知默认有符号（C 语义） */
static bool value_is_unsigned(ISelContext* isel, ValueName v) {
    C251GenContext *ctx = isel->ctx;
    if (v >= 0) {
        char *k = c251_key(v);
        Ctype *t = (Ctype*)dict_get(ctx->value_type, k);
        free(k);
        if (t) return get_attr(t->attr).ctype_unsigned;
    }
    return false;
}

/* CMP lhs,rhs：lhs 必须物化在寄存器（比较方向不可交换）；rhs 可为寄存器/常量/槽 */
static void emit_cmp(ISelContext* isel, ValueName s1, ValueName s2, int avoid_wr) {
    C251GenContext *ctx = isel->ctx;
    int r1 = isel_value_reg(ctx, s1);
    if (r1 < 0) {
        int t = isel_temp_wr(isel, avoid_wr, -1);
        if (load_value_to_wr(isel, s1, t) < 0) {
            fprintf(stderr, "c251 isel: CMP lhs 无法物化 (v%d)\n", s1);
            return;
        }
        r1 = t;
    }
    char r1buf[16]; wr_name(r1buf, sizeof(r1buf), r1);
    int r2 = isel_value_reg(ctx, s2);
    if (r2 >= 0) {
        char r2buf[16]; wr_name(r2buf, sizeof(r2buf), r2);
        isel_emit(isel, "CMP", r1buf, r2buf);
        return;
    }
    if (s2 >= 0) {
        char *k = c251_key(s2);
        int64_t *cv = (int64_t*)dict_get(ctx->value_to_const, k);
        free(k);
        if (cv) {
            char imm[32]; snprintf(imm, sizeof(imm), "#%lld", *cv & 0xFFFF);
            isel_emit(isel, "CMP", r1buf, imm);
            return;
        }
        char *sp = c251_value_spill(ctx, s2);
        if (sp) {
            int t2 = isel_temp_wr(isel, r1, avoid_wr);
            char t2buf[16]; wr_name(t2buf, sizeof(t2buf), t2);
            isel_emit(isel, "MOV", t2buf, sp);
            isel_emit(isel, "CMP", r1buf, t2buf);
            return;
        }
    }
    fprintf(stderr, "c251 isel: CMP rhs 无来源 (v%d)\n", s2);
    isel_emit(isel, "CMP", r1buf, "#0");
}

/* 比较结果物化为 0/1（M2 简化）：CMP; MOV dest,#0; Bcc L1; MOV dest,#1; L1:
 * jcc = "结果为 0" 时跳走的条件（即比较成立的否定条件） */
static void emit_compare_result(ISelContext* isel, Instr* ins, const char* jcc) {
    C251GenContext *ctx = isel->ctx;
    ValueName s1 = src1_of(ins), s2 = src2_of(ins);
    int wr = isel_alloc_wr(isel, ins->dest);
    emit_cmp(isel, s1, s2, wr);
    char *lbl = isel_new_label(isel, "?C");
    if (wr >= 0) {
        char wbuf[16]; wr_name(wbuf, sizeof(wbuf), wr);
        isel_emit(isel, "MOV", wbuf, "#0");
        isel_emit(isel, jcc, lbl, NULL);
        isel_emit(isel, "MOV", wbuf, "#1");
    } else {
        int tmp = isel_temp_wr(isel, -1, -1);
        char tbuf[16]; wr_name(tbuf, sizeof(tbuf), tmp);
        isel_emit(isel, "MOV", tbuf, "#0");
        isel_emit(isel, jcc, lbl, NULL);
        isel_emit(isel, "MOV", tbuf, "#1");
        char *sp = c251_alloc_spill(ctx, ins->dest);
        isel_emit(isel, "MOV", sp, tbuf);
    }
    isel_emit_label(isel, lbl);
    free(lbl);
}

/* ins->labels 含 "imm" 标记 → 常量值在 ins->imm.ival（ssa_pass 约定） */
static bool has_imm_label(Instr* ins) {
    if (!ins || !ins->labels) return false;
    for (Iter it = list_iter(ins->labels); !iter_end(it);) {
        const char *l = iter_next(&it);
        if (l && strcmp(l, "imm") == 0) return true;
    }
    return false;
}

/* 编码器 imm 支持：ADD/SUB 有 WRj,#imm16（2E/9E）；MUL 只支持 WRj,WRk（AD）。
 * MUL 遇 imm 必须物化到寄存器，否则发射不可编码指令（编码器返回 -1、无字节产生）。 */
static bool op_supports_imm(int op) {
    return op == IROP_ADD || op == IROP_SUB;
}

/* 用立即数发射 op：支持 imm 的 op 直接 op WRj,#imm；否则物化 imm 到临时寄存器再 op */
static void emit_op_with_imm(ISelContext* isel, const char* opm, int op,
                             const char* wbuf, int wr, int r1, long long val) {
    char imm[32]; snprintf(imm, sizeof(imm), "#%lld", val & 0xFFFF);
    if (op_supports_imm(op)) {
        isel_emit(isel, opm, wbuf, imm);
    } else {
        int tmp = isel_temp_wr(isel, wr, r1);
        char tbuf[16]; wr_name(tbuf, sizeof(tbuf), tmp);
        isel_emit(isel, "MOV", tbuf, imm);
        isel_emit(isel, opm, wbuf, tbuf);
    }
}

/* 发射 "opm wbuf(已含 s1), src2"：src2 可为 寄存器/常量/溢出槽/imm-label */
static void emit_binop_src2(ISelContext* isel, const char* opm, int op,
                            const char* wbuf, int w, ValueName s1, ValueName s2,
                            bool imm_label, long long imm_val) {
    C251GenContext *ctx = isel->ctx;
    int r2 = isel_value_reg(ctx, s2);
    if (r2 >= 0) {
        char r2buf[16]; wr_name(r2buf, sizeof(r2buf), r2);
        isel_emit(isel, opm, wbuf, r2buf);
        return;
    }
    int64_t *cv = NULL;
    if (s2 >= 0) {
        char *k = c251_key(s2);
        cv = (int64_t*)dict_get(ctx->value_to_const, k);
        free(k);
    }
    if (cv) { emit_op_with_imm(isel, opm, op, wbuf, w, isel_value_reg(ctx, s1), *cv); return; }
    if (s2 >= 0) {
        char *sp = c251_value_spill(ctx, s2);
        if (sp) {
            int t2 = isel_temp_wr(isel, w, isel_value_reg(ctx, s1));
            char t2buf[16]; wr_name(t2buf, sizeof(t2buf), t2);
            isel_emit(isel, "MOV", t2buf, sp);
            isel_emit(isel, opm, wbuf, t2buf);
            return;
        }
        fprintf(stderr, "c251 isel: op 的 s2 无寄存器/常量/槽 (v%d)\n", s2);
        isel_emit(isel, "MOV", wbuf, "#0");
        return;
    }
    if (imm_label) { emit_op_with_imm(isel, opm, op, wbuf, w, isel_value_reg(ctx, s1), imm_val); return; }
    /* 单操作数兜底 */
    isel_emit(isel, "MOV", wbuf, "#0");
}

void isel_instr(ISelContext* isel, Instr* ins, Instr* next) {
    if (!isel || !ins) return;
    C251GenContext *ctx = isel->ctx;

    /* 记录值类型（供比较有符号判断等；def 先于 use，SSA 顺序保证） */
    if (ins->dest >= 0 && ins->type) {
        dict_put(ctx->value_type, c251_key(ins->dest), ins->type);
    }

    switch (ins->op) {
    case IROP_NOP:
        break;
    case IROP_CONST: {
        /* 记录常量值（供 imm 折叠；任何分配路径都记录） */
        int64_t *cv = malloc(sizeof(int64_t)); *cv = ins->imm.ival;
        dict_put(ctx->value_to_const, c251_key(ins->dest), cv);

        int wr = isel_alloc_wr(isel, ins->dest);
        char imm[32];
        int is_byte = ins->type && ins->type->size <= 1;
        snprintf(imm, sizeof(imm), "#%lld",
                 is_byte ? (ins->imm.ival & 0xFF) : (ins->imm.ival & 0xFFFF));
        if (wr >= 0) {
            char wbuf[16]; wr_name(wbuf, sizeof(wbuf), wr);
            isel_emit(isel, "MOV", wbuf, imm);
        } else {
            /* dest 溢出：临时寄存器存槽（编码器无 MOV dir16,#imm） */
            int tmp = isel_temp_wr(isel, -1, -1);
            char tbuf[16]; wr_name(tbuf, sizeof(tbuf), tmp);
            isel_emit(isel, "MOV", tbuf, imm);
            char *sp = c251_alloc_spill(ctx, ins->dest);
            isel_emit(isel, "MOV", sp, tbuf);
        }
        break;
    }
    case IROP_PARAM:
        break; /* M1: 参数直接是 SSA 值，无需额外处理 */
    case IROP_ADD:
    case IROP_SUB:
    case IROP_MUL: {
        const char *opm = (ins->op == IROP_ADD) ? "ADD" : (ins->op == IROP_SUB) ? "SUB" : "MUL";
        ValueName s1 = src1_of(ins), s2 = src2_of(ins);
        bool il = has_imm_label(ins);
        int wr = isel_alloc_wr(isel, ins->dest);
        if (wr >= 0) {
            char wbuf[16]; wr_name(wbuf, sizeof(wbuf), wr);
            load_value_to_wr(isel, s1, wr);
            emit_binop_src2(isel, opm, ins->op, wbuf, wr, s1, s2, il, ins->imm.ival);
        } else {
            /* dest 溢出：计算到临时 → 存槽 */
            int tmp = isel_temp_wr(isel, -1, -1);
            char tbuf[16]; wr_name(tbuf, sizeof(tbuf), tmp);
            load_value_to_wr(isel, s1, tmp);
            emit_binop_src2(isel, opm, ins->op, tbuf, tmp, s1, s2, il, ins->imm.ival);
            char *sp = c251_alloc_spill(ctx, ins->dest);
            isel_emit(isel, "MOV", sp, tbuf);
        }
        break;
    }
    case IROP_EQ: case IROP_NE: case IROP_LT: case IROP_GT: case IROP_LE: case IROP_GE: {
        /* M2 简化：比较结果物化为 0/1 值（BR 直接比较优化在任务 5） */
        bool us = value_is_unsigned(isel, src1_of(ins)) || value_is_unsigned(isel, src2_of(ins));
        const char *jcc;
        switch (ins->op) {
        case IROP_EQ: jcc = "JNE"; break;               /* 相等→1；不等跳走置 0 */
        case IROP_NE: jcc = "JE";  break;               /* 不等→1；相等跳走置 0 */
        case IROP_LT: jcc = us ? "JNC" : "JSGE"; break;/* 无符号 a<b→cy=1; 有符号 a<b→N≠OV */
        case IROP_GT: jcc = us ? "JLE" : "JSLE"; break;
        case IROP_LE: jcc = us ? "JG"  : "JSG";  break;
        case IROP_GE: jcc = us ? "JC"  : "JSL";  break;
        default: jcc = "JNE"; break;
        }
        emit_compare_result(isel, ins, jcc);
        break;
    }
    case IROP_RET: {
        ValueName v = src1_of(ins);
        if (v >= 0) {
            int r = isel_value_reg(ctx, v);
            if (r >= 0) {
                if (r != 6) { char rbuf[16]; wr_name(rbuf, sizeof(rbuf), r); isel_emit(isel, "MOV", "WR6", rbuf); }
            } else {
                load_value_to_wr(isel, v, 6);   /* const → MOV WR6,#imm; spill → MOV WR6,__spill_N */
            }
        } else if (has_imm_label(ins)) {
            /* ret const → 常量直接进 WR6 */
            char imm[32]; snprintf(imm, sizeof(imm), "#%lld", ins->imm.ival & 0xFFFF);
            isel_emit(isel, "MOV", "WR6", imm);
        }
        isel_emit(isel, "RET", NULL, NULL);
        break;
    }
    case IROP_LOAD: {
        /* 真实寻址：ptr 是 ADDR 产物 → 查 value_to_addr 得符号名 → MOV WRj,SYMBOL */
        ValueName ptr = src1_of(ins);
        char *sym = value_to_addr_lookup(ctx, ptr);
        int wr = isel_alloc_wr(isel, ins->dest);
        if (sym) {
            if (wr >= 0) {
                char wbuf[16]; wr_name(wbuf, sizeof(wbuf), wr);
                isel_emit(isel, "MOV", wbuf, sym);
            } else {
                int tmp = isel_temp_wr(isel, -1, -1);
                char tbuf[16]; wr_name(tbuf, sizeof(tbuf), tmp);
                isel_emit(isel, "MOV", tbuf, sym);
                char *sp = c251_alloc_spill(ctx, ins->dest);
                isel_emit(isel, "MOV", sp, tbuf);
            }
        } else {
            /* 指针变量/数组元素 → M2.5 支持 */
            fprintf(stderr, "c251 isel: LOAD 指针寻址 M2.5 支持 (v%d)\n", ptr);
            if (wr >= 0) {
                char wbuf[16]; wr_name(wbuf, sizeof(wbuf), wr);
                isel_emit(isel, "MOV", wbuf, "#0");
            } else {
                int tmp = isel_temp_wr(isel, -1, -1);
                char tbuf[16]; wr_name(tbuf, sizeof(tbuf), tmp);
                isel_emit(isel, "MOV", tbuf, "#0");
                char *sp = c251_alloc_spill(ctx, ins->dest);
                isel_emit(isel, "MOV", sp, tbuf);
            }
        }
        break;
    }
    case IROP_STORE: {
        /* store ptr, val → MOV SYMBOL,WRj（编码器 dir16 写形态） */
        ValueName ptr = src1_of(ins), val = src2_of(ins);
        char *sym = value_to_addr_lookup(ctx, ptr);
        if (!sym) {
            fprintf(stderr, "c251 isel: STORE 指针寻址 M2.5 支持 (v%d)\n", ptr);
            break;
        }
        int r = isel_value_reg(ctx, val);
        if (r >= 0) {
            char rbuf[16]; wr_name(rbuf, sizeof(rbuf), r);
            isel_emit(isel, "MOV", sym, rbuf);
        } else {
            /* 值未物化（常量/溢出槽）：加载到临时再存 */
            int tmp = isel_temp_wr(isel, -1, -1);
            char tbuf[16]; wr_name(tbuf, sizeof(tbuf), tmp);
            if (load_value_to_wr(isel, val, tmp) == 0) {
                isel_emit(isel, "MOV", sym, tbuf);
            } else {
                fprintf(stderr, "c251 isel: STORE 值未物化 (v%d)\n", val);
            }
        }
        break;
    }
    case IROP_ADDR: {
        /* 符号名在 labels[0]（带 '@' 前缀），去前缀后记录 dest→符号名 */
        const char *sym = (ins->labels && list_len(ins->labels) > 0)
            ? (const char*)list_get(ins->labels, 0) : NULL;
        if (sym && sym[0] == '@') sym++;
        if (sym && sym[0]) {
            dict_put(ctx->value_to_addr, c251_key(ins->dest), strdup(sym));
        }
        break;
    }
    default:
        break; /* M2 扩展 */
    }
}

void isel_block(ISelContext* isel, Block* block) {
    if (!isel || !block) return;
    /* 构建块指令视图（alloc_wr/死值扫描需要） */
    int n = list_len(block->instrs);
    Instr **arr = malloc(sizeof(Instr*) * (n > 0 ? n : 1));
    int idx = 0;
    for (Iter it = list_iter(block->instrs); !iter_end(it);) {
        arr[idx++] = iter_next(&it);
    }
    isel->block_instrs = arr;
    isel->block_instr_count = idx;
    for (int i = 0; i < idx; i++) {
        isel->block_instr_pos = i;
        /* M1: 无前瞻（isel_instr 的 next 参数暂未使用，M2 引入） */
        isel_instr(isel, arr[i], NULL);
    }
    isel->block_instrs = NULL;
    free(arr);
}

void isel_function(C251GenContext* ctx, Func* func) {
    if (!ctx || !func) return;
    if (ctx->value_to_reg) { dict_free(ctx->value_to_reg, free); ctx->value_to_reg = make_dict(NULL); }
    if (ctx->value_to_const) { dict_free(ctx->value_to_const, free); ctx->value_to_const = make_dict(NULL); }
    if (ctx->value_to_addr) { dict_free(ctx->value_to_addr, free); ctx->value_to_addr = make_dict(NULL); }
    /* value_to_spill 跨函数保留（EDATA 槽可复用；槽符号持续有效） */
    ctx->label_counter = 0;   /* 每函数重置寄存器分配计数器（多函数编译必需） */

    /* 预扫描跨块活值（死值释放的安全边界） */
    Dict *global_live = compute_global_live(func);

    int sec_idx = obj_add_section(ctx->obj, "?PR?", SEC_CODE, 0, 1);
    Section* sec = obj_get_section(ctx->obj, sec_idx);
    int flags = SYM_FLAG_GLOBAL;
    obj_add_symbol(ctx->obj, func->name, SYM_FUNC, sec_idx, sec->size, 0, flags);
    ctx->current_func = func;

    ISelContext isel = {0};
    isel.ctx = ctx;
    isel.sec = sec;
    isel.label_counter = 0;
    isel.next_wr = 0;
    for (int i = 0; i < 4; i++) isel.reg_val[i] = -1;
    isel.global_live = global_live;

    /* 函数标签 */
    char label[256];
    snprintf(label, sizeof(label), "_%s:", func->name);
    isel_emit(&isel, label, NULL, NULL);

    for (Iter it = list_iter(func->blocks); !iter_end(it);) {
        Block* block = iter_next(&it);
        isel_block(&isel, block);
    }

    dict_free(global_live, free);
}
