#include "c251_isel.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 值名 → dict key（malloc，dict_free 负责释放；与 c51 的 int_to_key 同模式） */
static char* k251_key(int n) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%02XH", n);
    return strdup(buf);
}

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

int isel_alloc_wr(C251GenContext* ctx, ValueName val) {
    /* M1: 顺序分配 WR0/2/4/6；已分配过的值复用；超 4 个活值显式报错（M2 换分层 linscan） */
    char key[32]; snprintf(key, sizeof(key), "%02XH", val);
    int *exist = (int*)dict_get(ctx->value_to_reg, key);
    if (exist) return *exist;
    int wr = ctx->label_counter * 2;   /* 独立分配计数器: 0→0, 1→2, 2→4, 3→6 */
    if (wr > 6) {
        fprintf(stderr, "c251 isel: M1 寄存器不足 (值 %d), 溢出支持在 M2\n", val);
        wr = 0;
    }
    ctx->label_counter++;
    int *slot = malloc(sizeof(int)); *slot = wr;
    dict_put(ctx->value_to_reg, k251_key(val), slot);
    return wr;
}

int isel_value_reg(C251GenContext* ctx, ValueName val) {
    char key[32]; snprintf(key, sizeof(key), "%02XH", val);
    int *r = (int*)dict_get(ctx->value_to_reg, key);
    return r ? *r : -1;
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

/* ins->labels 含 "imm" 标记 → 常量值在 ins->imm.ival（ssa_pass 约定） */
static bool has_imm_label(Instr* ins) {
    if (!ins || !ins->labels) return false;
    for (Iter it = list_iter(ins->labels); !iter_end(it);) {
        const char *l = iter_next(&it);
        if (l && strcmp(l, "imm") == 0) return true;
    }
    return false;
}

void isel_instr(ISelContext* isel, Instr* ins, Instr* next) {
    if (!isel || !ins) return;
    C251GenContext *ctx = isel->ctx;

    switch (ins->op) {
    case IROP_NOP:
        break;
    case IROP_CONST: {
        int wr = isel_alloc_wr(ctx, ins->dest);
        char wbuf[16]; wr_name(wbuf, sizeof(wbuf), wr);
        char imm[32];
        int is_byte = ins->type && ins->type->size <= 1;
        if (is_byte)
            snprintf(imm, sizeof(imm), "#%lld", ins->imm.ival & 0xFF);
        else
            snprintf(imm, sizeof(imm), "#%lld", ins->imm.ival & 0xFFFF);
        isel_emit(isel, "MOV", wbuf, imm);
        /* 记录常量值（供 ADD #imm 折叠） */
        int64_t *cv = malloc(sizeof(int64_t)); *cv = ins->imm.ival;
        dict_put(ctx->value_to_const, k251_key(ins->dest), cv);
        break;
    }
    case IROP_PARAM:
        break; /* M1: 参数直接是 SSA 值，无需额外处理 */
    case IROP_ADD:
    case IROP_SUB:
    case IROP_MUL: {
        int wr = isel_alloc_wr(ctx, ins->dest);
        const char *opm = (ins->op == IROP_ADD) ? "ADD" : (ins->op == IROP_SUB) ? "SUB" : "MUL";
        char wbuf[16]; wr_name(wbuf, sizeof(wbuf), wr);

        /* 物化 s1 到 dest（dest = s1 op s2） */
        ValueName s1 = src1_of(ins);
        int r1 = isel_value_reg(ctx, s1);
        if (r1 >= 0 && r1 != wr) {
            char r1buf[16]; wr_name(r1buf, sizeof(r1buf), r1);
            isel_emit(isel, "MOV", wbuf, r1buf);
        }

        ValueName s2 = src2_of(ins);
        if (s2 >= 0) {
            int r2 = isel_value_reg(ctx, s2);
            if (r2 >= 0) {
                char r2buf[16]; wr_name(r2buf, sizeof(r2buf), r2);
                isel_emit(isel, opm, wbuf, r2buf);
            } else {
                /* s2 无寄存器：查 value_to_const（CONST 已物化但被跳过的兜底） */
                int64_t *cv = (int64_t*)dict_get(ctx->value_to_const, k251_key(s2));
                if (cv) {
                    char imm[32]; snprintf(imm, sizeof(imm), "#%lld", *cv & 0xFFFF);
                    isel_emit(isel, opm, wbuf, imm);
                } else {
                    /* 罕见兜底: 未知 s2 → 物化 #0（M2 完整处理） */
                    char w2buf[16]; wr_name(w2buf, sizeof(w2buf), 0);
                    isel_emit(isel, "MOV", w2buf, "#0");
                    isel_emit(isel, opm, wbuf, w2buf);
                }
            }
        } else if (has_imm_label(ins)) {
            /* ssa_pass 常量内联: args=[lhs], labels=["imm"], imm.ival=常量 */
            char imm[32]; snprintf(imm, sizeof(imm), "#%lld", ins->imm.ival & 0xFFFF);
            isel_emit(isel, opm, wbuf, imm);
        } else {
            /* 单操作数无 imm（TRUNC 语义不应到 ADD）: 兜底 */
            char w2buf[16]; wr_name(w2buf, sizeof(w2buf), 0);
            isel_emit(isel, "MOV", w2buf, "#0");
            isel_emit(isel, opm, wbuf, w2buf);
        }
        break;
    }
    case IROP_RET: {
        ValueName v = src1_of(ins);
        if (v >= 0) {
            int r = isel_value_reg(ctx, v);
            if (r >= 0 && r != 6) {
                char rbuf[16]; wr_name(rbuf, sizeof(rbuf), r);
                isel_emit(isel, "MOV", "WR6", rbuf);
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
        /* M1: 占位（真实寻址 M2；当前产生占位 MOV 防值无定义） */
        int wr = isel_alloc_wr(ctx, ins->dest);
        char wbuf[16]; wr_name(wbuf, sizeof(wbuf), wr);
        isel_emit(isel, "MOV", wbuf, "#0");
        break;
    }
    case IROP_STORE:
    case IROP_ADDR:
        break; /* M1 占位，M2 实现 */
    default:
        break; /* M2 扩展 */
    }
}

void isel_block(ISelContext* isel, Block* block) {
    if (!isel || !block) return;
    for (Iter it = list_iter(block->instrs); !iter_end(it);) {
        Instr *ins = iter_next(&it);
        /* M1: 无前瞻（isel_instr 的 next 参数暂未使用，M2 引入） */
        isel_instr(isel, ins, NULL);
    }
}

void isel_function(C251GenContext* ctx, Func* func) {
    if (!ctx || !func) return;
    if (ctx->value_to_reg) { dict_free(ctx->value_to_reg, free); ctx->value_to_reg = make_dict(NULL); }
    if (ctx->value_to_const) { dict_free(ctx->value_to_const, free); ctx->value_to_const = make_dict(NULL); }
    ctx->label_counter = 0;   /* 每函数重置寄存器分配计数器（多函数编译必需） */

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

    /* 函数标签 */
    char label[256];
    snprintf(label, sizeof(label), "_%s:", func->name);
    isel_emit(&isel, label, NULL, NULL);

    for (Iter it = list_iter(func->blocks); !iter_end(it);) {
        Block* block = iter_next(&it);
        isel_block(&isel, block);
    }
}
