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

/* 查 ADDR 产物指向的全局符号名（无则 NULL） */
static char* value_to_addr_lookup(C251GenContext* ctx, ValueName val) {
    if (!ctx || !ctx->value_to_addr) return NULL;
    return (char*)dict_get(ctx->value_to_addr, k251_key(val));
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

/* 编码器 imm 支持：ADD/SUB 有 WRj,#imm16（2E/9E）；MUL 只支持 WRj,WRk（AD）。
 * MUL 遇 imm 必须物化到寄存器，否则发射不可编码指令（编码器返回 -1、无字节产生）。 */
static bool op_supports_imm(int op) {
    return op == IROP_ADD || op == IROP_SUB;
}

/* 从 {WR0,WR2,WR4,WR6} 选一个避开 used_a/used_b 的临时寄存器 */
static int pick_temp_wr(int used_a, int used_b) {
    for (int w = 0; w <= 6; w += 2)
        if (w != used_a && w != used_b) return w;
    return 0;
}

/* 用立即数发射 op：支持 imm 的 op 直接 op WRj,#imm；否则物化 imm 到临时寄存器再 op */
static void emit_op_with_imm(ISelContext* isel, const char* opm, int op,
                             const char* wbuf, int wr, int r1, long long val) {
    char imm[32]; snprintf(imm, sizeof(imm), "#%lld", val & 0xFFFF);
    if (op_supports_imm(op)) {
        isel_emit(isel, opm, wbuf, imm);
    } else {
        int tmp = pick_temp_wr(wr, r1);
        char tbuf[16]; wr_name(tbuf, sizeof(tbuf), tmp);
        isel_emit(isel, "MOV", tbuf, imm);
        isel_emit(isel, opm, wbuf, tbuf);
    }
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
                    emit_op_with_imm(isel, opm, ins->op, wbuf, wr, r1, *cv);
                } else {
                    /* 罕见兜底: 未知 s2 → 物化 #0（M2 完整处理） */
                    char w2buf[16]; wr_name(w2buf, sizeof(w2buf), 0);
                    isel_emit(isel, "MOV", w2buf, "#0");
                    isel_emit(isel, opm, wbuf, w2buf);
                }
            }
        } else if (has_imm_label(ins)) {
            /* ssa_pass 常量内联: args=[lhs], labels=["imm"], imm.ival=常量 */
            emit_op_with_imm(isel, opm, ins->op, wbuf, wr, r1, ins->imm.ival);
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
        /* 真实寻址：ptr 是 ADDR 产物 → 查 value_to_addr 得符号名 → MOV WRj,SYMBOL */
        ValueName ptr = src1_of(ins);
        char *sym = value_to_addr_lookup(ctx, ptr);
        int wr = isel_alloc_wr(ctx, ins->dest);
        char wbuf[16]; wr_name(wbuf, sizeof(wbuf), wr);
        if (sym) {
            isel_emit(isel, "MOV", wbuf, sym);   /* MOV WRj,dir16 */
        } else {
            /* 指针变量/数组元素 → M2.5 支持 */
            fprintf(stderr, "c251 isel: LOAD 指针寻址 M2.5 支持 (v%d)\n", ptr);
            isel_emit(isel, "MOV", wbuf, "#0");
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
            /* 值未物化：查常量 → 物化临时寄存器再 MOV（编码器无 MOV SYM,#imm 形态） */
            int64_t *cv = (int64_t*)dict_get(ctx->value_to_const, k251_key(val));
            if (cv) {
                int tmp = pick_temp_wr(-1, -1);
                char tbuf[16]; wr_name(tbuf, sizeof(tbuf), tmp);
                char imm[32]; snprintf(imm, sizeof(imm), "#%lld", *cv & 0xFFFF);
                isel_emit(isel, "MOV", tbuf, imm);
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
            dict_put(ctx->value_to_addr, k251_key(ins->dest), strdup(sym));
        }
        break;
    }
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
    if (ctx->value_to_addr) { dict_free(ctx->value_to_addr, free); ctx->value_to_addr = make_dict(NULL); }
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
