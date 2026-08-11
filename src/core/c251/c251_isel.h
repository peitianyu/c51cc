#ifndef C251_ISEL_H
#define C251_ISEL_H

#include "c251_gen.h"

/* 指令选择上下文（M1 精简版） */
typedef struct ISelContext {
    C251GenContext* ctx;
    Section* sec;
    int label_counter;
    /* 简化寄存器分配状态（M2 换分层 linscan） */
    int next_wr;            /* 下一个可分配 WR 索引: 0/2/4/6 */
} ISelContext;

/* 指令选择主入口 */
void isel_function(C251GenContext* ctx, Func* func);
void isel_block(ISelContext* isel, Block* block);
void isel_instr(ISelContext* isel, Instr* ins, Instr* next);

/* 发射汇编指令 */
void isel_emit(ISelContext* isel, const char* op, const char* arg1, const char* arg2);

/* 值 → 寄存器分配（M1 简化：WR0/2/4/6 顺序分配，超 4 个活值显式报错） */
int isel_alloc_wr(C251GenContext* ctx, ValueName val);
int isel_value_reg(C251GenContext* ctx, ValueName val);

#endif
