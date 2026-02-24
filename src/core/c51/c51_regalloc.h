#ifndef C51_REGALLOC_H
#define C51_REGALLOC_H

#include "c51_isel.h"

/* 寄存器约定声明（在 c51_regalloc.c 中定义） */
extern const int param_regs_char[];
extern const int param_regs_int_h[];
extern const int param_regs_int_l[];

/* 为值分配寄存器（返回分配的基寄存器号） */
int alloc_reg_for_value(ISelContext* isel, ValueName val, int size);

/* 为函数参数分配寄存器 */
void alloc_param_regs(ISelContext* isel, Func* f);

#endif
