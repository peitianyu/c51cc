#include "c51_regalloc.h"
#include <stdlib.h>
#include <string.h>

/* C51参数寄存器约定（定义在此处） */
const int param_regs_char[] = {7, 5, 3, 2, 4, 6};
const int param_regs_int_h[] = {6, 4, 2};
const int param_regs_int_l[] = {7, 5, 3};

/* 为值分配寄存器（参照原实现，优先使用高编号寄存器） */
int alloc_reg_for_value(ISelContext* isel, ValueName val, int size) {
    if (!isel || !isel->ctx) return -1;

    int existing = isel_get_value_reg(isel, val);
    if (existing >= 0) return existing;

    /* 使用R0、R1、R2作为临时寄存器（不用R3-R7，它们保留给参数） */
    for (int reg = 2; reg >= 0; reg--) {
        if (reg + size > 3) continue;  /* 只使用R0、R1、R2 */

        bool available = true;
        for (int j = 0; j < size; j++) {
            if (isel->reg_busy[reg + j]) { available = false; break; }
        }

        if (available) {
            for (int j = 0; j < size; j++) {
                isel->reg_busy[reg + j] = true;
                isel->reg_val[reg + j] = val;
            }

            int* reg_num = malloc(sizeof(int));
            *reg_num = reg;
            char* key = int_to_key(val);
            dict_put(isel->ctx->value_to_reg, key, reg_num);

            return reg;
        }
    }

    return -1;  /* 不再默认返回0，返回-1表示分配失败，让调用者使用默认值 */
}

/* 为函数参数分配寄存器（扫描 entry 中的 PARAM 指令） */
void alloc_param_regs(ISelContext* isel, Func* f) {
    if (!f->params || !f->param_types) return;

    int param_idx = 0;
    Iter pit = list_iter(f->params);
    Iter tit = list_iter(f->param_types);

    while (!iter_end(pit) && !iter_end(tit)) {
        char* param_name = iter_next(&pit);
        Ctype* param_type = iter_next(&tit);

        if (f->entry && f->entry->instrs) {
            for (Iter it = list_iter(f->entry->instrs); !iter_end(it);) {
                Instr* ins = iter_next(&it);
                if (ins && ins->op == IROP_PARAM && ins->labels && ins->labels->len > 0) {
                    const char* name = list_get(ins->labels, 0);
                    if (name && param_name && strcmp(name, param_name) == 0) {
                        int size = param_type ? param_type->size : 1;
                        int reg = -1;

                        if (size == 1) {
                            if (param_idx < 6) reg = param_regs_char[param_idx];
                        } else {
                            if (param_idx < 3) reg = param_regs_int_h[param_idx];
                        }

                        if (reg >= 0) {
                            int* reg_num = malloc(sizeof(int));
                            *reg_num = reg;
                            dict_put(isel->ctx->value_to_reg, int_to_key(ins->dest), reg_num);

                            for (int j = 0; j < size && (reg + j) < 8; j++) {
                                isel->reg_busy[reg + j] = true;
                                isel->reg_val[reg + j] = ins->dest;
                            }
                        }
                        break;
                    }
                }
            }
        }
        param_idx++;
    }
}
