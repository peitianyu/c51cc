#include "c51_regalloc.h"
#include <stdlib.h>
#include <string.h>

/* C51参数寄存器约定（定义在此处） */
const int param_regs_char[] = {7, 5, 3, 2, 4, 6};
const int param_regs_int_h[] = {6, 4, 2};
const int param_regs_int_l[] = {7, 5, 3};

/* ============================================================
 * 线性扫描寄存器分配实现
 * ============================================================ */

/* 全局线性扫描上下文（在函数处理期间使用） */
static LinearScanContext* g_linscan_ctx = NULL;
static C51GenContext* g_gen_ctx = NULL;

/* 比较函数：按start时间排序活跃区间 */
static int compare_intervals(const void* a, const void* b) {
    int idx_a = *(const int*)a;
    int idx_b = *(const int*)b;
    
    if (!g_linscan_ctx) return 0;
    
    LiveInterval* ia = &g_linscan_ctx->intervals[idx_a];
    LiveInterval* ib = &g_linscan_ctx->intervals[idx_b];
    
    if (ia->start != ib->start) return ia->start - ib->start;
    return ia->end - ib->end;
}

/* 初始化线性扫描分配器 */
LinearScanContext* linscan_create(void) {
    LinearScanContext* lsc = malloc(sizeof(LinearScanContext));
    memset(lsc, 0, sizeof(LinearScanContext));
    
    lsc->interval_capacity = 256;
    lsc->intervals = malloc(sizeof(LiveInterval) * lsc->interval_capacity);
    memset(lsc->intervals, 0, sizeof(LiveInterval) * lsc->interval_capacity);
    lsc->interval_count = 0;
    
    lsc->active_regs[0] = -1;
    lsc->active_regs[1] = -1;
    lsc->active_regs[2] = -1;
    lsc->active_reg_end[0] = -1;
    lsc->active_reg_end[1] = -1;
    lsc->active_reg_end[2] = -1;
    
    return lsc;
}

/* 销毁线性扫描分配器 */
void linscan_destroy(LinearScanContext* lsc) {
    if (!lsc) return;
    
    if (lsc->intervals) free(lsc->intervals);
    if (lsc->sorted_intervals) free(lsc->sorted_intervals);
    
    free(lsc);
}

/* 递归获取值定义的指令序号（用于PHI） */
static int get_value_def_idx(ValueName val, Func* func, int* idx_map) {
    if (!func) return 0;
    
    /* 快速查询已计算的 */
    if (idx_map && val > 0 && val < 1000000) {
        int cached = idx_map[val];
        if (cached >= 0) return cached;
    }
    
    /* 遍历所有块查找定义 */
    int current_idx = 0;
    for (Iter bit = list_iter(func->blocks); !iter_end(bit);) {
        Block* block = iter_next(&bit);
        
        if (block->instrs) {
            for (Iter it = list_iter(block->instrs); !iter_end(it);) {
                Instr* ins = iter_next(&it);
                if (ins && ins->dest == val) {
                    if (idx_map && val > 0 && val < 1000000) {
                        idx_map[val] = current_idx;
                    }
                    return current_idx;
                }
                current_idx++;
            }
        }
        
        if (block->phis) {
            for (Iter it = list_iter(block->phis); !iter_end(it);) {
                Instr* ins = iter_next(&it);
                if (ins && ins->dest == val) {
                    if (idx_map && val > 0 && val < 1000000) {
                        idx_map[val] = current_idx;
                    }
                    return current_idx;
                }
                current_idx++;
            }
        }
    }
    
    return 0;
}

/* 为函数的所有指令计算活跃区间 */
void linscan_compute_intervals(LinearScanContext* lsc, Func* func, C51GenContext* genctx) {
    if (!lsc || !func) return;
    
    lsc->interval_count = 0;
    
    /* 映射表：ValueName -> 最后使用的指令序号 */
    int* last_use = malloc(sizeof(int) * 1000000);
    memset(last_use, -1, sizeof(int) * 1000000);
    
    /* 映射表：ValueName -> 定义的指令序号 */
    int* def_idx = malloc(sizeof(int) * 1000000);
    memset(def_idx, -1, sizeof(int) * 1000000);
    
    int instr_count = 0;
    
    /* 第一遍：找出每个值的最后使用位置 */
    for (Iter bit = list_iter(func->blocks); !iter_end(bit);) {
        Block* block = iter_next(&bit);
        
        if (block->instrs) {
            for (Iter it = list_iter(block->instrs); !iter_end(it);) {
                Instr* ins = iter_next(&it);
                
                if (ins) {
                    /* 记录该指令使用的所有值 */
                    if (ins->args) {
                        for (int j = 0; j < ins->args->len; j++) {
                            ValueName* pv = list_get(ins->args, j);
                            if (pv && *pv > 0 && *pv < 1000000) {
                                last_use[*pv] = instr_count;
                            }
                        }
                    }
                    
                    instr_count++;
                }
            }
        }
    }
    
    /* 第二遍：为每个值创建活跃区间 */
    instr_count = 0;
    for (Iter bit = list_iter(func->blocks); !iter_end(bit);) {
        Block* block = iter_next(&bit);
        
        if (block->instrs) {
            for (Iter it = list_iter(block->instrs); !iter_end(it);) {
                Instr* ins = iter_next(&it);
                
                if (ins && ins->dest > 0 && ins->dest < 1000000) {
                    /* 检查是否已为该值创建区间 */
                    bool found = false;
                    for (int i = 0; i < lsc->interval_count; i++) {
                        if (lsc->intervals[i].val == ins->dest) {
                            found = true;
                            break;
                        }
                    }
                    
                    if (!found) {
                        /* 新建活跃区间 */
                        if (lsc->interval_count >= lsc->interval_capacity) {
                            lsc->interval_capacity *= 2;
                            lsc->intervals = realloc(lsc->intervals, 
                                                      sizeof(LiveInterval) * lsc->interval_capacity);
                        }
                        
                        LiveInterval* iv = &lsc->intervals[lsc->interval_count];
                        iv->val = ins->dest;
                        iv->start = instr_count;
                        iv->end = (ins->dest > 0 && ins->dest < 1000000) ? last_use[ins->dest] : instr_count;
                        if (iv->end < iv->start) iv->end = iv->start;  /* 值被定义但未使用 */
                        
                        /* 获取值大小 */
                        iv->size = 1;
                        if (genctx && genctx->value_type && ins->type) {
                            iv->size = ins->type->size > 0 ? ins->type->size : 1;
                        }
                        
                        iv->reg = -1;
                        iv->spill_slot = -1;
                        iv->is_param = (ins->op == IROP_PARAM);
                        
                        lsc->interval_count++;
                    }
                    
                    instr_count++;
                }
            }
        }
    }
    
    free(last_use);
    free(def_idx);
}

/* 释放寄存器中过期的值 */
static void expire_old_intervals(LinearScanContext* lsc, int current_instr) {
    for (int r = 0; r < 3; r++) {
        if (lsc->active_regs[r] >= 0 && lsc->active_reg_end[r] < current_instr) {
            /* 该寄存器中的值已过期，释放它 */
            lsc->active_regs[r] = -1;
            lsc->active_reg_end[r] = -1;
        }
    }
}

/* 在活跃区间中找到end最大的区间索引 */
static int find_longest_interval(LinearScanContext* lsc) {
    int longest_idx = -1;
    int longest_end = -1;
    
    for (int r = 0; r < 3; r++) {
        if (lsc->active_regs[r] >= 0 && lsc->active_reg_end[r] > longest_end) {
            longest_end = lsc->active_reg_end[r];
            longest_idx = r;
        }
    }
    
    return longest_idx;
}

/* 执行线性扫描寄存器分配 */
void linscan_allocate(LinearScanContext* lsc, C51GenContext* genctx) {
    if (!lsc || !genctx) return;
    
    /* 创建排序数组 */
    lsc->sorted_intervals = malloc(sizeof(int) * lsc->interval_count);
    for (int i = 0; i < lsc->interval_count; i++) {
        lsc->sorted_intervals[i] = i;
    }
    
    /* 全局变量用于qsort中的比较函数 */
    g_linscan_ctx = lsc;
    g_gen_ctx = genctx;
    
    /* 按start时间排序 */
    qsort(lsc->sorted_intervals, lsc->interval_count, sizeof(int), compare_intervals);
    
    /* 清除活跃寄存器列表 */
    for (int r = 0; r < 3; r++) {
        lsc->active_regs[r] = -1;
        lsc->active_reg_end[r] = -1;
    }
    
    /* 处理每个活跃区间 */
    for (int i = 0; i < lsc->interval_count; i++) {
        int idx = lsc->sorted_intervals[i];
        LiveInterval* interval = &lsc->intervals[idx];
        
        /* 释放过期的值 */
        expire_old_intervals(lsc, interval->start);
        
        /* 初始化寄存器为未分配 */
        interval->reg = -1;
        
        /* 参数值不重新分配（已在alloc_param_regs中分配） */
        if (interval->is_param) {
            continue;
        }
        
        /* 尝试分配寄存器 */
        bool allocated = false;
        
        /* 查找空闲寄存器 */
        for (int r = 0; r < 3; r++) {
            if (lsc->active_regs[r] < 0) {
                /* 该寄存器空闲，分配给该区间 */
                lsc->active_regs[r] = interval->val;
                lsc->active_reg_end[r] = interval->end;
                interval->reg = r;
                allocated = true;
                break;
            }
        }
        
        /* 如果没有空闲寄存器，考虑溢出 */
        if (!allocated) {
            int spill_reg = find_longest_interval(lsc);
            
            if (spill_reg >= 0) {
                /* 查找要溢出的区间对象 */
                LiveInterval* spill_interval = NULL;
                int spill_reg_val = lsc->active_regs[spill_reg];
                
                for (int j = 0; j < lsc->interval_count; j++) {
                    if (lsc->intervals[j].val == spill_reg_val) {
                        spill_interval = &lsc->intervals[j];
                        break;
                    }
                }
                
                /* 如果要溢出的值的生命周期比当前值长，则溢出它 */
                if (spill_interval && spill_interval->end > interval->end && 
                    !spill_interval->is_param) {
                    /* 溢出该值到累加器A */
                    spill_interval->reg = -2;  /* -2 表示在A中 */
                    
                    /* 将当前值分配给该寄存器 */
                    lsc->active_regs[spill_reg] = interval->val;
                    lsc->active_reg_end[spill_reg] = interval->end;
                    interval->reg = spill_reg;
                    allocated = true;
                }
            }
            
            /* 仍未分配，放在A中 */
            if (!allocated) {
                interval->reg = -2;  /* -2 表示在A中 */
            }
        }
    }
    
    /* 将分配结果存储到value_to_reg字典中 */
    if (genctx->value_to_reg) {
        for (int i = 0; i < lsc->interval_count; i++) {
            LiveInterval* iv = &lsc->intervals[i];
            
            if (iv->val > 0) {
                /* 跳过参数值，它们已在alloc_param_regs中处理过 */
                if (iv->is_param) {
                    continue;
                }
                
                int* reg_num = malloc(sizeof(int));
                *reg_num = iv->reg;
                
                char* key = int_to_key(iv->val);
                dict_put(genctx->value_to_reg, key, reg_num);
                /* key 已被字典接管 */
            }
        }
    }
}

/* ============================================================
 * 传统（非线性扫描）寄存器分配函数（用于回退）
 * ============================================================ */

/* 为值分配寄存器（返回分配的基寄存器号） */
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

