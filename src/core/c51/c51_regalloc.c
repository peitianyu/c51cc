#include "c51_regalloc.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

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

/* Keil约定下，R6/R7主要承担返回值与参数传递，
 * 临时值优先使用 R0-R5，避免与ABI关键寄存器冲突。 */
static const int k_temp_reg_min = 0;
static const int k_temp_reg_max = 7;

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
    
    /* 初始化可分配的寄存器列表 (R0-R7，除了特殊用途的) */
    for (int r = 0; r < 8; r++) {
        lsc->active_regs[r] = -1;
        lsc->active_reg_end[r] = -1;
    }
    
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
    (void)genctx;

    const int kMaxValue = 1000000;
    lsc->interval_count = 0;

    int* val_to_iv = malloc(sizeof(int) * kMaxValue);
    for (int i = 0; i < kMaxValue; i++) val_to_iv[i] = -1;

    int instr_idx = 0;

    for (Iter bit = list_iter(func->blocks); !iter_end(bit);) {
        Block* block = iter_next(&bit);

        /* PHI 和普通指令按线性顺序统一处理 */
        for (int pass = 0; pass < 2; pass++) {
            List* lst = (pass == 0) ? block->phis : block->instrs;
            if (!lst) continue;

            for (Iter it = list_iter(lst); !iter_end(it);) {
                Instr* ins = iter_next(&it);
                if (!ins) continue;

                if (ins->dest > 0 && ins->dest < kMaxValue) {
                    int iv_idx = val_to_iv[ins->dest];
                    if (iv_idx < 0) {
                        if (lsc->interval_count >= lsc->interval_capacity) {
                            lsc->interval_capacity *= 2;
                            lsc->intervals = realloc(lsc->intervals,
                                sizeof(LiveInterval) * lsc->interval_capacity);
                        }
                        iv_idx = lsc->interval_count++;
                        val_to_iv[ins->dest] = iv_idx;

                        LiveInterval* iv = &lsc->intervals[iv_idx];
                        iv->val = ins->dest;
                        iv->start = instr_idx;
                        iv->end = instr_idx;
                        iv->size = (ins->type && ins->type->size > 0) ? ins->type->size : 1;
                        iv->reg = -1;
                        iv->spill_slot = -1;
                        iv->is_param = (ins->op == IROP_PARAM);
                    } else {
                        LiveInterval* iv = &lsc->intervals[iv_idx];
                        if (instr_idx < iv->start) iv->start = instr_idx;
                        if (instr_idx > iv->end) iv->end = instr_idx;
                    }
                }

                if (ins->args) {
                    for (int j = 0; j < ins->args->len; j++) {
                        ValueName* pv = list_get(ins->args, j);
                        if (!pv || *pv <= 0 || *pv >= kMaxValue) continue;

                        int iv_idx = val_to_iv[*pv];
                        if (iv_idx < 0) {
                            /* 防御：先用使用点建立区间，后续遇到定义再回填start */
                            if (lsc->interval_count >= lsc->interval_capacity) {
                                lsc->interval_capacity *= 2;
                                lsc->intervals = realloc(lsc->intervals,
                                    sizeof(LiveInterval) * lsc->interval_capacity);
                            }
                            iv_idx = lsc->interval_count++;
                            val_to_iv[*pv] = iv_idx;

                            LiveInterval* iv = &lsc->intervals[iv_idx];
                            iv->val = *pv;
                            iv->start = instr_idx;
                            iv->end = instr_idx;
                            iv->size = 1;
                            iv->reg = -1;
                            iv->spill_slot = -1;
                            iv->is_param = false;
                        } else {
                            LiveInterval* iv = &lsc->intervals[iv_idx];
                            if (instr_idx > iv->end) iv->end = instr_idx;
                        }
                    }
                }

                instr_idx++;
            }
        }
    }

    free(val_to_iv);
}

/* 释放寄存器中过期的值 */
static void expire_old_intervals(LinearScanContext* lsc, int current_instr) {
    for (int r = 0; r < 8; r++) {
        if (lsc->active_regs[r] >= 0 && lsc->active_reg_end[r] <= current_instr) {
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
    
    for (int r = k_temp_reg_min; r <= k_temp_reg_max; r++) {
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
    for (int r = 0; r < 8; r++) {
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

        /* 参数值：它们已经被预先分配到参数约定的寄存器 */
        if (interval->is_param) {
            char* key = int_to_key(interval->val);
            int* param_reg_ptr = (int*)dict_get(genctx->value_to_reg, key);
            free(key);
            if (param_reg_ptr) {
                interval->reg = *param_reg_ptr;
                if (interval->reg >= 0 && interval->reg < 8) {
                    lsc->active_regs[interval->reg] = interval->val;
                    lsc->active_reg_end[interval->reg] = interval->end;
                    if (interval->size == 2 && interval->reg + 1 < 8) {
                        lsc->active_regs[interval->reg + 1] = interval->val;
                        lsc->active_reg_end[interval->reg + 1] = interval->end;
                    }
                }
            }
            continue;
        }

        /* 返回值寄存器保护：如果是函数返回值，生命周期内禁止分配R7/R6等 */
        // TODO: 可根据函数返回类型进一步保护R7/R6/R5/R4等

        /* 尝试分配寄存器：按Keil约定优先使用R0-R5 */
        bool allocated = false;
        for (int r = k_temp_reg_min; r <= k_temp_reg_max; r++) {
            /* 跳过生命周期未结束的参数/返回寄存器 */
            if (lsc->active_regs[r] >= 0 && lsc->active_reg_end[r] >= interval->start) continue;
            /* 双字节变量需保证r+1也可用且不冲突 */
            if (interval->size == 2) {
                if (r + 1 > k_temp_reg_max) continue;
                if ((lsc->active_regs[r + 1] >= 0 && lsc->active_reg_end[r + 1] >= interval->start)) continue;
            }
            /* 分配 */
            lsc->active_regs[r] = interval->val;
            lsc->active_reg_end[r] = interval->end;
            interval->reg = r;
            if (interval->size == 2) {
                lsc->active_regs[r + 1] = interval->val;
                lsc->active_reg_end[r + 1] = interval->end;
            }
            allocated = true;
            break;
        }

        /* 如果没有空闲寄存器，优先抢占生命周期最晚结束的临时寄存器 */
        if (!allocated) {
            int spill_reg = find_longest_interval(lsc);
            if (spill_reg >= 0) {
                LiveInterval* spill_interval = NULL;
                int spill_reg_val = lsc->active_regs[spill_reg];
                for (int j = 0; j < lsc->interval_count; j++) {
                    if (lsc->intervals[j].val == spill_reg_val) {
                        spill_interval = &lsc->intervals[j];
                        break;
                    }
                }
                if (spill_interval && spill_interval->end > interval->end && !spill_interval->is_param) {
                    spill_interval->reg = -1;  /* 被抢占，后续按需重分配 */
                    lsc->active_regs[spill_reg] = interval->val;
                    lsc->active_reg_end[spill_reg] = interval->end;
                    interval->reg = spill_reg;
                    if (interval->size == 2 && spill_reg + 1 <= k_temp_reg_max) {
                        lsc->active_regs[spill_reg + 1] = interval->val;
                        lsc->active_reg_end[spill_reg + 1] = interval->end;
                    }
                    allocated = true;
                }
            }
            if (!allocated) {
                /* 无空寄存器可用：将此区间 spill 到内存（生成一个临时 spill 符号） */
                if (genctx) {
                    int sid = genctx->next_spill_id++;
                    char buf[64];
                    snprintf(buf, sizeof(buf), "__spill_%d", sid);
                    char* name = strdup(buf);

                    /* 把 spill 符号记录到 value_to_addr（便于后续 emit_load/emit_store 使用）
                     * 并在 ObjFile 中为该符号分配数据段空间，使其成为可链接的数据符号。 */
                    char* key = int_to_key(interval->val);
                    dict_put(genctx->value_to_addr, key, name);

                    /* 在目标 ObjFile 中为 spill 符号创建合适的 section 并注册符号 */
                    if (genctx->obj) {
                        SectionKind use_kind = genctx->spill_section;
                        if (genctx->spill_use_xdata_for_large && interval->size > 1) {
                            use_kind = SEC_XDATA;
                        }
                        const char* sec_name = "?DT?";
                        if (use_kind == SEC_IDATA) sec_name = "?ID?";
                        else if (use_kind == SEC_XDATA) sec_name = "?XD?";
                        else if (use_kind == SEC_DATA) sec_name = "?DT?";

                        int sec_idx = obj_add_section(genctx->obj, sec_name, use_kind, 0, 1);
                        Section* sec = obj_get_section(genctx->obj, sec_idx);
                        int offset = sec->size;
                        /* 追加零字节作为占位 */
                        section_append_zeros(sec, interval->size);
                        /* 把符号添加到符号表，设置为局部数据符号 */
                        obj_add_symbol(genctx->obj, name, SYM_DATA, sec_idx, offset, interval->size, SYM_FLAG_LOCAL);
                    }

                    /* 也在 value_to_spill 记录（便于后续查询） */
                    char* key2 = int_to_key(interval->val);
                    char* name2 = strdup(buf);
                    dict_put(genctx->value_to_spill, key2, name2);

                    /* 在 value_to_reg 中标记为已 spill（使用 -3 表示） */
                    int* rptr = malloc(sizeof(int));
                    *rptr = -3;
                    char* key3 = int_to_key(interval->val);
                    dict_put(genctx->value_to_reg, key3, rptr);

                    interval->spill_slot = sid;
                    interval->reg = -3; /* 表示溢出 */
                    continue;
                }

                /* 兜底：避免返回负寄存器导致后续错误默认到R7 */
                interval->reg = k_temp_reg_min;
                lsc->active_regs[k_temp_reg_min] = interval->val;
                lsc->active_reg_end[k_temp_reg_min] = interval->end;
                if (interval->size == 2 && k_temp_reg_min + 1 <= k_temp_reg_max) {
                    lsc->active_regs[k_temp_reg_min + 1] = interval->val;
                    lsc->active_reg_end[k_temp_reg_min + 1] = interval->end;
                }
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
/* 注意：这个函数现在只查询线性扫描已经分配的结果，不再做动态分配 */
int alloc_reg_for_value(ISelContext* isel, ValueName val, int size) {
    if (!isel || !isel->ctx) return -1;

    /* 首先检查是否已经被线性扫描分配过 */
    int existing = isel_get_value_reg(isel, val);
    if (existing >= 0 || existing == -2 || existing == -3) {
        /* 已经在线性扫描中分配了，直接返回 */
        return existing;
    }

    /* 
     * 如果值还没被分配（existing < 0 且不等于 -2），
     * 尝试在残留的未被占用的寄存器中分配
     */
    for (int reg = k_temp_reg_min; reg <= k_temp_reg_max; reg++) {
        if (reg + size - 1 > k_temp_reg_max) continue;

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

    /* 兜底：避免-1触发错误默认寄存器路径 */
    {
        int fallback = k_temp_reg_min;
        for (int j = 0; j < size && (fallback + j) <= k_temp_reg_max; j++) {
            isel->reg_busy[fallback + j] = true;
            isel->reg_val[fallback + j] = val;
        }
        int* reg_num = malloc(sizeof(int));
        *reg_num = fallback;
        char* key = int_to_key(val);
        dict_put(isel->ctx->value_to_reg, key, reg_num);
        return fallback;
    }
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

