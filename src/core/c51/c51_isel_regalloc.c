#include "c51_isel_regalloc.h"
#include "c51_isel_internal.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* register allocation (no debug) */

/* C51参数寄存器约定（定义在此处） */
const int param_regs_char[] = {7, 5, 3, 2, 4, 6};
const int param_regs_int_h[] = {6, 4, 2};
const int param_regs_int_l[] = {7, 5, 3};

int c51_abi_type_size(const Ctype* type) {
    if (!type) return 1;
    if (type->type != CTYPE_PTR) {
        return (type->size > 0) ? type->size : 1;
    }

    CtypeAttr attr = get_attr(type->attr);
    switch (attr.ctype_data) {
        case 1: /* data */
        case 2: /* idata */
        case 3: /* pdata */
        case 4: /* xdata */
        case 5: /* edata */
        case 6: /* code */
            return 2;
        default:
            return (type->size > 0) ? type->size : 2;
    }
}

/* ============================================================
 * 线性扫描寄存器分配实现
 * ============================================================ */

/* 全局线性扫描上下文（在函数处理期间使用） */
static LinearScanContext* g_linscan_ctx = NULL;
static C51GenContext* g_gen_ctx = NULL;

typedef struct {
    int id;
    int size;
    int end;
    SectionKind kind;
    char* name;
} SpillSlotInfo;

/* Keil约定下，R6/R7主要承担返回值与参数传递，
 * 临时值优先使用 R0-R5，避免与ABI关键寄存器冲突。 */
static const int k_temp_reg_min = 0;
static const int k_temp_reg_max = 7;

/* 比较函数：按start时间排序活跃区间 */
static int compare_intervals(const void* a, const void* b) {
    /* 统计信息（用于调试/性能分析） */
    int peak_live = 0;
    int spill_count = 0;
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
                    int dest_size = ins->type ? c51_abi_type_size(ins->type) : 1;
                    if (genctx && genctx->value_type) {
                        char* type_key = int_to_key(ins->dest);
                        Ctype* recorded = (Ctype*)dict_get(genctx->value_type, type_key);
                        free(type_key);
                        if (recorded) dest_size = c51_abi_type_size(recorded);
                    }
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
                        iv->size = dest_size;
                        iv->reg = -1;
                        iv->spill_slot = -1;
                        iv->is_param = (ins->op == IROP_PARAM);
                    } else {
                        LiveInterval* iv = &lsc->intervals[iv_idx];
                        if (instr_idx < iv->start) iv->start = instr_idx;
                        if (instr_idx > iv->end) iv->end = instr_idx;
                        if (dest_size > iv->size) iv->size = dest_size;
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
                            if (genctx && genctx->value_type) {
                                char* type_key = int_to_key(*pv);
                                Ctype* recorded = (Ctype*)dict_get(genctx->value_type, type_key);
                                free(type_key);
                                if (recorded) iv->size = c51_abi_type_size(recorded);
                            }
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

static bool interval_fits_regs(LinearScanContext* lsc, int start_reg, int size, int current_start) {
    if (!lsc || size <= 0) return false;
    if (start_reg < k_temp_reg_min) return false;
    if (start_reg + size - 1 > k_temp_reg_max) return false;

    for (int i = 0; i < size; i++) {
        int reg = start_reg + i;
        if (lsc->active_regs[reg] >= 0 && lsc->active_reg_end[reg] >= current_start) {
            return false;
        }
    }
    return true;
}

static void occupy_interval_regs(LinearScanContext* lsc, LiveInterval* interval, int start_reg) {
    if (!lsc || !interval || start_reg < 0) return;
    interval->reg = start_reg;
    for (int i = 0; i < interval->size && start_reg + i <= k_temp_reg_max; i++) {
        lsc->active_regs[start_reg + i] = interval->val;
        lsc->active_reg_end[start_reg + i] = interval->end;
    }
}

static int find_reusable_spill_slot(SpillSlotInfo* slots, int slot_count,
                                    int size, SectionKind kind, int start) {
    for (int i = 0; i < slot_count; i++) {
        if (slots[i].size != size) continue;
        if (slots[i].kind != kind) continue;
        if (slots[i].end < start) return i;
    }
    return -1;
}

static bool interval_crosses_call(Func* func, int start, int end) {
    if (!func || end <= start) return false;

    int instr_idx = 0;
    for (Iter bit = list_iter(func->blocks); !iter_end(bit);) {
        Block* block = iter_next(&bit);

        for (int pass = 0; pass < 2; pass++) {
            List* lst = (pass == 0) ? block->phis : block->instrs;
            if (!lst) continue;

            for (Iter it = list_iter(lst); !iter_end(it);) {
                Instr* ins = iter_next(&it);
                if (!ins) continue;

                if (instr_idx > start && instr_idx < end && ins->op == IROP_CALL) {
                    return true;
                }

                instr_idx++;
            }
        }
    }

    return false;
}

static const char* ensure_local_value_symbol(C51GenContext* genctx, const char* name, int size, SectionKind use_kind) {
    if (!genctx || !genctx->obj || !name || size <= 0) return NULL;

    const char* sec_name = "?DT?";
    if (use_kind == SEC_IDATA) sec_name = "?ID?";
    else if (use_kind == SEC_XDATA) sec_name = "?XD?";

    int sec_idx = obj_add_section(genctx->obj, sec_name, use_kind, 0, 1);
    Section* sec = obj_get_section(genctx->obj, sec_idx);
    int offset = sec->size;
    section_append_zeros(sec, size);
    obj_add_symbol(genctx->obj, name, SYM_DATA, sec_idx, offset, size, SYM_FLAG_LOCAL);
    return name;
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

    SpillSlotInfo* spill_slots = NULL;
    int spill_slot_count = 0;
    int spill_slot_capacity = 0;
    /* 统计信息（用于调试/性能分析） */
    int peak_live = 0;
    int spill_count = 0;
    
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
                int abi_size = interval->size;
                if (genctx && genctx->value_type) {
                    char* type_key = int_to_key(interval->val);
                    Ctype* type = (Ctype*)dict_get(genctx->value_type, type_key);
                    free(type_key);
                    abi_size = c51_abi_type_size(type);
                }
                interval->reg = *param_reg_ptr;
                if (interval->reg >= 0 && interval->reg < 8) {
                    for (int j = 0; j < abi_size && interval->reg + j < 8; j++) {
                        lsc->active_regs[interval->reg + j] = interval->val;
                        lsc->active_reg_end[interval->reg + j] = interval->end;
                    }
                }
            }
            continue;
        }

        /* 返回值寄存器保护：如果是函数返回值，生命周期内禁止分配R7/R6等 */
        // TODO: 可根据函数返回类型进一步保护R7/R6/R5/R4等

        bool force_spill = false;
        if (genctx && genctx->current_func && interval->size <= 2) {
            force_spill = interval_crosses_call(genctx->current_func, interval->start, interval->end);
        }

        /* 尝试分配寄存器：按Keil约定优先使用R0-R5 */
        bool allocated = false;
        if (!force_spill) {
            for (int r = k_temp_reg_min; r <= k_temp_reg_max; r++) {
                if (!interval_fits_regs(lsc, r, interval->size, interval->start)) continue;
                occupy_interval_regs(lsc, interval, r);
                allocated = true;
                break;
            }
        }

        /* 如果没有空闲寄存器，直接spill，避免多字节值被部分抢占后破坏布局 */
        if (!allocated) {
            if (!allocated) {
                /* 无空寄存器可用：将此区间 spill 到内存（生成一个临时 spill 符号） */
                if (genctx) {
                    SectionKind use_kind = genctx->spill_section;
                    if (genctx->spill_use_xdata_for_large && interval->size > 1) {
                        use_kind = SEC_XDATA;
                    }

                    int slot_index = find_reusable_spill_slot(
                        spill_slots, spill_slot_count, interval->size, use_kind, interval->start);

                    const char* slot_name = NULL;
                    int sid = -1;

                    if (slot_index >= 0) {
                        spill_slots[slot_index].end = interval->end;
                        sid = spill_slots[slot_index].id;
                        slot_name = spill_slots[slot_index].name;
                    } else {
                        sid = genctx->next_spill_id++;
                        char buf[64];
                        snprintf(buf, sizeof(buf), "__spill_%d", sid);

                        if (spill_slot_count >= spill_slot_capacity) {
                            spill_slot_capacity = spill_slot_capacity ? spill_slot_capacity * 2 : 16;
                            spill_slots = realloc(spill_slots, sizeof(SpillSlotInfo) * spill_slot_capacity);
                        }

                        spill_slots[spill_slot_count].id = sid;
                        spill_slots[spill_slot_count].size = interval->size;
                        spill_slots[spill_slot_count].end = interval->end;
                        spill_slots[spill_slot_count].kind = use_kind;
                        spill_slots[spill_slot_count].name = strdup(buf);
                        slot_name = spill_slots[spill_slot_count].name;
                        spill_slot_count++;

                        ensure_local_value_symbol(genctx, slot_name, interval->size, use_kind);
                    }

                    char* key = int_to_key(interval->val);
                    dict_put(genctx->value_to_addr, key, strdup(slot_name));

                    char* key2 = int_to_key(interval->val);
                    dict_put(genctx->value_to_spill, key2, strdup(slot_name));

                    /* 在 value_to_reg 中标记为已 spill（使用 -3 表示） */
                    int* rptr = malloc(sizeof(int));
                    *rptr = -3;
                    char* key3 = int_to_key(interval->val);
                    dict_put(genctx->value_to_reg, key3, rptr);

                    interval->spill_slot = sid;
                    interval->reg = -3; /* 表示溢出 */
                    /* 统计溢出次数 */
                    spill_count++;
                    continue;
                }

                /* 兜底：避免返回负寄存器导致后续错误默认到R7 */
                interval->reg = k_temp_reg_min;
                occupy_interval_regs(lsc, interval, k_temp_reg_min);
            }
        }

        /* 更新当前活跃寄存器数并记录峰值（每个区间处理后） */
        {
            int curr_active = 0;
            for (int rr = 0; rr < 8; rr++) {
                if (lsc->active_regs[rr] >= 0) curr_active++;
            }
            if (curr_active > peak_live) peak_live = curr_active;
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

        /* 更新当前活跃寄存器数并记录峰值 */
        int curr_active = 0;
        for (int rr = 0; rr < 8; rr++) {
            if (lsc->active_regs[rr] >= 0) curr_active++;
        }
        if (curr_active > peak_live) peak_live = curr_active;
    }

    for (int i = 0; i < spill_slot_count; i++) {
        free(spill_slots[i].name);
    }
    free(spill_slots);
}

/* 注意：这个函数现在只查询线性扫描已经分配的结果，不再做动态分配 */
int alloc_reg_for_value(ISelContext* isel, ValueName val, int size) {
    if (!isel || !isel->ctx) return -1;

    /* 首先检查是否已经被线性扫描分配过 */
    int existing = isel_get_value_reg(isel, val);
    if (existing >= 0 && existing + size - 1 > k_temp_reg_max) {
        existing = -1;
    }
    if (existing >= 0 || existing == -2 || existing == -3) {
        /* If linear scan already assigned a register, ensure the
         * isel context marks those physical registers as busy so
         * temporaries won't clobber them. This prevents reusing a
         * dest register for a temporary immediately after it's used.
         */
        if (existing >= 0 && isel) {
            for (int j = 0; j < size; j++) {
                if (existing + j >= 0 && existing + j < 8) {
                    isel->reg_busy[existing + j] = true;
                    isel->reg_val[existing + j] = val;
                }
            }
        }
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

            /* allocation recorded */

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
        /* fallback allocation recorded */
        return fallback;
    }
}

// 参数寄存器映射表（按参数位置索引 0,1,2）
static const int regs_size1[] = {7, 5, 3};           // 1字节：R7, R5, R3
static const int regs_size2_high[] = {6, 4, 2};      // 2字节高字节：R6, R4, R2
static const int regs_size2_low[]  = {7, 5, 3};      // 2字节低字节：R7, R5, R3
static const int regs_size3[] = {1, 2, 3};           // 3字节指针：R1,R2,R3（仅第1个参数可用）
static const int regs_size4[] = {4, 5, 6, 7};        // 4字节long/float：R4-R7（仅第1个参数可用）

/**
 * 获取指定位置和大小参数的期望寄存器组
 * @param idx       参数位置（0表示第一个）
 * @param size      参数大小（字节）
 * @param regs_out  输出寄存器数组（需至少能存4个int）
 * @param count_out 输出寄存器个数
 * @return          是否有期望的寄存器组（若位置超出或类型不支持返回false）
 */
static bool get_param_register_set(int idx, int size, int* regs_out, int* count_out) {
    if (size == 1) {                     // char / 1字节指针
        if (idx < 3) {
            regs_out[0] = regs_size1[idx];
            *count_out = 1;
            return true;
        }
    } else if (size == 2) {              // int / 2字节指针
        if (idx < 3) {
            regs_out[0] = regs_size2_high[idx];
            regs_out[1] = regs_size2_low[idx];
            *count_out = 2;
            return true;
        }
    } else if (size == 3) {              // 通用指针
        if (idx == 0) {                  // 仅第一个参数可用寄存器
            memcpy(regs_out, regs_size3, sizeof(regs_size3));
            *count_out = 3;
            return true;
        }
    } else if (size == 4) {              // long / float
        if (idx == 0) {                  // 仅第一个参数可用寄存器
            memcpy(regs_out, regs_size4, sizeof(regs_size4));
            *count_out = 4;
            return true;
        }
    }
    return false;
}

/**
 * 为函数参数分配寄存器（遵循Keil C51约定）
 */
void alloc_param_regs(ISelContext* isel, Func* f) {
    if (!f->params || !f->param_types) return;

    int n = list_len(f->params);
    if (n == 0) return;

    bool used_regs[8] = {false};          // 跟踪已分配的寄存器
    /* 为避免不同大小的参数互相“挤占”导致语义上首个 int 未落在 R6:R7，
     * 我们按参数大小类别维护独立的索引：
     *  - size1_idx: 第几个 1 字节参数
     *  - size2_idx: 第几个 2 字节参数
     *  - size3_idx: 第几个 3 字节参数
     *  - size4_idx: 第几个 4 字节参数
     * 这样分配时会保证 "第一个 2 字节参数" 始终使用 R6:R7（若可用）。
     */
    int size1_idx = 0, size2_idx = 0, size3_idx = 0, size4_idx = 0;
    Iter pit = list_iter(f->params);
    Iter tit = list_iter(f->param_types);

    // 遍历所有参数（按声明顺序），但为每个大小类别计算位置索引
    int param_pos = 0;
    while (!iter_end(pit) && !iter_end(tit)) {
        char* param_name = iter_next(&pit);
        Ctype* param_type = iter_next(&tit);
        if (!param_name || !param_type) continue;

        int size = c51_abi_type_size(param_type);  // ABI 视角下的参数字节数
        int expected_regs[4];
        int reg_count;

        int class_idx = 0;
        if (size == 1) { class_idx = size1_idx; }
        else if (size == 2) { class_idx = size2_idx; }
        else if (size == 3) { class_idx = size3_idx; }
        else if (size == 4) { class_idx = size4_idx; }

        // 获取期望的寄存器组（按该大小类别的序号）
        bool has_regs = get_param_register_set(class_idx, size, expected_regs, &reg_count);
        if (!has_regs) {
            /* 该大小类别的此序号没有可用寄存器组，
             * 将该参数降级为内存传递：为其创建一个符号并记录到 value_to_addr，
             * 同时在 value_to_reg 中标记为已 spill（-3），使被调函数从该符号加载。 */
            if (isel && isel->ctx) {
                C51GenContext* gen = isel->ctx;
                char buf[128];
                snprintf(buf, sizeof(buf), "__param_%s_%d", f->name, param_pos);
                char* name = strdup(buf);
                char* key = NULL;
                Instr* param_ins_loc = NULL;
                if (f->entry && f->entry->instrs) {
                    for (Iter it2 = list_iter(f->entry->instrs); !iter_end(it2);) {
                        Instr* ii = iter_next(&it2);
                        if (ii && ii->op == IROP_PARAM && ii->labels && ii->labels->len > 0) {
                            const char* nm = list_get(ii->labels, 0);
                            if (nm && strcmp(nm, param_name) == 0) { param_ins_loc = ii; break; }
                        }
                    }
                }
                if (param_ins_loc) {
                    key = int_to_key(param_ins_loc->dest);
                    dict_put(gen->value_to_addr, key, name);
                    int* rptr = malloc(sizeof(int)); *rptr = -3;
                    char* k2 = int_to_key(param_ins_loc->dest);
                    dict_put(gen->value_to_reg, k2, rptr);

                    if (gen->obj) {
                        int size_bytes = size;
                        SectionKind use_kind = gen->spill_section;
                        if (gen->spill_use_xdata_for_large && size_bytes > 1) use_kind = SEC_XDATA;
                        const char* sec_name = "?DT?";
                        if (use_kind == SEC_IDATA) sec_name = "?ID?";
                        else if (use_kind == SEC_XDATA) sec_name = "?XD?";
                        int sec_idx = obj_add_section(gen->obj, sec_name, use_kind, 0, 1);
                        Section* sec = obj_get_section(gen->obj, sec_idx);
                        int offset = sec->size;
                        section_append_zeros(sec, size_bytes);
                        obj_add_symbol(gen->obj, name, SYM_DATA, sec_idx, offset, size_bytes, SYM_FLAG_LOCAL);
                    }
                } else {
                    free(name);
                }
            }
            param_pos++;
            continue;
        }

        // 检查期望寄存器组是否全部空闲
        bool all_free = true;
        for (int j = 0; j < reg_count; j++) {
            if (used_regs[expected_regs[j]]) {
                all_free = false;
                break;
            }
        }

        if (!all_free) {
            /* 冲突：将该参数降级为内存传递（创建符号并记录），然后继续处理下一个参数 */
            if (isel && isel->ctx) {
                C51GenContext* gen = isel->ctx;
                char buf[128];
                snprintf(buf, sizeof(buf), "__param_%s_%d", f->name, param_pos);
                char* name = strdup(buf);
                Instr* param_ins_loc = NULL;
                if (f->entry && f->entry->instrs) {
                    for (Iter it2 = list_iter(f->entry->instrs); !iter_end(it2);) {
                        Instr* ii = iter_next(&it2);
                        if (ii && ii->op == IROP_PARAM && ii->labels && ii->labels->len > 0) {
                            const char* nm = list_get(ii->labels, 0);
                            if (nm && strcmp(nm, param_name) == 0) { param_ins_loc = ii; break; }
                        }
                    }
                }
                if (param_ins_loc) {
                    char* key = int_to_key(param_ins_loc->dest);
                    dict_put(gen->value_to_addr, key, name);
                    int* rptr = malloc(sizeof(int)); *rptr = -3;
                    char* k2 = int_to_key(param_ins_loc->dest);
                    dict_put(gen->value_to_reg, k2, rptr);
                    if (gen->obj) {
                        int size_bytes = size;
                        SectionKind use_kind = gen->spill_section;
                        if (gen->spill_use_xdata_for_large && size_bytes > 1) use_kind = SEC_XDATA;
                        const char* sec_name = "?DT?";
                        if (use_kind == SEC_IDATA) sec_name = "?ID?";
                        else if (use_kind == SEC_XDATA) sec_name = "?XD?";
                        int sec_idx = obj_add_section(gen->obj, sec_name, use_kind, 0, 1);
                        Section* sec = obj_get_section(gen->obj, sec_idx);
                        int offset = sec->size;
                        section_append_zeros(sec, size_bytes);
                        obj_add_symbol(gen->obj, name, SYM_DATA, sec_idx, offset, size_bytes, SYM_FLAG_LOCAL);
                    }
                } else {
                    free(name);
                }
            }
            param_pos++;
            continue;
        }

        // 找到对应的PARAM指令（按参数名匹配）
        Instr* param_ins = NULL;
        if (f->entry && f->entry->instrs) {
            for (Iter it = list_iter(f->entry->instrs); !iter_end(it);) {
                Instr* ins = iter_next(&it);
                if (ins && ins->op == IROP_PARAM && ins->labels && ins->labels->len > 0) {
                    const char* name = list_get(ins->labels, 0);
                    if (name && strcmp(name, param_name) == 0) {
                        param_ins = ins;
                        break;
                    }
                }
            }
        }

        if (param_ins) {
            // 分配寄存器：将期望组全部标记为占用
            for (int j = 0; j < reg_count; j++) {
                int r = expected_regs[j];
                used_regs[r] = true;
            }

            if (size <= 2 && isel && isel->ctx) {
                C51GenContext* gen = isel->ctx;
                char buf[128];
                snprintf(buf, sizeof(buf), "__arg_%s_%d", f->name, param_pos);

                SectionKind use_kind = gen->spill_section;
                if (gen->spill_use_xdata_for_large && size > 1) {
                    use_kind = SEC_XDATA;
                }
                ensure_local_value_symbol(gen, buf, size, use_kind);

                char* addr_key = int_to_key(param_ins->dest);
                dict_put(gen->value_to_addr, addr_key, strdup(buf));

                int* reg_num = malloc(sizeof(int));
                *reg_num = -3;
                char* reg_key = int_to_key(param_ins->dest);
                dict_put(gen->value_to_reg, reg_key, reg_num);

                if (size == 1) {
                    emit_store_symbol_byte(isel, buf, 0, isel_reg_name(expected_regs[0]), NULL);
                } else {
                    emit_store_symbol_byte(isel, buf, 0, isel_reg_name(expected_regs[1]), NULL);
                    emit_store_symbol_byte(isel, buf, 1, isel_reg_name(expected_regs[0]), NULL);
                }
            } else {
                for (int j = 0; j < reg_count; j++) {
                    int r = expected_regs[j];
                    isel->reg_busy[r] = true;
                    isel->reg_val[r] = param_ins->dest;
                }

                int* reg_num = malloc(sizeof(int));
                *reg_num = expected_regs[0];
                char* key = int_to_key(param_ins->dest);
                dict_put(isel->ctx->value_to_reg, key, reg_num);
            }
        }

        // 增加对应大小类别的索引
        if (size == 1) size1_idx++;
        else if (size == 2) size2_idx++;
        else if (size == 3) size3_idx++;
        else if (size == 4) size4_idx++;
        param_pos++;
    }
}