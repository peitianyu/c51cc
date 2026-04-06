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

/* 全局线性扫描上下文（在函数处理期间使用�?*/
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
 * 临时值优先使�?R0-R5，避免与ABI关键寄存器冲突�?*/
static const int k_temp_reg_min = C51_ALLOCATABLE_REG_MIN;
static const int k_temp_reg_max = C51_ALLOCATABLE_REG_MAX;

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

/* 递归获取值定义的指令序号（用于PHI�?*/
static int get_value_def_idx(ValueName val, Func* func, int* idx_map) {
    if (!func) return 0;
    
    /* 快速查询已计算�?*/
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

static int get_value_interval_size(C51GenContext* genctx, Func* func, ValueName val) {
    if (genctx && genctx->value_type) {
        char* type_key = int_to_key(val);
        Ctype* recorded = (Ctype*)dict_get(genctx->value_type, type_key);
        free(type_key);
        if (recorded) return c51_abi_type_size(recorded);
    }

    Instr* def = find_def_instr_in_func(func, val);
    if (def && def->type) return c51_abi_type_size(def->type);
    return 1;
}

/* 为函数的所有指令计算活跃区�?*/
void linscan_compute_intervals(LinearScanContext* lsc, Func* func, C51GenContext* genctx) {
    if (!lsc || !func) return;
    (void)genctx;
    int dbg = getenv("C51CC_REGDEBUG") != NULL;

    const int kMaxValue = 1000000;
    lsc->interval_count = 0;

    int max_block_id = 0;
    for (Iter bit = list_iter(func->blocks); !iter_end(bit);) {
        Block* block = iter_next(&bit);
        if (block && (int)block->id > max_block_id) max_block_id = (int)block->id;
    }

    int* val_to_iv = malloc(sizeof(int) * kMaxValue);
    for (int i = 0; i < kMaxValue; i++) val_to_iv[i] = -1;

    int* block_edge_idx = malloc(sizeof(int) * (max_block_id + 1));
    for (int i = 0; i <= max_block_id; i++) block_edge_idx[i] = -1;

    int instr_idx = 0;

    for (Iter bit = list_iter(func->blocks); !iter_end(bit);) {
        Block* block = iter_next(&bit);
        int block_start_idx = instr_idx;

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

        if (block && block->id <= (uint32_t)max_block_id) {
            block_edge_idx[block->id] = (instr_idx > block_start_idx) ? (instr_idx - 1) : block_start_idx;
        }
    }

    for (Iter bit = list_iter(func->blocks); !iter_end(bit);) {
        Block* block = iter_next(&bit);
        if (!block || !block->phis) continue;

        for (Iter it = list_iter(block->phis); !iter_end(it);) {
            Instr* ins = iter_next(&it);
            if (!ins || ins->op != IROP_PHI || !ins->args || !ins->labels) continue;

            int edge_count = ins->args->len < ins->labels->len ? ins->args->len : ins->labels->len;
            for (int i = 0; i < edge_count; i++) {
                ValueName* pv = list_get(ins->args, i);
                const char* pred_label = list_get(ins->labels, i);
                if (!pv || *pv <= 0 || *pv >= kMaxValue || !pred_label) continue;

                int pred_id = parse_block_id(pred_label);
                if (pred_id < 0 || pred_id > max_block_id) continue;

                int use_idx = block_edge_idx[pred_id];
                if (use_idx < 0) continue;

                int iv_idx = val_to_iv[*pv];
                if (iv_idx < 0) {
                    if (lsc->interval_count >= lsc->interval_capacity) {
                        lsc->interval_capacity *= 2;
                        lsc->intervals = realloc(lsc->intervals,
                            sizeof(LiveInterval) * lsc->interval_capacity);
                    }

                    iv_idx = lsc->interval_count++;
                    val_to_iv[*pv] = iv_idx;

                    LiveInterval* iv = &lsc->intervals[iv_idx];
                    iv->val = *pv;
                    iv->start = use_idx;
                    iv->end = use_idx;
                    iv->size = get_value_interval_size(genctx, func, *pv);
                    iv->reg = -1;
                    iv->spill_slot = -1;
                    iv->is_param = false;
                } else {
                    LiveInterval* iv = &lsc->intervals[iv_idx];
                    if (use_idx < iv->start) iv->start = use_idx;
                    if (use_idx > iv->end) iv->end = use_idx;
                }
            }
        }
    }

    free(val_to_iv);
    free(block_edge_idx);
}

/* 释放寄存器中过期的�?*/
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
    
    /* 清除活跃寄存器列�?*/
    for (int r = 0; r < 8; r++) {
        lsc->active_regs[r] = -1;
        lsc->active_reg_end[r] = -1;
    }

    SpillSlotInfo* spill_slots = NULL;
    int spill_slot_count = 0;
    int spill_slot_capacity = 0;
    /* 统计信息（用于调�?性能分析�?*/
    int peak_live = 0;
    int spill_count = 0;
    
    /* 处理每个活跃区间 */
    for (int i = 0; i < lsc->interval_count; i++) {
        int idx = lsc->sorted_intervals[i];
        LiveInterval* interval = &lsc->intervals[idx];

        /* 释放过期的�?*/
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

        /* CONST values: do not assign a physical register; they will be
           rematerialized as immediate operands whenever needed.
           This avoids wasting registers on constants that span long intervals. */
        if (genctx && genctx->current_func) {
            Instr* cdef = find_def_instr_in_func(genctx->current_func, interval->val);
            if (cdef && cdef->op == IROP_CONST) {
                /* Mark as "no register needed" (-4 = rematerializable CONST).
                   alloc_reg_for_value will return -1 directly for this value,
                   causing emit_const to skip materialization. */
                interval->reg = -4;
                continue;
            }
        }

        /* 返回值寄存器保护：如果是函数返回值，生命周期内禁止分配R7/R6�?*/
        // TODO: 可根据函数返回类型进一步保护R7/R6/R5/R4�?

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
                /* 无空寄存器可用：将此区间 spill 到内存（生成一个临�?spill 符号�?*/
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

                    /* Write spill slot to value_to_spill only.
                     * Do NOT write to value_to_addr: that dict is filled by
                     * emit_addr() during code generation and maps ptr values
                     * to sbit/SFR names.  Writing "__spill_N" there would
                     * corrupt sbit name lookups (e.g. get_sbit_var_name). */
                    char* key2 = int_to_key(interval->val);
                    dict_put(genctx->value_to_spill, key2, strdup(slot_name));

                    /* �?value_to_reg 中标记为�?spill（使�?-3 表示�?*/
                    int* rptr = malloc(sizeof(int));
                    *rptr = SPILL_REG;
                    char* key3 = int_to_key(interval->val);
                    dict_put(genctx->value_to_reg, key3, rptr);

                    interval->spill_slot = sid;
                    interval->reg = SPILL_REG; /* 表示溢出 */
                    /* 统计溢出次数 */
                    spill_count++;
                    continue;
                }

                /* 兜底：避免返回负寄存器导致后续错误默认到R7 */
                interval->reg = k_temp_reg_min;
                occupy_interval_regs(lsc, interval, k_temp_reg_min);
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

    /* 将分配结果存储到value_to_reg字典�?*/
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

        /* 更新当前活跃寄存器数并记录峰�?*/
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

    /* ============================================================
     * Phi Coalescing: after linear scan, try to eliminate Phi copies
     * by reusing the Phi-dest register for the Phi-source value.
     *
     * For each Phi node:  dest = phi(src_i from pred_i)
     *   If dest and src_i are in different registers, check whether
     *   the src_i interval only lives up to the edge (no other users
     *   conflict with dest's register after src_i's definition ends).
     *   If safe, rebind src_i to the same register as dest.
     * ============================================================ */
    if (genctx && genctx->current_func && genctx->value_to_reg) {
        Func* coalesce_func = genctx->current_func;

        /* Build val -> interval index map for fast lookup */
        const int kMaxVal = 1000000;
        int* val_iv_map = malloc(sizeof(int) * kMaxVal);
        for (int i = 0; i < kMaxVal; i++) val_iv_map[i] = -1;
        for (int i = 0; i < lsc->interval_count; i++) {
            LiveInterval* iv = &lsc->intervals[i];
            if (iv->val > 0 && iv->val < kMaxVal) val_iv_map[iv->val] = i;
        }

        for (Iter bit = list_iter(coalesce_func->blocks); !iter_end(bit);) {
            Block* blk = iter_next(&bit);
            if (!blk || !blk->phis) continue;

            for (Iter pit = list_iter(blk->phis); !iter_end(pit);) {
                Instr* phi = iter_next(&pit);
                if (!phi || phi->op != IROP_PHI || !phi->args) continue;

                int dst_val = phi->dest;
                if (dst_val <= 0 || dst_val >= kMaxVal) continue;

                /* Get destination register */
                int dst_iv = val_iv_map[dst_val];
                if (dst_iv < 0) continue;
                int dst_reg = lsc->intervals[dst_iv].reg;
                int dst_size = lsc->intervals[dst_iv].size;
                if (dst_reg < 0 || dst_reg == SPILL_REG) continue;

                /* For each source of this phi */
                for (int ai = 0; ai < phi->args->len; ai++) {
                    ValueName* psrc = list_get(phi->args, ai);
                    if (!psrc || *psrc <= 0 || *psrc >= kMaxVal) continue;
                    int src_val = *psrc;

                    int src_iv = val_iv_map[src_val];
                    if (src_iv < 0) continue;
                    int src_reg = lsc->intervals[src_iv].reg;
                    if (src_reg == dst_reg) continue;              /* already same */
                    if (src_reg < 0 || src_reg == SPILL_REG) continue; /* spilled */
                    if (lsc->intervals[src_iv].size != dst_size) continue; /* size mismatch */

                    /* Check: does rebinding src to dst_reg cause any conflict?
                     * A conflict exists if there is another value (≠ dst_val, ≠ src_val)
                     * that is assigned to dst_reg and whose live interval overlaps
                     * src's live interval [src_start, src_end]. */
                    int src_start = lsc->intervals[src_iv].start;
                    int src_end   = lsc->intervals[src_iv].end;
                    bool conflict = false;
                    for (int ci = 0; ci < lsc->interval_count && !conflict; ci++) {
                        if (ci == src_iv || ci == dst_iv) continue;
                        LiveInterval* other = &lsc->intervals[ci];
                        if (other->val <= 0) continue;
                        /* Check if other occupies any of dst_reg..dst_reg+dst_size-1 */
                        bool other_uses_dst_reg = false;
                        if (other->reg >= 0 && other->reg != SPILL_REG) {
                            for (int ri = 0; ri < other->size; ri++) {
                                int r = other->reg + ri;
                                for (int dr = 0; dr < dst_size; dr++) {
                                    if (r == dst_reg + dr) { other_uses_dst_reg = true; break; }
                                }
                                if (other_uses_dst_reg) break;
                            }
                        }
                        if (!other_uses_dst_reg) continue;
                        /* Overlap check: [src_start, src_end] vs [other_start, other_end] */
                        if (other->end >= src_start && other->start <= src_end) {
                            conflict = true;
                        }
                    }

                    if (!conflict) {
                        /* Safe to rebind: change src_val's register to dst_reg */
                        lsc->intervals[src_iv].reg = dst_reg;
                        /* Also update value_to_reg dict */
                        char* k = int_to_key(src_val);
                        int* rp = malloc(sizeof(int));
                        *rp = dst_reg;
                        dict_put(genctx->value_to_reg, k, rp);
                    }
                }
            }
        }
        free(val_iv_map);
    }

    /* DEBUG: print interval allocations */
    if (genctx && genctx->current_func && getenv("C51CC_REGDEBUG")) {
        fprintf(stderr, "[regalloc] func=%s intervals=%d\n",
            genctx->current_func->name ? genctx->current_func->name : "?",
            lsc->interval_count);
        for (int i = 0; i < lsc->interval_count; i++) {
            LiveInterval* iv = &lsc->intervals[i];
            if (iv->reg == SPILL_REG)
                fprintf(stderr, "  v%d: start=%d end=%d size=%d SPILL\n",
                    iv->val, iv->start, iv->end, iv->size);
            else
                fprintf(stderr, "  v%d: start=%d end=%d size=%d reg=R%d\n",
                    iv->val, iv->start, iv->end, iv->size, iv->reg);
        }
    }
}
int alloc_reg_for_value(ISelContext* isel, ValueName val, int size) {
    if (!isel || !isel->ctx) return -1;

    /* 首先检查是否已经被线性扫描分配过 */
    int existing = isel_get_value_reg(isel, val);
    if (existing >= 0 && existing + size - 1 > k_temp_reg_max) {
        existing = -1;
    }
    /* -4 means rematerializable CONST: no physical register, skip dynamic alloc */
    if (existing == -4) return -1;
    if (existing >= 0 || existing == ACC_REG || existing == SPILL_REG) {
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
     * 尝试在残留的未被占用的寄存器中分�?
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

    /* 兜底：避�?1触发错误默认寄存器路�?*/
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

// 参数寄存器映射表（按参数位置索引 0,1,2�?
static const int regs_size1[] = {7, 5, 3};           // 1字节：R7, R5, R3
static const int regs_size2_high[] = {6, 4, 2};      // 2字节高字节：R6, R4, R2
static const int regs_size2_low[]  = {7, 5, 3};      // 2字节低字节：R7, R5, R3
static const int regs_size3[] = {1, 2, 3};           // 3字节指针：R1,R2,R3（仅�?个参数可用）
static const int regs_size4[] = {4, 5, 6, 7};        // 4字节long/float：R4-R7（仅�?个参数可用）

/**
 * 获取指定位置和大小参数的期望寄存器组
 * @param idx       参数位置�?表示第一个）
 * @param size      参数大小（字节）
 * @param regs_out  输出寄存器数组（需至少能存4个int�?
 * @param count_out 输出寄存器个�?
 * @return          是否有期望的寄存器组（若位置超出或类型不支持返回false�?
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

/* 将参数降级为内存传递：创建 __param_F_N 符号并写入 value_to_addr/value_to_reg */
static void spill_param_to_memory(C51GenContext* gen, Func* f,
                                  const char* param_name, int param_pos, int size) {
    char buf[128];
    snprintf(buf, sizeof(buf), "__param_%s_%d", f->name, param_pos);
    char* name = strdup(buf);

    /* 找到对应 PARAM 指令 */
    Instr* param_ins = NULL;
    if (f->entry && f->entry->instrs) {
        for (Iter it = list_iter(f->entry->instrs); !iter_end(it);) {
            Instr* ii = iter_next(&it);
            if (ii && ii->op == IROP_PARAM && ii->labels && ii->labels->len > 0) {
                const char* nm = list_get(ii->labels, 0);
                if (nm && strcmp(nm, param_name) == 0) { param_ins = ii; break; }
            }
        }
    }
    if (!param_ins) { free(name); return; }

    char* key = int_to_key(param_ins->dest);
    dict_put(gen->value_to_addr, key, name);
    int* rptr = malloc(sizeof(int)); *rptr = SPILL_REG;
    char* k2 = int_to_key(param_ins->dest);
    dict_put(gen->value_to_reg, k2, rptr);

    if (gen->obj) {
        SectionKind use_kind = gen->spill_section;
        if (gen->spill_use_xdata_for_large && size > 1) use_kind = SEC_XDATA;
        const char* sec_name = "?DT?";
        if (use_kind == SEC_IDATA) sec_name = "?ID?";
        else if (use_kind == SEC_XDATA) sec_name = "?XD?";
        int sec_idx = obj_add_section(gen->obj, sec_name, use_kind, 0, 1);
        Section* sec = obj_get_section(gen->obj, sec_idx);
        int offset = sec->size;
        section_append_zeros(sec, size);
        obj_add_symbol(gen->obj, name, SYM_DATA, sec_idx, offset, size, SYM_FLAG_LOCAL);
    }
}

/**
 * 为函数参数分配寄存器（遵循Keil C51约定）
 */
void alloc_param_regs(ISelContext* isel, Func* f) {
    if (!f->params || !f->param_types) return;

    int n = list_len(f->params);
    if (n == 0) return;

    bool used_regs[8] = {false};          // 跟踪已分配的寄存�?
    /* 为避免不同大小的参数互相“挤占”导致语义上首个 int 未落�?R6:R7�?
     * 我们按参数大小类别维护独立的索引�?
     *  - size1_idx: 第几�?1 字节参数
     *  - size2_idx: 第几�?2 字节参数
     *  - size3_idx: 第几�?3 字节参数
     *  - size4_idx: 第几�?4 字节参数
     * 这样分配时会保证 "第一�?2 字节参数" 始终使用 R6:R7（若可用）�?
     */
    int size1_idx = 0, size2_idx = 0, size3_idx = 0, size4_idx = 0;
    Iter pit = list_iter(f->params);
    Iter tit = list_iter(f->param_types);

    // 遍历所有参数（按声明顺序），但为每个大小类别计算位置索�?
    int param_pos = 0;
    while (!iter_end(pit) && !iter_end(tit)) {
        char* param_name = iter_next(&pit);
        Ctype* param_type = iter_next(&tit);
        if (!param_name || !param_type) continue;

        int size = c51_abi_type_size(param_type);  // ABI 视角下的参数字节�?
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
            /* 该大小类别的此序号没有可用寄存器组，降级为内存传递 */
            if (isel && isel->ctx)
                spill_param_to_memory(isel->ctx, f, param_name, param_pos, size);
            param_pos++;
            continue;
        }

        // 检查期望寄存器组是否全部空�?
        bool all_free = true;
        for (int j = 0; j < reg_count; j++) {
            if (used_regs[expected_regs[j]]) {
                all_free = false;
                break;
            }
        }

        if (!all_free) {
            /* 冲突：将该参数降级为内存传递 */
            if (isel && isel->ctx)
                spill_param_to_memory(isel->ctx, f, param_name, param_pos, size);
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
            // 分配寄存器：将期望组全部标记为占�?
            for (int j = 0; j < reg_count; j++) {
                int r = expected_regs[j];
                used_regs[r] = true;
            }

            if (size <= 2 && isel && isel->ctx) {
                /* Check if this parameter needs to be addressable (any ADDR @param_name used).
                   If not, keep it in registers �?no __arg_N memory slot needed. */
                bool param_needs_addr = false;
                if (f->blocks) {
                    for (Iter bbit = list_iter(f->blocks); !iter_end(bbit) && !param_needs_addr;) {
                        Block *blk = iter_next(&bbit);
                        if (!blk || !blk->instrs) continue;
                        for (Iter iit2 = list_iter(blk->instrs); !iter_end(iit2) && !param_needs_addr;) {
                            Instr *ii = iter_next(&iit2);
                            if (!ii || ii->op != IROP_ADDR || !ii->labels || ii->labels->len == 0) continue;
                            const char *lbl = list_get(ii->labels, 0);
                            if (!lbl) continue;
                            const char *lbl_name = (lbl[0] == '@') ? lbl + 1 : lbl;
                            if (strcmp(lbl_name, param_name) == 0) param_needs_addr = true;
                        }
                    }
                }

                if (param_needs_addr) {
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
                    *reg_num = SPILL_REG;
                    char* reg_key = int_to_key(param_ins->dest);
                    dict_put(gen->value_to_reg, reg_key, reg_num);

                    if (size == 1) {
                        emit_store_symbol_byte(isel, buf, 0, isel_reg_name(expected_regs[0]), NULL);
                    } else {
                        emit_store_symbol_byte(isel, buf, 0, isel_reg_name(expected_regs[1]), NULL);
                        emit_store_symbol_byte(isel, buf, 1, isel_reg_name(expected_regs[0]), NULL);
                    }
                } else {
                    /* No address taken: keep parameter in registers */
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
        }

        // 增加对应大小类别的索�?
        if (size == 1) size1_idx++;
        else if (size == 2) size2_idx++;
        else if (size == 3) size3_idx++;
        else if (size == 4) size4_idx++;
        param_pos++;
    }
}
