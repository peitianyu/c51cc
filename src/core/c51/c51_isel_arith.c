#include "c51_isel_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "c51_isel_regalloc.h"

static void store_spilled_dest_if_needed(ISelContext* isel, ValueName val, int reg, int size, Instr* ins) {
    if (!isel || val <= 0 || reg < 0) return;
    if (isel_value_is_spilled(isel, val)) {
        isel_store_spill_from_reg(isel, val, reg, size, ins);
    }
}

static bool value_is_zero_extended_byte_in_func(Func* func, ValueName value, ValueName* seen, int seen_count) {
    Instr* def;

    if (!func || value <= 0) return false;
    for (int i = 0; i < seen_count; i++) {
        if (seen[i] == value) return true;
    }

    def = find_def_instr_in_func(func, value);
    if (!def) return false;
    if (def->op == IROP_CONST) {
        return (def->imm.ival & ~0xFFLL) == 0;
    }
    if (def->op == IROP_TRUNC) {
        return true;
    }
    if (def->op == IROP_PHI && def->args) {
        ValueName next_seen[16];
        int next_count = seen_count;

        if (next_count >= 16) return false;
        memcpy(next_seen, seen, sizeof(ValueName) * seen_count);
        next_seen[next_count++] = value;

        for (int i = 0; i < def->args->len; i++) {
            ValueName arg = *(ValueName*)list_get(def->args, i);
            if (!value_is_zero_extended_byte_in_func(func, arg, next_seen, next_count)) {
                return false;
            }
        }
        return true;
    }
    return false;
}

void emit_const(ISelContext* isel, Instr* ins, Instr* next) {
    /* 优先使用 value_type 字典中推断的类型大小（可能比 ins->type 更窄） */
    int size = get_value_size(isel, ins->dest);
    if (size <= 0) size = ins->type ? c51_abi_type_size(ins->type) : 1;
    int val = (int)(ins->imm.ival & 0xFFFF);

    if (isel && isel->last_const_reg != -100 && isel->last_const_size == size && isel->last_const_val == val) {
        if (isel->ctx && isel->ctx->value_to_reg) {
            int* reg_num = malloc(sizeof(int));
            *reg_num = isel->last_const_reg;
            char* k = int_to_key(ins->dest);
            dict_put(isel->ctx->value_to_reg, k, reg_num);
        }
        return;
    }

    /* Try to bind to PHI target if the next instruction is a JMP,
     * so that no extra MOV copies are needed at the loop back edge.
     * alloc_dest_reg internally calls alloc_reg_for_value as fallback. */
    int reg = alloc_dest_reg(isel, ins, next, size, true);
    /* reg == -1 means this CONST is rematerializable (no physical register assigned).
     * It will be inlined as an immediate operand wherever it is used. Skip materializing. */
    if (reg == -1) return;
    int phys_reg = reg;
    if (phys_reg < 0) phys_reg = 0;

    if (size == 1) {
        char imm_str[16];
        snprintf(imm_str, sizeof(imm_str), "#%d", val & 0xFF);
        emit_mov(isel, isel_reg_name(phys_reg), imm_str, ins);
    } else if (size == 2) {
        char imm_high[16], imm_low[16];
        snprintf(imm_high, sizeof(imm_high), "#%d", (val >> 8) & 0xFF);
        snprintf(imm_low, sizeof(imm_low), "#%d", val & 0xFF);

        emit_mov(isel, isel_reg_name(phys_reg), imm_high, ins);
        emit_mov(isel, isel_reg_name(phys_reg + 1), imm_low, ins);
    }

    store_spilled_dest_if_needed(isel, ins->dest, phys_reg, size, ins);

    if (isel) {
        isel->last_const_reg = reg;
        isel->last_const_val = val;
        isel->last_const_size = size;
    }
}

void emit_add(ISelContext* isel, Instr* ins, Instr* next) {
    ValueName src1 = get_src1_value(ins);
    Ctype* src1_type = get_value_type(isel, src1);
    int size = ins->type ? c51_abi_type_size(ins->type) : 1;
    int src1_size = get_value_size(isel, src1);
    int64_t imm_val;
    bool src2_is_imm = is_imm_operand(ins, &imm_val);
    ValueName src2 = get_src2_value(ins);
    if (!src2_is_imm && src2 > 0 && try_get_value_const(isel, src2, &imm_val)) {
        src2_is_imm = true;
    }
    if (src2_is_imm) src2 = -1;
    const char* src2_sym = (!src2_is_imm) ? lookup_value_addr_symbol(isel, src2) : NULL;
    bool src2_spilled_mem = (!src2_is_imm) && src2_sym && isel_get_value_reg(isel, src2) == SPILL_REG;

    int dst_reg = alloc_dest_reg(isel, ins, next, size, true);
    int src1_base_reg = isel_get_value_reg(isel, src1);
    if (dst_reg >= 0 && src1_base_reg >= 0 && src1 != ins->dest) {
        int src1_begin = src1_base_reg;
        int src1_end = src1_base_reg + src1_size - 1;
        int dst_begin = dst_reg;
        int dst_end = dst_reg + size - 1;
        bool overlaps = !(dst_end < src1_begin || dst_begin > src1_end);
        /* For INC-like operations (src2 == +1 immediate), in-place update is safe
         * because we read src1 lo before writing dst lo, and read src1 hi after.
         * Avoid reallocating to a different register which would cause PHI copies. */
        bool is_inc_inplace = (src2_is_imm && imm_val == 1 && dst_reg == src1_base_reg);
        if (overlaps && !is_inc_inplace) {
            int alt_reg = alloc_temp_reg(isel, ins->dest, size);
            if (alt_reg >= 0) {
                dst_reg = alt_reg;
                if (isel && isel->ctx && isel->ctx->value_to_reg) {
                    int* reg_num = malloc(sizeof(int));
                    if (reg_num) {
                        *reg_num = dst_reg;
                        char* key = int_to_key(ins->dest);
                        dict_put(isel->ctx->value_to_reg, key, reg_num);
                    }
                }
            }
        }
    }

    if (isel && isel->ctx && isel->ctx->value_to_addr) {
        char* k = int_to_key(src1);
        const char* addrname = (const char*)dict_get(isel->ctx->value_to_addr, k);
        free(k);
        if (addrname && src2_is_imm && src1_type && src1_type->type == CTYPE_PTR) {
            int addr_dst = alloc_reg_for_value(isel, ins->dest, 2);
            int phys_addr_dst = addr_dst;
            if (phys_addr_dst < 0) phys_addr_dst = 0;
            const char* dst_hi = isel_reg_name(phys_addr_dst);
            const char* dst_lo = isel_reg_name(phys_addr_dst + 1);
            emit_mov(isel, dst_hi, isel_get_hi_reg(isel, src1), ins);
            emit_mov(isel, dst_lo, isel_get_lo_reg(isel, src1), NULL);

            char* ssa = instr_to_ssa_str(ins);
            emit_mov(isel, "A", dst_lo, NULL);
            int imm_low = (int)(imm_val & 0xFF);
            if (imm_low == 1) {
                isel_emit(isel, "INC", "A", NULL, ssa);
            } else if (imm_low == 2) {
                isel_emit(isel, "INC", "A", NULL, ssa);
                isel_emit(isel, "INC", "A", NULL, NULL);
            } else {
                char imm_str[16]; snprintf(imm_str, sizeof(imm_str), "#%d", imm_low);
                isel_emit(isel, "ADD", "A", imm_str, ssa);
            }
            if (ssa) free(ssa);
            emit_mov(isel, dst_lo, "A", NULL);

            emit_mov(isel, "A", dst_hi, NULL);
            int imm_high = (int)((imm_val >> 8) & 0xFF);
            if (imm_high == 0) {
                isel_emit(isel, "ADDC", "A", "#0", NULL);
            } else {
                char imm_hs[16]; snprintf(imm_hs, sizeof(imm_hs), "#%d", imm_high);
                isel_emit(isel, "ADDC", "A", imm_hs, NULL);
            }
            emit_mov(isel, dst_hi, "A", NULL);

            if (isel->ctx && isel->ctx->value_to_reg) {
                int* regp = malloc(sizeof(int)); *regp = addr_dst;
                char* key = int_to_key(ins->dest);
                dict_put(isel->ctx->value_to_reg, key, regp);
            }
            store_spilled_dest_if_needed(isel, ins->dest, phys_addr_dst, 2, ins);
            return;
        }
    }
    if (dst_reg < 0) dst_reg = 0;

    /* If next instruction is RET, write result directly into return registers R7/R6
     * to avoid an extra MOV copy after the addition. */
    bool add_direct_to_ret = false;
    if (next && next->op == IROP_RET) {
        int ret_phys_add = (size == 2) ? 6 : 7;
        if (dst_reg != ret_phys_add) {
            /* Safety: don't redirect if src1 or src2 overlaps R6/R7 */
            int s1_base = isel_get_value_reg(isel, src1);
            int s1_sz = src1_size;
            bool s1_safe = (s1_base < 0) || (s1_base + s1_sz - 1 < 6);
            int s2_base = src2_is_imm ? -1 : isel_get_value_reg(isel, src2);
            int s2_sz = src2_is_imm ? 0 : get_value_size(isel, src2);
            bool s2_safe = (s2_base < 0) || (s2_base + s2_sz - 1 < 6);
            if (s1_safe && s2_safe) {
                dst_reg = ret_phys_add;
                add_direct_to_ret = true;
            }
        }
    }

    const char* src1_lo = isel_get_lo_reg(isel, src1);
    const char* dst_lo = isel_reg_name(dst_reg + (size == 2 ? 1 : 0));
    const char* src1_hi_preserved = NULL;
    const char* src2_hi_preserved = NULL;
    int src1_hi_tmp = -1;
    int src2_hi_tmp = -1;
    int src2_size = (!src2_is_imm) ? get_value_size(isel, src2) : 0;
    /* 检�?src2 是否�?IDATA spill: 如果是，可以直接�?ADD A, sym 避免中转 B */
    bool src2_idata_direct = false;
    if (src2_spilled_mem && src2_sym) {
        SectionKind src2_sec = get_symbol_section_kind(isel, src2_sym);
        src2_idata_direct = (src2_sec == SEC_IDATA);
    }
    if (src2_spilled_mem && !src2_idata_direct) {
        emit_load_symbol_byte(isel, src2_sym, 0, "B", NULL);
    }

    if (size == 2) {
        if (src1_size == 2) {
            int src1_base_reg = isel_get_value_reg(isel, src1);
            const char* src1_hi = (src1_base_reg >= 0) ? isel_reg_name(src1_base_reg) : NULL;
            if (dst_lo && src1_hi && strcmp(dst_lo, src1_hi) == 0) {
                src1_hi_tmp = alloc_temp_reg(isel, -1, 1);
                src1_hi_preserved = (src1_hi_tmp >= 0) ? isel_reg_name(src1_hi_tmp) : "B";
                emit_mov(isel, src1_hi_preserved, src1_hi, NULL);
            }
        }
        if (!src2_is_imm && !src2_spilled_mem && src2_size == 2) {
            int src2_base_reg = isel_get_value_reg(isel, src2);
            const char* src2_hi = (src2_base_reg >= 0) ? isel_reg_name(src2_base_reg) : NULL;
            if (dst_lo && src2_hi && strcmp(dst_lo, src2_hi) == 0) {
                src2_hi_tmp = alloc_temp_reg(isel, -1, 1);
                src2_hi_preserved = (src2_hi_tmp >= 0) ? isel_reg_name(src2_hi_tmp) : "B";
                emit_mov(isel, src2_hi_preserved, src2_hi, NULL);
            }
        }
    }

    /* 16-bit += 1 optimization: use INC Rlo; CJNE Rlo, #0, skip; INC Rhi
     * This avoids loading through A and saves 3 instructions vs ADD+ADDC path. */
    if (size == 2 && src1_size == 2 && src2_is_imm && imm_val == 1 && !src1_hi_preserved) {
        int src1_base_reg2 = isel_get_value_reg(isel, src1);
        const char* s1_hi = (src1_base_reg2 >= 0) ? isel_reg_name(src1_base_reg2) : NULL;
        const char* s1_lo = (src1_base_reg2 >= 0) ? isel_reg_name(src1_base_reg2 + 1) : NULL;
        const char* d_hi  = isel_reg_name(dst_reg);
        const char* d_lo  = isel_reg_name(dst_reg + 1);

        if (s1_lo && s1_hi && d_lo && d_hi) {
            char* ssa = instr_to_ssa_str(ins);

            /* If not in-place, copy src to dst first */
            if (dst_reg != src1_base_reg2) {
                emit_mov(isel, d_hi, s1_hi, ins);
                emit_mov(isel, d_lo, s1_lo, NULL);
                if (ssa) { /* already annotated above */ free(ssa); ssa = NULL; }
            }

            /* INC lo; CJNE lo, #0, skip_inc_hi; INC hi */
            char* skip_lbl = isel_new_label(isel, "Linc16_skip");
            isel_emit(isel, "INC", d_lo, NULL, ssa);
            if (ssa) { free(ssa); ssa = NULL; }
            {
                char arg2[64];
                snprintf(arg2, sizeof(arg2), "#0, %s", skip_lbl);
                isel_emit(isel, "CJNE", d_lo, arg2, NULL);
            }
            isel_emit(isel, "INC", d_hi, NULL, NULL);
            isel_emit_label(isel, skip_lbl);
            free(skip_lbl);

            store_spilled_dest_if_needed(isel, ins->dest, dst_reg, size, ins);
            if (src1_hi_tmp >= 0) free_temp_reg(isel, src1_hi_tmp, 1);
            if (src2_hi_tmp >= 0) free_temp_reg(isel, src2_hi_tmp, 1);
            return;
        }
    }

    emit_mov(isel, "A", src1_lo, ins);

    if (src2_is_imm) {
        int imm_low = (int)(imm_val & 0xFF);
        if (imm_low == 1 && size == 1) {
            char* ssa = instr_to_ssa_str(ins);
            isel_emit(isel, "INC", "A", NULL, ssa);
            free(ssa);
        } else if (imm_low == 2 && size == 1) {
            char* ssa = instr_to_ssa_str(ins);
            isel_emit(isel, "INC", "A", NULL, ssa);
            free(ssa);
            isel_emit(isel, "INC", "A", NULL, NULL);
        } else {
            char imm_str[16];
            snprintf(imm_str, sizeof(imm_str), "#%d", imm_low);
            char* ssa = instr_to_ssa_str(ins);
            isel_emit(isel, "ADD", "A", imm_str, ssa);
            free(ssa);
        }
    } else {
        if (src2_spilled_mem) {
            if (src2_idata_direct) {
                /* IDATA 直接地址：ADD A, sym  (节省通过 B 的中�? */
                isel_emit(isel, "ADD", "A", src2_sym, NULL);
            } else {
                isel_emit(isel, "ADD", "A", "B", NULL);
            }
        } else {
            const char* src2_lo = isel_get_lo_reg(isel, src2);
            isel_emit(isel, "ADD", "A", src2_lo, NULL);
        }
    }

    emit_mov(isel, dst_lo, "A", NULL);

    if (size == 2) {
        const char* dst_hi = isel_reg_name(dst_reg);

        if (src1_size == 2) {
            const char* src1_hi = src1_hi_preserved ? src1_hi_preserved : isel_get_hi_reg(isel, src1);
            emit_mov(isel, "A", src1_hi, NULL);
        } else {
            emit_mov(isel, "A", "#0", NULL);
        }

        if (src2_is_imm) {
            char imm_str[16];
            snprintf(imm_str, sizeof(imm_str), "#%d", (int)((imm_val >> 8) & 0xFF));
            isel_emit(isel, "ADDC", "A", imm_str, NULL);
        } else {
            if (src2_size == 2) {
                if (src2_spilled_mem) {
                    if (src2_idata_direct) {
                        /* IDATA 直接：ADDC A, (sym+1) �?节省 save/load/B 中转�?4 条指�?*/
                        char ref[256];
                        snprintf(ref, sizeof(ref), "(%s + 1)", src2_sym);
                        isel_emit(isel, "ADDC", "A", ref, NULL);
                    } else {
                        emit_mov(isel, dst_hi, "A", NULL);
                        emit_load_symbol_byte(isel, src2_sym, 1, "B", NULL);
                        emit_mov(isel, "A", dst_hi, NULL);
                        isel_emit(isel, "ADDC", "A", "B", NULL);
                    }
                } else {
                    const char* src2_hi = src2_hi_preserved ? src2_hi_preserved : isel_get_hi_reg(isel, src2);
                    isel_emit(isel, "ADDC", "A", src2_hi, NULL);
                }
            } else {
                isel_emit(isel, "ADDC", "A", "#0", NULL);
            }
        }

        emit_mov(isel, dst_hi, "A", NULL);
    }

    store_spilled_dest_if_needed(isel, ins->dest, dst_reg, size, ins);

    if (src1_hi_tmp >= 0) free_temp_reg(isel, src1_hi_tmp, 1);
    if (src2_hi_tmp >= 0) free_temp_reg(isel, src2_hi_tmp, 1);

    if (next && next->op == IROP_RET) {
        int ret_size = next->type ? c51_abi_type_size(next->type) : 1;
        if (!add_direct_to_ret) {
            /* Fallback: result is in dst_reg, emit copy if needed */
            const char* ret_lo = isel_reg_name(dst_reg + (size == 2 ? 1 : 0));
            const char* ret_hi = isel_reg_name(dst_reg);

            if (strcmp(ret_lo, "R7") != 0) {
                emit_mov(isel, "R7", ret_lo, NULL);
            }
            if (ret_size == 2) {
                if (size == 2) {
                    if (strcmp(ret_hi, "R6") != 0) {
                        emit_mov(isel, "R6", ret_hi, NULL);
                    }
                } else {
                    emit_mov(isel, "R6", "#0", NULL);
                }
            }
        }
        /* add_direct_to_ret: result was written directly to R7/R6, no copy needed */
        if (isel->ctx && isel->ctx->value_to_reg) {
            int* reg_num = malloc(sizeof(int));
            *reg_num = (size == 2) ? 6 : 7;
            char* key = int_to_key(ins->dest);
            dict_put(isel->ctx->value_to_reg, key, reg_num);
        }
    }
}





/* 判断一个 SHL/SHR 指令是否是 rotate8 idiom 的一部分。
 * rotate8 idiom: (v << n) | (v >> (8-n))，其中 v 是 8-bit 值。
 * 如果是，则 emit_shift 应该跳过代码生成（由 emit_bitwise 的 ORL 路径统一处理）。
 * 条件：
 *   1. 该 shift 的结果 dest 在函数里有且仅有一个使用者，是一个 IROP_OR 指令
 *   2. 该 OR 的另一个操作数也是一个 shift（SHL 或 SHR）
 *   3. 两个 shift 的源操作数相同
 *   4. 两个 shift 的移位量之和 == 8（mod 8 == 0，且都非 0）
 *   5. 两个 shift 的类型都是 size==1（或者源操作数是 size==1）
 */
static bool shift_is_rotate8_part(ISelContext* isel, Instr* ins) {
    if (!isel || !isel->ctx || !isel->ctx->current_func) return false;
    Func* func = isel->ctx->current_func;
    if (!ins) return false;
    ValueName my_dest = ins->dest;
    if (my_dest <= 0) return false;

    /* ins 本身必须是 size==1 shift */
    int my_size = ins->type ? c51_abi_type_size(ins->type) : 1;
    if (my_size != 1) return false;

    /* 获取移位量 */
    int64_t my_cnt = 0;
    if (!is_imm_operand(ins, &my_cnt) && !try_get_value_const(isel, get_src2_value(ins), &my_cnt))
        return false;
    my_cnt &= 7;
    if (my_cnt == 0) return false;

    /* 查找 func 中使用 my_dest 的所有指令，必须恰好只有一个 OR */
    Instr* or_ins = NULL;
    for (Iter it = list_iter(func->blocks); !iter_end(it);) {
        Block* b = iter_next(&it);
        if (!b) continue;
        for (Iter jt = list_iter(b->instrs); !iter_end(jt);) {
            Instr* candidate = iter_next(&jt);
            if (!candidate || candidate->op == IROP_NOP) continue;
            if (!candidate->args) continue;
            bool uses_me = false;
            for (int i = 0; i < candidate->args->len; i++) {
                ValueName* pv = list_get(candidate->args, i);
                if (pv && *pv == my_dest) { uses_me = true; break; }
            }
            if (uses_me) {
                if (or_ins != NULL) return false; /* 多个使用者，不确定 */
                or_ins = candidate;
            }
        }
    }
    if (!or_ins || or_ins->op != IROP_OR) return false;

    /* OR 的另一个操作数必须也是一个 shift */
    ValueName or_lhs = get_src1_value(or_ins);
    ValueName or_rhs = get_src2_value(or_ins);
    ValueName other_val = (or_lhs == my_dest) ? or_rhs : or_lhs;
    if (other_val <= 0) return false;
    Instr* other_def = find_def_instr_in_func(func, other_val);
    if (!other_def) return false;
    if (other_def->op != IROP_SHL && other_def->op != IROP_SHR) return false;

    /* 两个 shift 必须方向相反 */
    if (ins->op == other_def->op) return false;

    /* 两个 shift 的源操作数必须相同 */
    ValueName my_src = get_src1_value(ins);
    ValueName other_src = get_src1_value(other_def);
    if (my_src != other_src) return false;

    /* 源操作数必须是 8-bit */
    if (get_value_size(isel, my_src) != 1) return false;

    /* 移位量之和必须 == 8 */
    int64_t other_cnt = 0;
    if (!is_imm_operand(other_def, &other_cnt) && !try_get_value_const(isel, get_src2_value(other_def), &other_cnt))
        return false;
    other_cnt &= 7;
    if (other_cnt == 0) return false;
    if (((my_cnt + other_cnt) & 7) != 0) return false;

    return true;
}

void emit_neg(ISelContext* isel, Instr* ins) {
    ValueName src = get_src1_value(ins);
    int size = ins->type ? c51_abi_type_size(ins->type) : 1;
    int dst_reg = alloc_reg_for_value(isel, ins->dest, size);
    const char* dst_lo = isel_reg_name(dst_reg + (size == 2 ? 1 : 0));
    const char* src_lo = isel_get_lo_reg(isel, src);

    isel_emit(isel, "CLR", "C", NULL, NULL);
    isel_emit(isel, "MOV", "A", "#0", NULL);
    isel_emit(isel, "SUBB", "A", src_lo, NULL);
    emit_mov(isel, dst_lo, "A", ins);

    if (size == 2) {
        const char* dst_hi = isel_reg_name(dst_reg);
        const char* src_hi = isel_get_hi_reg(isel, src);
        isel_emit(isel, "MOV", "A", "#0", NULL);
        isel_emit(isel, "SUBB", "A", src_hi, NULL);
        emit_mov(isel, dst_hi, "A", NULL);
    }

    store_spilled_dest_if_needed(isel, ins->dest, dst_reg, size, ins);
}

void emit_shift(ISelContext* isel, Instr* ins, Instr* next, bool is_shr) {
    ValueName src = get_src1_value(ins);
    int size = ins->type ? c51_abi_type_size(ins->type) : 1;
    int dst_reg = alloc_dest_reg(isel, ins, next, size, true);

    /* 如果这个 shift 是 rotate8 idiom 的一部分（由 ORL 统一处理），跳过代码生成 */
    if (size == 1 && shift_is_rotate8_part(isel, ins)) {
        return;
    }

    int phys_dst_reg = dst_reg;
    bool temp_result = false;

    /* 如果下一条指令是 RET，且结果寄存器不�?R6/R7�?
     * 直接将结果写入返回寄存器，避免移位后�?MOV R7/R6, Rx 的冗余拷�?*/
    if (next && next->op == IROP_RET && size == 2) {
        int ret_base = 6; /* R6:R7 */
        int src_base = isel_get_value_reg(isel, src);
        bool src_safe = (src_base < 0) || (src_base >= ret_base);
        if (src_safe && phys_dst_reg != ret_base) {
            phys_dst_reg = ret_base;
            dst_reg = ret_base;
            if (isel && isel->ctx && isel->ctx->value_to_reg) {
                int* reg_num = malloc(sizeof(int));
                if (reg_num) {
                    *reg_num = ret_base;
                    char* k = int_to_key(ins->dest);
                    dict_put(isel->ctx->value_to_reg, k, reg_num);
                }
            }
        }
    }

    if (phys_dst_reg < 0 || phys_dst_reg + size - 1 > 7) {
        phys_dst_reg = alloc_temp_reg(isel, ins->dest, size);
        temp_result = phys_dst_reg >= 0;
    }
    if (phys_dst_reg < 0) phys_dst_reg = 0;

    const char* dst_lo = isel_reg_name(phys_dst_reg + (size == 2 ? 1 : 0));
    const char* dst_hi = isel_reg_name(phys_dst_reg);
    emit_copy_value(isel, ins, src, phys_dst_reg, size);

    int64_t imm = 0;
    if (size == 1) {
        if (is_imm_operand(ins, &imm)) {
            int cnt = (int)(imm & 0x1F);
            if (cnt == 0) return;
            /* ---- 8-bit shift 特殊情况优化 ---- */
            bool is_unsigned = false;
            if (ins && ins->type) {
                is_unsigned = get_attr(ins->type->attr).ctype_unsigned;
            }
            if (cnt >= 8) {
                /* 移位�?>= 8: 结果�?0 (无符�?/ 左移) 或符号扩�?(有符号右�? */
                emit_mov(isel, "A", dst_lo, ins);
                if (is_shr && !is_unsigned) {
                    /* 算术右移 >=8: 结果�?0x00 �?0xFF */
                    isel_emit(isel, "MOV", "C", "ACC.7", NULL);
                    isel_emit(isel, "MOV", "A", "#0", NULL);
                    isel_emit(isel, "SUBB", "A", "#0", NULL); /* A = 0 or 0xFF */
                } else {
                    isel_emit(isel, "MOV", "A", "#0", NULL);
                }
                emit_mov(isel, dst_lo, "A", NULL);
                return;
            }
            if (is_shr && cnt == 7) {
                /* shr x, 7: 取最高位 */
                emit_mov(isel, "A", dst_lo, ins);
                if (is_unsigned) {
                    /* 逻辑右移7: A = (old_A >> 7) = bit7 �?RL A; ANL A, #1 */
                    isel_emit(isel, "RL", "A", NULL, NULL);
                    isel_emit(isel, "ANL", "A", "#1", NULL);
                } else {
                    /* 算术右移7: 结果 0x00 �?0xFF */
                    isel_emit(isel, "MOV", "C", "ACC.7", NULL);
                    isel_emit(isel, "MOV", "A", "#0", NULL);
                    isel_emit(isel, "SUBB", "A", "#0", NULL);
                }
                emit_mov(isel, dst_lo, "A", NULL);
                return;
            }
            if (!is_shr && cnt == 7) {
                /* shl x, 7: 取最低位放到 bit7 �?RR A; ANL A, #0x80 */
                emit_mov(isel, "A", dst_lo, ins);
                isel_emit(isel, "RR", "A", NULL, NULL);
                isel_emit(isel, "ANL", "A", "#128", NULL);
                emit_mov(isel, dst_lo, "A", NULL);
                return;
            }
            if (cnt == 4) {
                /* 移位4: �?SWAP + 掩码 */
                emit_mov(isel, "A", dst_lo, ins);
                isel_emit(isel, "SWAP", "A", NULL, NULL);
                if (is_shr) {
                    if (is_unsigned) {
                        isel_emit(isel, "ANL", "A", "#0FH", NULL);
                    } else {
                        /* 算术右移4: SWAP 后高4位是符号扩展 */
                        char* l_pos = isel_new_label(isel, "Lshr4_pos");
                        char lb_pos[64];
                        snprintf(lb_pos, sizeof(lb_pos), "%s:", l_pos);
                        isel_emit(isel, "ANL", "A", "#0FH", NULL);
                        isel_emit(isel, "JNB", "ACC.3", l_pos, NULL);
                        isel_emit(isel, "ORL", "A", "#0F0H", NULL);
                        isel_emit(isel, lb_pos, NULL, NULL, NULL);
                        free(l_pos);
                    }
                } else {
                    isel_emit(isel, "ANL", "A", "#0F0H", NULL);
                }
                emit_mov(isel, dst_lo, "A", NULL);
                return;
            }
            if (is_shr && is_unsigned && cnt >= 5) {
                /* 无符号右�?-6: 用左旋转 (8-cnt) �?+ 掩码更高�?*/
                int rot = 8 - cnt;
                emit_mov(isel, "A", dst_lo, ins);
                for (int i = 0; i < rot; i++) {
                    isel_emit(isel, "RL", "A", NULL, NULL);
                }
                char mask_str[16];
                snprintf(mask_str, sizeof(mask_str), "#%d", (1 << (8 - cnt)) - 1);
                isel_emit(isel, "ANL", "A", mask_str, NULL);
                emit_mov(isel, dst_lo, "A", NULL);
                return;
            }
            if (!is_shr && cnt >= 5) {
                /* 左移5-6: 用右旋转 (8-cnt) �?+ 掩码更高�?*/
                int rot = 8 - cnt;
                emit_mov(isel, "A", dst_lo, ins);
                for (int i = 0; i < rot; i++) {
                    isel_emit(isel, "RR", "A", NULL, NULL);
                }
                char mask_str[16];
                snprintf(mask_str, sizeof(mask_str), "#%d", (0xFF << cnt) & 0xFF);
                isel_emit(isel, "ANL", "A", mask_str, NULL);
                emit_mov(isel, dst_lo, "A", NULL);
                return;
            }
            /* 一般情�? 1-3 次移位，逐次生成 */
            for (int i = 0; i < cnt; i++) {
                emit_mov(isel, "A", dst_lo, ins);
                if (is_shr) {
                    if (is_unsigned) {
                        isel_emit(isel, "CLR", "C", NULL, NULL);
                    } else {
                        isel_emit(isel, "MOV", "C", "ACC.7", NULL);
                    }
                    isel_emit(isel, "RRC", "A", NULL, NULL);
                } else {
                    isel_emit(isel, "CLR", "C", NULL, NULL);
                    isel_emit(isel, "RLC", "A", NULL, NULL);
                }
                emit_mov(isel, dst_lo, "A", NULL);
            }
            return;
        }

        ValueName cntv = get_src2_value(ins);
        const char* tcnt = isel_get_lo_reg(isel, cntv);

        /* 为计数分配临时寄存器，避免在第一个循环中破坏原始计数 */
        int tcnt_tmp = alloc_temp_reg(isel, -1, 1);
        const char* tcnt_reg = (tcnt_tmp >= 0) ? isel_reg_name(tcnt_tmp) : tcnt;
        if (tcnt_tmp >= 0) {
            emit_mov(isel, tcnt_reg, tcnt, NULL);
        }

        char* l_loop = isel_new_label(isel, "Lsh_loop");
        char* l_end = isel_new_label(isel, "Lsh_end");
        char lb_loop[64], lb_end[64];
        snprintf(lb_loop, sizeof(lb_loop), "%s:", l_loop);
        snprintf(lb_end, sizeof(lb_end), "%s:", l_end);

        isel_emit(isel, lb_loop, NULL, NULL, NULL);
        emit_mov(isel, "A", tcnt_reg, NULL);
        isel_emit(isel, "JZ", l_end, NULL, NULL);

        emit_mov(isel, "A", dst_lo, NULL);
        if (is_shr) {
            bool is_unsigned = false;
            if (ins && ins->type) is_unsigned = get_attr(ins->type->attr).ctype_unsigned;
            if (is_unsigned) {
                isel_emit(isel, "CLR", "C", NULL, NULL);
            } else {
                isel_emit(isel, "MOV", "C", "ACC.7", NULL);
            }
            isel_emit(isel, "RRC", "A", NULL, NULL);
        } else {
            isel_emit(isel, "CLR", "C", NULL, NULL);
            isel_emit(isel, "RLC", "A", NULL, NULL);
        }
        emit_mov(isel, dst_lo, "A", NULL);

        isel_emit(isel, "DEC", tcnt_reg, NULL, NULL);
        isel_emit(isel, "SJMP", l_loop, NULL, NULL);
        isel_emit(isel, lb_end, NULL, NULL, NULL);

        free(l_loop); free(l_end);

        if (tcnt_tmp >= 0) free_temp_reg(isel, tcnt_tmp, 1);
        store_spilled_dest_if_needed(isel, ins->dest, phys_dst_reg, size, ins);
        if (temp_result) free_temp_reg(isel, phys_dst_reg, size);
        return;
    } else if (size == 2) {
        /* 16-bit shift: handle immediate and variable counts */
        if (is_imm_operand(ins, &imm)) {
            int cnt = (int)(imm & 0x1F);
            bool is_unsigned = false;
            if (ins && ins->type) is_unsigned = get_attr(ins->type->attr).ctype_unsigned;

            /* ---- 16-bit shift 特殊情况优化 ---- */
            if (cnt == 0) {
                store_spilled_dest_if_needed(isel, ins->dest, phys_dst_reg, size, ins);
                if (temp_result) free_temp_reg(isel, phys_dst_reg, size);
                return;
            }
            if (cnt >= 16) {
                /* 移位 >= 16: 结果为 0 (无符号/左移) 或符号扩展 (有符号右移) */
                if (is_shr && !is_unsigned) {
                    emit_mov(isel, "A", dst_hi, NULL);
                    isel_emit(isel, "MOV", "C", "ACC.7", NULL);
                    isel_emit(isel, "MOV", "A", "#0", NULL);
                    isel_emit(isel, "SUBB", "A", "#0", NULL);
                    emit_mov(isel, dst_lo, "A", NULL);
                    emit_mov(isel, dst_hi, "A", NULL);
                } else {
                    emit_mov(isel, dst_lo, "#0", NULL);
                    emit_mov(isel, dst_hi, "#0", NULL);
                }
                store_spilled_dest_if_needed(isel, ins->dest, phys_dst_reg, size, ins);
                if (temp_result) free_temp_reg(isel, phys_dst_reg, size);
                return;
            }
            if (cnt == 8) {
                /* 移位 8 位: lo/hi 字节交换 + 其中一半清零/符号扩展 */
                if (is_shr) {
                    if (is_unsigned) {
                        /* unsigned >>8: result_lo = src_hi, result_hi = 0 */
                        emit_mov(isel, "A", dst_hi, NULL);
                        emit_mov(isel, dst_lo, "A", NULL);
                        emit_mov(isel, dst_hi, "#0", NULL);
                    } else {
                        /* signed >>8: result_lo = src_hi, result_hi = sign(src_hi) */
                        emit_mov(isel, "A", dst_hi, NULL);
                        emit_mov(isel, dst_lo, "A", NULL);
                        isel_emit(isel, "MOV", "C", "ACC.7", NULL);
                        isel_emit(isel, "MOV", "A", "#0", NULL);
                        isel_emit(isel, "SUBB", "A", "#0", NULL);
                        emit_mov(isel, dst_hi, "A", NULL);
                    }
                } else {
                    /* <<8: result_hi = src_lo, result_lo = 0 */
                    emit_mov(isel, "A", dst_lo, NULL);
                    emit_mov(isel, dst_hi, "A", NULL);
                    emit_mov(isel, dst_lo, "#0", NULL);
                }
                store_spilled_dest_if_needed(isel, ins->dest, phys_dst_reg, size, ins);
                if (temp_result) free_temp_reg(isel, phys_dst_reg, size);
                return;
            }
            for (int i = 0; i < cnt; i++) {
                if (is_shr) {
                    if (is_unsigned) {
                        /* logical right shift */
                        emit_mov(isel, "A", dst_hi, NULL);
                        isel_emit(isel, "CLR", "C", NULL, NULL);
                        isel_emit(isel, "RRC", "A", NULL, NULL);
                        emit_mov(isel, dst_hi, "A", NULL);
                        emit_mov(isel, "A", dst_lo, NULL);
                        isel_emit(isel, "RRC", "A", NULL, NULL);
                        emit_mov(isel, dst_lo, "A", NULL);
                    } else {
                        /* arithmetic right shift */
                        emit_mov(isel, "A", dst_hi, NULL);
                        isel_emit(isel, "MOV", "C", "ACC.7", NULL);
                        isel_emit(isel, "RRC", "A", NULL, NULL);
                        emit_mov(isel, dst_hi, "A", NULL);
                        emit_mov(isel, "A", dst_lo, NULL);
                        isel_emit(isel, "RRC", "A", NULL, NULL);
                        emit_mov(isel, dst_lo, "A", NULL);
                    }
                } else {
                    /* left shift */
                    emit_mov(isel, "A", dst_lo, NULL);
                    isel_emit(isel, "CLR", "C", NULL, NULL);
                    isel_emit(isel, "RLC", "A", NULL, NULL);
                    emit_mov(isel, dst_lo, "A", NULL);
                    emit_mov(isel, "A", dst_hi, NULL);
                    isel_emit(isel, "RLC", "A", NULL, NULL);
                    emit_mov(isel, dst_hi, "A", NULL);
                }
            }
            store_spilled_dest_if_needed(isel, ins->dest, phys_dst_reg, size, ins);
            if (temp_result) free_temp_reg(isel, phys_dst_reg, size);
            return;
        }

        ValueName cntv = get_src2_value(ins);
        const char* tcnt = isel_get_lo_reg(isel, cntv);
        int tcnt_tmp = alloc_temp_reg(isel, -1, 1);
        const char* tcnt_reg = (tcnt_tmp >= 0) ? isel_reg_name(tcnt_tmp) : tcnt;
        if (tcnt_tmp >= 0) emit_mov(isel, tcnt_reg, tcnt, NULL);

        char* l_loop = isel_new_label(isel, "Lsh_loop16");
        char* l_end = isel_new_label(isel, "Lsh_end16");
        char lb_loop[64], lb_end[64];
        snprintf(lb_loop, sizeof(lb_loop), "%s:", l_loop);
        snprintf(lb_end, sizeof(lb_end), "%s:", l_end);

        isel_emit(isel, lb_loop, NULL, NULL, NULL);
        emit_mov(isel, "A", tcnt_reg, NULL);
        isel_emit(isel, "JZ", l_end, NULL, NULL);

        bool is_unsigned = false;
        if (ins && ins->type) is_unsigned = get_attr(ins->type->attr).ctype_unsigned;

        if (is_shr) {
            if (is_unsigned) {
                emit_mov(isel, "A", dst_hi, NULL);
                isel_emit(isel, "CLR", "C", NULL, NULL);
                isel_emit(isel, "RRC", "A", NULL, NULL);
                emit_mov(isel, dst_hi, "A", NULL);
                emit_mov(isel, "A", dst_lo, NULL);
                isel_emit(isel, "RRC", "A", NULL, NULL);
                emit_mov(isel, dst_lo, "A", NULL);
            } else {
                emit_mov(isel, "A", dst_hi, NULL);
                isel_emit(isel, "MOV", "C", "ACC.7", NULL);
                isel_emit(isel, "RRC", "A", NULL, NULL);
                emit_mov(isel, dst_hi, "A", NULL);
                emit_mov(isel, "A", dst_lo, NULL);
                isel_emit(isel, "RRC", "A", NULL, NULL);
                emit_mov(isel, dst_lo, "A", NULL);
            }
        } else {
            emit_mov(isel, "A", dst_lo, NULL);
            isel_emit(isel, "CLR", "C", NULL, NULL);
            isel_emit(isel, "RLC", "A", NULL, NULL);
            emit_mov(isel, dst_lo, "A", NULL);
            emit_mov(isel, "A", dst_hi, NULL);
            isel_emit(isel, "RLC", "A", NULL, NULL);
            emit_mov(isel, dst_hi, "A", NULL);
        }

        isel_emit(isel, "DEC", tcnt_reg, NULL, NULL);
        isel_emit(isel, "SJMP", l_loop, NULL, NULL);
        isel_emit(isel, lb_end, NULL, NULL, NULL);

        free(l_loop); free(l_end);
        if (tcnt_tmp >= 0) free_temp_reg(isel, tcnt_tmp, 1);
        store_spilled_dest_if_needed(isel, ins->dest, phys_dst_reg, size, ins);
        if (temp_result) free_temp_reg(isel, phys_dst_reg, size);
        return;
    }

    /* other sizes unsupported */
    fprintf(stderr, "c51 backend: unsupported SHIFT size %d\n", size);
    exit(1);
}

void emit_mul(ISelContext* isel, Instr* ins, Instr* next) {
    ValueName a = get_src1_value(ins);
    ValueName b = get_src2_value(ins);
    int size = ins->type ? c51_abi_type_size(ins->type) : 1;

    if (size == 1) {
        int dst_reg = alloc_dest_reg(isel, ins, next, size, true);
        const char* dst_lo = isel_reg_name(dst_reg);
        emit_mov(isel, dst_lo, "#0", ins);
        int t = alloc_temp_reg(isel, -1, 1);
        const char* t_lo = (t >= 0) ? isel_reg_name(t) : "B";
        if (t >= 0) {
            emit_mov(isel, t_lo, isel_get_lo_reg(isel, b), NULL);
            emit_mov(isel, "B", t_lo, NULL);
            free_temp_reg(isel, t, 1);
        } else {
            emit_mov(isel, "B", isel_get_lo_reg(isel, b), NULL);
        }
        emit_mov(isel, "A", isel_get_lo_reg(isel, a), ins);
        isel_emit(isel, "MUL", "AB", NULL, NULL);
        emit_mov(isel, dst_lo, "A", ins);
        store_spilled_dest_if_needed(isel, ins->dest, dst_reg, size, ins);
        return;
    } else if (size == 2) {
        // Use Keil runtime ?C?IMUL: arg0 in R6:R7, arg1 in R4:R5 -> result in R6:R7
        // Low 16 bits of product are the same for signed/unsigned.

        // Reload operands first (before allocating dst, to avoid register pressure issues)
        int a_reg = isel_get_value_reg(isel, a);
        int b_reg = (b == a) ? a_reg : isel_get_value_reg(isel, b);

        if (a_reg < 0) {
            a_reg = isel_reload_spill(isel, a, 2, ins);
            if (a_reg < 0) a_reg = 0;
        }
        if (b_reg < 0) {
            b_reg = (b == a) ? a_reg : isel_reload_spill(isel, b, 2, ins);
            if (b_reg < 0) b_reg = a_reg;
        }

        // Now allocate dst (result lands in R6:R7 after LCALL, move to dst if different)
        int dst_reg = alloc_dest_reg(isel, ins, next, size, true);
        // alloc_dest_reg may return a single-byte reg index; ensure it's the hi byte of a pair
        if (dst_reg > 6) dst_reg = 6;  // clamp to valid 16-bit pair start

        // Parallel move: a->R6:R7, b->R4:R5
        RegMove moves[4] = {
            {.dst = 6, .src = a_reg},
            {.dst = 7, .src = a_reg + 1},
            {.dst = 4, .src = b_reg},
            {.dst = 5, .src = b_reg + 1},
        };
        emit_parallel_reg_moves(isel, moves, 4, ins);

        isel_emit(isel, "LCALL", "?C?IMUL", NULL, instr_to_ssa_str(ins));

        // Result in R6:R7 -> dst
        if (dst_reg != 6) {
            RegMove rmov[2] = {{.dst = dst_reg, .src = 6}, {.dst = dst_reg + 1, .src = 7}};
            emit_parallel_reg_moves(isel, rmov, 2, ins);
        }
        store_spilled_dest_if_needed(isel, ins->dest, dst_reg, size, ins);
        return;
    }
}

void emit_div_mod(ISelContext* isel, Instr* ins, bool want_mod) {
    ValueName num = get_src1_value(ins);
    ValueName den = get_src2_value(ins);
    int size = ins->type ? c51_abi_type_size(ins->type) : 1;

    int dst_reg = alloc_reg_for_value(isel, ins->dest, size);
    const char* dst_lo = isel_reg_name(dst_reg + (size == 2 ? 1 : 0));
    const char* dst_hi = isel_reg_name(dst_reg);

    bool is_unsigned = get_attr(ins->type->attr).ctype_unsigned;

    if (size == 1) {
        if (is_unsigned) {
            // unsigned 8-bit: use DIV AB
            const char* num_src = isel_get_lo_reg(isel, num);
            const char* den_src = isel_get_lo_reg(isel, den);
            int tnum = -1;
            const char* safe_num = num_src;

            if (strcmp(num_src, "A") == 0 || strcmp(den_src, "A") == 0) {
                tnum = alloc_temp_reg(isel, -1, 1);
                if (tnum >= 0) {
                    safe_num = isel_reg_name(tnum);
                    emit_mov(isel, safe_num, num_src, NULL);
                }
            }

            emit_mov(isel, "A", safe_num, ins);
            emit_mov(isel, "B", den_src, NULL);
            isel_emit(isel, "DIV", "AB", NULL, NULL);
            if (want_mod)
                emit_mov(isel, dst_lo, "B", ins);
            else
                emit_mov(isel, dst_lo, "A", ins);
            store_spilled_dest_if_needed(isel, ins->dest, dst_reg, size, ins);
            if (tnum >= 0) free_temp_reg(isel, tnum, 1);
            return;
        }

        // signed 8-bit: use Keil runtime ?C?SCDIV
        // Convention: A = num, B = den -> LCALL ?C?SCDIV -> A = quotient, B = remainder
        {
            const char* num_src = isel_get_lo_reg(isel, num);
            const char* den_src = isel_get_lo_reg(isel, den);

            // If den is in A, save it to a temp first to avoid clobbering
            int tden = -1;
            if (strcmp(den_src, "A") == 0) {
                tden = alloc_temp_reg(isel, -1, 1);
                const char* tmp = (tden >= 0) ? isel_reg_name(tden) : "R7";
                emit_mov(isel, tmp, den_src, NULL);
                den_src = (tden >= 0) ? isel_reg_name(tden) : "R7";
            }
            emit_mov(isel, "A", num_src, ins);
            emit_mov(isel, "B", den_src, NULL);
            if (tden >= 0) free_temp_reg(isel, tden, 1);
            isel_emit(isel, "LCALL", "?C?SCDIV", NULL, instr_to_ssa_str(ins));
            // quotient in A, remainder in B
            if (want_mod)
                emit_mov(isel, dst_lo, "B", ins);
            else
                emit_mov(isel, dst_lo, "A", ins);
        }
        store_spilled_dest_if_needed(isel, ins->dest, dst_reg, size, ins);
        return;
    } else if (size == 2) {
        if (!is_unsigned) {
            // signed 16-bit div/mod: use Keil runtime ?C?SIDIV
            // num -> R6:R7, den -> R4:R5; quotient R6:R7, remainder R4:R5
            int num_reg = isel_get_value_reg(isel, num);
            int den_reg = (den == num) ? num_reg : isel_get_value_reg(isel, den);

            // Reload spilled operands
            if (num_reg < 0) {
                num_reg = isel_reload_spill(isel, num, 2, ins);
                if (num_reg < 0) num_reg = 0;
            }
            if (den_reg < 0) {
                den_reg = (den == num) ? num_reg : isel_reload_spill(isel, den, 2, ins);
                if (den_reg < 0) den_reg = num_reg;
            }

            // Parallel move: num->R6:R7, den->R4:R5
            RegMove moves[4] = {
                {.dst = 6, .src = num_reg},
                {.dst = 7, .src = num_reg + 1},
                {.dst = 4, .src = den_reg},
                {.dst = 5, .src = den_reg + 1},
            };
            emit_parallel_reg_moves(isel, moves, 4, ins);

            isel_emit(isel, "LCALL", "?C?SIDIV", NULL, instr_to_ssa_str(ins));

            // quotient in R6:R7, remainder in R4:R5
            if (!want_mod) {
                // quotient -> dst
                if (dst_reg != 6) {
                    RegMove rmov[2] = {{.dst = dst_reg, .src = 6}, {.dst = dst_reg + 1, .src = 7}};
                    emit_parallel_reg_moves(isel, rmov, 2, ins);
                }
            } else {
                // remainder -> dst
                if (dst_reg != 4) {
                    RegMove rmov[2] = {{.dst = dst_reg, .src = 4}, {.dst = dst_reg + 1, .src = 5}};
                    emit_parallel_reg_moves(isel, rmov, 2, ins);
                }
            }
            store_spilled_dest_if_needed(isel, ins->dest, dst_reg, size, ins);
            return;
        }

        // unsigned 16-bit division/mod: use Keil runtime ?C?UIDIV
        // Convention: num -> R6:R7, den -> R4:R5
        //   -> LCALL ?C?UIDIV -> quotient in R6:R7, remainder in R4:R5
        {
            int num_reg = isel_get_value_reg(isel, num);
            int den_reg = (den == num) ? num_reg : isel_get_value_reg(isel, den);

            if (num_reg < 0) {
                num_reg = isel_reload_spill(isel, num, 2, ins);
                if (num_reg < 0) num_reg = 0;
            }
            if (den_reg < 0) {
                den_reg = (den == num) ? num_reg : isel_reload_spill(isel, den, 2, ins);
                if (den_reg < 0) den_reg = num_reg;
            }

            RegMove moves[4] = {
                {.dst = 6, .src = num_reg},
                {.dst = 7, .src = num_reg + 1},
                {.dst = 4, .src = den_reg},
                {.dst = 5, .src = den_reg + 1},
            };
            emit_parallel_reg_moves(isel, moves, 4, ins);

            isel_emit(isel, "LCALL", "?C?UIDIV", NULL, instr_to_ssa_str(ins));

            // quotient in R6:R7, remainder in R4:R5
            if (!want_mod) {
                if (dst_reg != 6) {
                    RegMove rmov[2] = {{.dst = dst_reg, .src = 6}, {.dst = dst_reg + 1, .src = 7}};
                    emit_parallel_reg_moves(isel, rmov, 2, ins);
                }
            } else {
                if (dst_reg != 4) {
                    RegMove rmov[2] = {{.dst = dst_reg, .src = 4}, {.dst = dst_reg + 1, .src = 5}};
                    emit_parallel_reg_moves(isel, rmov, 2, ins);
                }
            }
            store_spilled_dest_if_needed(isel, ins->dest, dst_reg, size, ins);
            return;
        }
    }

    fprintf(stderr, "c51 backend: only 8/16-bit DIV/MOD supported\n");
    exit(1);
}

void emit_select(ISelContext* isel, Instr* ins, Instr* next) {
    if (!ins->args || ins->args->len < 3) return;
    ValueName cond = *(ValueName*)list_get(ins->args, 0);
    ValueName tv = *(ValueName*)list_get(ins->args, 1);
    ValueName fv = *(ValueName*)list_get(ins->args, 2);

    int size = ins->type ? c51_abi_type_size(ins->type) : get_value_size(isel, ins->dest);
    int tv_size = get_value_size(isel, tv);
    int fv_size = get_value_size(isel, fv);
    if (tv_size > size) size = tv_size;
    if (fv_size > size) size = fv_size;
    if (size < 1) size = 1;
    int dst_reg = alloc_reg_for_value(isel, ins->dest, size);
    int phys_dst_reg = dst_reg;
    bool temp_result = false;
    if (phys_dst_reg < 0 || phys_dst_reg + size - 1 > 7) {
        phys_dst_reg = alloc_temp_reg(isel, ins->dest, size);
        temp_result = phys_dst_reg >= 0;
    }
    if (phys_dst_reg < 0) phys_dst_reg = 0;

    /* �?select 结果直接�?RET 使用时，强制分配�?R6/R7，避�?RET 前额外拷�?*/
    if (next && next->op == IROP_RET && size == 2 && phys_dst_reg != 6) {
        int tv_reg = isel_get_value_reg(isel, tv);
        int fv_reg = isel_get_value_reg(isel, fv);
        /* 确保 tv/fv 的源寄存器不�?R6/R7 范围内（避免覆盖源） */
        bool tv_safe = (tv_reg < 0) || (tv_reg + size - 1 < 6);
        bool fv_safe = (fv_reg < 0) || (fv_reg + size - 1 < 6);
        if (tv_safe && fv_safe) {
            /* 释放旧分配，重新绑定�?R6 */
            if (phys_dst_reg >= 0 && phys_dst_reg <= 7) {
                for (int j = 0; j < size; j++) {
                    if (isel->reg_val[phys_dst_reg + j] == ins->dest)
                        isel->reg_val[phys_dst_reg + j] = 0;
                    isel->reg_busy[phys_dst_reg + j] = false;
                }
            }
            phys_dst_reg = 6;
            dst_reg = 6;
            temp_result = false;
            /* 更新 value_to_reg */
            int* rptr = malloc(sizeof(int));
            *rptr = 6;
            char* key = int_to_key(ins->dest);
            dict_put(isel->ctx->value_to_reg, key, rptr);
            isel->reg_busy[6] = true; isel->reg_val[6] = ins->dest;
            isel->reg_busy[7] = true; isel->reg_val[7] = ins->dest;
        }
    }

    const char* dst_lo = isel_reg_name(phys_dst_reg + (size == 2 ? 1 : 0));
    const char* dst_hi = isel_reg_name(phys_dst_reg);

    char* l_true = isel_new_label(isel, "Lsel_true");
    char* l_end = isel_new_label(isel, "Lsel_end");
    char lb_true[64], lb_end[64];
    snprintf(lb_true, sizeof(lb_true), "%s:", l_true);
    snprintf(lb_end, sizeof(lb_end), "%s:", l_end);

    if (get_value_size(isel, cond) == 2) {
        /* 16位cond测试：加载lo，保存，再加载hi到A，ORL A, lo_saved */
        const char* cond_lo_raw = isel_get_lo_reg(isel, cond);
        int cond_lo_tmp = -1;
        const char* cond_lo_safe;
        if (strcmp(cond_lo_raw, "A") == 0) {
            /* lo在A中，需先保存到临时寄存�?*/
            int tr = alloc_temp_reg(isel, -1, 1);
            if (tr >= 0) {
                emit_mov(isel, isel_reg_name(tr), "A", NULL);
                cond_lo_tmp = tr;
                cond_lo_safe = isel_reg_name(tr);
            } else {
                isel_emit(isel, "MOV", "B", "A", NULL);
                cond_lo_safe = "B";
            }
        } else {
            cond_lo_safe = cond_lo_raw;
        }
        emit_mov(isel, "A", isel_get_hi_reg(isel, cond), NULL);
        isel_emit(isel, "ORL", "A", cond_lo_safe, NULL);
        if (cond_lo_tmp >= 0) free_temp_reg(isel, cond_lo_tmp, 1);
    } else {
        isel_ensure_in_acc(isel, cond);
    }

    const char* src_tv_lo = isel_get_extended_lo_reg(isel, tv, size);
    const char* src_tv_hi = isel_get_extended_hi_reg(isel, tv, size);
    const char* src_fv_lo = isel_get_extended_lo_reg(isel, fv, size);
    const char* src_fv_hi = isel_get_extended_hi_reg(isel, fv, size);

    bool need_temp_tv = (strcmp(src_tv_lo, "A") == 0) || (strcmp(src_tv_lo, dst_lo) == 0);
    bool need_temp_fv = (strcmp(src_fv_lo, "A") == 0) || (strcmp(src_fv_lo, dst_lo) == 0);
    if (size == 2) {
        need_temp_tv = need_temp_tv || (strcmp(src_tv_hi, "A") == 0) || (strcmp(src_tv_hi, dst_hi) == 0) ||
                       (strcmp(src_tv_lo, dst_hi) == 0) || (strcmp(src_tv_hi, dst_lo) == 0);
        need_temp_fv = need_temp_fv || (strcmp(src_fv_hi, "A") == 0) || (strcmp(src_fv_hi, dst_hi) == 0) ||
                       (strcmp(src_fv_lo, dst_hi) == 0) || (strcmp(src_fv_hi, dst_lo) == 0);
    }

    int tr_tv = -1, tr_fv = -1;
    const char* tv_lo_src = src_tv_lo;
    const char* tv_hi_src = src_tv_hi;
    const char* fv_lo_src = src_fv_lo;
    const char* fv_hi_src = src_fv_hi;

    if (need_temp_tv) {
        tr_tv = alloc_temp_reg(isel, tv, size);
        if (tr_tv >= 0) {
            tv_lo_src = isel_reg_name(tr_tv + (size == 2 ? 1 : 0));
            tv_hi_src = isel_reg_name(tr_tv);
            if (size == 2) isel_emit(isel, "MOV", tv_hi_src, src_tv_hi, NULL);
            isel_emit(isel, "MOV", tv_lo_src, src_tv_lo, NULL);
        }
    }
    if (need_temp_fv) {
        tr_fv = alloc_temp_reg(isel, fv, size);
        if (tr_fv >= 0) {
            fv_lo_src = isel_reg_name(tr_fv + (size == 2 ? 1 : 0));
            fv_hi_src = isel_reg_name(tr_fv);
            if (size == 2) isel_emit(isel, "MOV", fv_hi_src, src_fv_hi, NULL);
            isel_emit(isel, "MOV", fv_lo_src, src_fv_lo, NULL);
        }
    }

    isel_emit(isel, "JNZ", l_true, NULL, NULL);
    emit_mov(isel, dst_lo, fv_lo_src, ins);
    if (size == 2) emit_mov(isel, dst_hi, fv_hi_src, NULL);
    isel_emit(isel, "SJMP", l_end, NULL, NULL);
    isel_emit(isel, lb_true, NULL, NULL, NULL);
    emit_mov(isel, dst_lo, tv_lo_src, ins);
    if (size == 2) emit_mov(isel, dst_hi, tv_hi_src, NULL);
    isel_emit(isel, lb_end, NULL, NULL, NULL);

    store_spilled_dest_if_needed(isel, ins->dest, phys_dst_reg, size, ins);

    if (tr_tv >= 0) free_temp_reg(isel, tr_tv, size);
    if (tr_fv >= 0) free_temp_reg(isel, tr_fv, size);
    if (temp_result) free_temp_reg(isel, phys_dst_reg, size);

    free(l_true); free(l_end);
}

void emit_simple_cast(ISelContext* isel, Instr* ins, bool sign_extend) {
    ValueName src = get_src1_value(ins);
    int src_size = get_value_size(isel, src);
    int dst_size = ins->type ? c51_abi_type_size(ins->type) : src_size;
    int dst_reg = alloc_reg_for_value(isel, ins->dest, dst_size);
    const char* dst_lo = isel_reg_name(dst_reg + (dst_size == 2 ? 1 : 0));
    const char* dst_hi = isel_reg_name(dst_reg);
    const char* src_lo = isel_get_lo_reg(isel, src);

    emit_mov(isel, dst_lo, src_lo, ins);
    if (dst_size == 2) {
        if (src_size == 2) {
            emit_mov(isel, dst_hi, isel_get_hi_reg(isel, src), NULL);
        } else if (sign_extend) {
            char* l_neg = isel_new_label(isel, "Lsext_neg");
            char* l_end = isel_new_label(isel, "Lsext_end");
            char lb_neg[64], lb_end[64];
            snprintf(lb_neg, sizeof(lb_neg), "%s:", l_neg);
            snprintf(lb_end, sizeof(lb_end), "%s:", l_end);
            emit_mov(isel, "A", src_lo, NULL);
            isel_emit(isel, "ANL", "A", "#128", NULL);
            isel_emit(isel, "JNZ", l_neg, NULL, NULL);
            emit_mov(isel, dst_hi, "#0", NULL);
            isel_emit(isel, "SJMP", l_end, NULL, NULL);
            isel_emit(isel, lb_neg, NULL, NULL, NULL);
            emit_mov(isel, dst_hi, "#255", NULL);
            isel_emit(isel, lb_end, NULL, NULL, NULL);
            free(l_neg); free(l_end);
        } else {
            emit_mov(isel, dst_hi, "#0", NULL);
        }
    }

    store_spilled_dest_if_needed(isel, ins->dest, dst_reg, dst_size, ins);
}

void emit_sub(ISelContext* isel, Instr* ins, Instr* next) {
    ValueName src1 = get_src1_value(ins);
    int size = ins->type ? c51_abi_type_size(ins->type) : 1;
    int src1_size = get_value_size(isel, src1);
    int64_t imm_val;
    bool src2_is_imm = is_imm_operand(ins, &imm_val);
    ValueName src2 = src2_is_imm ? -1 : get_src2_value(ins);
    const char* src2_sym = (!src2_is_imm) ? lookup_value_addr_symbol(isel, src2) : NULL;
    bool src2_spilled_mem = (!src2_is_imm) && src2_sym && isel_get_value_reg(isel, src2) == SPILL_REG;

    const char* src1_lo = isel_get_lo_reg(isel, src1);
    int dst_reg = alloc_dest_reg(isel, ins, next, size, true);
    int phys_dst_reg = dst_reg;
    bool temp_result = false;
    if (phys_dst_reg < 0 || phys_dst_reg + size - 1 > 7) {
        phys_dst_reg = alloc_temp_reg(isel, ins->dest, size);
        temp_result = phys_dst_reg >= 0;
    }
    if (phys_dst_reg < 0) phys_dst_reg = 0;

    /* If next instruction is RET, write result directly into return registers R7/R6
     * to avoid an extra MOV copy after the subtraction. */
    int ret_size_sub = (next && next->op == IROP_RET && next->type)
                       ? c51_abi_type_size(next->type) : 0;
    bool direct_to_ret = false;
    if (next && next->op == IROP_RET && !temp_result) {
        int ret_phys = (ret_size_sub == 2 || size == 2) ? 6 : 7;
        if (phys_dst_reg != ret_phys) {
            /* Safety: don't redirect if src1 overlaps R6/R7 (would corrupt read) */
            int src1_base = isel_get_value_reg(isel, src1);
            bool src1_safe = (src1_base < 0) || (src1_base + src1_size - 1 < 6);
            if (src1_safe) {
                phys_dst_reg = ret_phys;
                direct_to_ret = true;
            }
        }
    }

    const char* dst_lo = isel_reg_name(phys_dst_reg + (size == 2 ? 1 : 0));
    const char* src1_hi_preserved = NULL;
    const char* src2_hi_preserved = NULL;
    int src1_hi_tmp = -1;
    int src2_hi_tmp = -1;
    int src2_size = (!src2_is_imm) ? get_value_size(isel, src2) : 0;

    if (size == 2) {
        if (src1_size == 2) {
            int src1_base_reg = isel_get_value_reg(isel, src1);
            const char* src1_hi = (src1_base_reg >= 0) ? isel_reg_name(src1_base_reg) : NULL;
            if (dst_lo && src1_hi && strcmp(dst_lo, src1_hi) == 0) {
                src1_hi_tmp = alloc_temp_reg(isel, -1, 1);
                src1_hi_preserved = (src1_hi_tmp >= 0) ? isel_reg_name(src1_hi_tmp) : "B";
                emit_mov(isel, src1_hi_preserved, src1_hi, NULL);
            }
        }
        if (!src2_is_imm && !src2_spilled_mem && src2_size == 2) {
            int src2_base_reg = isel_get_value_reg(isel, src2);
            const char* src2_hi = (src2_base_reg >= 0) ? isel_reg_name(src2_base_reg) : NULL;
            if (dst_lo && src2_hi && strcmp(dst_lo, src2_hi) == 0) {
                src2_hi_tmp = alloc_temp_reg(isel, -1, 1);
                src2_hi_preserved = (src2_hi_tmp >= 0) ? isel_reg_name(src2_hi_tmp) : "B";
                emit_mov(isel, src2_hi_preserved, src2_hi, NULL);
            }
        }
    }

    /* 检�?src2 是否�?IDATA spill: 如果是，可以直接�?SUBB A, sym 避免中转 B */
    bool src2_idata_direct_sub = false;
    if (src2_spilled_mem && src2_sym) {
        SectionKind src2_sec_sub = get_symbol_section_kind(isel, src2_sym);
        src2_idata_direct_sub = (src2_sec_sub == SEC_IDATA);
    }
    /* 16-bit sub-1 special case: use DEC Rlo; JNZ skip; DEC Rhi; skip:
     * This matches the compact pattern keil generates and avoids CLR C + SUBB pair. */
    if (size == 2 && src2_is_imm && imm_val == 1 && src1_size == 2 && !src2_spilled_mem) {
        const char* src1_hi = src1_hi_preserved ? src1_hi_preserved : isel_get_hi_reg(isel, src1);
        const char* dst_hi = isel_reg_name(phys_dst_reg);

        /* Copy src to dst first (in-place DEC is safe when dst == src) */
        if (strcmp(dst_lo, src1_lo) != 0) {
            emit_mov(isel, dst_lo, src1_lo, ins);
        }
        if (strcmp(dst_hi, src1_hi) != 0) {
            emit_mov(isel, dst_hi, src1_hi, ins);
        }

        char* l_skip = isel_new_label(isel, "Ldec16_skip");
        char lb_skip[64];
        snprintf(lb_skip, sizeof(lb_skip), "%s:", l_skip);

        char* ssa = instr_to_ssa_str(ins);
        /* DEC low byte */
        isel_emit(isel, "DEC", dst_lo, NULL, ssa);
        free(ssa);
        /* If dst_lo wrapped from 0x00 to 0xFF, borrow occurred �?DEC high byte
         * CJNE Rlo, #255, skip  �?jumps to skip if Rlo != 0xFF, falls through if Rlo == 0xFF */
        {
            char cjne_arg2[64];
            snprintf(cjne_arg2, sizeof(cjne_arg2), "#255,%s", l_skip);
            isel_emit(isel, "CJNE", dst_lo, cjne_arg2, NULL);
        }
        isel_emit(isel, "DEC", dst_hi, NULL, NULL);
        isel_emit(isel, lb_skip, NULL, NULL, NULL);
        free(l_skip);

        store_spilled_dest_if_needed(isel, ins->dest, phys_dst_reg, size, ins);
        if (src1_hi_tmp >= 0) free_temp_reg(isel, src1_hi_tmp, 1);
        if (src2_hi_tmp >= 0) free_temp_reg(isel, src2_hi_tmp, 1);
        if (next && next->op == IROP_RET) {
            int ret_size = next->type ? c51_abi_type_size(next->type) : 1;
            if (!direct_to_ret) {
                const char* ret_lo = isel_reg_name(phys_dst_reg + 1);
                const char* ret_hi = isel_reg_name(phys_dst_reg);
                if (strcmp(ret_lo, "R7") != 0) emit_mov(isel, "R7", ret_lo, ins);
                if (ret_size == 2 && strcmp(ret_hi, "R6") != 0) emit_mov(isel, "R6", ret_hi, ins);
            }
            if (isel->ctx && isel->ctx->value_to_reg) {
                int* reg_num = malloc(sizeof(int));
                *reg_num = 6;
                char* key = int_to_key(ins->dest);
                dict_put(isel->ctx->value_to_reg, key, reg_num);
            }
        }
        if (temp_result) free_temp_reg(isel, phys_dst_reg, size);
        return;
    }

    /* src2_spilled_mem 且非 IDATA 直接：预加载 B (IDATA 直接时在 SUBB 指令中使�?sym 字面�? */
    if (src2_spilled_mem && !src2_idata_direct_sub) {
        emit_load_symbol_byte(isel, src2_sym, 0, "B", NULL);
    }
    emit_mov(isel, "A", src1_lo, ins);

    if (src2_is_imm) {
        int imm_low = (int)(imm_val & 0xFF);
        if (imm_low == 1 && size == 1) {
            char* ssa = instr_to_ssa_str(ins);
            isel_emit(isel, "DEC", "A", NULL, ssa);
            free(ssa);
        } else if (imm_low == 2 && size == 1) {
            char* ssa = instr_to_ssa_str(ins);
            isel_emit(isel, "DEC", "A", NULL, ssa);
            free(ssa);
            isel_emit(isel, "DEC", "A", NULL, NULL);
        } else {
            isel_emit(isel, "CLR", "C", NULL, NULL);
            char imm_str[16];
            snprintf(imm_str, sizeof(imm_str), "#%d", imm_low);
            char* ssa = instr_to_ssa_str(ins);
            isel_emit(isel, "SUBB", "A", imm_str, ssa);
            free(ssa);
        }
    } else {
        isel_emit(isel, "CLR", "C", NULL, NULL);
        char* ssa = instr_to_ssa_str(ins);
        if (src2_spilled_mem) {
            if (src2_idata_direct_sub) {
                /* IDATA 直接地址：SUBB A, sym */
                isel_emit(isel, "SUBB", "A", src2_sym, ssa);
            } else {
                isel_emit(isel, "SUBB", "A", "B", ssa);
            }
        } else {
            const char* src2_lo = isel_get_lo_reg(isel, src2);
            isel_emit(isel, "SUBB", "A", src2_lo, ssa);
        }
        free(ssa);
    }

    emit_mov(isel, dst_lo, "A", ins);

    if (size == 2) {
        const char* dst_hi = isel_reg_name(phys_dst_reg);

        if (src1_size == 2) {
            const char* src1_hi = src1_hi_preserved ? src1_hi_preserved : isel_get_hi_reg(isel, src1);
            emit_mov(isel, "A", src1_hi, ins);
        } else {
            emit_mov(isel, "A", "#0", ins);
        }

        if (src2_is_imm) {
            char imm_str[16];
            snprintf(imm_str, sizeof(imm_str), "#%d", (int)((imm_val >> 8) & 0xFF));
            isel_emit(isel, "SUBB", "A", imm_str, NULL);
        } else {
            if (src2_size == 2) {
                if (src2_spilled_mem) {
                    if (src2_idata_direct_sub) {
                        /* IDATA 直接：SUBB A, (sym+1) */
                        char ref[256];
                        snprintf(ref, sizeof(ref), "(%s + 1)", src2_sym);
                        isel_emit(isel, "SUBB", "A", ref, NULL);
                    } else {
                        emit_mov(isel, dst_hi, "A", NULL);
                        emit_load_symbol_byte(isel, src2_sym, 1, "B", NULL);
                        emit_mov(isel, "A", dst_hi, NULL);
                        isel_emit(isel, "SUBB", "A", "B", NULL);
                    }
                } else {
                    const char* src2_hi = src2_hi_preserved ? src2_hi_preserved : isel_get_hi_reg(isel, src2);
                    isel_emit(isel, "SUBB", "A", src2_hi, NULL);
                }
            } else {
                isel_emit(isel, "SUBB", "A", "#0", NULL);
            }
        }

        emit_mov(isel, dst_hi, "A", ins);
    }

    store_spilled_dest_if_needed(isel, ins->dest, phys_dst_reg, size, ins);

    if (src1_hi_tmp >= 0) free_temp_reg(isel, src1_hi_tmp, 1);
    if (src2_hi_tmp >= 0) free_temp_reg(isel, src2_hi_tmp, 1);

    if (next && next->op == IROP_RET) {
        int ret_size = next->type ? c51_abi_type_size(next->type) : 1;
        if (!direct_to_ret) {
            /* Fallback: result is already in phys_dst_reg, emit copy if needed */
            const char* ret_lo = NULL;
            const char* ret_hi = NULL;
            if (phys_dst_reg >= 0) {
                ret_lo = isel_reg_name(phys_dst_reg + (size == 2 ? 1 : 0));
                ret_hi = isel_reg_name(phys_dst_reg);
            } else {
                ret_lo = isel_get_lo_reg(isel, ins->dest);
                ret_hi = isel_get_hi_reg(isel, ins->dest);
            }
            if (ret_lo && strcmp(ret_lo, "R7") != 0) {
                emit_mov(isel, "R7", ret_lo, ins);
            }
            if (ret_size == 2) {
                if (size == 2) {
                    if (ret_hi && strcmp(ret_hi, "R6") != 0) {
                        emit_mov(isel, "R6", ret_hi, ins);
                    }
                } else {
                    emit_mov(isel, "R6", "#00H", ins);
                }
            }
        }
        /* direct_to_ret: result was written directly to R7/R6, no copy needed */
        if (isel->ctx && isel->ctx->value_to_reg) {
            int* reg_num = malloc(sizeof(int));
            *reg_num = (size == 2) ? 6 : 7;
            char* key = int_to_key(ins->dest);
            dict_put(isel->ctx->value_to_reg, key, reg_num);
        }
    }

    if (temp_result) {
        free_temp_reg(isel, phys_dst_reg, size);
    }
}

void emit_trunc(ISelContext* isel, Instr* ins) {
    ValueName src = get_src1_value(ins);
    int src_size = get_value_size(isel, src);

    {
        Func* func = (isel && isel->ctx) ? isel->ctx->current_func : NULL;
        ValueName seen_values[16];
        Instr* src_def = func ? find_def_instr_in_func(func, src) : NULL;
        if (src_def && src_def->op == IROP_OR) {
            ValueName lhs = get_src1_value(src_def);
            ValueName rhs = get_src2_value(src_def);
            Instr* lhs_def = find_def_instr_in_func(func, lhs);
            Instr* rhs_def = find_def_instr_in_func(func, rhs);
            if (lhs_def && rhs_def &&
                ((lhs_def->op == IROP_SHL && rhs_def->op == IROP_SHR) ||
                 (lhs_def->op == IROP_SHR && rhs_def->op == IROP_SHL))) {
                ValueName rot_src_l = get_src1_value(lhs_def);
                ValueName rot_src_r = get_src1_value(rhs_def);
                int64_t lhs_cnt = 0;
                int64_t rhs_cnt = 0;

                if (rot_src_l == rot_src_r && rot_src_l > 0 &&
                    (is_imm_operand(lhs_def, &lhs_cnt) || try_get_value_const(isel, get_src2_value(lhs_def), &lhs_cnt)) &&
                    (is_imm_operand(rhs_def, &rhs_cnt) || try_get_value_const(isel, get_src2_value(rhs_def), &rhs_cnt))) {
                    lhs_cnt &= 7;
                    rhs_cnt &= 7;
                    if (((lhs_cnt + rhs_cnt) & 7) == 0 && lhs_cnt != 0 && rhs_cnt != 0) {
                        if (value_is_zero_extended_byte_in_func(func, rot_src_l, seen_values, 0)) {
                            int dst_reg = safe_alloc_reg_for_value(isel, ins->dest, 1);
                            int rot_count = (lhs_def->op == IROP_SHL) ? (int)lhs_cnt : (int)rhs_cnt;
                            bool rot_left = lhs_def->op == IROP_SHL;
                            const char* src_lo = isel_get_lo_reg(isel, rot_src_l);

                            if (dst_reg >= 0) {
                                emit_mov(isel, "A", src_lo, ins);
                                if (rot_count > 4) {
                                    rot_count = 8 - rot_count;
                                    rot_left = !rot_left;
                                }
                                for (int i = 0; i < rot_count; i++) {
                                    isel_emit(isel, rot_left ? "RL" : "RR", "A", NULL, NULL);
                                }
                                emit_mov(isel, isel_reg_name(dst_reg), "A", NULL);
                                store_spilled_dest_if_needed(isel, ins->dest, dst_reg, 1, ins);
                                return;
                            }
                        }
                    }
                }
            }
        }
    }

    if (src_size == 2) {
        int src_base = isel_get_value_reg(isel, src);
        if (src_base >= 0) {
            int lo_reg = src_base + 1;

            int* reg_num = malloc(sizeof(int));
            *reg_num = lo_reg;
            char* key = int_to_key(ins->dest);
            dict_put(isel->ctx->value_to_reg, key, reg_num);

            if (lo_reg < 8) {
                isel->reg_busy[lo_reg] = true;
                isel->reg_val[lo_reg] = ins->dest;
            }
        } else if (src_base == ACC_REG) {
            int* reg_num = malloc(sizeof(int));
            *reg_num = ACC_REG;
            char* key = int_to_key(ins->dest);
            dict_put(isel->ctx->value_to_reg, key, reg_num);
        } else {
            int dst_reg = safe_alloc_reg_for_value(isel, ins->dest, 1);
            if (dst_reg >= 0) {
                const char* src_lo = isel_get_lo_reg(isel, src);
                emit_mov(isel, isel_reg_name(dst_reg), src_lo, ins);
                store_spilled_dest_if_needed(isel, ins->dest, dst_reg, 1, ins);
            }
        }
    } else {
        int* reg_num = malloc(sizeof(int));
        *reg_num = isel_get_value_reg(isel, src);
        char* key = int_to_key(ins->dest);
        dict_put(isel->ctx->value_to_reg, key, reg_num);
    }
}
