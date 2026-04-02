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

void emit_const(ISelContext* isel, Instr* ins) {
    int size = ins->type ? c51_abi_type_size(ins->type) : 1;
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

    int reg = alloc_reg_for_value(isel, ins->dest, size);
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
    bool src2_spilled_mem = (!src2_is_imm) && src2_sym && isel_get_value_reg(isel, src2) == -3;

    int dst_reg = alloc_dest_reg(isel, ins, next, size, true);
    int src1_base_reg = isel_get_value_reg(isel, src1);
    if (dst_reg >= 0 && src1_base_reg >= 0 && src1 != ins->dest) {
        int src1_begin = src1_base_reg;
        int src1_end = src1_base_reg + src1_size - 1;
        int dst_begin = dst_reg;
        int dst_end = dst_reg + size - 1;
        bool overlaps = !(dst_end < src1_begin || dst_begin > src1_end);
        if (overlaps) {
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
    if (src2_spilled_mem) {
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
            isel_emit(isel, "ADD", "A", "B", NULL);
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
                    emit_mov(isel, dst_hi, "A", NULL);
                    emit_load_symbol_byte(isel, src2_sym, 1, "B", NULL);
                    emit_mov(isel, "A", dst_hi, NULL);
                    isel_emit(isel, "ADDC", "A", "B", NULL);
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

void emit_shift(ISelContext* isel, Instr* ins, bool is_shr) {
    ValueName src = get_src1_value(ins);
    int size = ins->type ? c51_abi_type_size(ins->type) : 1;
    int dst_reg = alloc_dest_reg(isel, ins, NULL, size, true);
    int phys_dst_reg = dst_reg;
    bool temp_result = false;
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
                /* 移位量 >= 8: 结果为 0 (无符号 / 左移) 或符号扩展 (有符号右移) */
                emit_mov(isel, "A", dst_lo, ins);
                if (is_shr && !is_unsigned) {
                    /* 算术右移 >=8: 结果为 0x00 或 0xFF */
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
                    /* 逻辑右移7: A = (old_A >> 7) = bit7 → RL A; ANL A, #1 */
                    isel_emit(isel, "RL", "A", NULL, NULL);
                    isel_emit(isel, "ANL", "A", "#1", NULL);
                } else {
                    /* 算术右移7: 结果 0x00 或 0xFF */
                    isel_emit(isel, "MOV", "C", "ACC.7", NULL);
                    isel_emit(isel, "MOV", "A", "#0", NULL);
                    isel_emit(isel, "SUBB", "A", "#0", NULL);
                }
                emit_mov(isel, dst_lo, "A", NULL);
                return;
            }
            if (!is_shr && cnt == 7) {
                /* shl x, 7: 取最低位放到 bit7 → RR A; ANL A, #0x80 */
                emit_mov(isel, "A", dst_lo, ins);
                isel_emit(isel, "RR", "A", NULL, NULL);
                isel_emit(isel, "ANL", "A", "#128", NULL);
                emit_mov(isel, dst_lo, "A", NULL);
                return;
            }
            if (cnt == 4) {
                /* 移位4: 用 SWAP + 掩码 */
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
                /* 无符号右移5-6: 用左旋转 (8-cnt) 次 + 掩码更高效 */
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
                /* 左移5-6: 用右旋转 (8-cnt) 次 + 掩码更高效 */
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
            /* 一般情况: 1-3 次移位，逐次生成 */
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
    int dst_reg = alloc_dest_reg(isel, ins, next, size, true);
    const char* dst_lo = isel_reg_name(dst_reg + (size == 2 ? 1 : 0));
    const char* dst_hi = isel_reg_name(dst_reg);

    if (size == 1) {
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
        // compute low 16 bits of 16x16 multiply using three 8x8 MULs
        const char* alo = isel_get_lo_reg(isel, a);
        const char* ahi = isel_get_hi_reg(isel, a);
        const char* blo = isel_get_lo_reg(isel, b);
        const char* bhi = isel_get_hi_reg(isel, b);

        int t_acc = alloc_temp_reg(isel, -1, 1); // accumulator for high byte
        int t_tmp = alloc_temp_reg(isel, -1, 1); // temp for p1/p2 low
        const char* acc = (t_acc >= 0) ? isel_reg_name(t_acc) : "R0";
        const char* tpp = (t_tmp >= 0) ? isel_reg_name(t_tmp) : "R1";

        // p0 = alo * blo
        emit_mov(isel, "B", blo, NULL);
        emit_mov(isel, "A", alo, ins);
        isel_emit(isel, "MUL", "AB", NULL, NULL); // A=p0_low, B=p0_high
        emit_mov(isel, dst_lo, "A", ins);
        emit_mov(isel, acc, "B", NULL); // acc = p0_high

        // p1 = ahi * blo
        emit_mov(isel, "B", blo, NULL);
        emit_mov(isel, "A", ahi, NULL);
        isel_emit(isel, "MUL", "AB", NULL, NULL); // A=p1_low
        emit_mov(isel, tpp, "A", NULL); // tpp = p1_low
        emit_mov(isel, "A", acc, NULL);
        isel_emit(isel, "ADD", "A", tpp, NULL);
        emit_mov(isel, acc, "A", NULL);

        // p2 = alo * bhi
        emit_mov(isel, "B", bhi, NULL);
        emit_mov(isel, "A", alo, NULL);
        isel_emit(isel, "MUL", "AB", NULL, NULL); // A=p2_low
        emit_mov(isel, tpp, "A", NULL); // tpp = p2_low
        emit_mov(isel, "A", acc, NULL);
        isel_emit(isel, "ADD", "A", tpp, NULL);
        emit_mov(isel, dst_hi, "A", NULL);

        if (t_acc >= 0) free_temp_reg(isel, t_acc, 1);
        if (t_tmp >= 0) free_temp_reg(isel, t_tmp, 1);
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

        // signed 8-bit: existing algorithm (abs -> DIV AB -> fix signs)
        int tr  = alloc_temp_reg(isel, -1, 1);   // num_tmp
        int td  = alloc_temp_reg(isel, -1, 1);   // den_tmp
        int tsn = alloc_temp_reg(isel, -1, 1);   // s_num
        int tsd = alloc_temp_reg(isel, -1, 1);   // s_den

        const char* num_tmp = (tr  >= 0) ? isel_reg_name(tr)  : "R1";
        const char* den_tmp = (td  >= 0) ? isel_reg_name(td)  : "R2";
        const char* s_num   = (tsn >= 0) ? isel_reg_name(tsn) : "R3";
        const char* s_den   = (tsd >= 0) ? isel_reg_name(tsd) : "R4";

        char* l_num_pos    = isel_new_label(isel, "Lnum_pos");
        char* l_den_pos    = isel_new_label(isel, "Lden_pos");
        char* l_no_negq    = isel_new_label(isel, "Lno_negq");
        char* l_no_rem_neg = isel_new_label(isel, "Lno_rem_neg");

        emit_mov(isel, s_num, "#0", NULL);
        emit_mov(isel, s_den, "#0", NULL);

        // num abs
        emit_mov(isel, num_tmp, isel_get_lo_reg(isel, num), NULL);
        emit_mov(isel, "A", num_tmp, NULL);
        isel_emit(isel, "ANL", "A", "#128", NULL);
        isel_emit(isel, "JZ", l_num_pos, NULL, NULL);
        emit_mov(isel, "A", num_tmp, NULL);
        isel_emit(isel, "CPL", "A", NULL, NULL);
        isel_emit(isel, "INC", "A", NULL, NULL);
        emit_mov(isel, num_tmp, "A", NULL);
        isel_emit(isel, "MOV", s_num, "#1", NULL);
        isel_emit(isel, l_num_pos, NULL, NULL, NULL);

        // den abs
        emit_mov(isel, den_tmp, isel_get_lo_reg(isel, den), NULL);
        emit_mov(isel, "A", den_tmp, NULL);
        isel_emit(isel, "ANL", "A", "#128", NULL);
        isel_emit(isel, "JZ", l_den_pos, NULL, NULL);
        emit_mov(isel, "A", den_tmp, NULL);
        isel_emit(isel, "CPL", "A", NULL, NULL);
        isel_emit(isel, "INC", "A", NULL, NULL);
        emit_mov(isel, den_tmp, "A", NULL);
        isel_emit(isel, "MOV", s_den, "#1", NULL);
        isel_emit(isel, l_den_pos, NULL, NULL, NULL);

        // divide
        emit_mov(isel, "A", num_tmp, NULL);
        emit_mov(isel, "B", den_tmp, NULL);
        isel_emit(isel, "DIV", "AB", NULL, NULL);

        if (want_mod) {
            emit_mov(isel, "A", s_num, NULL);
            isel_emit(isel, "JZ", l_no_rem_neg, NULL, NULL);
            emit_mov(isel, "A", "B", NULL);
            isel_emit(isel, "CPL", "A", NULL, NULL);
            isel_emit(isel, "INC", "A", NULL, NULL);
            emit_mov(isel, "B", "A", NULL);
            isel_emit(isel, l_no_rem_neg, NULL, NULL, NULL);
            emit_mov(isel, dst_lo, "B", ins);
        } else {
            emit_mov(isel, num_tmp, "A", NULL);
            emit_mov(isel, "A", s_num, NULL);
            isel_emit(isel, "XRL", "A", s_den, NULL);
            isel_emit(isel, "JZ", l_no_negq, NULL, NULL);
            emit_mov(isel, "A", num_tmp, NULL);
            isel_emit(isel, "CPL", "A", NULL, NULL);
            isel_emit(isel, "INC", "A", NULL, NULL);
            emit_mov(isel, num_tmp, "A", NULL);
            isel_emit(isel, l_no_negq, NULL, NULL, NULL);
            emit_mov(isel, dst_lo, num_tmp, ins);
        }

        store_spilled_dest_if_needed(isel, ins->dest, dst_reg, size, ins);

        if (tr  >= 0) free_temp_reg(isel, tr,  1);
        if (td  >= 0) free_temp_reg(isel, td,  1);
        if (tsn >= 0) free_temp_reg(isel, tsn, 1);
        if (tsd >= 0) free_temp_reg(isel, tsd, 1);
        free(l_num_pos); free(l_den_pos); free(l_no_negq); free(l_no_rem_neg);
        return;
    } else if (size == 2) {
        // 16-bit division/mod: implement simple unsigned long division via repeated subtraction
        // temps: rem (2), den_tmp (2), quotient in dst, flags for signs if signed
        int tr  = alloc_temp_reg(isel, -1, 2); // rem
        int td  = alloc_temp_reg(isel, -1, 2); // den_tmp
        int tsn = -1, tsd = -1;
        const char* rem_lo = (tr >= 0) ? isel_reg_name(tr + 1) : "R1";
        const char* rem_hi = (tr >= 0) ? isel_reg_name(tr)     : "R2";
        const char* den_lo = (td >= 0) ? isel_reg_name(td + 1) : "R3";
        const char* den_hi = (td >= 0) ? isel_reg_name(td)     : "R4";

        const char* q_lo = dst_lo;
        const char* q_hi = dst_hi;

        if (is_unsigned) {
            // copy operands
            emit_mov(isel, rem_lo, isel_get_lo_reg(isel, num), NULL);
            emit_mov(isel, rem_hi, isel_get_hi_reg(isel, num), NULL);
            emit_mov(isel, den_lo, isel_get_lo_reg(isel, den), NULL);
            emit_mov(isel, den_hi, isel_get_hi_reg(isel, den), NULL);
            // zero quotient
            emit_mov(isel, q_lo, "#0", NULL);
            emit_mov(isel, q_hi, "#0", NULL);

            char* l_check = isel_new_label(isel, "Ldiv_check");
            char* l_done  = isel_new_label(isel, "Ldiv_done");
            char lb_check[64], lb_done[64];
            snprintf(lb_check, sizeof(lb_check), "%s:", l_check);
            snprintf(lb_done, sizeof(lb_done), "%s:", l_done);

            isel_emit(isel, lb_check, NULL, NULL, NULL);
            // compare rem and den (unsigned): if rem < den -> done; if rem >= den -> subtract
            emit_mov(isel, "A", rem_hi, NULL);
            isel_emit(isel, "CLR", "C", NULL, NULL);
            isel_emit(isel, "SUBB", "A", den_hi, NULL);
            isel_emit(isel, "JC", l_done, NULL, NULL); // rem_hi < den_hi -> done
            char* l_eq_high = isel_new_label(isel, "Ldiv_eq_high");
            isel_emit(isel, "JZ", l_eq_high, NULL, NULL); // equal high -> check low

            // rem_hi > den_hi -> subtract
            // subtract den from rem (16-bit)
            emit_mov(isel, "A", rem_lo, NULL);
            isel_emit(isel, "CLR", "C", NULL, NULL);
            isel_emit(isel, "SUBB", "A", den_lo, NULL);
            emit_mov(isel, rem_lo, "A", NULL);
            emit_mov(isel, "A", rem_hi, NULL);
            isel_emit(isel, "SUBB", "A", den_hi, NULL);
            emit_mov(isel, rem_hi, "A", NULL);

            // increment quotient (16-bit)
            emit_mov(isel, "A", q_lo, NULL);
            isel_emit(isel, "ADD", "A", "#1", NULL);
            emit_mov(isel, q_lo, "A", NULL);
            emit_mov(isel, "A", q_hi, NULL);
            isel_emit(isel, "ADDC", "A", "#0", NULL);
            emit_mov(isel, q_hi, "A", NULL);

            // loop back
            isel_emit(isel, "SJMP", l_check, NULL, NULL);
            isel_emit(isel, lb_done, NULL, NULL, NULL);
            isel_emit(isel, l_eq_high, NULL, NULL, NULL);
            // equal high bytes: compare low
            emit_mov(isel, "A", rem_lo, NULL);
            isel_emit(isel, "CLR", "C", NULL, NULL);
            isel_emit(isel, "SUBB", "A", den_lo, NULL);
            isel_emit(isel, "JC", l_done, NULL, NULL); // rem_lo < den_lo -> done
            // else fallthrough to subtract

            // store result
            if (want_mod) {
                emit_mov(isel, q_lo, rem_lo, ins);
                emit_mov(isel, q_hi, rem_hi, NULL);
            } else {
                emit_mov(isel, dst_lo, q_lo, ins);
                emit_mov(isel, dst_hi, q_hi, NULL);
            }

            store_spilled_dest_if_needed(isel, ins->dest, dst_reg, size, ins);

            free(l_check); free(l_done);
            if (tr >= 0) free_temp_reg(isel, tr, 2);
            if (td >= 0) free_temp_reg(isel, td, 2);
            return;
        } else {
            // signed 16-bit: take abs of operands into rem/den_tmp, record signs
            tsn = alloc_temp_reg(isel, -1, 1);
            tsd = alloc_temp_reg(isel, -1, 1);
            const char* s_num = (tsn >= 0) ? isel_reg_name(tsn) : "R5";
            const char* s_den = (tsd >= 0) ? isel_reg_name(tsd) : "R6";
            char* l_num_pos = isel_new_label(isel, "Lnum_pos16");
            char* l_den_pos = isel_new_label(isel, "Lden_pos16");
            char lb_tmp[64];

            emit_mov(isel, s_num, "#0", NULL);
            emit_mov(isel, s_den, "#0", NULL);

            // load num into rem
            emit_mov(isel, rem_lo, isel_get_lo_reg(isel, num), NULL);
            emit_mov(isel, rem_hi, isel_get_hi_reg(isel, num), NULL);
            // test sign: check rem_hi & 0x80
            emit_mov(isel, "A", rem_hi, NULL);
            isel_emit(isel, "ANL", "A", "#128", NULL);
            isel_emit(isel, "JZ", l_num_pos, NULL, NULL);
            // negative: rem = -rem (two's complement 16)
            emit_mov(isel, "A", rem_lo, NULL);
            isel_emit(isel, "CPL", "A", NULL, NULL);
            emit_mov(isel, rem_lo, "A", NULL);
            emit_mov(isel, "A", rem_hi, NULL);
            isel_emit(isel, "CPL", "A", NULL, NULL);
            emit_mov(isel, rem_hi, "A", NULL);
            // add 1 to low, propagate
            emit_mov(isel, "A", rem_lo, NULL);
            isel_emit(isel, "ADD", "A", "#1", NULL);
            emit_mov(isel, rem_lo, "A", NULL);
            emit_mov(isel, "A", rem_hi, NULL);
            isel_emit(isel, "ADDC", "A", "#0", NULL);
            emit_mov(isel, rem_hi, "A", NULL);
            isel_emit(isel, "MOV", s_num, "#1", NULL);
            isel_emit(isel, l_num_pos, NULL, NULL, NULL);

            // load den into den_tmp
            emit_mov(isel, den_lo, isel_get_lo_reg(isel, den), NULL);
            emit_mov(isel, den_hi, isel_get_hi_reg(isel, den), NULL);
            emit_mov(isel, "A", den_hi, NULL);
            isel_emit(isel, "ANL", "A", "#128", NULL);
            isel_emit(isel, "JZ", l_den_pos, NULL, NULL);
            emit_mov(isel, "A", den_lo, NULL);
            isel_emit(isel, "CPL", "A", NULL, NULL);
            emit_mov(isel, den_lo, "A", NULL);
            emit_mov(isel, "A", den_hi, NULL);
            isel_emit(isel, "CPL", "A", NULL, NULL);
            emit_mov(isel, den_hi, "A", NULL);
            emit_mov(isel, "A", den_lo, NULL);
            isel_emit(isel, "ADD", "A", "#1", NULL);
            emit_mov(isel, den_lo, "A", NULL);
            emit_mov(isel, "A", den_hi, NULL);
            isel_emit(isel, "ADDC", "A", "#0", NULL);
            emit_mov(isel, den_hi, "A", NULL);
            isel_emit(isel, "MOV", s_den, "#1", NULL);
            isel_emit(isel, l_den_pos, NULL, NULL, NULL);

            // perform unsigned division on rem/den_tmp into q
            emit_mov(isel, q_lo, "#0", NULL);
            emit_mov(isel, q_hi, "#0", NULL);

            char* l_check = isel_new_label(isel, "Ldiv_check16");
            char* l_done  = isel_new_label(isel, "Ldiv_done16");
            char lb_check[64], lb_done[64];
            snprintf(lb_check, sizeof(lb_check), "%s:", l_check);
            snprintf(lb_done, sizeof(lb_done), "%s:", l_done);

            isel_emit(isel, lb_check, NULL, NULL, NULL);
            // compare rem and den (unsigned): if rem < den -> done
            emit_mov(isel, "A", rem_hi, NULL);
            isel_emit(isel, "CLR", "C", NULL, NULL);
            isel_emit(isel, "SUBB", "A", den_hi, NULL);
            isel_emit(isel, "JC", l_done, NULL, NULL);
            char* l_eq_high2 = isel_new_label(isel, "Ldiv_eq_high2");
            isel_emit(isel, "JZ", l_eq_high2, NULL, NULL);

            // subtract den from rem
            emit_mov(isel, "A", rem_lo, NULL);
            isel_emit(isel, "CLR", "C", NULL, NULL);
            isel_emit(isel, "SUBB", "A", den_lo, NULL);
            emit_mov(isel, rem_lo, "A", NULL);
            emit_mov(isel, "A", rem_hi, NULL);
            isel_emit(isel, "SUBB", "A", den_hi, NULL);
            emit_mov(isel, rem_hi, "A", NULL);

            // inc quotient
            emit_mov(isel, "A", q_lo, NULL);
            isel_emit(isel, "ADD", "A", "#1", NULL);
            emit_mov(isel, q_lo, "A", NULL);
            emit_mov(isel, "A", q_hi, NULL);
            isel_emit(isel, "ADDC", "A", "#0", NULL);
            emit_mov(isel, q_hi, "A", NULL);

            isel_emit_label(isel, l_eq_high2);
            isel_emit(isel, "SJMP", l_check, NULL, NULL);
            isel_emit(isel, lb_done, NULL, NULL, NULL);

            if (want_mod) {
                // remainder in rem; if original numerator negative, negate rem
                char* l_rem_pos = isel_new_label(isel, "Lrem_pos16");
                emit_mov(isel, "A", s_num, NULL);
                isel_emit(isel, "JZ", l_rem_pos, NULL, NULL);
                // negate rem
                emit_mov(isel, "A", rem_lo, NULL);
                isel_emit(isel, "CPL", "A", NULL, NULL);
                emit_mov(isel, rem_lo, "A", NULL);
                emit_mov(isel, "A", rem_hi, NULL);
                isel_emit(isel, "CPL", "A", NULL, NULL);
                emit_mov(isel, rem_hi, "A", NULL);
                emit_mov(isel, "A", rem_lo, NULL);
                isel_emit(isel, "ADD", "A", "#1", NULL);
                emit_mov(isel, rem_lo, "A", NULL);
                emit_mov(isel, "A", rem_hi, NULL);
                isel_emit(isel, "ADDC", "A", "#0", NULL);
                emit_mov(isel, rem_hi, "A", NULL);
                isel_emit(isel, l_rem_pos, NULL, NULL, NULL);
                emit_mov(isel, dst_lo, rem_lo, ins);
                emit_mov(isel, dst_hi, rem_hi, NULL);
            } else {
                // quotient in q; if signs xor, negate quotient
                char* l_q_pos = isel_new_label(isel, "Lq_pos16");
                emit_mov(isel, "A", s_num, NULL);
                isel_emit(isel, "XRL", "A", s_den, NULL);
                isel_emit(isel, "JZ", l_q_pos, NULL, NULL);
                // negate q
                emit_mov(isel, "A", q_lo, NULL);
                isel_emit(isel, "CPL", "A", NULL, NULL);
                emit_mov(isel, q_lo, "A", NULL);
                emit_mov(isel, "A", q_hi, NULL);
                isel_emit(isel, "CPL", "A", NULL, NULL);
                emit_mov(isel, q_hi, "A", NULL);
                emit_mov(isel, "A", q_lo, NULL);
                isel_emit(isel, "ADD", "A", "#1", NULL);
                emit_mov(isel, q_lo, "A", NULL);
                emit_mov(isel, "A", q_hi, NULL);
                isel_emit(isel, "ADDC", "A", "#0", NULL);
                emit_mov(isel, q_hi, "A", NULL);
                isel_emit(isel, l_q_pos, NULL, NULL, NULL);
                emit_mov(isel, dst_lo, q_lo, ins);
                emit_mov(isel, dst_hi, q_hi, NULL);
            }

            store_spilled_dest_if_needed(isel, ins->dest, dst_reg, size, ins);

            if (tr >= 0) free_temp_reg(isel, tr, 2);
            if (td >= 0) free_temp_reg(isel, td, 2);
            if (tsn >= 0) free_temp_reg(isel, tsn, 1);
            if (tsd >= 0) free_temp_reg(isel, tsd, 1);
            free(l_check); free(l_done);
            free(l_num_pos); free(l_den_pos);
            return;
        }
    }

    fprintf(stderr, "c51 backend: only 8/16-bit DIV/MOD supported\n");
    exit(1);
}

void emit_select(ISelContext* isel, Instr* ins) {
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

    const char* dst_lo = isel_reg_name(phys_dst_reg + (size == 2 ? 1 : 0));
    const char* dst_hi = isel_reg_name(phys_dst_reg);

    char* l_true = isel_new_label(isel, "Lsel_true");
    char* l_end = isel_new_label(isel, "Lsel_end");
    char lb_true[64], lb_end[64];
    snprintf(lb_true, sizeof(lb_true), "%s:", l_true);
    snprintf(lb_end, sizeof(lb_end), "%s:", l_end);

    if (get_value_size(isel, cond) == 2) {
        emit_mov(isel, "A", isel_get_hi_reg(isel, cond), NULL);
        isel_emit(isel, "ORL", "A", isel_get_lo_reg(isel, cond), NULL);
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
    bool src2_spilled_mem = (!src2_is_imm) && src2_sym && isel_get_value_reg(isel, src2) == -3;

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
        /* If dst_lo wrapped from 0x00 to 0xFF, borrow occurred → DEC high byte
         * CJNE Rlo, #255, skip  — jumps to skip if Rlo != 0xFF, falls through if Rlo == 0xFF */
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

    if (src2_spilled_mem) {
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
            isel_emit(isel, "SUBB", "A", "B", ssa);
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
                    emit_mov(isel, dst_hi, "A", NULL);
                    emit_load_symbol_byte(isel, src2_sym, 1, "B", NULL);
                    emit_mov(isel, "A", dst_hi, NULL);
                    isel_emit(isel, "SUBB", "A", "B", NULL);
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
        } else if (src_base == -2) {
            int* reg_num = malloc(sizeof(int));
            *reg_num = -2;
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
