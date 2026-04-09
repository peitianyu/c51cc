#include "c51_isel_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "c51_isel_regalloc.h"

/* Save an operand into the B register so that it can be used as a 'direct'
 * address operand in CJNE.  The 8051 CJNE instruction only supports:
 *   CJNE A, #imm, rel
 *   CJNE A, direct, rel   (B register = SFR 0xF0 is a valid 'direct' address)
 *   CJNE Rn, #imm, rel
 *   CJNE @Ri, #imm, rel
 * There is NO "CJNE A, Rn, rel" form.  Any Rn, spill-symbol, or A operand
 * that will appear as the second operand of CJNE must be moved into B first. */
static const char* save_acc_operand_in_b(ISelContext* isel, const char* operand) {
    if (!operand) return "B";
    /* Already in B – nothing to do */
    if (strcmp(operand, "B") == 0) return "B";
    /* Immediate constants are legal as CJNE A,#imm,rel – no save needed */
    if (operand[0] == '#') return operand;
    /* For all other operands (A, R0-R7, IDATA symbols, etc.) load into B */
    isel_emit(isel, "MOV", "B", operand, NULL);
    return "B";
}

static const char* save_acc_operand_for_cmp(ISelContext* isel, const char* operand, int* temp_reg) {
    if (temp_reg) *temp_reg = -1;
    if (!operand || strcmp(operand, "A") != 0) {
        return operand;
    }

    int reg = alloc_temp_reg(isel, -1, 1);
    if (reg >= 0) {
        const char* name = isel_reg_name(reg);
        emit_mov(isel, name, "A", NULL);
        if (temp_reg) *temp_reg = reg;
        return name;
    }

    if (isel) {
        for (int candidate = 0; candidate < 8; candidate++) {
            if (isel->reg_busy[candidate]) continue;
            isel->reg_busy[candidate] = true;
            isel->reg_val[candidate] = -1;
            const char* name = isel_reg_name(candidate);
            emit_mov(isel, name, "A", NULL);
            if (temp_reg) *temp_reg = candidate;
            return name;
        }
    }

    isel_emit(isel, "MOV", "B", "A", NULL);
    return "B";
}

static void free_saved_cmp_operand(ISelContext* isel, int temp_reg) {
    if (temp_reg >= 0) {
        free_temp_reg(isel, temp_reg, 1);
    }
}

#define get_cmp_lo_reg isel_get_extended_lo_reg
#define get_cmp_hi_reg isel_get_extended_hi_reg

/* Get a safe 16-bit comparison operand (lo byte) that is NOT "A" or "B".
 * For spilled values, returns the IDATA symbol directly (e.g. "__spill_3")
 * which is a valid 'direct' address for SUBB A, direct.
 * For register-allocated values, returns the register name.
 * For constants, returns "#imm".
 * Never emits any instructions (no side effects). */
static const char* get_s16cmp_lo_operand(ISelContext* isel, ValueName val) {
    int64_t imm_val = 0;
    if (try_get_value_const(isel, val, &imm_val)) {
        static char imm_bufs[4][20];
        static int imm_buf_idx = 0;
        char* buf = imm_bufs[imm_buf_idx & 3];
        imm_buf_idx++;
        snprintf(buf, 20, "#%d", (int)(imm_val & 0xFF));
        return buf;
    }
    int base_reg = isel_get_value_reg(isel, val);
    if (base_reg == SPILL_REG) {
        const char* sym = lookup_value_addr_symbol(isel, val);
        if (sym) return sym;   /* direct IDATA address = lo byte */
    }
    if (base_reg >= 0 && base_reg < 8) return isel_reg_name(base_reg + 1); /* lo */
    if (base_reg == ACC_REG) return "A";
    return "R7"; /* fallback */
}

/* Get a safe 16-bit comparison operand (hi byte) that is NOT "A" or "B".
 * For spilled 16-bit values, returns "(symbol + 1)" string. */
static const char* get_s16cmp_hi_operand(ISelContext* isel, ValueName val) {
    int64_t imm_val = 0;
    if (try_get_value_const(isel, val, &imm_val)) {
        static char imm_bufs[4][20];
        static int imm_buf_idx = 0;
        char* buf = imm_bufs[imm_buf_idx & 3];
        imm_buf_idx++;
        snprintf(buf, 20, "#%d", (int)((imm_val >> 8) & 0xFF));
        return buf;
    }
    int actual_size = get_value_size(isel, val);
    if (actual_size <= 1) return "#0"; /* zero-extend */
    int base_reg = isel_get_value_reg(isel, val);
    if (base_reg == SPILL_REG) {
        const char* sym = lookup_value_addr_symbol(isel, val);
        if (sym) {
            /* Return "(sym + 1)" – use a static rotating buffer */
            static char hi_bufs[4][128];
            static int hi_buf_idx = 0;
            char* buf = hi_bufs[hi_buf_idx & 3];
            hi_buf_idx++;
            snprintf(buf, 128, "(%s + 1)", sym);
            return buf;
        }
    }
    if (base_reg >= 0 && base_reg < 8) return isel_reg_name(base_reg); /* hi */
    if (base_reg == ACC_REG) return "A";
    return "R6"; /* fallback */
}

static void emit_far_cond_jump1(ISelContext* isel, const char* op, int taken_id, int other_id,
                                Instr* ins, const char* ssa) {
    char target_taken[32], target_other[32];
    block_label_name(target_taken, sizeof(target_taken), taken_id);
    block_label_name(target_other, sizeof(target_other), other_id);

    char* l_taken = isel_new_label(isel, "Lcmp_far_taken");
    isel_emit(isel, op, l_taken, NULL, ssa);
    emit_phi_copies_for_edge(isel, isel->current_block_id, other_id, ins);
    isel_emit(isel, "LJMP", target_other, NULL, NULL);
    isel_emit_label(isel, l_taken);
    emit_phi_copies_for_edge(isel, isel->current_block_id, taken_id, ins);
    isel_emit(isel, "LJMP", target_taken, NULL, NULL);
    free(l_taken);
}

static void emit_far_cond_jump2_same(ISelContext* isel, const char* op1, const char* op2,
                                     int taken_id, int other_id, Instr* ins, const char* ssa1) {
    char target_taken[32], target_other[32];
    block_label_name(target_taken, sizeof(target_taken), taken_id);
    block_label_name(target_other, sizeof(target_other), other_id);

    char* l_taken = isel_new_label(isel, "Lcmp_far_taken");
    isel_emit(isel, op1, l_taken, NULL, ssa1);
    isel_emit(isel, op2, l_taken, NULL, NULL);
    emit_phi_copies_for_edge(isel, isel->current_block_id, other_id, ins);
    isel_emit(isel, "LJMP", target_other, NULL, NULL);
    isel_emit_label(isel, l_taken);
    emit_phi_copies_for_edge(isel, isel->current_block_id, taken_id, ins);
    isel_emit(isel, "LJMP", target_taken, NULL, NULL);
    free(l_taken);
}

static void emit_block_jump(ISelContext* isel, Instr* ins, int block_id) {
    char target[32];
    block_label_name(target, sizeof(target), block_id);
    emit_phi_copies_for_edge(isel, isel->current_block_id, block_id, ins);
    isel_emit(isel, "LJMP", target, NULL, NULL);
}

static void emit_cond_branch_to_blocks(ISelContext* isel, const char* op,
                                       int true_id, int false_id,
                                       Instr* ins, const char* ssa) {
    char* l_true = isel_new_label(isel, "Lcmp_true");
    isel_emit(isel, op, l_true, NULL, ssa);
    emit_block_jump(isel, ins, false_id);
    isel_emit_label(isel, l_true);
    emit_block_jump(isel, ins, true_id);
    free(l_true);
}

static void emit_bit_branch_to_blocks(ISelContext* isel, const char* op, const char* bit,
                                      int true_id, int false_id,
                                      Instr* ins, const char* ssa) {
    char* l_true = isel_new_label(isel, "Lcmp_true");
    isel_emit(isel, op, bit, l_true, ssa);
    emit_block_jump(isel, ins, false_id);
    isel_emit_label(isel, l_true);
    emit_block_jump(isel, ins, true_id);
    free(l_true);
}

static bool emit_cmp_zero_branch(ISelContext* isel, Instr* ins, ValueName value,
                                 bool want_positive, bool want_negative,
                                 bool unsigned_cmp, int true_id, int false_id) {
    int width = get_value_size(isel, value) >= 2 ? 2 : 1;

    if (unsigned_cmp) {
        if (want_negative) {
            emit_block_jump(isel, ins, false_id);
            return true;
        }

        char* ssa = instr_to_ssa_str(ins);
        if (width == 2) {
            /* 16位：先加�?hi，再 ORL lo。若 lo 是IDATA需先保存到临时寄存�?*/
            const char* lo = get_cmp_lo_reg(isel, value, 2);
            int lo_tmp = -1;
            const char* lo_safe = save_acc_operand_for_cmp(isel, lo, &lo_tmp);
            const char* hi = get_cmp_hi_reg(isel, value, 2);
            emit_mov(isel, "A", hi, ins);
            isel_emit(isel, "ORL", "A", lo_safe, NULL);
            free_saved_cmp_operand(isel, lo_tmp);
        } else {
            const char* lo = isel_get_lo_reg(isel, value);
            emit_mov(isel, "A", lo, ins);
        }
        emit_cond_branch_to_blocks(isel, "JNZ", true_id, false_id, ins, ssa);
        free(ssa);
        return true;
    }

    const char* lo = width == 2 ? get_cmp_lo_reg(isel, value, 2) : isel_get_lo_reg(isel, value);
    const char* hi = width == 2 ? get_cmp_hi_reg(isel, value, 2) : NULL;

    if (want_negative) {
        char* ssa = instr_to_ssa_str(ins);
        emit_mov(isel, "A", width == 2 ? hi : lo, ins);
        emit_bit_branch_to_blocks(isel, "JB", "ACC.7", true_id, false_id, ins, ssa);
        free(ssa);
        return true;
    }

    if (want_positive) {
        if (width == 1) {
            char* l_zero = isel_new_label(isel, "Lcmp_zero_zero");
            char* ssa = instr_to_ssa_str(ins);
            emit_mov(isel, "A", lo, ins);
            isel_emit(isel, "JZ", l_zero, NULL, ssa);
            free(ssa);
            emit_bit_branch_to_blocks(isel, "JB", "ACC.7", false_id, true_id, ins, NULL);
            isel_emit_label(isel, l_zero);
            emit_block_jump(isel, ins, false_id);
            free(l_zero);
            return true;
        }

        char* l_hi_zero = isel_new_label(isel, "Lcmp_zero_hi_zero");
        char* ssa = instr_to_ssa_str(ins);
        emit_mov(isel, "A", hi, ins);
        isel_emit(isel, "JZ", l_hi_zero, NULL, ssa);
        free(ssa);
        emit_bit_branch_to_blocks(isel, "JB", "ACC.7", false_id, true_id, ins, NULL);
        isel_emit_label(isel, l_hi_zero);
        emit_mov(isel, "A", lo, NULL);
        emit_cond_branch_to_blocks(isel, "JNZ", true_id, false_id, ins, NULL);
        free(l_hi_zero);
        return true;
    }

    return false;
}

static bool match_rotate8_idiom(ISelContext* isel, ValueName lhs, ValueName rhs,
                                ValueName* out_src, int* out_count, bool* out_left) {
    Func* func;
    Instr* lhs_def;
    Instr* rhs_def;
    int64_t lhs_cnt = 0;
    int64_t rhs_cnt = 0;
    ValueName lhs_src;
    ValueName rhs_src;

    if (!isel || !isel->ctx || !isel->ctx->current_func) return false;
    func = isel->ctx->current_func;
    lhs_def = find_def_instr_in_func(func, lhs);
    rhs_def = find_def_instr_in_func(func, rhs);
    if (!lhs_def || !rhs_def) return false;
    if (!((lhs_def->op == IROP_SHL && rhs_def->op == IROP_SHR) ||
          (lhs_def->op == IROP_SHR && rhs_def->op == IROP_SHL))) {
        return false;
    }

    lhs_src = get_src1_value(lhs_def);
    rhs_src = get_src1_value(rhs_def);
    if (lhs_src <= 0 || rhs_src <= 0 || lhs_src != rhs_src) return false;
    if (get_value_size(isel, lhs_src) != 1) return false;

    if (!(is_imm_operand(lhs_def, &lhs_cnt) || try_get_value_const(isel, get_src2_value(lhs_def), &lhs_cnt))) return false;
    if (!(is_imm_operand(rhs_def, &rhs_cnt) || try_get_value_const(isel, get_src2_value(rhs_def), &rhs_cnt))) return false;

    lhs_cnt &= 7;
    rhs_cnt &= 7;
    if (((lhs_cnt + rhs_cnt) & 7) != 0) return false;
    if (lhs_cnt == 0 || rhs_cnt == 0) return false;

    if (lhs_def->op == IROP_SHL) {
        if (out_left) *out_left = true;
        if (out_count) *out_count = (int)lhs_cnt;
    } else {
        if (out_left) *out_left = false;
        if (out_count) *out_count = (int)lhs_cnt;
    }
    if (out_src) *out_src = lhs_src;
    return true;
}

static bool value_is_zero_extended_byte_logic(Func* func, ValueName value, ValueName* seen, int seen_count) {
    Instr* def;

    if (!func || value <= 0) return false;
    for (int i = 0; i < seen_count; i++) {
        if (seen[i] == value) return true;
    }

    def = find_def_instr_in_func(func, value);
    if (!def) return false;
    if (def->op == IROP_CONST) return (def->imm.ival & ~0xFFLL) == 0;
    if (def->op == IROP_TRUNC) return true;
    /* A 1-byte typed value (e.g. unsigned char load/param) is always a byte */
    if (def->type && c51_abi_type_size(def->type) == 1) return true;
    if (def->op == IROP_PHI && def->args) {
        ValueName next_seen[16];
        int next_count = seen_count;
        if (next_count >= 16) return false;
        memcpy(next_seen, seen, sizeof(ValueName) * seen_count);
        next_seen[next_count++] = value;
        for (int i = 0; i < def->args->len; i++) {
            ValueName arg = *(ValueName*)list_get(def->args, i);
            if (!value_is_zero_extended_byte_logic(func, arg, next_seen, next_count)) {
                return false;
            }
        }
        return true;
    }
    return false;
}

void emit_bitwise(ISelContext* isel, Instr* ins, Instr* next, const char* op_mnem) {
    ValueName src1 = get_src1_value(ins);
    int size = ins && ins->type ? c51_abi_type_size(ins->type) : get_value_size(isel, ins->dest);
    if (size < 1) size = 1;
    int64_t imm_val;
    bool src2_is_imm = is_imm_operand(ins, &imm_val);
    ValueName src2 = get_src2_value(ins);

    /* Also treat src2 as immediate if it resolves to a compile-time constant
     * (e.g. the result of a CONST instruction used directly as src2). */
    if (!src2_is_imm && src2 > 0) {
        src2_is_imm = try_get_value_const(isel, src2, &imm_val);
    }
    /* Likewise, if src1 is a constant and src2 is not, swap them so that
     * the immediate-path handles the operation cleanly. */
    if (!src2_is_imm) {
        int64_t imm1 = 0;
        if (try_get_value_const(isel, src1, &imm1)) {
            imm_val = imm1;
            src2_is_imm = true;
            /* swap: src1 becomes the register operand, src2 was already it */
            ValueName tmp_src = src1; src1 = src2; src2 = tmp_src;
        }
    }

    /* 检查 src2 是否是 IDATA spill：如果是，可以用 ANL/ORL/XRL A, sym 直接地址避免中转 */
    const char* src2_sym = (!src2_is_imm) ? lookup_value_addr_symbol(isel, src2) : NULL;
    bool src2_spilled_mem = (!src2_is_imm) && src2_sym && isel_get_value_reg(isel, src2) == SPILL_REG;
    bool src2_idata_direct = false;
    if (src2_spilled_mem && src2_sym) {
        SectionKind src2_bitw_sec = get_symbol_section_kind(isel, src2_sym);
        src2_idata_direct = (src2_bitw_sec == SEC_IDATA);
    }

    int reg = -1;
    if (!src2_is_imm && !src2_spilled_mem && isel && isel->ctx && isel->ctx->value_to_reg && ins && ins->dest > 0) {
        char* key = int_to_key(ins->dest);
        int* reg_ptr = (int*)dict_get(isel->ctx->value_to_reg, key);
        free(key);
        if (reg_ptr && *reg_ptr >= 0 && *reg_ptr + size - 1 < 8) {
            reg = *reg_ptr;
            for (int j = 0; j < size; j++) {
                isel->reg_busy[reg + j] = true;
            }
        }
    }
    if (reg < 0) reg = alloc_dest_reg(isel, ins, next, size, true);
    int phys_reg = reg;
    bool temp_result = false;

    /* Fast path: dst is a spilled value and src2 is immediate.
     * Write the result directly to the spill symbol via A to avoid allocating
     * a temporary physical register that might clobber live variables. */
    if (reg == SPILL_REG && src2_is_imm && ins && ins->dest > 0) {
        const char* spill_sym = NULL;
        if (isel && isel->ctx && isel->ctx->value_to_spill) {
            char* spk = int_to_key(ins->dest);
            spill_sym = (const char*)dict_get(isel->ctx->value_to_spill, spk);
            free(spk);
        }
        if (spill_sym && get_symbol_section_kind(isel, spill_sym) == SEC_IDATA) {
            const char* s1_lo = isel_get_lo_reg(isel, src1);
            uint8_t lo_byte = (uint8_t)(imm_val & 0xFF);
            bool is_and = (strcmp(op_mnem, "ANL") == 0);
            bool is_or  = (strcmp(op_mnem, "ORL") == 0);
            bool is_xor = (strcmp(op_mnem, "XRL") == 0);
            /* Compute lo byte */
            if (is_and && lo_byte == 0xFF) {
                emit_mov(isel, "A", s1_lo, ins);
            } else if (is_and && lo_byte == 0x00) {
                isel_emit(isel, "MOV", "A", "#0", NULL);
            } else if ((is_or || is_xor) && lo_byte == 0x00) {
                emit_mov(isel, "A", s1_lo, ins);
            } else {
                emit_mov(isel, "A", s1_lo, ins);
                char imm_str[16];
                snprintf(imm_str, sizeof(imm_str), "#%d", (int)lo_byte);
                isel_emit(isel, op_mnem, "A", imm_str, NULL);
            }
            isel_emit(isel, "MOV", spill_sym, "A", NULL);
            if (size == 2) {
                char ref[256];
                snprintf(ref, sizeof(ref), "(%s + 1)", spill_sym);
                uint8_t hi_byte = (uint8_t)((imm_val >> 8) & 0xFF);
                int src1_size_l = get_value_size(isel, src1);
                const char* s1_hi = (src1_size_l == 1) ? "#0" : isel_get_hi_reg(isel, src1);
                if (is_and && hi_byte == 0xFF) {
                    if (s1_hi) emit_mov(isel, "A", s1_hi, NULL);
                    else isel_emit(isel, "MOV", "A", "#0", NULL);
                    isel_emit(isel, "MOV", ref, "A", NULL);
                } else if (is_and && hi_byte == 0x00) {
                    isel_emit(isel, "MOV", ref, "#0", NULL);
                } else if ((is_or || is_xor) && hi_byte == 0x00) {
                    if (s1_hi) emit_mov(isel, "A", s1_hi, NULL);
                    else isel_emit(isel, "MOV", "A", "#0", NULL);
                    isel_emit(isel, "MOV", ref, "A", NULL);
                } else {
                    if (s1_hi) emit_mov(isel, "A", s1_hi, NULL);
                    else isel_emit(isel, "MOV", "A", "#0", NULL);
                    char imm_str[16];
                    snprintf(imm_str, sizeof(imm_str), "#%d", (int)hi_byte);
                    isel_emit(isel, op_mnem, "A", imm_str, NULL);
                    isel_emit(isel, "MOV", ref, "A", NULL);
                }
            }
            return;
        }
    }

    if (phys_reg < 0 || phys_reg + size - 1 > 7) {
        phys_reg = alloc_temp_reg(isel, ins ? ins->dest : -1, size);
        temp_result = phys_reg >= 0;
    }
    if (phys_reg < 0) phys_reg = 0;

    if (strcmp(op_mnem, "ORL") == 0 && size == 2 && next && next->op == IROP_TRUNC && get_src1_value(next) == ins->dest) {
        Func* func = (isel && isel->ctx) ? isel->ctx->current_func : NULL;
        ValueName rot_src = -1;
        int rot_count = 0;
        bool rot_left = true;
        ValueName seen_values[16];
        if (match_rotate8_idiom(isel, src1, src2, &rot_src, &rot_count, &rot_left) &&
            value_is_zero_extended_byte_logic(func, rot_src, seen_values, 0)) {
            int dst_reg = safe_alloc_reg_for_value(isel, next->dest, 1);
            const char* src_lo = isel_get_lo_reg(isel, rot_src);
            if (dst_reg >= 0) {
                int effective = rot_count & 7;
                char* ssa = instr_to_ssa_str(ins);
                emit_mov(isel, "A", src_lo, ins);
                if (effective > 4) {
                    effective = 8 - effective;
                    rot_left = !rot_left;
                }
                for (int i = 0; i < effective; i++) {
                    isel_emit(isel, rot_left ? "RL" : "RR", "A", NULL, (i == 0) ? ssa : NULL);
                }
                free(ssa);
                emit_mov(isel, isel_reg_name(dst_reg), "A", NULL);
                emit_store_spilled_result(isel, next->dest, dst_reg, 1, next);
                next->op = IROP_NOP;
                return;
            }
        }
    }

    if (strcmp(op_mnem, "ORL") == 0 && size == 1 && !src2_is_imm) {
        ValueName rot_src = -1;
        int rot_count = 0;
        bool rot_left = true;
        if (match_rotate8_idiom(isel, src1, src2, &rot_src, &rot_count, &rot_left)) {
            const char* dst_lo = isel_reg_name(phys_reg);
            int effective = rot_count & 7;
            char* ssa = instr_to_ssa_str(ins);

            emit_mov(isel, "A", isel_get_lo_reg(isel, rot_src), ins);
            if (effective != 0) {
                if (effective > 4) {
                    effective = 8 - effective;
                    rot_left = !rot_left;
                }
                for (int i = 0; i < effective; i++) {
                    isel_emit(isel, rot_left ? "RL" : "RR", "A", NULL, (i == 0) ? ssa : NULL);
                }
            }
            free(ssa);
            emit_mov(isel, dst_lo, "A", ins);
            emit_store_spilled_result(isel, ins->dest, phys_reg, size, ins);
            if (temp_result) {
                free_temp_reg(isel, phys_reg, size);
            }
            return;
        }
    }

    const char* dst_lo = isel_reg_name(phys_reg + (size == 2 ? 1 : 0));
    const char* dst_hi = isel_reg_name(phys_reg);

    /* Get actual sizes of source operands (for zero-extension of narrow operands) */
    int src1_size = get_value_size(isel, src1);
    int src2_size = src2_is_imm ? size : get_value_size(isel, src2);

    if (src2_is_imm && size == 2 && isel_get_value_reg(isel, src1) == SPILL_REG) {
        const char* src1_sym = NULL;
        bool is_and = (strcmp(op_mnem, "ANL") == 0);
        bool is_or  = (strcmp(op_mnem, "ORL") == 0);
        bool is_xor = (strcmp(op_mnem, "XRL") == 0);
        uint8_t lo_byte = (uint8_t)(imm_val & 0xFF);
        uint8_t hi_byte = (uint8_t)((imm_val >> 8) & 0xFF);

        if (isel && isel->ctx && isel->ctx->value_to_spill) {
            char* sk = int_to_key(src1);
            src1_sym = (const char*)dict_get(isel->ctx->value_to_spill, sk);
            free(sk);
        }
        if (!src1_sym) src1_sym = lookup_value_addr_symbol(isel, src1);

        if (src1_sym) {
            emit_load_symbol_byte(isel, src1_sym, 0, "A", ins);
            if (!((is_and && lo_byte == 0xFF) || ((is_or || is_xor) && lo_byte == 0x00))) {
                char imm_str[16];
                snprintf(imm_str, sizeof(imm_str), "#%d", (int)lo_byte);
                if (is_and && lo_byte == 0x00) {
                    isel_emit(isel, "MOV", "A", "#0", NULL);
                } else {
                    isel_emit(isel, op_mnem, "A", imm_str, NULL);
                }
            }
            emit_mov(isel, dst_lo, "A", ins);

            emit_load_symbol_byte(isel, src1_sym, 1, "A", NULL);
            if (!((is_and && hi_byte == 0xFF) || ((is_or || is_xor) && hi_byte == 0x00))) {
                char imm_str[16];
                snprintf(imm_str, sizeof(imm_str), "#%d", (int)hi_byte);
                if (is_and && hi_byte == 0x00) {
                    isel_emit(isel, "MOV", "A", "#0", NULL);
                } else {
                    isel_emit(isel, op_mnem, "A", imm_str, NULL);
                }
            }
            emit_mov(isel, dst_hi, "A", NULL);

            emit_store_spilled_result(isel, ins->dest, phys_reg, size, ins);
            if (temp_result) {
                free_temp_reg(isel, phys_reg, size);
            }
            return;
        }
    }

    int src1_lo_tmp = -1;
    int src1_hi_tmp = -1;
    const char* src1_lo = save_acc_operand_for_cmp(isel, isel_get_lo_reg(isel, src1), &src1_lo_tmp);
    /* If src1 is 1 byte and result is 2 bytes, hi of src1 is zero-extended (#0) */
    const char* src1_hi = size == 2
        ? (src1_size == 1 ? "#0" : save_acc_operand_for_cmp(isel, isel_get_hi_reg(isel, src1), &src1_hi_tmp))
        : NULL;

    if (src2_is_imm) {
        uint8_t lo_byte = (uint8_t)(imm_val & 0xFF);
        bool is_and = (strcmp(op_mnem, "ANL") == 0);
        bool is_or  = (strcmp(op_mnem, "ORL") == 0);
        bool is_xor = (strcmp(op_mnem, "XRL") == 0);
        /* 低字节特殊值优�?*/
        if (is_and && lo_byte == 0xFF) {
            /* ANL A, #0xFF = no-op：直�?MOV dst_lo, src1_lo */
            emit_mov(isel, dst_lo, src1_lo, ins);
        } else if (is_and && lo_byte == 0x00) {
            /* ANL A, #0 = CLR A：直�?MOV dst_lo, #0 */
            isel_emit(isel, "MOV", dst_lo, "#0", NULL);
        } else if ((is_or || is_xor) && lo_byte == 0x00) {
            /* ORL/XRL A, #0 = no-op：直�?MOV dst_lo, src1_lo */
            emit_mov(isel, dst_lo, src1_lo, ins);
        } else {
            emit_mov(isel, "A", src1_lo, ins);
            char imm_str[16];
            snprintf(imm_str, sizeof(imm_str), "#%d", (int)lo_byte);
            isel_emit(isel, op_mnem, "A", imm_str, NULL);
            emit_mov(isel, dst_lo, "A", ins);
        }
        if (size == 2) {
            uint8_t hi_byte = (uint8_t)((imm_val >> 8) & 0xFF);
            if (is_and && hi_byte == 0xFF) {
                emit_mov(isel, dst_hi, src1_hi, ins);
            } else if (is_and && hi_byte == 0x00) {
                isel_emit(isel, "MOV", dst_hi, "#0", NULL);
            } else if ((is_or || is_xor) && hi_byte == 0x00) {
                emit_mov(isel, dst_hi, src1_hi, ins);
            } else {
                emit_mov(isel, "A", src1_hi, ins);
                char imm_str[16];
                snprintf(imm_str, sizeof(imm_str), "#%d", (int)hi_byte);
                isel_emit(isel, op_mnem, "A", imm_str, NULL);
                emit_mov(isel, dst_hi, "A", ins);
            }
        }
    } else if (src2_idata_direct) {
        /* IDATA 直接地址：ANL/ORL/XRL A, sym (无需临时寄存器中�? */
        emit_mov(isel, "A", src1_lo, ins);
        isel_emit(isel, op_mnem, "A", src2_sym, NULL);
        emit_mov(isel, dst_lo, "A", ins);
        if (size == 2) {
            char ref[256];
            snprintf(ref, sizeof(ref), "(%s + 1)", src2_sym);
            emit_mov(isel, "A", src1_hi, ins);
            isel_emit(isel, op_mnem, "A", ref, NULL);
            emit_mov(isel, dst_hi, "A", ins);
        }
    } else {
        int src2_lo_tmp = -1;
        const char* src2_lo = save_acc_operand_for_cmp(isel, isel_get_lo_reg(isel, src2), &src2_lo_tmp);
        emit_mov(isel, "A", src1_lo, ins);
        isel_emit(isel, op_mnem, "A", src2_lo, NULL);
        free_saved_cmp_operand(isel, src2_lo_tmp);
        emit_mov(isel, dst_lo, "A", ins);
        if (size == 2) {
            /* Determine hi-byte of each operand: use "#0" for zero-extended 1-byte values */
            const char* s1hi = (src1_size == 1) ? "#0" : src1_hi;
            int src2_hi_tmp = -1;
            const char* src2_hi_raw = (src2_size == 1) ? NULL
                : save_acc_operand_for_cmp(isel, isel_get_hi_reg(isel, src2), &src2_hi_tmp);
            const char* s2hi = (src2_size == 1) ? "#0" : src2_hi_raw;
            bool is_and = (strcmp(op_mnem, "ANL") == 0);
            /* Optimize: if both hi-bytes are 0, result hi is always 0 */
            if (strcmp(s1hi, "#0") == 0 && strcmp(s2hi, "#0") == 0) {
                isel_emit(isel, "MOV", dst_hi, "#0", NULL);
            } else if (strcmp(s1hi, "#0") == 0 && is_and) {
                /* ANL #0, anything = 0 */
                isel_emit(isel, "MOV", dst_hi, "#0", NULL);
            } else if (strcmp(s2hi, "#0") == 0 && is_and) {
                isel_emit(isel, "MOV", dst_hi, "#0", NULL);
            } else {
                emit_mov(isel, "A", s1hi, ins);
                isel_emit(isel, op_mnem, "A", s2hi, NULL);
                emit_mov(isel, dst_hi, "A", ins);
            }
            free_saved_cmp_operand(isel, src2_hi_tmp);
        }
    }

    if (phys_reg >= 0 && phys_reg + size - 1 < 8) {
        for (int j = 0; j < size; j++) {
            isel->reg_val[phys_reg + j] = ins->dest;
        }
    }

    emit_store_spilled_result(isel, ins->dest, phys_reg, size, ins);

    if (temp_result) {
        free_temp_reg(isel, phys_reg, size);
    }

    free_saved_cmp_operand(isel, src1_lo_tmp);
    free_saved_cmp_operand(isel, src1_hi_tmp);
}

void emit_not(ISelContext* isel, Instr* ins, Instr* next) {
    ValueName src1 = get_src1_value(ins);
    int src_size = get_value_size(isel, src1);
    int dst_size = get_value_size(isel, ins->dest);

    int reg = alloc_dest_reg(isel, ins, next, dst_size, true);
    int phys_reg = reg;
    bool temp_result = false;
    if (phys_reg < 0 || phys_reg + dst_size - 1 > 7) {
        phys_reg = alloc_temp_reg(isel, ins ? ins->dest : -1, dst_size);
        temp_result = phys_reg >= 0;
    }
    if (phys_reg < 0) phys_reg = 0;

    const char* dst_lo = NULL;
    const char* dst_hi = NULL;
    dst_lo = isel_reg_name(phys_reg + (dst_size == 2 ? 1 : 0));
    dst_hi = dst_size == 2 ? isel_reg_name(phys_reg) : NULL;

    int src_reg = isel_get_value_reg(isel, src1);
    const char* src1_lo;
    const char* src1_hi;

    if (src_size == 1) {
        if (src_reg >= 0) {
            src1_lo = isel_reg_name(src_reg);
        } else {
            src1_lo = isel_get_lo_reg(isel, src1);
        }
        src1_hi = NULL;
    } else {
        if (src_reg >= 0) {
            src1_lo = isel_reg_name(src_reg + 1);
            src1_hi = isel_reg_name(src_reg);
        } else {
            src1_lo = isel_get_lo_reg(isel, src1);
            src1_hi = isel_get_hi_reg(isel, src1);
        }
    }

    emit_mov(isel, "A", src1_lo, ins);
    isel_emit(isel, "CPL", "A", NULL, NULL);
    if (dst_lo) {
        emit_mov(isel, dst_lo, "A", ins);
    }

    if (dst_size == 2 && dst_hi) {
        if (src_size == 2 && src1_hi) {
            emit_mov(isel, "A", src1_hi, ins);
            isel_emit(isel, "CPL", "A", NULL, NULL);
        } else {
            isel_emit(isel, "MOV", "A", "#0FFH", NULL);
        }
        emit_mov(isel, dst_hi, "A", ins);
    }

    emit_store_spilled_result(isel, ins->dest, phys_reg, dst_size, ins);

    if (temp_result) {
        free_temp_reg(isel, phys_reg, dst_size);
    }
}

void emit_ne(ISelContext* isel, Instr* ins, Instr* next) {
    ValueName src1 = get_src1_value(ins);
    int size = ins && ins->type ? c51_abi_type_size(ins->type) : get_value_size(isel, ins->dest);
    if (size < 1) size = 1;
    int64_t imm_val;
    bool src2_is_imm = is_imm_operand(ins, &imm_val);
    ValueName src2 = get_src2_value(ins);

    int reg = alloc_reg_for_value(isel, ins->dest, size);
    bool temp_result = false;
    if (reg < 0 || reg + size - 1 > 7) {
        reg = alloc_temp_reg(isel, ins ? ins->dest : -1, size);
        temp_result = reg >= 0;
    }
    if (reg < 0) reg = 0;

    /* NE→SELECT folding: v_ne = ne(src1, src2); v_sel = select(v_ne, tv, fv)
     * Optimization: directly use CJNE to jump to the true/false branches of
     * the select without materializing the bool result.
     * Output:   CJNE ..., Lne_sel_t
     *           MOV dst, fv  ; equal → false value
     *           SJMP Lne_sel_e
     * Lne_sel_t:
     *           MOV dst, tv  ; not-equal → true value
     * Lne_sel_e:
     */
    if (next && next->op == IROP_SELECT && next->args && next->args->len >= 3) {
        ValueName sel_cond = *(ValueName*)list_get(next->args, 0);
        if (sel_cond == ins->dest) {
            ValueName tv = *(ValueName*)list_get(next->args, 1);
            ValueName fv = *(ValueName*)list_get(next->args, 2);
            int sel_size = next->type ? c51_abi_type_size(next->type) : get_value_size(isel, next->dest);
            if (sel_size < 1) sel_size = 1;
            int dst_reg = alloc_reg_for_value(isel, next->dest, sel_size);
            bool dst_temp = false;
            if (dst_reg < 0 || dst_reg + sel_size - 1 > 7) {
                dst_reg = alloc_temp_reg(isel, next->dest, sel_size);
                dst_temp = dst_reg >= 0;
            }
            if (dst_reg < 0) dst_reg = 0;

            char* l_taken = isel_new_label(isel, "Lne_sel_t");
            char* l_end   = isel_new_label(isel, "Lne_sel_e");
            char lbuf_taken[64], lbuf_end[64];
            snprintf(lbuf_taken, sizeof(lbuf_taken), "%s:", l_taken);
            snprintf(lbuf_end,   sizeof(lbuf_end),   "%s:", l_end);

            int cmp_is_16 = (get_value_size(isel, src1) == 2);
            int64_t cst2 = 0;
            bool src2_is_const = try_get_value_const(isel, src2, &cst2);
            if (!src2_is_const && src2_is_imm) { cst2 = imm_val; src2_is_const = true; }

            if (src2_is_const && cmp_is_16 && ((cst2 >> 8) & 0xFF) == 0) {
                const char* s1_lo = isel_get_extended_lo_reg(isel, src1, 2);
                const char* s1_hi = isel_get_extended_hi_reg(isel, src1, 2);
                char imm_lo[16];
                snprintf(imm_lo, sizeof(imm_lo), "#%d", (int)(cst2 & 0xFF));
                emit_mov(isel, "A", s1_lo, ins);
                isel_emit(isel, "XRL", "A", imm_lo, NULL);
                isel_emit(isel, "ORL", "A", s1_hi, NULL);
                isel_emit(isel, "JNZ", l_taken, NULL, NULL);
            } else {
                const char* s1_lo = isel_get_extended_lo_reg(isel, src1, cmp_is_16 ? 2 : 1);
                emit_mov(isel, "A", s1_lo, ins);
                if (src2_is_const) {
                    char arg2[64];
                    snprintf(arg2, sizeof(arg2), "#%d, %s", (int)(cst2 & 0xFF), l_taken);
                    isel_emit(isel, "CJNE", "A", arg2, NULL);
                } else {
                    const char* s2_lo = save_acc_operand_in_b(isel,
                        isel_get_extended_lo_reg(isel, src2, cmp_is_16 ? 2 : 1));
                    char arg2[64];
                    snprintf(arg2, sizeof(arg2), "%s, %s", s2_lo, l_taken);
                    isel_emit(isel, "CJNE", "A", arg2, NULL);
                }
                if (cmp_is_16) {
                    const char* s1_hi = isel_get_extended_hi_reg(isel, src1, 2);
                    emit_mov(isel, "A", s1_hi, NULL);
                    if (src2_is_const) {
                        char arg2[64];
                        snprintf(arg2, sizeof(arg2), "#%d, %s", (int)((cst2 >> 8) & 0xFF), l_taken);
                        isel_emit(isel, "CJNE", "A", arg2, NULL);
                    } else {
                        const char* s2_hi = save_acc_operand_in_b(isel,
                            isel_get_extended_hi_reg(isel, src2, 2));
                        char arg2[64];
                        snprintf(arg2, sizeof(arg2), "%s, %s", s2_hi, l_taken);
                        isel_emit(isel, "CJNE", "A", arg2, NULL);
                    }
                }
            }

            /* equal path: dst = fv */
            const char* fv_lo = isel_get_extended_lo_reg(isel, fv, sel_size);
            const char* fv_hi = isel_get_extended_hi_reg(isel, fv, sel_size);
            const char* dst_lo = isel_reg_name(dst_reg + (sel_size == 2 ? 1 : 0));
            const char* dst_hi = isel_reg_name(dst_reg);
            if (sel_size == 2) emit_mov(isel, dst_hi, fv_hi, next);
            emit_mov(isel, dst_lo, fv_lo, next);
            emit_store_spilled_result(isel, next->dest, dst_reg, sel_size, next);
            isel_emit(isel, "SJMP", l_end, NULL, NULL);

            /* not-equal path: dst = tv */
            isel_emit(isel, lbuf_taken, NULL, NULL, NULL);
            const char* tv_lo = isel_get_extended_lo_reg(isel, tv, sel_size);
            const char* tv_hi = isel_get_extended_hi_reg(isel, tv, sel_size);
            if (sel_size == 2) emit_mov(isel, dst_hi, tv_hi, next);
            emit_mov(isel, dst_lo, tv_lo, next);
            emit_store_spilled_result(isel, next->dest, dst_reg, sel_size, next);

            isel_emit(isel, lbuf_end, NULL, NULL, NULL);

            free(l_taken);
            free(l_end);
            if (dst_temp) free_temp_reg(isel, dst_reg, sel_size);
            if (temp_result) free_temp_reg(isel, reg, size);
            next->op = IROP_NOP; /* suppress SELECT codegen */
            return;
        }
    }

    /* JMP-PHI-aware NE compare: ne(x,0); jmp b_merge where b_merge has
     * phi[ne_result, const_0] that feeds a br (or ne+br).
     * Pattern:
     *   b_cur:  v_ne = ne(src, 0); jmp b_merge
     *   b_other: v_zero = const 0; jmp b_merge   (other pred of b_merge)
     *   b_merge: v_phi = phi[v_ne, v_zero]; br v_phi, b_true, b_false
     * or:
     *   b_merge: v_phi = phi[v_ne, v_zero]; v_ne2 = ne(v_phi, 0); br v_ne2, b_true, b_false
     * Optimization: emit direct conditional jump to b_true / b_false
     */
    if (next && next->op == IROP_JMP && next->labels && next->labels->len > 0
        && isel->ctx && isel->ctx->current_func) {
        const char* jmp_lbl = (const char*)list_get(next->labels, 0);
        int merge_id = parse_block_id(jmp_lbl);
        Func* func = isel->ctx->current_func;
        Block* b_merge = find_block_by_id(func, merge_id);
        if (b_merge && b_merge->phis) {
            char cur_block_lbl[32];
            snprintf(cur_block_lbl, sizeof(cur_block_lbl), "block%d", isel->current_block_id);

            /* Find the PHI in b_merge that uses ins->dest from this block */
            Instr* target_phi = NULL;
            for (Iter pit = list_iter(b_merge->phis); !iter_end(pit);) {
                Instr* phi = iter_next(&pit);
                if (!phi || phi->op != IROP_PHI || !phi->args || !phi->labels) continue;
                int n = phi->labels->len;
                if (n != 2) continue; /* only handle 2-input PHI */
                int idx_cur = -1, idx_other = -1;
                for (int k = 0; k < n; k++) {
                    const char* l = (const char*)list_get(phi->labels, k);
                    if (l && strcmp(l, cur_block_lbl) == 0) idx_cur = k;
                    else idx_other = k;
                }
                if (idx_cur < 0 || idx_other < 0) continue;
                if (idx_cur >= phi->args->len || idx_other >= phi->args->len) continue;
                ValueName val_cur = *(ValueName*)list_get(phi->args, idx_cur);
                if (val_cur != ins->dest) continue;
                ValueName val_other = *(ValueName*)list_get(phi->args, idx_other);
                /* other input must be const 0 for the optimization to be valid */
                if (!is_const_zero_def(func, val_other)) continue;
                target_phi = phi;
                break;
            }

            if (target_phi) {
                /* Inspect b_merge instrs to find br that uses phi dest */
                int merge_n = b_merge->instrs ? b_merge->instrs->len : 0;
                Instr** merge_instrs = NULL;
                if (merge_n > 0) {
                    merge_instrs = malloc(sizeof(Instr*) * merge_n);
                    int mi = 0;
                    for (Iter it2 = list_iter(b_merge->instrs); !iter_end(it2);) {
                        merge_instrs[mi++] = iter_next(&it2);
                    }
                }

                int final_true_id = -1, final_false_id = -1;

                for (int mi = 0; mi < merge_n; mi++) {
                    Instr* minstr = merge_instrs[mi];
                    if (!minstr || minstr->op == IROP_NOP || minstr->op == IROP_CONST
                        || minstr->op == IROP_PHI) continue;

                    /* Case A: direct BR on phi dest */
                    if (minstr->op == IROP_BR && minstr->args && minstr->args->len > 0
                        && minstr->labels && minstr->labels->len >= 2) {
                        ValueName br_cond = *(ValueName*)list_get(minstr->args, 0);
                        if (br_cond == target_phi->dest) {
                            final_true_id  = parse_block_id((const char*)list_get(minstr->labels, 0));
                            final_false_id = parse_block_id((const char*)list_get(minstr->labels, 1));
                        }
                        break;
                    }

                    /* Case B: ne(phi_dest, 0) then br ne2 */
                    if (minstr->op == IROP_NE && minstr->args && minstr->args->len >= 2) {
                        ValueName ne_a = get_src1_value(minstr);
                        int64_t ne_imm = 0;
                        bool ne_imm_ok = is_imm_operand(minstr, &ne_imm);
                        ValueName ne_b = get_src2_value(minstr);
                        bool is_ne_phi_zero = false;
                        if (ne_imm_ok && ne_imm == 0 && ne_a == target_phi->dest) {
                            is_ne_phi_zero = true;
                        } else if (ne_a == target_phi->dest && is_const_zero_def(func, ne_b)) {
                            is_ne_phi_zero = true;
                        } else if (ne_b == target_phi->dest && is_const_zero_def(func, ne_a)) {
                            is_ne_phi_zero = true;
                        }
                        if (!is_ne_phi_zero) break;
                        /* Find subsequent BR */
                        for (int mj = mi + 1; mj < merge_n; mj++) {
                            Instr* mj_ins = merge_instrs[mj];
                            if (!mj_ins || mj_ins->op == IROP_NOP || mj_ins->op == IROP_CONST) continue;
                            if (mj_ins->op == IROP_BR && mj_ins->args && mj_ins->args->len > 0
                                && mj_ins->labels && mj_ins->labels->len >= 2) {
                                ValueName br_cond = *(ValueName*)list_get(mj_ins->args, 0);
                                if (br_cond == minstr->dest) {
                                    final_true_id  = parse_block_id((const char*)list_get(mj_ins->labels, 0));
                                    final_false_id = parse_block_id((const char*)list_get(mj_ins->labels, 1));
                                }
                            }
                            break;
                        }
                        break;
                    }
                    break; /* unexpected instruction, can't optimize */
                }

                if (merge_instrs) free(merge_instrs);

                if (final_true_id >= 0 && final_false_id >= 0) {
                    char target_t[32], target_f[32];
                    block_label_name(target_t, sizeof(target_t), final_true_id);
                    block_label_name(target_f, sizeof(target_f), final_false_id);

                    char* l_ne_taken = isel_new_label(isel, "Lne_phi_taken");

                    int64_t cst2 = 0;
                    bool src2_is_const = try_get_value_const(isel, src2, &cst2);
                    if (!src2_is_const && src2_is_imm) { cst2 = imm_val; src2_is_const = true; }
                    int cmp_is_16 = (get_value_size(isel, src1) == 2);

                    if (src2_is_const && cmp_is_16 && ((cst2 >> 8) & 0xFF) == 0) {
                        const char* s1_lo = isel_get_extended_lo_reg(isel, src1, 2);
                        const char* s1_hi = isel_get_extended_hi_reg(isel, src1, 2);
                        char imm_lo[16];
                        snprintf(imm_lo, sizeof(imm_lo), "#%d", (int)(cst2 & 0xFF));
                        emit_mov(isel, "A", s1_lo, ins);
                        isel_emit(isel, "XRL", "A", imm_lo, NULL);
                        isel_emit(isel, "ORL", "A", s1_hi, NULL);
                        isel_emit(isel, "JNZ", l_ne_taken, NULL, NULL);
                    } else {
                        const char* s1_lo = isel_get_extended_lo_reg(isel, src1, cmp_is_16 ? 2 : 1);
                        emit_mov(isel, "A", s1_lo, ins);
                        if (src2_is_const) {
                            char arg2[64];
                            snprintf(arg2, sizeof(arg2), "#%d, %s", (int)(cst2 & 0xFF), l_ne_taken);
                            isel_emit(isel, "CJNE", "A", arg2, NULL);
                        } else {
                            const char* s2_lo = save_acc_operand_in_b(isel,
                                isel_get_extended_lo_reg(isel, src2, cmp_is_16 ? 2 : 1));
                            char arg2[64];
                            snprintf(arg2, sizeof(arg2), "%s, %s", s2_lo, l_ne_taken);
                            isel_emit(isel, "CJNE", "A", arg2, NULL);
                        }
                        if (cmp_is_16) {
                            const char* s1_hi = isel_get_extended_hi_reg(isel, src1, 2);
                            emit_mov(isel, "A", s1_hi, NULL);
                            if (src2_is_const) {
                                char arg2[64];
                                snprintf(arg2, sizeof(arg2), "#%d, %s", (int)((cst2 >> 8) & 0xFF), l_ne_taken);
                                isel_emit(isel, "CJNE", "A", arg2, NULL);
                            } else {
                                const char* s2_hi = save_acc_operand_in_b(isel, isel_get_extended_hi_reg(isel, src2, 2));
                                char arg2[64];
                                snprintf(arg2, sizeof(arg2), "%s, %s", s2_hi, l_ne_taken);
                                isel_emit(isel, "CJNE", "A", arg2, NULL);
                            }
                        }
                    }

                    /* ne==false path: phi gets 0, branch condition is false */
                    emit_phi_copies_for_edge(isel, isel->current_block_id, merge_id, ins);
                    isel_emit(isel, "LJMP", target_f, NULL, NULL);

                    /* ne==true path: phi gets ne_result (nonzero), branch condition is true */
                    isel_emit_label(isel, l_ne_taken);
                    emit_phi_copies_for_edge(isel, isel->current_block_id, merge_id, ins);
                    isel_emit(isel, "LJMP", target_t, NULL, NULL);

                    free(l_ne_taken);
                    next->op = IROP_NOP; /* suppress the original jmp */
                    if (temp_result) free_temp_reg(isel, reg, size);
                    return;
                }
            }
        }
    }

    /* BR-aware NE compare: if result directly feeds a BR, emit direct branches
     * NE=true �?goes to true branch, NE=false (equal) �?goes to false branch */
    if (next && next->op == IROP_BR && next->args && next->args->len > 0) {
        ValueName cond = *(ValueName*)list_get(next->args, 0);
        if (cond == ins->dest) {
            const char* lbl_t = (const char*)list_get(next->labels, 0);
            const char* lbl_f = (const char*)list_get(next->labels, 1);
            int id_t = parse_block_id(lbl_t);
            int id_f = parse_block_id(lbl_f);
            if (id_t >= 0 && id_f >= 0) {
                char target_t[32], target_f[32];
                block_label_name(target_t, sizeof(target_t), id_t);
                block_label_name(target_f, sizeof(target_f), id_f);

                /* l_ne_taken: trampoline for not-equal (true) path */
                char* l_ne_taken = isel_new_label(isel, "Lne_taken");

                int64_t cst2 = 0;
                bool src2_is_const = try_get_value_const(isel, src2, &cst2);
                if (!src2_is_const && src2_is_imm) { cst2 = imm_val; src2_is_const = true; }
                int cmp_is_16 = (get_value_size(isel, src1) == 2);

                if (src2_is_const && cmp_is_16 && ((cst2 >> 8) & 0xFF) == 0) {
                    /* 16-bit NE constant (hi==0): XRL+ORL+JNZ �?taken trampoline */
                    const char* s1_lo = isel_get_extended_lo_reg(isel, src1, 2);
                    const char* s1_hi = isel_get_extended_hi_reg(isel, src1, 2);
                    char imm_lo[16];
                    snprintf(imm_lo, sizeof(imm_lo), "#%d", (int)(cst2 & 0xFF));

                    emit_mov(isel, "A", s1_lo, ins);
                    isel_emit(isel, "XRL", "A", imm_lo, NULL);
                    isel_emit(isel, "ORL", "A", s1_hi, NULL);
                    isel_emit(isel, "JNZ", l_ne_taken, NULL, NULL);
                } else {
                    /* General CJNE path */
                    const char* s1_lo = isel_get_extended_lo_reg(isel, src1, cmp_is_16 ? 2 : 1);
                    emit_mov(isel, "A", s1_lo, ins);
                    if (src2_is_const) {
                        char arg2[64];
                        snprintf(arg2, sizeof(arg2), "#%d, %s", (int)(cst2 & 0xFF), l_ne_taken);
                        isel_emit(isel, "CJNE", "A", arg2, NULL);
                    } else {
                        const char* s2_lo = save_acc_operand_in_b(isel, isel_get_extended_lo_reg(isel, src2, cmp_is_16 ? 2 : 1));
                        char arg2[64];
                        snprintf(arg2, sizeof(arg2), "%s, %s", s2_lo, l_ne_taken);
                        isel_emit(isel, "CJNE", "A", arg2, NULL);
                    }
                    if (cmp_is_16) {
                        const char* s1_hi = isel_get_extended_hi_reg(isel, src1, 2);
                        emit_mov(isel, "A", s1_hi, NULL);
                        if (src2_is_const) {
                            char arg2[64];
                            snprintf(arg2, sizeof(arg2), "#%d, %s", (int)((cst2 >> 8) & 0xFF), l_ne_taken);
                            isel_emit(isel, "CJNE", "A", arg2, NULL);
                        } else {
                            const char* s2_hi = save_acc_operand_in_b(isel, isel_get_extended_hi_reg(isel, src2, 2));
                            char arg2[64];
                            snprintf(arg2, sizeof(arg2), "%s, %s", s2_hi, l_ne_taken);
                            isel_emit(isel, "CJNE", "A", arg2, NULL);
                        }
                    }
                }

                /* Equal path �?false branch */
                emit_phi_copies_for_edge(isel, isel->current_block_id, id_f, ins);
                isel_emit(isel, "LJMP", target_f, NULL, NULL);

                /* Not-equal trampoline �?true branch */
                isel_emit_label(isel, l_ne_taken);
                emit_phi_copies_for_edge(isel, isel->current_block_id, id_t, ins);
                isel_emit(isel, "LJMP", target_t, NULL, NULL);

                free(l_ne_taken);
                next->op = IROP_NOP;
                if (temp_result) free_temp_reg(isel, reg, size);
                return;
            }
        }
    }

    char* l_true = isel_new_label(isel, "Lne_true");
    char* l_false = isel_new_label(isel, "Lne_false");
    char* l_end = isel_new_label(isel, "Lne_end");
    char lbuf_true[64];
    char lbuf_false[64];
    char lbuf_end[64];
    snprintf(lbuf_true, sizeof(lbuf_true), "%s:", l_true);
    snprintf(lbuf_false, sizeof(lbuf_false), "%s:", l_false);
    snprintf(lbuf_end, sizeof(lbuf_end), "%s:", l_end);

    if (size == 2) {
        /* Use safe operand accessors: for spilled values these return the IDATA
         * symbol directly (e.g. "__spill_3") which can be used as a direct
         * address in "MOV A, direct" and "CJNE A, direct, rel" without
         * triggering the IDATA indirect load sequence in emit_mov. */
        const char* src1_lo = get_s16cmp_lo_operand(isel, src1);
        const char* src1_hi = get_s16cmp_hi_operand(isel, src1);

        /* Load src1_lo to A, compare with src2_lo */
        isel_emit(isel, "MOV", "A", src1_lo, NULL);
        if (src2_is_imm) {
            char imm_str[32];
            snprintf(imm_str, sizeof(imm_str), "#%d, %s", (int)(imm_val & 0xFF), l_true);
            isel_emit(isel, "CJNE", "A", imm_str, NULL);
        } else {
            /* For CJNE A, direct, rel: src2 direct address is also valid.
             * We save src2_lo into B only if it's "A" (would be overwritten). */
            const char* s2_lo_raw = get_s16cmp_lo_operand(isel, src2);
            const char* s2_lo;
            if (s2_lo_raw && strcmp(s2_lo_raw, "A") == 0) {
                isel_emit(isel, "MOV", "B", "A", NULL);
                s2_lo = "B";
            } else {
                s2_lo = s2_lo_raw;
            }
            char arg2[64];
            snprintf(arg2, sizeof(arg2), "%s, %s", s2_lo, l_true);
            isel_emit(isel, "CJNE", "A", arg2, NULL);
        }

        /* Load src1_hi to A, compare with src2_hi */
        isel_emit(isel, "MOV", "A", src1_hi, NULL);
        if (src2_is_imm) {
            char imm_str[32];
            snprintf(imm_str, sizeof(imm_str), "#%d, %s", (int)((imm_val >> 8) & 0xFF), l_true);
            isel_emit(isel, "CJNE", "A", imm_str, NULL);
        } else {
            const char* s2_hi_raw = get_s16cmp_hi_operand(isel, src2);
            const char* s2_hi;
            if (s2_hi_raw && strcmp(s2_hi_raw, "A") == 0) {
                isel_emit(isel, "MOV", "B", "A", NULL);
                s2_hi = "B";
            } else {
                s2_hi = s2_hi_raw;
            }
            char arg2[64];
            snprintf(arg2, sizeof(arg2), "%s, %s", s2_hi, l_true);
            isel_emit(isel, "CJNE", "A", arg2, NULL);
        }
    } else {
        int src1_lo_tmp = -1;
        const char* src1_lo = save_acc_operand_for_cmp(isel, isel_get_lo_reg(isel, src1), &src1_lo_tmp);
        emit_mov(isel, "A", src1_lo, ins);
        if (src2_is_imm) {
            char imm_str[32];
            snprintf(imm_str, sizeof(imm_str), "#%d, %s", (int)(imm_val & 0xFF), l_true);
            isel_emit(isel, "CJNE", "A", imm_str, NULL);
        } else {
            const char* s2_lo = save_acc_operand_in_b(isel, isel_get_lo_reg(isel, src2));
            char arg2[64];
            snprintf(arg2, sizeof(arg2), "%s, %s", s2_lo, l_true);
            isel_emit(isel, "CJNE", "A", arg2, NULL);
        }
        free_saved_cmp_operand(isel, src1_lo_tmp);
    }

    emit_set_bool_result(isel, ins, reg, size, false);
    isel_emit(isel, "SJMP", l_end, NULL, NULL);
    isel_emit(isel, lbuf_true, NULL, NULL, NULL);
    emit_set_bool_result(isel, ins, reg, size, true);
    isel_emit(isel, lbuf_end, NULL, NULL, NULL);

    free(l_true);
    free(l_false);
    free(l_end);
    if (temp_result) {
        free_temp_reg(isel, reg, size);
    }
}

void emit_lnot(ISelContext* isel, Instr* ins, Instr* next) {
    ValueName src = get_src1_value(ins);
    /* LNOT result is always 0 or 1, use 1 byte regardless of declared type (int) */
    int size = 1;
    int src_size = get_value_size(isel, src);
    if (src_size < 1) src_size = 1;
    if (src_size < 1) src_size = 1;

    int reg = alloc_reg_for_value(isel, ins->dest, size);
    bool temp_result = false;
    if (reg < 0 || reg + size - 1 > 7) {
        reg = alloc_temp_reg(isel, ins ? ins->dest : -1, size);
        temp_result = reg >= 0;
    }
    if (reg < 0) reg = 0;

    char* l_true = isel_new_label(isel, "Lnot_true");
    char* l_false = isel_new_label(isel, "Lnot_false");
    char* l_end = isel_new_label(isel, "Lnot_end");
    char lbuf_true[64], lbuf_false[64], lbuf_end[64];
    snprintf(lbuf_true, sizeof(lbuf_true), "%s:", l_true);
    snprintf(lbuf_false, sizeof(lbuf_false), "%s:", l_false);
    snprintf(lbuf_end, sizeof(lbuf_end), "%s:", l_end);

    if (src_size == 2) {
        int lo_tmp = -1;
        int hi_tmp = -1;
        const char* lo = save_acc_operand_for_cmp(isel, isel_get_lo_reg(isel, src), &lo_tmp);
        const char* hi = save_acc_operand_for_cmp(isel, isel_get_hi_reg(isel, src), &hi_tmp);
        emit_mov(isel, "A", hi, ins);
        isel_emit(isel, "ORL", "A", lo, NULL);
        free_saved_cmp_operand(isel, lo_tmp);
        free_saved_cmp_operand(isel, hi_tmp);
    } else {
        int src_tmp = -1;
        const char* value = save_acc_operand_for_cmp(isel, isel_get_lo_reg(isel, src), &src_tmp);
        emit_mov(isel, "A", value, ins);
        free_saved_cmp_operand(isel, src_tmp);
    }

    isel_emit(isel, "JZ", l_true, NULL, NULL);
    isel_emit(isel, "SJMP", l_false, NULL, NULL);
    isel_emit(isel, lbuf_true, NULL, NULL, NULL);
    emit_set_bool_result(isel, ins, reg, size, true);
    isel_emit(isel, "SJMP", l_end, NULL, NULL);
    isel_emit(isel, lbuf_false, NULL, NULL, NULL);
    emit_set_bool_result(isel, ins, reg, size, false);
    isel_emit(isel, lbuf_end, NULL, NULL, NULL);

    free(l_true);
    free(l_false);
    free(l_end);
    if (temp_result) {
        free_temp_reg(isel, reg, size);
    }
}

void emit_land(ISelContext* isel, Instr* ins, Instr* next) {
    ValueName s1 = get_src1_value(ins);
    ValueName s2 = get_src2_value(ins);
    /* LAND result is always 0 or 1, use 1 byte */
    int size = 1;

    int dst_reg = alloc_reg_for_value(isel, ins->dest, size);
    bool temp_result = false;
    if (dst_reg < 0 || dst_reg + size - 1 > 7) {
        dst_reg = alloc_temp_reg(isel, ins ? ins->dest : -1, size);
        temp_result = dst_reg >= 0;
    }
    if (dst_reg < 0) dst_reg = 0;

    char* l_true = isel_new_label(isel, "Land_true");
    char* l_false = isel_new_label(isel, "Land_false");
    char* l_end = isel_new_label(isel, "Land_end");
    char lb_true[64], lb_false[64], lb_end[64];
    snprintf(lb_true, sizeof(lb_true), "%s:", l_true);
    snprintf(lb_false, sizeof(lb_false), "%s:", l_false);
    snprintf(lb_end, sizeof(lb_end), "%s:", l_end);

    /* test s1 != 0 */
    if (get_value_size(isel, s1) == 2) {
        int tmp1 = -1, tmp2 = -1;
        const char* lo = save_acc_operand_for_cmp(isel, isel_get_lo_reg(isel, s1), &tmp1);
        const char* hi = save_acc_operand_for_cmp(isel, isel_get_hi_reg(isel, s1), &tmp2);
        emit_mov(isel, "A", hi, ins);
        isel_emit(isel, "ORL", "A", lo, NULL);
        free_saved_cmp_operand(isel, tmp1);
        free_saved_cmp_operand(isel, tmp2);
    } else {
        int tmp = -1;
        const char* v = save_acc_operand_for_cmp(isel, isel_get_lo_reg(isel, s1), &tmp);
        emit_mov(isel, "A", v, ins);
        free_saved_cmp_operand(isel, tmp);
    }

    /* if s1 == 0 -> false */
    isel_emit(isel, "JZ", l_false, NULL, NULL);

    /* test s2 != 0 */
    if (get_value_size(isel, s2) == 2) {
        int tmp1 = -1, tmp2 = -1;
        const char* lo = save_acc_operand_for_cmp(isel, isel_get_lo_reg(isel, s2), &tmp1);
        const char* hi = save_acc_operand_for_cmp(isel, isel_get_hi_reg(isel, s2), &tmp2);
        emit_mov(isel, "A", hi, NULL);
        isel_emit(isel, "ORL", "A", lo, NULL);
        free_saved_cmp_operand(isel, tmp1);
        free_saved_cmp_operand(isel, tmp2);
    } else {
        int tmp = -1;
        const char* v = save_acc_operand_for_cmp(isel, isel_get_lo_reg(isel, s2), &tmp);
        emit_mov(isel, "A", v, NULL);
        free_saved_cmp_operand(isel, tmp);
    }

    isel_emit(isel, "JZ", l_false, NULL, NULL);

    /* both non-zero -> true */
    isel_emit(isel, "SJMP", l_true, NULL, NULL);

    /* false */
    isel_emit(isel, lb_false, NULL, NULL, NULL);
    emit_set_bool_result(isel, ins, dst_reg, size, false);
    isel_emit(isel, "SJMP", l_end, NULL, NULL);

    /* true */
    isel_emit(isel, lb_true, NULL, NULL, NULL);
    emit_set_bool_result(isel, ins, dst_reg, size, true);
    isel_emit(isel, lb_end, NULL, NULL, NULL);

    free(l_true); free(l_false); free(l_end);
    if (temp_result) free_temp_reg(isel, dst_reg, size);
}

void emit_lor(ISelContext* isel, Instr* ins, Instr* next) {
    ValueName s1 = get_src1_value(ins);
    ValueName s2 = get_src2_value(ins);
    /* LOR result is always 0 or 1, use 1 byte */
    int size = 1;

    int dst_reg = alloc_reg_for_value(isel, ins->dest, size);
    bool temp_result = false;
    if (dst_reg < 0 || dst_reg + size - 1 > 7) {
        dst_reg = alloc_temp_reg(isel, ins ? ins->dest : -1, size);
        temp_result = dst_reg >= 0;
    }
    if (dst_reg < 0) dst_reg = 0;

    char* l_true = isel_new_label(isel, "Lor_true");
    char* l_false = isel_new_label(isel, "Lor_false");
    char* l_end = isel_new_label(isel, "Lor_end");
    char lb_true[64], lb_false[64], lb_end[64];
    snprintf(lb_true, sizeof(lb_true), "%s:", l_true);
    snprintf(lb_false, sizeof(lb_false), "%s:", l_false);
    snprintf(lb_end, sizeof(lb_end), "%s:", l_end);

    /* test s1 != 0 */
    if (get_value_size(isel, s1) == 2) {
        int tmp1 = -1, tmp2 = -1;
        const char* lo = save_acc_operand_for_cmp(isel, isel_get_lo_reg(isel, s1), &tmp1);
        const char* hi = save_acc_operand_for_cmp(isel, isel_get_hi_reg(isel, s1), &tmp2);
        emit_mov(isel, "A", hi, ins);
        isel_emit(isel, "ORL", "A", lo, NULL);
        free_saved_cmp_operand(isel, tmp1);
        free_saved_cmp_operand(isel, tmp2);
    } else {
        int tmp = -1;
        const char* v = save_acc_operand_for_cmp(isel, isel_get_lo_reg(isel, s1), &tmp);
        emit_mov(isel, "A", v, ins);
        free_saved_cmp_operand(isel, tmp);
    }

    /* if s1 != 0 -> true */
    isel_emit(isel, "JNZ", l_true, NULL, NULL);

    /* test s2 != 0 */
    if (get_value_size(isel, s2) == 2) {
        int tmp1 = -1, tmp2 = -1;
        const char* lo = save_acc_operand_for_cmp(isel, isel_get_lo_reg(isel, s2), &tmp1);
        const char* hi = save_acc_operand_for_cmp(isel, isel_get_hi_reg(isel, s2), &tmp2);
        emit_mov(isel, "A", hi, NULL);
        isel_emit(isel, "ORL", "A", lo, NULL);
        free_saved_cmp_operand(isel, tmp1);
        free_saved_cmp_operand(isel, tmp2);
    } else {
        int tmp = -1;
        const char* v = save_acc_operand_for_cmp(isel, isel_get_lo_reg(isel, s2), &tmp);
        emit_mov(isel, "A", v, NULL);
        free_saved_cmp_operand(isel, tmp);
    }

    isel_emit(isel, "JNZ", l_true, NULL, NULL);

    /* false */
    isel_emit(isel, lb_false, NULL, NULL, NULL);
    emit_set_bool_result(isel, ins, dst_reg, size, false);
    isel_emit(isel, "SJMP", l_end, NULL, NULL);

    /* true */
    isel_emit(isel, lb_true, NULL, NULL, NULL);
    emit_set_bool_result(isel, ins, dst_reg, size, true);
    isel_emit(isel, lb_end, NULL, NULL, NULL);

    free(l_true); free(l_false); free(l_end);
    if (temp_result) free_temp_reg(isel, dst_reg, size);
}

void emit_cmp_eq(ISelContext* isel, Instr* ins, Instr* next) {
    ValueName src1 = get_src1_value(ins);
    ValueName src2 = get_src2_value(ins);
    int size = ins && ins->type ? c51_abi_type_size(ins->type) : get_value_size(isel, ins->dest);
    if (size < 1) size = 1;
    int dst_reg = alloc_reg_for_value(isel, ins->dest, size);
    bool temp_result = false;
    if (dst_reg < 0 || dst_reg + size - 1 > 7) {
        dst_reg = alloc_temp_reg(isel, ins ? ins->dest : -1, size);
        temp_result = dst_reg >= 0;
    }
    if (dst_reg < 0) dst_reg = 0;

    /* BR-aware EQ compare: if result directly feeds a BR, emit direct CJNE branches
       and skip bool materialization entirely. */
    if (next && next->op == IROP_BR && next->args && next->args->len > 0) {
        ValueName cond = *(ValueName*)list_get(next->args, 0);
        if (cond == ins->dest) {
            const char* lbl_t = (const char*)list_get(next->labels, 0);
            const char* lbl_f = (const char*)list_get(next->labels, 1);
            int id_t = parse_block_id(lbl_t);
            int id_f = parse_block_id(lbl_f);
            if (id_t >= 0 && id_f >= 0) {
                char target_t[32], target_f[32];
                block_label_name(target_t, sizeof(target_t), id_t);
                block_label_name(target_f, sizeof(target_f), id_f);

                /* Emit: CJNE lo �?l_ne; [CJNE hi �?l_ne;]
                   (equal) phi_true + LJMP true_target
                   l_ne:   phi_false + LJMP false_target
                   If src2 is a constant, use immediate form for CJNE (avoids loading const to reg). */
                char* l_ne = isel_new_label(isel, "Leq_ne");
                char lb_ne[64];
                snprintf(lb_ne, sizeof(lb_ne), "%s:", l_ne);

                int64_t cst2 = 0;
                bool src2_is_const = is_imm_operand(ins, &cst2)
                                     || (src2 > 0 && try_get_value_const(isel, src2, &cst2));
                int cmp_is_16 = (!src2_is_const && get_value_size(isel, src2) == 2)
                                 || get_value_size(isel, src1) == 2
                                 || (src2_is_const && (cst2 > 0xFF || cst2 < 0));

                if (src2_is_const) {
                    /* 16-bit constant: use XRL+ORL+JZ/JNZ when hi==0 (most common case)
                     * MOV A,lo; XRL A,#cst_lo; ORL A,hi_reg; JZ equal
                     * Otherwise fall back to CJNE×2 */
                    if (cmp_is_16 && ((cst2 >> 8) & 0xFF) == 0) {
                        const char* s1_lo = isel_get_extended_lo_reg(isel, src1, 2);
                        const char* s1_hi = isel_get_extended_hi_reg(isel, src1, 2);
                        char imm_lo[16];
                        snprintf(imm_lo, sizeof(imm_lo), "#%d", (int)(cst2 & 0xFF));

                        emit_mov(isel, "A", s1_lo, ins);
                        isel_emit(isel, "XRL", "A", imm_lo, NULL);
                        isel_emit(isel, "ORL", "A", s1_hi, NULL);
                        /* JNZ �?not-equal path; fall-through �?equal path */
                        isel_emit(isel, "JNZ", l_ne, NULL, NULL);

                        /* Equal path �?true */
                        emit_phi_copies_for_edge(isel, isel->current_block_id, id_t, ins);
                        isel_emit(isel, "LJMP", target_t, NULL, NULL);

                        /* Not-equal path �?false */
                        isel_emit_label(isel, l_ne);
                        emit_phi_copies_for_edge(isel, isel->current_block_id, id_f, ins);
                        isel_emit(isel, "LJMP", target_f, NULL, NULL);

                        free(l_ne);
                        next->op = IROP_NOP;
                        if (temp_result) free_temp_reg(isel, dst_reg, size);
                        return;
                    }

                    /* Constant src2: use CJNE A, #imm directly, no register needed */
                    char imm_lo[16], imm_hi[16];
                    snprintf(imm_lo, sizeof(imm_lo), "#%d", (int)(cst2 & 0xFF));
                    snprintf(imm_hi, sizeof(imm_hi), "#%d", (int)((cst2 >> 8) & 0xFF));

                    const char* s1_lo = isel_get_extended_lo_reg(isel, src1, 2);
                    emit_mov(isel, "A", s1_lo, ins);
                    {
                        char arg2[64];
                        snprintf(arg2, sizeof(arg2), "%s, %s", imm_lo, l_ne);
                        isel_emit(isel, "CJNE", "A", arg2, NULL);
                    }

                    if (cmp_is_16) {
                        const char* s1_hi = isel_get_extended_hi_reg(isel, src1, 2);
                        emit_mov(isel, "A", s1_hi, NULL);
                        {
                            char arg2[64];
                            snprintf(arg2, sizeof(arg2), "%s, %s", imm_hi, l_ne);
                            isel_emit(isel, "CJNE", "A", arg2, NULL);
                        }
                    }
                } else {
                    /* Non-constant src2: load into register, use reg form */
                    const char* s2_lo = save_acc_operand_in_b(isel, isel_get_extended_lo_reg(isel, src2, 2));
                    const char* s1_lo = isel_get_extended_lo_reg(isel, src1, 2);
                    emit_mov(isel, "A", s1_lo, ins);
                    {
                        char arg2[64];
                        snprintf(arg2, sizeof(arg2), "%s, %s", s2_lo, l_ne);
                        isel_emit(isel, "CJNE", "A", arg2, NULL);
                    }

                    if (cmp_is_16) {
                        const char* s2_hi = save_acc_operand_in_b(isel, isel_get_extended_hi_reg(isel, src2, 2));
                        const char* s1_hi = isel_get_extended_hi_reg(isel, src1, 2);
                        emit_mov(isel, "A", s1_hi, NULL);
                        {
                            char arg2[64];
                            snprintf(arg2, sizeof(arg2), "%s, %s", s2_hi, l_ne);
                            isel_emit(isel, "CJNE", "A", arg2, NULL);
                        }
                    }
                }

                /* Equal path �?true */
                emit_phi_copies_for_edge(isel, isel->current_block_id, id_t, ins);
                isel_emit(isel, "LJMP", target_t, NULL, NULL);

                /* Not-equal path �?false */
                isel_emit_label(isel, l_ne);
                emit_phi_copies_for_edge(isel, isel->current_block_id, id_f, ins);
                isel_emit(isel, "LJMP", target_f, NULL, NULL);

                free(l_ne);
                next->op = IROP_NOP;
                if (temp_result) free_temp_reg(isel, dst_reg, size);
                return;
            }
        }
    }

    /* For EQ result: CJNE jumps to false on mismatch; fall-through is true.
     * This avoids the extra SJMP l_true that the old layout required.
     * Layout:
     *   CJNE A, s2_lo, l_false
     *   [CJNE A, s2_hi, l_false]   (16-bit only)
     *   MOV Rx, #1                  �?true (fall-through)
     *   SJMP l_end
     * l_false:
     *   MOV Rx, #0
     * l_end:
     */
    char* l_false = isel_new_label(isel, "Leq_false");
    char* l_end = isel_new_label(isel, "Leq_end");
    char lb_false[64], lb_end[64];
    snprintf(lb_false, sizeof(lb_false), "%s:", l_false);
    snprintf(lb_end,  sizeof(lb_end),  "%s:", l_end);

    int64_t s2_cst = 0;
    bool s2_is_const = is_imm_operand(ins, &s2_cst)
                       || (src2 > 0 && try_get_value_const(isel, src2, &s2_cst));
    bool s_cmp_is_16 = (!s2_is_const && get_value_size(isel, src2) == 2)
                        || get_value_size(isel, src1) == 2
                        || (s2_is_const && (s2_cst > 0xFF || s2_cst < 0));

    const char* s1_lo = isel_get_extended_lo_reg(isel, src1, 2);
    emit_mov(isel, "A", s1_lo, ins);
    {
        char arg2[64];
        if (s2_is_const) {
            char imm_buf[16];
            snprintf(imm_buf, sizeof(imm_buf), "#%d", (int)(s2_cst & 0xFF));
            snprintf(arg2, sizeof(arg2), "%s, %s", imm_buf, l_false);
        } else {
            const char* s2_lo = save_acc_operand_in_b(isel, isel_get_extended_lo_reg(isel, src2, 2));
            snprintf(arg2, sizeof(arg2), "%s, %s", s2_lo, l_false);
        }
        isel_emit(isel, "CJNE", "A", arg2, NULL);
    }

    if (s_cmp_is_16) {
        const char* s1_hi = isel_get_extended_hi_reg(isel, src1, 2);
        emit_mov(isel, "A", s1_hi, NULL);
        {
            char arg2[64];
            if (s2_is_const) {
                char imm_buf[16];
                snprintf(imm_buf, sizeof(imm_buf), "#%d", (int)((s2_cst >> 8) & 0xFF));
                snprintf(arg2, sizeof(arg2), "%s, %s", imm_buf, l_false);
            } else {
                const char* s2_hi = save_acc_operand_in_b(isel, isel_get_extended_hi_reg(isel, src2, 2));
                snprintf(arg2, sizeof(arg2), "%s, %s", s2_hi, l_false);
            }
            isel_emit(isel, "CJNE", "A", arg2, NULL);
        }
    }

    /* true: fall-through path */
    emit_set_bool_result(isel, ins, dst_reg, size, true);
    isel_emit(isel, "SJMP", l_end, NULL, NULL);
    /* false: jump target */
    isel_emit(isel, lb_false, NULL, NULL, NULL);
    emit_set_bool_result(isel, ins, dst_reg, size, false);
    isel_emit(isel, lb_end, NULL, NULL, NULL);

    free(l_false); free(l_end);
    if (temp_result) {
        free_temp_reg(isel, dst_reg, size);
    }
}

void emit_signed_cmp8_result(ISelContext* isel, Instr* ins, int dst_reg, int size, ValueName lhs, ValueName rhs, int cmp_type) {
    /* Keil-style sign-flip trick for 8-bit signed compare:
     * XOR both operands with 0x80 to flip the sign bit, then do an unsigned
     * subtraction.  This avoids the 4-instruction sign-bit branch sequence.
     *
     * Strategy by cmp_type (a = lhs, b = rhs):
     *   LT (a <  b): CLR C;  A = (a^80)-(b^80);     JC  true  (borrow �?a<b)
     *   GE (a >= b): CLR C;  A = (a^80)-(b^80);     JNC true  (no borrow �?a>=b)
     *   LE (a <= b): SETB C; A = (a^80)-(b^80)-1;   JC  true  (borrow �?a<=b)
     *   GT (a >  b): SETB C; A = (a^80)-(b^80)-1;   JNC true  (no borrow �?a>b)
     */
    bool temp_result = false;
    if (dst_reg < 0 || dst_reg + size - 1 > 7) {
        dst_reg = alloc_temp_reg(isel, ins ? ins->dest : -1, size);
        temp_result = dst_reg >= 0;
    }
    if (dst_reg < 0) dst_reg = 0;

    char* l_true = isel_new_label(isel, "Lscmp_true");
    char* l_end  = isel_new_label(isel, "Lscmp_end");
    char lb_true[64], lb_end[64];
    snprintf(lb_true, sizeof(lb_true), "%s:", l_true);
    snprintf(lb_end,  sizeof(lb_end),  "%s:", l_end);

    const char* llo = isel_get_lo_reg(isel, lhs);
    char rlo_imm_buf[16];
    int64_t rhs_const = 0;
    const char* rlo_raw;
    bool rhs_is_imm = is_imm_operand(ins, &rhs_const);
    bool rhs_is_const = try_get_value_const(isel, rhs, &rhs_const);

    if (rhs_is_imm || rhs_is_const) {
        snprintf(rlo_imm_buf, sizeof(rlo_imm_buf), "#%d", (int)((uint8_t)rhs_const));
        rlo_raw = rlo_imm_buf;
    } else {
        rlo_raw = isel_get_lo_reg(isel, rhs);
    }

    /* Determine CLR/SETB C */
    bool set_carry = (cmp_type == SIGNED_CMP_LE || cmp_type == SIGNED_CMP_GT);
    isel_emit(isel, set_carry ? "SETB" : "CLR", "C", NULL, NULL);

    /* Prepare (rhs ^ 0x80) into a temp operand */
    if (rlo_raw && rlo_raw[0] == '#') {
        /* Immediate rhs: fold XOR into the constant */
        int v = (int)strtol(rlo_raw + 1, NULL, 0);
        char rlo_xored[32];
        snprintf(rlo_xored, sizeof(rlo_xored), "#%d", (v ^ 0x80) & 0xFF);
        /* Emit:  MOV A, lhs; XRL A, #128; SUBB A, #(rhs^80) */
        emit_mov(isel, "A", llo, ins);
        isel_emit(isel, "XRL", "A", "#128", NULL);
        isel_emit(isel, "SUBB", "A", rlo_xored, NULL);
    } else {
        /* Register/memory rhs: always use B register as scratch.
         * Using alloc_temp_reg() here can pick a live register (e.g. a phi
         * source/result in R0/R1), corrupting values that are still needed
         * after the compare result is materialized. */
        const char* rlo_xored = "B";
        emit_mov(isel, "A", rlo_raw, NULL);
        isel_emit(isel, "XRL", "A", "#128", NULL);
        isel_emit(isel, "MOV", "B", "A", NULL);
        /* Emit:  MOV A, lhs; XRL A, #128; SUBB A, tmp */
        emit_mov(isel, "A", llo, ins);
        isel_emit(isel, "XRL", "A", "#128", NULL);
        isel_emit(isel, "SUBB", "A", rlo_xored, NULL);
    }

    /* Branch: carry set means "a < b" (unsigned after flip) */
    const char* jump_true  = (cmp_type == SIGNED_CMP_LT || cmp_type == SIGNED_CMP_LE) ? "JC" : "JNC";
    const char* jump_false = (cmp_type == SIGNED_CMP_LT || cmp_type == SIGNED_CMP_LE) ? "JNC" : "JC";
    (void)jump_false;
    isel_emit(isel, jump_true, l_true, NULL, NULL);

    /* false path: fall through */
    emit_set_bool_result(isel, ins, dst_reg, size, false);
    isel_emit(isel, "SJMP", l_end, NULL, NULL);
    isel_emit(isel, lb_true, NULL, NULL, NULL);
    emit_set_bool_result(isel, ins, dst_reg, size, true);
    isel_emit(isel, lb_end, NULL, NULL, NULL);

    free(l_true);
    free(l_end);
    if (temp_result) {
        free_temp_reg(isel, dst_reg, size);
    }
}

/* Helper: emit the 5-instruction core of the XRL sign-flip comparison.
 * Emits:
 *   [SETB/CLR C]
 *   MOV A, llo
 *   SUBB A, rlo_op
 *   MOV A, lhi
 *   XRL A, #128
 *   SUBB A, rhi_xored_op
 * where rhi_xored_op = hi_rhs ^ 0x80 (either a folded immediate or a temp reg).
 * On return, carry=0 means GT/GE; carry=1 means LT/LE (after SETB/CLR chosen accordingly).
 *
 * cmp_type: GT/LE �?SETB C; LT/GE �?CLR C
 * Returns a temp reg index to free (or -1 if none was used).
 */
static int emit_s16cmp_core(ISelContext* isel, Instr* ins,
                             const char* lhi, const char* llo,
                             const char* rhi_raw, const char* rlo_op,
                             int cmp_type) {
    bool set_carry = (cmp_type == SIGNED_CMP_GT || cmp_type == SIGNED_CMP_LE);
    isel_emit(isel, set_carry ? "SETB" : "CLR", "C", NULL, NULL);
    /* Use isel_emit directly (not emit_mov) so that IDATA symbol names are
     * emitted as-is for "MOV A, direct" without triggering the IDATA indirect
     * load sequence in emit_mov (which would wrongly use @R0 indirection). */
    char* ssa = instr_to_ssa_str(ins);
    isel_emit(isel, "MOV", "A", llo, ssa);
    free(ssa);
    isel_emit(isel, "SUBB", "A", rlo_op, NULL);

    /* Now prepare rhi ^ 0x80 */
    if (rhi_raw && rhi_raw[0] == '#') {
        /* Immediate: fold XOR into constant, then do lhi XRL and SUBB imm
         * MOV A, lhi; XRL A, #128; SUBB A, rhi_xored  (3 instructions) */
        char rhi_xored[32];
        int v = (int)strtol(rhi_raw + 1, NULL, 0);
        snprintf(rhi_xored, sizeof(rhi_xored), "#%d", (v ^ 0x80) & 0xFF);
        isel_emit(isel, "MOV", "A", lhi, NULL);
        isel_emit(isel, "XRL", "A", "#128", NULL);
        isel_emit(isel, "SUBB", "A", rhi_xored, NULL);
        return -1;
    } else {
        /* Register rhi: compute rhi^0x80 into a temp register, then SUBB from A (lhi^0x80).
         * Try to allocate a scratch Rn for rhi^0x80 to avoid needing B register.
         * This is important because lhi or llo may already be saved in B by
         * save_acc_operand_for_cmp when no Rn was available. */
        int rhi_tmp = alloc_temp_reg(isel, -1, 1);
        if (rhi_tmp >= 0) {
            /* Preferred path: use Rn for scratch, works even if lhi == "B" */
            const char* tmp_name = isel_reg_name(rhi_tmp);
            isel_emit(isel, "MOV", "A", rhi_raw, NULL);   /* A = rhi */
            isel_emit(isel, "XRL", "A", "#128", NULL);     /* A = rhi^0x80 */
            isel_emit(isel, "MOV", tmp_name, "A", NULL);   /* tmp = rhi^0x80 */
            isel_emit(isel, "MOV", "A", lhi, NULL);        /* A = lhi */
            isel_emit(isel, "XRL", "A", "#128", NULL);     /* A = lhi^0x80 */
            isel_emit(isel, "SUBB", "A", tmp_name, NULL);  /* A = lhi^0x80 - rhi^0x80 - C */
            free_temp_reg(isel, rhi_tmp, 1);
        } else {
            /* Fallback: use B as scratch. lhi must not be "B" in this path.
             * If lhi == "B", we cannot safely read B after clobbering it with rhi^0x80.
             * In practice lhi should not be "B" if Rn regs are all busy (contradictory),
             * but guard it anyway. */
            isel_emit(isel, "MOV", "A", rhi_raw, NULL);   /* A = rhi */
            isel_emit(isel, "XRL", "A", "#128", NULL);     /* A = rhi^0x80 */
            isel_emit(isel, "MOV", "B", "A", NULL);        /* B = rhi^0x80 */
            isel_emit(isel, "MOV", "A", lhi, NULL);        /* A = lhi (must not be B!) */
            isel_emit(isel, "XRL", "A", "#128", NULL);     /* A = lhi^0x80 */
            isel_emit(isel, "SUBB", "A", "B", NULL);       /* A = lhi^0x80 - rhi^0x80 - C */
        }
        return -1;
    }
}

/* Emit signed 16-bit comparison result using sign-bit XOR trick (Keil style).
 * Technique: flip bit-15 of both operands, then treat as unsigned SUBB.
 * This reduces ~20 instructions to ~8 and avoids extra labels.
 *
 * cmp_type: SIGNED_CMP_LT / GT / LE / GE
 */
static void emit_signed_cmp16_result(ISelContext* isel, Instr* ins, int dst_reg, int size,
                                     ValueName lhs, ValueName rhs, int cmp_type) {
    bool temp_result = false;
    if (dst_reg < 0 || dst_reg + size - 1 > 7) {
        dst_reg = alloc_temp_reg(isel, ins ? ins->dest : -1, size);
        temp_result = dst_reg >= 0;
    }
    if (dst_reg < 0) dst_reg = 0;

    /* carry=0 → GT/GE true; carry=1 → LT/LE true */
    const char* jump_true = (cmp_type == SIGNED_CMP_LT || cmp_type == SIGNED_CMP_LE) ? "JC" : "JNC";

    /* Use safe operand accessors that return direct IDATA addresses for spilled
     * values, avoiding A-register clobbering when fetching lhs then rhs. */
    const char* llo = get_s16cmp_lo_operand(isel, lhs);
    const char* lhi = get_s16cmp_hi_operand(isel, lhs);
    char rhi_imm_buf[16], rlo_imm_buf[16];
    int64_t rhs_const = 0;
    const char* rhi_raw;
    const char* rlo_raw;
    bool rhs_is_imm = is_imm_operand(ins, &rhs_const);
    bool rhs_is_const = try_get_value_const(isel, rhs, &rhs_const);

    if (rhs_is_imm || rhs_is_const) {
        uint16_t rv = (uint16_t)((int16_t)rhs_const);
        snprintf(rlo_imm_buf, sizeof(rlo_imm_buf), "#%d", (int)(rv & 0xFF));
        snprintf(rhi_imm_buf, sizeof(rhi_imm_buf), "#%d", (int)((rv >> 8) & 0xFF));
        rlo_raw = rlo_imm_buf;
        rhi_raw = rhi_imm_buf;
    } else {
        rhi_raw = get_s16cmp_hi_operand(isel, rhs);
        rlo_raw = get_s16cmp_lo_operand(isel, rhs);
    }

    /* rlo_op is used directly as SUBB operand; for non-immediate non-A operands
     * it is already a safe direct address (Rn or IDATA sym), so no need to save. */
    const char* rlo_op = rlo_raw;

    char* l_true = isel_new_label(isel, "Lscmp16_true");
    char* l_false = isel_new_label(isel, "Lscmp16_false");
    char* l_end = isel_new_label(isel, "Lscmp16_end");
    char lb_true[64], lb_false[64], lb_end[64];
    snprintf(lb_true, sizeof(lb_true), "%s:", l_true);
    snprintf(lb_false, sizeof(lb_false), "%s:", l_false);
    snprintf(lb_end, sizeof(lb_end), "%s:", l_end);

    emit_s16cmp_core(isel, ins, lhi, llo, rhi_raw, rlo_op, cmp_type);

    isel_emit(isel, jump_true, l_true, NULL, NULL);
    isel_emit(isel, lb_false, NULL, NULL, NULL);
    emit_set_bool_result(isel, ins, dst_reg, size, false);
    isel_emit(isel, "SJMP", l_end, NULL, NULL);
    isel_emit(isel, lb_true, NULL, NULL, NULL);
    emit_set_bool_result(isel, ins, dst_reg, size, true);
    isel_emit(isel, lb_end, NULL, NULL, NULL);

    free(l_true);
    free(l_false);
    free(l_end);
    if (temp_result) {
        free_temp_reg(isel, dst_reg, size);
    }
}

static void emit_signed_cmp8_branch(ISelContext* isel, Instr* ins, ValueName lhs, ValueName rhs,
                                    int cmp_type, int true_id, int false_id) {
    /* Use the same XOR sign-flip trick as emit_signed_cmp8_result to avoid
     * emitting two separate code paths that each call emit_phi_copies_for_edge.
     * Calling emit_phi_copies_for_edge twice for the same edge can produce
     * inconsistent code when isel_reload_spill has a side-effect on the first
     * call that changes the allocation state seen by the second call.
     *
     * Strategy (a = lhs, b = rhs):
     *   LT (a <  b): CLR C;  A = (a^80)-(b^80);   JC  true  (borrow → a < b)
     *   GE (a >= b): CLR C;  A = (a^80)-(b^80);   JNC true
     *   LE (a <= b): SETB C; A = (a^80)-(b^80)-1; JC  true  (borrow → a <= b)
     *   GT (a >  b): SETB C; A = (a^80)-(b^80)-1; JNC true
     */
    const char* llo = isel_get_lo_reg(isel, lhs);
    const char* rlo_raw = isel_get_lo_reg(isel, rhs);

    bool set_carry = (cmp_type == SIGNED_CMP_LE || cmp_type == SIGNED_CMP_GT);
    isel_emit(isel, set_carry ? "SETB" : "CLR", "C", NULL, NULL);

    if (rlo_raw && rlo_raw[0] == '#') {
        /* Immediate rhs: fold XOR into the constant */
        int v = (int)strtol(rlo_raw + 1, NULL, 0);
        char rlo_xored[32];
        snprintf(rlo_xored, sizeof(rlo_xored), "#%d", (v ^ 0x80) & 0xFF);
        emit_mov(isel, "A", llo, ins);
        isel_emit(isel, "XRL", "A", "#128", NULL);
        isel_emit(isel, "SUBB", "A", rlo_xored, NULL);
    } else {
        /* Register/memory rhs: compute rhs^0x80 into B register as scratch.
         * We must NOT use alloc_temp_reg here because it may assign a register
         * that overlaps with a live phi-source variable (e.g. v22 in R1:R0),
         * which would corrupt its value before emit_phi_copies_for_edge reads it. */
        emit_mov(isel, "A", rlo_raw, NULL);
        isel_emit(isel, "XRL", "A", "#128", NULL);
        isel_emit(isel, "MOV", "B", "A", NULL);
        emit_mov(isel, "A", llo, ins);
        isel_emit(isel, "XRL", "A", "#128", NULL);
        isel_emit(isel, "SUBB", "A", "B", NULL);
    }

    /* carry set ↔ a < b (after sign-flip, unsigned).
     * For SETB C case carry also absorbs the -1, making it ↔ a <= b. */
    bool jump_c_taken = (cmp_type == SIGNED_CMP_LT || cmp_type == SIGNED_CMP_LE);
    char* ssa = instr_to_ssa_str(ins);
    if (jump_c_taken) {
        emit_far_cond_jump1(isel, "JC", true_id, false_id, ins, ssa);
    } else {
        emit_far_cond_jump1(isel, "JNC", true_id, false_id, ins, ssa);
    }
    free(ssa);
}

/* Emit signed 16-bit comparison branch using sign-bit XOR trick (Keil style).
 * Same technique as emit_signed_cmp16_result but jumps directly to target blocks.
 * cmp_type: SIGNED_CMP_LT / GT / LE / GE
 */
static void emit_signed_cmp16_branch(ISelContext* isel, Instr* ins, ValueName lhs, ValueName rhs,
                                     int cmp_type, int true_id, int false_id) {
    bool jump_c_taken = (cmp_type == SIGNED_CMP_LT || cmp_type == SIGNED_CMP_LE);

    /* Use safe operand accessors that return direct IDATA addresses for spilled
     * values, avoiding A-register clobbering when fetching lhs then rhs. */
    const char* llo = get_s16cmp_lo_operand(isel, lhs);
    const char* lhi = get_s16cmp_hi_operand(isel, lhs);

    /* If rhs is a known constant, use immediate strings directly */
    char rhi_imm_buf[16], rlo_imm_buf[16];
    int64_t rhs_const = 0;
    const char* rhi_raw;
    const char* rlo_raw;
    bool rhs_is_imm = is_imm_operand(ins, &rhs_const);
    bool rhs_is_const = try_get_value_const(isel, rhs, &rhs_const);

    if (rhs_is_imm || rhs_is_const) {
        uint16_t rv = (uint16_t)((int16_t)rhs_const);
        snprintf(rlo_imm_buf, sizeof(rlo_imm_buf), "#%d", (int)(rv & 0xFF));
        snprintf(rhi_imm_buf, sizeof(rhi_imm_buf), "#%d", (int)((rv >> 8) & 0xFF));
        rlo_raw = rlo_imm_buf;
        rhi_raw = rhi_imm_buf;
    } else {
        rhi_raw = get_s16cmp_hi_operand(isel, rhs);
        rlo_raw = get_s16cmp_lo_operand(isel, rhs);
    }

    const char* rlo_op = rlo_raw;

    char* ssa = instr_to_ssa_str(ins);
    emit_s16cmp_core(isel, ins, lhi, llo, rhi_raw, rlo_op, cmp_type);

    if (jump_c_taken) {
        emit_far_cond_jump1(isel, "JC", true_id, false_id, ins, ssa);
    } else {
        emit_far_cond_jump1(isel, "JNC", true_id, false_id, ins, ssa);
    }

    free(ssa);
}

static Ctype* get_compare_operand_type(ISelContext* isel, ValueName value) {
    Ctype* type = get_value_type(isel, value);
    if (type) return type;
    if (!isel || !isel->ctx || !isel->ctx->current_func || value <= 0) return NULL;

    Instr* def = find_def_instr_in_func(isel->ctx->current_func, value);
    if (def && def->type) return def->type;
    return NULL;
}

static bool type_prefers_unsigned_compare(Ctype* type) {
    if (!type) return false;
    if (type->type == CTYPE_PTR || type->type == CTYPE_BOOL) return true;
    return get_attr(type->attr).ctype_unsigned;
}

bool is_unsigned_compare(ISelContext* isel, ValueName a, ValueName b) {
    Ctype* ta = get_compare_operand_type(isel, a);
    Ctype* tb = get_compare_operand_type(isel, b);

    if (type_prefers_unsigned_compare(ta)) return true;
    if (type_prefers_unsigned_compare(tb)) return true;

    if (!ta && try_get_value_const(isel, a, NULL) && tb) {
        return type_prefers_unsigned_compare(tb);
    }
    if (!tb && try_get_value_const(isel, b, NULL) && ta) {
        return type_prefers_unsigned_compare(ta);
    }

    return false;
}

void emit_cmp_lt_gt(ISelContext* isel, Instr* ins, Instr* next, bool is_gt) {
    ValueName a = get_src1_value(ins);
    ValueName b = get_src2_value(ins);
    ValueName lhs = a;
    ValueName rhs = b;
    bool unsigned_cmp = is_unsigned_compare(isel, lhs, rhs);

    /* Check if rhs is encoded as an inline immediate in the instruction */
    int64_t rhs_imm_val = 0;
    bool rhs_is_imm = is_imm_operand(ins, &rhs_imm_val)
                      || (rhs > 0 && try_get_value_const(isel, rhs, &rhs_imm_val));

    int size = ins && ins->type ? c51_abi_type_size(ins->type) : get_value_size(isel, ins->dest);
    if (size < 1) size = 1;
    int dst_reg = alloc_reg_for_value(isel, ins->dest, size);
    bool temp_result = false;
    if (dst_reg < 0 || dst_reg + size - 1 > 7) {
        dst_reg = alloc_temp_reg(isel, ins ? ins->dest : -1, size);
        temp_result = dst_reg >= 0;
    }
    if (dst_reg < 0) dst_reg = 0;
    int w = (get_value_size(isel, lhs) == 2 || (!rhs_is_imm && get_value_size(isel, rhs) == 2)) ? 2 : 1;
    /* If rhs is an immediate >= 256, it must be treated as 16-bit */
    if (rhs_is_imm && (rhs_imm_val > 0xFF || rhs_imm_val < 0)) w = 2;

    if (next && next->op == IROP_BR && next->args && next->args->len > 0) {
        ValueName cond = *(ValueName*)list_get(next->args, 0);
        if (cond == ins->dest) {
            int64_t lhs_const = 0;
            int64_t rhs_const = 0;
            bool lhs_is_zero = try_get_value_const(isel, lhs, &lhs_const) && lhs_const == 0;
            bool rhs_is_zero = try_get_value_const(isel, rhs, &rhs_const) && rhs_const == 0;
            if (lhs_is_zero || rhs_is_zero) {
                int id_t = parse_block_id((const char*)list_get(next->labels, 0));
                int id_f = parse_block_id((const char*)list_get(next->labels, 1));
                if (id_t >= 0 && id_f >= 0) {
                    /* Check br_invert: LNOT+BR fusion sets invert=true, swap id_t/id_f */
                    bool br_inv0 = false;
                    if (br_invert_get(isel, next, &br_inv0) && br_inv0) {
                        int tmp = id_t; id_t = id_f; id_f = tmp;
                    }
                    ValueName value = lhs_is_zero ? rhs : lhs;
                    bool want_positive = false;
                    bool want_negative = false;

                    if (rhs_is_zero) {
                        want_positive = is_gt;
                        want_negative = !is_gt;
                    } else {
                        want_positive = !is_gt;
                        want_negative = is_gt;
                    }

                    if (emit_cmp_zero_branch(isel, ins, value, want_positive, want_negative,
                                             unsigned_cmp, id_t, id_f)) {
                        next->op = IROP_NOP;
                        if (temp_result) free_temp_reg(isel, dst_reg, size);
                        return;
                    }
                }
            }
        }
    }

    if (!unsigned_cmp && next && next->op == IROP_BR && next->args && next->args->len > 0) {
        ValueName cond = *(ValueName*)list_get(next->args, 0);
        if (cond == ins->dest) {
            int id_t = parse_block_id((const char*)list_get(next->labels, 0));
            int id_f = parse_block_id((const char*)list_get(next->labels, 1));
            /* Check br_invert: LNOT+BR fusion sets invert=true, which swaps id_t/id_f */
            bool br_inv = false;
            if (br_invert_get(isel, next, &br_inv) && br_inv) {
                int tmp = id_t; id_t = id_f; id_f = tmp;
            }
            if (w == 1) {
                emit_signed_cmp8_branch(isel, ins, lhs, rhs, is_gt ? SIGNED_CMP_GT : SIGNED_CMP_LT, id_t, id_f);
            } else {
                emit_signed_cmp16_branch(isel, ins, lhs, rhs,
                                         is_gt ? SIGNED_CMP_GT : SIGNED_CMP_LT, id_t, id_f);
            }
            next->op = IROP_NOP;
            if (temp_result) free_temp_reg(isel, dst_reg, size);
            return;
        }
    }

    char* l_true = isel_new_label(isel, "Lcmp_true");
    char* l_end = isel_new_label(isel, "Lcmp_end");
    char lb_true[64], lb_end[64];
    snprintf(lb_true, sizeof(lb_true), "%s:", l_true);
    snprintf(lb_end, sizeof(lb_end), "%s:", l_end);

    /* BR-aware signed compare: if this compare's result is immediately used by
       a following BR, emit direct conditional branches for signed comparisons
       (avoid materializing boolean). Wrap in a nested scope to avoid
       redeclaring locals like `llo`/`rlo`. */
    if (!unsigned_cmp && next && next->op == IROP_BR && next->args && next->args->len > 0) {
        {
            ValueName cond = *(ValueName*)list_get(next->args, 0);
            if (cond == ins->dest) {
                const char* lbl_t = (const char*)list_get(next->labels, 0);
                const char* lbl_f = (const char*)list_get(next->labels, 1);
                int id_t = parse_block_id(lbl_t);
                int id_f = parse_block_id(lbl_f);
                if (id_t >= 0 && id_f >= 0) {
                    /* Check br_invert: LNOT+BR fusion sets invert=true, swap id_t/id_f */
                    bool br_inv2 = false;
                    if (br_invert_get(isel, next, &br_inv2) && br_inv2) {
                        int tmp = id_t; id_t = id_f; id_f = tmp;
                    }
                    char target_t[32]; char target_f[32];
                    block_label_name(target_t, sizeof(target_t), id_t);
                    block_label_name(target_f, sizeof(target_f), id_f);

                    if (w == 1) {
                        /* 8-bit signed compare: use existing emit_signed_cmp8_branch */
                        emit_signed_cmp8_branch(isel, ins, lhs, rhs,
                                                is_gt ? SIGNED_CMP_GT : SIGNED_CMP_LT,
                                                id_t, id_f);
                        next->op = IROP_NOP;
                        return;
                    } else {
                        /* 16-bit signed compare: use compact XRL sign-flip technique */
                        emit_signed_cmp16_branch(isel, ins, lhs, rhs,
                                                 is_gt ? SIGNED_CMP_GT : SIGNED_CMP_LT,
                                                 id_t, id_f);
                        next->op = IROP_NOP;
                        return;
                    }
                }
            }
        }
    }

    if (unsigned_cmp && next && next->op == IROP_BR && next->args && next->args->len > 0) {
        ValueName cond = *(ValueName*)list_get(next->args, 0);
        if (cond == ins->dest) {
            const char* lbl_t = (const char*)list_get(next->labels, 0);
            const char* lbl_f = (const char*)list_get(next->labels, 1);
            int id_t = parse_block_id(lbl_t);
            int id_f = parse_block_id(lbl_f);
            char target_t[32]; char target_f[32];
            block_label_name(target_t, sizeof(target_t), id_t);
            block_label_name(target_f, sizeof(target_f), id_f);

            if (w == 1) {
                char rlo_imm_buf[16];
                const char* llo = isel_get_lo_reg(isel, lhs);
                const char* rlo;
                if (rhs_is_imm) {
                    snprintf(rlo_imm_buf, sizeof(rlo_imm_buf), "#%d", (int)(rhs_imm_val & 0xFF));
                    rlo = rlo_imm_buf;
                } else {
                    rlo = save_acc_operand_in_b(isel, isel_get_lo_reg(isel, rhs));
                }
                isel_emit(isel, "CLR", "C", NULL, NULL);
                emit_mov(isel, "A", llo, ins);
                isel_emit(isel, "SUBB", "A", rlo, NULL);

                if (!is_gt) {
                    char* ssa = instr_to_ssa_str(ins);
                    emit_far_cond_jump1(isel, "JC", id_t, id_f, ins, ssa);
                    free(ssa);
                } else {
                    char* ssa = instr_to_ssa_str(ins);
                    emit_far_cond_jump2_same(isel, "JC", "JZ", id_f, id_t, ins, ssa);
                    free(ssa);
                }

                next->op = IROP_NOP;
                if (temp_result) free_temp_reg(isel, dst_reg, size);
                return;
            } else {
                /* 16-bit unsigned LT/GT branch:
                 * For LT (a < b): check hi bytes first, then lo bytes.
                 * For GT (a > b): swap operands (a > b ≡ b < a). */
                char rlo_imm_buf[16], rhi_imm_buf[16];
                const char* rlo;
                const char* rhi;
                int rlo_tmp = -1;
                int rhi_tmp = -1;
                if (rhs_is_imm) {
                    snprintf(rlo_imm_buf, sizeof(rlo_imm_buf), "#%d", (int)(rhs_imm_val & 0xFF));
                    snprintf(rhi_imm_buf, sizeof(rhi_imm_buf), "#%d", (int)((rhs_imm_val >> 8) & 0xFF));
                    rlo = rlo_imm_buf;
                    rhi = rhi_imm_buf;
                } else {
                    rlo = save_acc_operand_for_cmp(isel,
                        isel_get_extended_lo_reg(isel, rhs, 2), &rlo_tmp);
                    rhi = save_acc_operand_for_cmp(isel,
                        isel_get_extended_hi_reg(isel, rhs, 2), &rhi_tmp);
                }
                const char* llo = isel_get_extended_lo_reg(isel, lhs, 2);
                const char* lhi = isel_get_extended_hi_reg(isel, lhs, 2);

                /* For LT: compare (lhs < rhs), for GT: compare (rhs < lhs) */
                const char* cmp_hi_a = is_gt ? rhi : lhi;
                const char* cmp_hi_b = is_gt ? lhi : rhi;
                const char* cmp_lo_a = is_gt ? rlo : llo;
                const char* cmp_lo_b = is_gt ? llo : rlo;

                char* l_check_low = isel_new_label(isel, "Lchk_lo16");
                char lb_check_low[64]; snprintf(lb_check_low, sizeof(lb_check_low), "%s:", l_check_low);

                /* Compare hi bytes: cmp_hi_a - cmp_hi_b */
                isel_emit(isel, "CLR", "C", NULL, NULL);
                emit_mov(isel, "A", cmp_hi_a, ins);
                isel_emit(isel, "SUBB", "A", cmp_hi_b, NULL);
                /* JC: hi_a < hi_b → result true → jump to id_t */
                char* l_hi_lt = isel_new_label(isel, "Lhi_lt");
                char* ssa = instr_to_ssa_str(ins);
                isel_emit(isel, "JC", l_hi_lt, NULL, ssa);
                free(ssa);
                /* JZ: hi bytes equal → check lo */
                isel_emit(isel, "JZ", l_check_low, NULL, NULL);
                /* hi_a > hi_b → result false */
                emit_block_jump(isel, ins, id_f);
                isel_emit_label(isel, l_check_low);
                /* Compare lo bytes: cmp_lo_a - cmp_lo_b */
                isel_emit(isel, "CLR", "C", NULL, NULL);
                emit_mov(isel, "A", cmp_lo_a, NULL);
                isel_emit(isel, "SUBB", "A", cmp_lo_b, NULL);
                /* JC: lo_a < lo_b → result true */
                isel_emit(isel, "JC", l_hi_lt, NULL, NULL);
                /* lo_a >= lo_b → result false */
                emit_block_jump(isel, ins, id_f);
                isel_emit_label(isel, l_hi_lt);
                emit_block_jump(isel, ins, id_t);

                free(l_check_low);
                free(l_hi_lt);
                free_saved_cmp_operand(isel, rlo_tmp);
                free_saved_cmp_operand(isel, rhi_tmp);
                next->op = IROP_NOP;
                if (temp_result) free_temp_reg(isel, dst_reg, size);
                return;
            }
        }
    }

    if (w == 1) {
        if (!unsigned_cmp) {
            emit_signed_cmp8_result(isel, ins, dst_reg, size, lhs, rhs,
                                    is_gt ? SIGNED_CMP_GT : SIGNED_CMP_LT);
            free(l_true); free(l_end);
            if (temp_result) {
                free_temp_reg(isel, dst_reg, size);
            }
            return;
        }

        char rlo_imm_buf_r[16];
        const char* rlo;
        if (rhs_is_imm) {
            snprintf(rlo_imm_buf_r, sizeof(rlo_imm_buf_r), "#%d", (int)(rhs_imm_val & 0xFF));
            rlo = rlo_imm_buf_r;
        } else {
            rlo = save_acc_operand_in_b(isel, isel_get_lo_reg(isel, rhs));
        }
        const char* llo = isel_get_lo_reg(isel, lhs);

        isel_emit(isel, "CLR", "C", NULL, NULL);
        emit_mov(isel, "A", llo, ins);
        isel_emit(isel, "SUBB", "A", rlo, NULL);

        if (!is_gt) {
            isel_emit(isel, "JC", l_true, NULL, NULL);
            emit_set_bool_result(isel, ins, dst_reg, size, false);
            isel_emit(isel, "SJMP", l_end, NULL, NULL);
            isel_emit(isel, lb_true, NULL, NULL, NULL);
            emit_set_bool_result(isel, ins, dst_reg, size, true);
            isel_emit(isel, lb_end, NULL, NULL, NULL);
        } else {
            char* l_false = isel_new_label(isel, "Lcmp_false_tmp");
            char lb_false[64]; snprintf(lb_false, sizeof(lb_false), "%s:", l_false);

            isel_emit(isel, "JC", l_false, NULL, NULL);
            isel_emit(isel, "JZ", l_false, NULL, NULL);
            isel_emit(isel, "SJMP", l_true, NULL, NULL);

            isel_emit(isel, lb_false, NULL, NULL, NULL);
            emit_set_bool_result(isel, ins, dst_reg, size, false);
            isel_emit(isel, "SJMP", l_end, NULL, NULL);

            isel_emit(isel, lb_true, NULL, NULL, NULL);
            emit_set_bool_result(isel, ins, dst_reg, size, true);
            isel_emit(isel, lb_end, NULL, NULL, NULL);

            free(l_false);
        }
    } else {
        if (!unsigned_cmp) {
            emit_signed_cmp16_result(isel, ins, dst_reg, size, lhs, rhs,
                                     is_gt ? SIGNED_CMP_GT : SIGNED_CMP_LT);
            free(l_true); free(l_end);
            if (temp_result) {
                free_temp_reg(isel, dst_reg, size);
            }
            return;
        }

        int rlo_tmp = -1;
        int rhi_tmp = -1;
        char rlo_imm_buf[16], rhi_imm_buf[16];
        const char* rlo;
        const char* rhi;
        if (rhs_is_imm) {
            snprintf(rlo_imm_buf, sizeof(rlo_imm_buf), "#%d", (int)(rhs_imm_val & 0xFF));
            snprintf(rhi_imm_buf, sizeof(rhi_imm_buf), "#%d", (int)((rhs_imm_val >> 8) & 0xFF));
            rlo = rlo_imm_buf;
            rhi = rhi_imm_buf;
        } else {
            rlo = save_acc_operand_for_cmp(isel, get_cmp_lo_reg(isel, rhs, 2), &rlo_tmp);
            rhi = save_acc_operand_for_cmp(isel, get_cmp_hi_reg(isel, rhs, 2), &rhi_tmp);
        }
        const char* llo = get_cmp_lo_reg(isel, lhs, 2);
        const char* lhi = get_cmp_hi_reg(isel, lhs, 2);

        isel_emit(isel, "CLR", "C", NULL, NULL);
        emit_mov(isel, "A", lhi, ins);
        isel_emit(isel, "SUBB", "A", rhi, NULL);

        if (!is_gt) {
            char* l_check_low = isel_new_label(isel, "Lcheck_low");
            char lb_check_low[64]; snprintf(lb_check_low, sizeof(lb_check_low), "%s:", l_check_low);

            isel_emit(isel, "JC", l_true, NULL, NULL);
            isel_emit(isel, "JZ", l_check_low, NULL, NULL);
            emit_set_bool_result(isel, ins, dst_reg, size, false);
            isel_emit(isel, "SJMP", l_end, NULL, NULL);

            isel_emit(isel, lb_check_low, NULL, NULL, NULL);
            isel_emit(isel, "CLR", "C", NULL, NULL);
            emit_mov(isel, "A", llo, NULL);
            isel_emit(isel, "SUBB", "A", rlo, NULL);
            isel_emit(isel, "JC", l_true, NULL, NULL);
            emit_set_bool_result(isel, ins, dst_reg, size, false);
            isel_emit(isel, "SJMP", l_end, NULL, NULL);
            isel_emit(isel, lb_true, NULL, NULL, NULL);
            emit_set_bool_result(isel, ins, dst_reg, size, true);
            isel_emit(isel, lb_end, NULL, NULL, NULL);

            free(l_check_low);
        } else {
            char* l_false = isel_new_label(isel, "Lcmp_false_tmp");
            char lb_false[64]; snprintf(lb_false, sizeof(lb_false), "%s:", l_false);
            char* l_check_low = isel_new_label(isel, "Lcheck_low");
            char lb_check_low[64]; snprintf(lb_check_low, sizeof(lb_check_low), "%s:", l_check_low);

            isel_emit(isel, "JC", l_false, NULL, NULL);
            isel_emit(isel, "JZ", l_check_low, NULL, NULL);
            isel_emit(isel, "SJMP", l_true, NULL, NULL);

            isel_emit(isel, lb_check_low, NULL, NULL, NULL);
            isel_emit(isel, "CLR", "C", NULL, NULL);
            emit_mov(isel, "A", llo, NULL);
            isel_emit(isel, "SUBB", "A", rlo, NULL);
            isel_emit(isel, "JC", l_false, NULL, NULL);
            isel_emit(isel, "JZ", l_false, NULL, NULL);
            isel_emit(isel, "SJMP", l_true, NULL, NULL);

            isel_emit(isel, lb_false, NULL, NULL, NULL);
            emit_set_bool_result(isel, ins, dst_reg, size, false);
            isel_emit(isel, "SJMP", l_end, NULL, NULL);

            isel_emit(isel, lb_true, NULL, NULL, NULL);
            emit_set_bool_result(isel, ins, dst_reg, size, true);
            isel_emit(isel, lb_end, NULL, NULL, NULL);

            free(l_false);
            free(l_check_low);
        }

        free_saved_cmp_operand(isel, rlo_tmp);
        free_saved_cmp_operand(isel, rhi_tmp);
    }

    free(l_true); free(l_end);
    if (temp_result) {
        free_temp_reg(isel, dst_reg, size);
    }
}

void emit_cmp_le_ge(ISelContext* isel, Instr* ins, Instr* next, bool is_ge) {
    ValueName a = get_src1_value(ins);
    ValueName b = get_src2_value(ins);
    ValueName lhs = is_ge ? a : b;
    ValueName rhs = is_ge ? b : a;
    bool unsigned_cmp = is_unsigned_compare(isel, lhs, rhs);

    /* Check if rhs (original b) is encoded as an inline immediate in the instruction.
     * For LE (is_ge=false): lhs=b, rhs=a. If original b is imm, then lhs is imm.
     * For GE (is_ge=true):  lhs=a, rhs=b. If original b is imm, then rhs is imm. */
    int64_t imm_val = 0;
    bool orig_b_is_imm = is_imm_operand(ins, &imm_val)
                         || (b > 0 && try_get_value_const(isel, b, &imm_val));
    /* After lhs/rhs swap: for GE, rhs==b is imm; for LE, lhs==b is imm */
    int64_t rhs_imm_val = is_ge ? imm_val : 0;
    int64_t lhs_imm_val = is_ge ? 0 : imm_val;
    bool rhs_is_imm = is_ge && orig_b_is_imm;
    bool lhs_is_imm = !is_ge && orig_b_is_imm;

    int size = ins && ins->type ? c51_abi_type_size(ins->type) : get_value_size(isel, ins->dest);
    if (size < 1) size = 1;
    int dst_reg = alloc_reg_for_value(isel, ins->dest, size);
    bool temp_result = false;
    if (dst_reg < 0 || dst_reg + size - 1 > 7) {
        dst_reg = alloc_temp_reg(isel, ins ? ins->dest : -1, size);
        temp_result = dst_reg >= 0;
    }
    if (dst_reg < 0) dst_reg = 0;
    int w = ((!lhs_is_imm && get_value_size(isel, lhs) == 2) || (!rhs_is_imm && get_value_size(isel, rhs) == 2)) ? 2 : 1;
    /* If either operand is an immediate >= 256, treat as 16-bit */
    if ((lhs_is_imm && (lhs_imm_val > 0xFF || lhs_imm_val < 0)) ||
        (rhs_is_imm && (rhs_imm_val > 0xFF || rhs_imm_val < 0))) w = 2;

    char* l_true = isel_new_label(isel, "Lcmp_true");
    char* l_end = isel_new_label(isel, "Lcmp_end");
    char lb_true[64], lb_end[64];
    snprintf(lb_true, sizeof(lb_true), "%s:", l_true);
    snprintf(lb_end, sizeof(lb_end), "%s:", l_end);

    if (unsigned_cmp && next && next->op == IROP_BR && next->args && next->args->len > 0) {
        ValueName cond = *(ValueName*)list_get(next->args, 0);
        if (cond == ins->dest) {
            const char* lbl_t = (const char*)list_get(next->labels, 0);
            const char* lbl_f = (const char*)list_get(next->labels, 1);
            int id_t = parse_block_id(lbl_t);
            int id_f = parse_block_id(lbl_f);
            char target_t[32]; char target_f[32];
            block_label_name(target_t, sizeof(target_t), id_t);
            block_label_name(target_f, sizeof(target_f), id_f);

            if (w == 1) {
                char llo_imm_buf[16], rlo_imm_buf[16];
                const char* llo;
                const char* rlo;
                if (lhs_is_imm) {
                    snprintf(llo_imm_buf, sizeof(llo_imm_buf), "#%d", (int)(lhs_imm_val & 0xFF));
                    llo = llo_imm_buf;
                } else {
                    llo = isel_get_lo_reg(isel, lhs);
                }
                if (rhs_is_imm) {
                    snprintf(rlo_imm_buf, sizeof(rlo_imm_buf), "#%d", (int)(rhs_imm_val & 0xFF));
                    rlo = rlo_imm_buf;
                } else {
                    rlo = save_acc_operand_in_b(isel, isel_get_lo_reg(isel, rhs));
                }
                isel_emit(isel, "CLR", "C", NULL, NULL);
                emit_mov(isel, "A", llo, ins);
                isel_emit(isel, "SUBB", "A", rlo, NULL);

                char* ssa = instr_to_ssa_str(ins);
                emit_far_cond_jump1(isel, "JNC", id_t, id_f, ins, ssa);
                free(ssa);

                next->op = IROP_NOP;
                return;
            } else {
                /* 16-bit unsigned GE/LE: must use carry-propagation (lo first, then hi).
                 * CLR C; MOV A,llo; SUBB A,rlo; MOV A,lhi; SUBB A,rhi
                 * After this, JNC = no borrow = lhs >= rhs (for GE),
                 *              JC  = borrow   = lhs <  rhs (for LE). */
                char rlo_imm_buf[16], rhi_imm_buf[16];
                char llo_imm_buf[16], lhi_imm_buf[16];
                const char* rlo;
                const char* rhi;
                const char* llo;
                const char* lhi;
                int rlo_tmp = -1;
                int rhi_tmp = -1;
                if (rhs_is_imm) {
                    snprintf(rlo_imm_buf, sizeof(rlo_imm_buf), "#%d", (int)(rhs_imm_val & 0xFF));
                    snprintf(rhi_imm_buf, sizeof(rhi_imm_buf), "#%d", (int)((rhs_imm_val >> 8) & 0xFF));
                    rlo = rlo_imm_buf;
                    rhi = rhi_imm_buf;
                } else {
                    rlo = save_acc_operand_for_cmp(isel,
                        isel_get_extended_lo_reg(isel, rhs, 2), &rlo_tmp);
                    rhi = save_acc_operand_for_cmp(isel,
                        isel_get_extended_hi_reg(isel, rhs, 2), &rhi_tmp);
                }
                if (lhs_is_imm) {
                    snprintf(llo_imm_buf, sizeof(llo_imm_buf), "#%d", (int)(lhs_imm_val & 0xFF));
                    snprintf(lhi_imm_buf, sizeof(lhi_imm_buf), "#%d", (int)((lhs_imm_val >> 8) & 0xFF));
                    llo = llo_imm_buf;
                    lhi = lhi_imm_buf;
                } else {
                    llo = isel_get_extended_lo_reg(isel, lhs, 2);
                    lhi = isel_get_extended_hi_reg(isel, lhs, 2);
                }

                isel_emit(isel, "CLR", "C", NULL, NULL);
                emit_mov(isel, "A", llo, ins);
                isel_emit(isel, "SUBB", "A", rlo, NULL);
                emit_mov(isel, "A", lhi, NULL);
                isel_emit(isel, "SUBB", "A", rhi, NULL);

                free_saved_cmp_operand(isel, rlo_tmp);
                free_saved_cmp_operand(isel, rhi_tmp);

                if (is_ge) {
                    char* ssa = instr_to_ssa_str(ins);
                    emit_far_cond_jump1(isel, "JNC", id_t, id_f, ins, ssa);
                    free(ssa);
                } else {
                    char* ssa = instr_to_ssa_str(ins);
                    emit_far_cond_jump1(isel, "JC", id_t, id_f, ins, ssa);
                    free(ssa);
                }

                next->op = IROP_NOP;
                return;
            }
        }
    }

    if (!unsigned_cmp && next && next->op == IROP_BR && next->args && next->args->len > 0) {
        ValueName cond = *(ValueName*)list_get(next->args, 0);
        if (cond == ins->dest) {
            int id_t = parse_block_id((const char*)list_get(next->labels, 0));
            int id_f = parse_block_id((const char*)list_get(next->labels, 1));
            /* Check br_invert: LNOT+BR fusion sets invert=true, which swaps id_t/id_f */
            bool br_inv = false;
            if (br_invert_get(isel, next, &br_inv) && br_inv) {
                int tmp = id_t; id_t = id_f; id_f = tmp;
            }
            if (w == 1) {
                emit_signed_cmp8_branch(isel, ins, a, b, is_ge ? SIGNED_CMP_GE : SIGNED_CMP_LE, id_t, id_f);
            } else {
                emit_signed_cmp16_branch(isel, ins, a, b,
                                         is_ge ? SIGNED_CMP_GE : SIGNED_CMP_LE, id_t, id_f);
            }
            next->op = IROP_NOP;
            if (temp_result) free_temp_reg(isel, dst_reg, size);
            return;
        }
    }

    if (w == 1) {
        if (!unsigned_cmp) {
            emit_signed_cmp8_result(isel, ins, dst_reg, size, a, b,
                                    is_ge ? SIGNED_CMP_GE : SIGNED_CMP_LE);
            free(l_true); free(l_end);
            if (temp_result) {
                free_temp_reg(isel, dst_reg, size);
            }
            return;
        }

        {
            char llo_imm_buf[16], rlo_imm_buf[16];
            const char* llo;
            const char* rlo;
            if (lhs_is_imm) {
                snprintf(llo_imm_buf, sizeof(llo_imm_buf), "#%d", (int)(lhs_imm_val & 0xFF));
                llo = llo_imm_buf;
            } else {
                llo = isel_get_lo_reg(isel, lhs);
            }
            if (rhs_is_imm) {
                snprintf(rlo_imm_buf, sizeof(rlo_imm_buf), "#%d", (int)(rhs_imm_val & 0xFF));
                rlo = rlo_imm_buf;
            } else {
                rlo = save_acc_operand_in_b(isel, isel_get_lo_reg(isel, rhs));
            }
            isel_emit(isel, "CLR", "C", NULL, NULL);
            emit_mov(isel, "A", llo, ins);
            isel_emit(isel, "SUBB", "A", rlo, NULL);
        }
    } else {
        if (!unsigned_cmp) {
            emit_signed_cmp16_result(isel, ins, dst_reg, size, a, b,
                                     is_ge ? SIGNED_CMP_GE : SIGNED_CMP_LE);
            free(l_true); free(l_end);
            if (temp_result) {
                free_temp_reg(isel, dst_reg, size);
            }
            return;
        }

        char rlo_imm_buf[16], rhi_imm_buf[16];
        char llo_imm_buf[16], lhi_imm_buf[16];
        const char* rlo;
        const char* rhi;
        const char* llo;
        const char* lhi;
        int rlo_tmp = -1;
        int rhi_tmp = -1;
        if (rhs_is_imm) {
            snprintf(rlo_imm_buf, sizeof(rlo_imm_buf), "#%d", (int)(rhs_imm_val & 0xFF));
            snprintf(rhi_imm_buf, sizeof(rhi_imm_buf), "#%d", (int)((rhs_imm_val >> 8) & 0xFF));
            rlo = rlo_imm_buf;
            rhi = rhi_imm_buf;
        } else {
            rlo = save_acc_operand_for_cmp(isel, isel_get_extended_lo_reg(isel, rhs, 2), &rlo_tmp);
            rhi = save_acc_operand_for_cmp(isel, isel_get_extended_hi_reg(isel, rhs, 2), &rhi_tmp);
        }
        if (lhs_is_imm) {
            snprintf(llo_imm_buf, sizeof(llo_imm_buf), "#%d", (int)(lhs_imm_val & 0xFF));
            snprintf(lhi_imm_buf, sizeof(lhi_imm_buf), "#%d", (int)((lhs_imm_val >> 8) & 0xFF));
            llo = llo_imm_buf;
            lhi = lhi_imm_buf;
        } else {
            llo = isel_get_extended_lo_reg(isel, lhs, 2);
            lhi = isel_get_extended_hi_reg(isel, lhs, 2);
        }
        isel_emit(isel, "CLR", "C", NULL, NULL);
        emit_mov(isel, "A", llo, ins);
        isel_emit(isel, "SUBB", "A", rlo, NULL);
        emit_mov(isel, "A", lhi, NULL);
        isel_emit(isel, "SUBB", "A", rhi, NULL);

        free_saved_cmp_operand(isel, rlo_tmp);
        free_saved_cmp_operand(isel, rhi_tmp);
    }

    isel_emit(isel, "JNC", l_true, NULL, NULL);
    emit_set_bool_result(isel, ins, dst_reg, size, false);
    isel_emit(isel, "SJMP", l_end, NULL, NULL);
    isel_emit(isel, lb_true, NULL, NULL, NULL);
    emit_set_bool_result(isel, ins, dst_reg, size, true);
    isel_emit(isel, lb_end, NULL, NULL, NULL);

    free(l_true); free(l_end);
    if (temp_result) {
        free_temp_reg(isel, dst_reg, size);
    }
}
