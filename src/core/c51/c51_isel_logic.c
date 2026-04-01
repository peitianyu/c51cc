#include "c51_isel_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "c51_isel_regalloc.h"

static const char* save_acc_operand_in_b(ISelContext* isel, const char* operand) {
    if (operand && strcmp(operand, "A") == 0) {
        isel_emit(isel, "MOV", "B", "A", NULL);
        return "B";
    }
    return operand;
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

void emit_bitwise(ISelContext* isel, Instr* ins, Instr* next, const char* op_mnem) {
    ValueName src1 = get_src1_value(ins);
    int size = ins && ins->type ? c51_abi_type_size(ins->type) : get_value_size(isel, ins->dest);
    if (size < 1) size = 1;
    int64_t imm_val;
    bool src2_is_imm = is_imm_operand(ins, &imm_val);
    ValueName src2 = get_src2_value(ins);

    int reg = alloc_dest_reg(isel, ins, next, size, true);
    int phys_reg = reg;
    bool temp_result = false;
    if (phys_reg < 0 || phys_reg + size - 1 > 7) {
        phys_reg = alloc_temp_reg(isel, ins ? ins->dest : -1, size);
        temp_result = phys_reg >= 0;
    }
    if (phys_reg < 0) phys_reg = 0;

    const char* dst_lo = isel_reg_name(phys_reg + (size == 2 ? 1 : 0));
    const char* dst_hi = isel_reg_name(phys_reg);

    int src1_lo_tmp = -1;
    int src1_hi_tmp = -1;
    const char* src1_lo = save_acc_operand_for_cmp(isel, isel_get_lo_reg(isel, src1), &src1_lo_tmp);
    const char* src1_hi = size == 2
        ? save_acc_operand_for_cmp(isel, isel_get_hi_reg(isel, src1), &src1_hi_tmp)
        : NULL;

    if (src2_is_imm) {
        emit_mov(isel, "A", src1_lo, ins);
        char imm_str[16];
        snprintf(imm_str, sizeof(imm_str), "#%d", (int)(imm_val & 0xFF));
        isel_emit(isel, op_mnem, "A", imm_str, NULL);
    } else {
        int src2_lo_tmp = -1;
        const char* src2_lo = save_acc_operand_for_cmp(isel, isel_get_lo_reg(isel, src2), &src2_lo_tmp);
        emit_mov(isel, "A", src1_lo, ins);
        isel_emit(isel, op_mnem, "A", src2_lo, NULL);
        free_saved_cmp_operand(isel, src2_lo_tmp);
    }
    emit_mov(isel, dst_lo, "A", ins);

    if (size == 2) {
        if (src2_is_imm) {
            emit_mov(isel, "A", src1_hi, ins);
            char imm_str[16];
            snprintf(imm_str, sizeof(imm_str), "#%d", (int)((imm_val >> 8) & 0xFF));
            isel_emit(isel, op_mnem, "A", imm_str, NULL);
        } else {
            int src2_hi_tmp = -1;
            const char* src2_hi = save_acc_operand_for_cmp(isel, isel_get_hi_reg(isel, src2), &src2_hi_tmp);
            emit_mov(isel, "A", src1_hi, ins);
            isel_emit(isel, op_mnem, "A", src2_hi, NULL);
            free_saved_cmp_operand(isel, src2_hi_tmp);
        }
        emit_mov(isel, dst_hi, "A", ins);
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
        int src1_lo_tmp = -1;
        int src1_hi_tmp = -1;
        int src2_lo_tmp = -1;
        int src2_hi_tmp = -1;
        const char* src1_lo = save_acc_operand_for_cmp(isel, isel_get_extended_lo_reg(isel, src1, 2), &src1_lo_tmp);
        const char* src1_hi = save_acc_operand_for_cmp(isel, isel_get_extended_hi_reg(isel, src1, 2), &src1_hi_tmp);
        const char* src2_lo = NULL;
        const char* src2_hi = NULL;

        if (!src2_is_imm) {
            src2_lo = save_acc_operand_for_cmp(isel, isel_get_extended_lo_reg(isel, src2, 2), &src2_lo_tmp);
        }

        emit_mov(isel, "A", src1_lo, ins);
        if (src2_is_imm) {
            char imm_str[32];
            snprintf(imm_str, sizeof(imm_str), "#%d, %s", (int)(imm_val & 0xFF), l_true);
            isel_emit(isel, "CJNE", "A", imm_str, NULL);
        } else {
            char arg2[64];
            snprintf(arg2, sizeof(arg2), "%s, %s", src2_lo, l_true);
            isel_emit(isel, "CJNE", "A", arg2, NULL);
        }

        if (!src2_is_imm) {
            src2_hi = save_acc_operand_for_cmp(isel, isel_get_extended_hi_reg(isel, src2, 2), &src2_hi_tmp);
        }
        emit_mov(isel, "A", src1_hi, NULL);
        if (src2_is_imm) {
            char imm_str[32];
            snprintf(imm_str, sizeof(imm_str), "#%d, %s", (int)((imm_val >> 8) & 0xFF), l_true);
            isel_emit(isel, "CJNE", "A", imm_str, NULL);
        } else {
            char arg2[64];
            snprintf(arg2, sizeof(arg2), "%s, %s", src2_hi, l_true);
            isel_emit(isel, "CJNE", "A", arg2, NULL);
        }
        free_saved_cmp_operand(isel, src1_lo_tmp);
        free_saved_cmp_operand(isel, src1_hi_tmp);
        free_saved_cmp_operand(isel, src2_lo_tmp);
        free_saved_cmp_operand(isel, src2_hi_tmp);
    } else {
        int src1_lo_tmp = -1;
        int src2_lo_tmp = -1;
        const char* src1_lo = save_acc_operand_for_cmp(isel, isel_get_lo_reg(isel, src1), &src1_lo_tmp);
        const char* src2_lo = NULL;
        if (!src2_is_imm) {
            src2_lo = save_acc_operand_for_cmp(isel, isel_get_lo_reg(isel, src2), &src2_lo_tmp);
        }
        emit_mov(isel, "A", src1_lo, ins);
        if (src2_is_imm) {
            char imm_str[32];
            snprintf(imm_str, sizeof(imm_str), "#%d, %s", (int)(imm_val & 0xFF), l_true);
            isel_emit(isel, "CJNE", "A", imm_str, NULL);
        } else {
            char arg2[64];
            snprintf(arg2, sizeof(arg2), "%s, %s", src2_lo, l_true);
            isel_emit(isel, "CJNE", "A", arg2, NULL);
        }
        free_saved_cmp_operand(isel, src1_lo_tmp);
        free_saved_cmp_operand(isel, src2_lo_tmp);
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
    int size = ins && ins->type ? c51_abi_type_size(ins->type) : get_value_size(isel, ins->dest);
    int src_size = get_value_size(isel, src);
    if (size < 1) size = 1;
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

    char* l_true = isel_new_label(isel, "Leq_true");
    char* l_false = isel_new_label(isel, "Leq_false");
    char* l_end = isel_new_label(isel, "Leq_end");
    char lb_true[64], lb_false[64], lb_end[64];
    snprintf(lb_true, sizeof(lb_true), "%s:", l_true);
    snprintf(lb_false, sizeof(lb_false), "%s:", l_false);
    snprintf(lb_end, sizeof(lb_end), "%s:", l_end);

    const char* s2_lo = save_acc_operand_in_b(isel, isel_get_extended_lo_reg(isel, src2, 2));
    const char* s1_lo = isel_get_extended_lo_reg(isel, src1, 2);
    emit_mov(isel, "A", s1_lo, ins);
    {
        char arg2[64];
        snprintf(arg2, sizeof(arg2), "%s, %s", s2_lo, l_false);
        isel_emit(isel, "CJNE", "A", arg2, NULL);
    }

    if (get_value_size(isel, src1) == 2 || get_value_size(isel, src2) == 2) {
        const char* s2_hi = save_acc_operand_in_b(isel, isel_get_extended_hi_reg(isel, src2, 2));
        const char* s1_hi = isel_get_extended_hi_reg(isel, src1, 2);
        emit_mov(isel, "A", s1_hi, NULL);
        {
            char arg2[64];
            snprintf(arg2, sizeof(arg2), "%s, %s", s2_hi, l_false);
            isel_emit(isel, "CJNE", "A", arg2, NULL);
        }
    }

    isel_emit(isel, "SJMP", l_true, NULL, NULL);
    isel_emit(isel, lb_false, NULL, NULL, NULL);
    emit_set_bool_result(isel, ins, dst_reg, size, false);
    isel_emit(isel, "SJMP", l_end, NULL, NULL);
    isel_emit(isel, lb_true, NULL, NULL, NULL);
    emit_set_bool_result(isel, ins, dst_reg, size, true);
    isel_emit(isel, lb_end, NULL, NULL, NULL);

    free(l_true); free(l_false); free(l_end);
    if (temp_result) {
        free_temp_reg(isel, dst_reg, size);
    }
}

void emit_signed_cmp8_result(ISelContext* isel, Instr* ins, int dst_reg, int size, ValueName lhs, ValueName rhs, int cmp_type) {
    bool temp_result = false;
    if (dst_reg < 0 || dst_reg + size - 1 > 7) {
        dst_reg = alloc_temp_reg(isel, ins ? ins->dest : -1, size);
        temp_result = dst_reg >= 0;
    }
    if (dst_reg < 0) dst_reg = 0;

    char* l_true = isel_new_label(isel, "Lscmp_true");
    char* l_false = isel_new_label(isel, "Lscmp_false");
    char* l_same = isel_new_label(isel, "Lscmp_same");
    char* l_end = isel_new_label(isel, "Lscmp_end");
    char lb_true[64], lb_false[64], lb_same[64], lb_end[64];
    snprintf(lb_true, sizeof(lb_true), "%s:", l_true);
    snprintf(lb_false, sizeof(lb_false), "%s:", l_false);
    snprintf(lb_same, sizeof(lb_same), "%s:", l_same);
    snprintf(lb_end, sizeof(lb_end), "%s:", l_end);

    const char* llo = isel_get_lo_reg(isel, lhs);
    const char* rlo = save_acc_operand_in_b(isel, isel_get_lo_reg(isel, rhs));

    emit_mov(isel, "A", llo, ins);
    isel_emit(isel, "XRL", "A", rlo, NULL);
    isel_emit(isel, "ANL", "A", "#128", NULL);
    isel_emit(isel, "JZ", l_same, NULL, NULL);

    emit_mov(isel, "A", llo, NULL);
    isel_emit(isel, "ANL", "A", "#128", NULL);
    switch (cmp_type) {
        case SIGNED_CMP_LT:
        case SIGNED_CMP_LE:
            isel_emit(isel, "JNZ", l_true, NULL, NULL);
            isel_emit(isel, "SJMP", l_false, NULL, NULL);
            break;
        case SIGNED_CMP_GT:
        case SIGNED_CMP_GE:
            isel_emit(isel, "JZ", l_true, NULL, NULL);
            isel_emit(isel, "SJMP", l_false, NULL, NULL);
            break;
    }

    isel_emit(isel, lb_same, NULL, NULL, NULL);
    isel_emit(isel, "CLR", "C", NULL, NULL);
    emit_mov(isel, "A", llo, NULL);
    isel_emit(isel, "SUBB", "A", rlo, NULL);
    switch (cmp_type) {
        case SIGNED_CMP_LT:
            isel_emit(isel, "JC", l_true, NULL, NULL);
            isel_emit(isel, "SJMP", l_false, NULL, NULL);
            break;
        case SIGNED_CMP_GT:
            isel_emit(isel, "JC", l_false, NULL, NULL);
            isel_emit(isel, "JZ", l_false, NULL, NULL);
            isel_emit(isel, "SJMP", l_true, NULL, NULL);
            break;
        case SIGNED_CMP_LE:
            isel_emit(isel, "JC", l_true, NULL, NULL);
            isel_emit(isel, "JZ", l_true, NULL, NULL);
            isel_emit(isel, "SJMP", l_false, NULL, NULL);
            break;
        case SIGNED_CMP_GE:
            isel_emit(isel, "JC", l_false, NULL, NULL);
            isel_emit(isel, "SJMP", l_true, NULL, NULL);
            break;
    }

    isel_emit(isel, lb_false, NULL, NULL, NULL);
    emit_set_bool_result(isel, ins, dst_reg, size, false);
    isel_emit(isel, "SJMP", l_end, NULL, NULL);
    isel_emit(isel, lb_true, NULL, NULL, NULL);
    emit_set_bool_result(isel, ins, dst_reg, size, true);
    isel_emit(isel, lb_end, NULL, NULL, NULL);

    free(l_true);
    free(l_false);
    free(l_same);
    free(l_end);
    if (temp_result) {
        free_temp_reg(isel, dst_reg, size);
    }
}

static void emit_signed_cmp16_result(ISelContext* isel, Instr* ins, int dst_reg, int size,
                                     ValueName lhs, ValueName rhs, bool is_gt) {
    bool temp_result = false;
    if (dst_reg < 0 || dst_reg + size - 1 > 7) {
        dst_reg = alloc_temp_reg(isel, ins ? ins->dest : -1, size);
        temp_result = dst_reg >= 0;
    }
    if (dst_reg < 0) dst_reg = 0;

    const char* lhi = get_cmp_hi_reg(isel, lhs, 2);
    const char* llo = get_cmp_lo_reg(isel, lhs, 2);
    int rhi_tmp = -1;
    int rlo_tmp = -1;
    const char* rhi = save_acc_operand_for_cmp(isel, get_cmp_hi_reg(isel, rhs, 2), &rhi_tmp);
    const char* rlo = save_acc_operand_for_cmp(isel, get_cmp_lo_reg(isel, rhs, 2), &rlo_tmp);

    char* l_true = isel_new_label(isel, "Lscmp16_true");
    char* l_false = isel_new_label(isel, "Lscmp16_false");
    char* l_same = isel_new_label(isel, "Lscmp16_same");
    char* l_check_low = isel_new_label(isel, "Lscmp16_low");
    char* l_end = isel_new_label(isel, "Lscmp16_end");
    char lb_true[64], lb_false[64], lb_same[64], lb_check_low[64], lb_end[64];
    snprintf(lb_true, sizeof(lb_true), "%s:", l_true);
    snprintf(lb_false, sizeof(lb_false), "%s:", l_false);
    snprintf(lb_same, sizeof(lb_same), "%s:", l_same);
    snprintf(lb_check_low, sizeof(lb_check_low), "%s:", l_check_low);
    snprintf(lb_end, sizeof(lb_end), "%s:", l_end);

    emit_mov(isel, "A", lhi, ins);
    isel_emit(isel, "XRL", "A", rhi, NULL);
    isel_emit(isel, "ANL", "A", "#128", NULL);
    isel_emit(isel, "JZ", l_same, NULL, NULL);

    emit_mov(isel, "A", lhi, NULL);
    isel_emit(isel, "ANL", "A", "#128", NULL);
    if (is_gt) {
        isel_emit(isel, "JZ", l_true, NULL, NULL);
        isel_emit(isel, "SJMP", l_false, NULL, NULL);
    } else {
        isel_emit(isel, "JZ", l_false, NULL, NULL);
        isel_emit(isel, "SJMP", l_true, NULL, NULL);
    }

    isel_emit(isel, lb_same, NULL, NULL, NULL);
    isel_emit(isel, "CLR", "C", NULL, NULL);
    emit_mov(isel, "A", lhi, NULL);
    isel_emit(isel, "SUBB", "A", rhi, NULL);
    if (is_gt) {
        isel_emit(isel, "JC", l_false, NULL, NULL);
        isel_emit(isel, "JZ", l_check_low, NULL, NULL);
        isel_emit(isel, "SJMP", l_true, NULL, NULL);
    } else {
        isel_emit(isel, "JC", l_true, NULL, NULL);
        isel_emit(isel, "JZ", l_check_low, NULL, NULL);
        isel_emit(isel, "SJMP", l_false, NULL, NULL);
    }

    isel_emit(isel, lb_check_low, NULL, NULL, NULL);
    isel_emit(isel, "CLR", "C", NULL, NULL);
    emit_mov(isel, "A", llo, NULL);
    isel_emit(isel, "SUBB", "A", rlo, NULL);
    if (is_gt) {
        isel_emit(isel, "JC", l_false, NULL, NULL);
        isel_emit(isel, "JZ", l_false, NULL, NULL);
        isel_emit(isel, "SJMP", l_true, NULL, NULL);
    } else {
        isel_emit(isel, "JC", l_true, NULL, NULL);
        isel_emit(isel, "SJMP", l_false, NULL, NULL);
    }

    isel_emit(isel, lb_false, NULL, NULL, NULL);
    emit_set_bool_result(isel, ins, dst_reg, size, false);
    isel_emit(isel, "SJMP", l_end, NULL, NULL);
    isel_emit(isel, lb_true, NULL, NULL, NULL);
    emit_set_bool_result(isel, ins, dst_reg, size, true);
    isel_emit(isel, lb_end, NULL, NULL, NULL);

    free(l_true);
    free(l_false);
    free(l_same);
    free(l_check_low);
    free(l_end);
    free_saved_cmp_operand(isel, rhi_tmp);
    free_saved_cmp_operand(isel, rlo_tmp);
    if (temp_result) {
        free_temp_reg(isel, dst_reg, size);
    }
}

static void emit_signed_cmp8_branch(ISelContext* isel, Instr* ins, ValueName lhs, ValueName rhs,
                                    int cmp_type, int true_id, int false_id) {
    char target_t[32], target_f[32];
    block_label_name(target_t, sizeof(target_t), true_id);
    block_label_name(target_f, sizeof(target_f), false_id);

    char* l_same = isel_new_label(isel, "Lscmp_same_tmp");
    char lb_same[64];
    snprintf(lb_same, sizeof(lb_same), "%s:", l_same);

    const char* llo = isel_get_lo_reg(isel, lhs);
    const char* rlo = save_acc_operand_in_b(isel, isel_get_lo_reg(isel, rhs));

    emit_mov(isel, "A", llo, ins);
    isel_emit(isel, "XRL", "A", rlo, NULL);
    isel_emit(isel, "ANL", "A", "#128", NULL);
    isel_emit(isel, "JZ", l_same, NULL, NULL);

    emit_mov(isel, "A", llo, NULL);
    isel_emit(isel, "ANL", "A", "#128", NULL);
    switch (cmp_type) {
        case SIGNED_CMP_LT:
        case SIGNED_CMP_LE:
            {
                char* ssa = instr_to_ssa_str(ins);
                emit_far_cond_jump1(isel, "JNZ", true_id, false_id, ins, ssa);
                free(ssa);
            }
            break;
        case SIGNED_CMP_GT:
        case SIGNED_CMP_GE:
            {
                char* ssa = instr_to_ssa_str(ins);
                emit_far_cond_jump1(isel, "JZ", true_id, false_id, ins, ssa);
                free(ssa);
            }
            break;
    }

    isel_emit_label(isel, l_same);
    isel_emit(isel, "CLR", "C", NULL, NULL);
    emit_mov(isel, "A", llo, NULL);
    isel_emit(isel, "SUBB", "A", rlo, NULL);
    switch (cmp_type) {
        case SIGNED_CMP_LT:
            emit_far_cond_jump1(isel, "JC", true_id, false_id, ins, NULL);
            break;
        case SIGNED_CMP_GT:
            emit_far_cond_jump2_same(isel, "JC", "JZ", false_id, true_id, ins, NULL);
            break;
        case SIGNED_CMP_LE:
            emit_far_cond_jump2_same(isel, "JC", "JZ", true_id, false_id, ins, NULL);
            break;
        case SIGNED_CMP_GE:
            emit_far_cond_jump1(isel, "JC", false_id, true_id, ins, NULL);
            break;
    }

    free(l_same);
}

static void emit_signed_cmp16_branch(ISelContext* isel, Instr* ins, ValueName lhs, ValueName rhs,
                                     bool is_gt, int true_id, int false_id) {
    char target_t[32], target_f[32];
    block_label_name(target_t, sizeof(target_t), true_id);
    block_label_name(target_f, sizeof(target_f), false_id);

    const char* lhi = get_cmp_hi_reg(isel, lhs, 2);
    const char* llo = get_cmp_lo_reg(isel, lhs, 2);
    int rhi_tmp = -1;
    int rlo_tmp = -1;
    const char* rhi = save_acc_operand_for_cmp(isel, get_cmp_hi_reg(isel, rhs, 2), &rhi_tmp);
    const char* rlo = save_acc_operand_for_cmp(isel, get_cmp_lo_reg(isel, rhs, 2), &rlo_tmp);

    char* l_same = isel_new_label(isel, "Lscmp16_same_tmp");
    char* l_check_low = isel_new_label(isel, "Lscmp16_low_tmp");
    char lb_same[64], lb_check_low[64];
    snprintf(lb_same, sizeof(lb_same), "%s:", l_same);
    snprintf(lb_check_low, sizeof(lb_check_low), "%s:", l_check_low);

    emit_mov(isel, "A", lhi, ins);
    isel_emit(isel, "XRL", "A", rhi, NULL);
    isel_emit(isel, "ANL", "A", "#128", NULL);
    isel_emit(isel, "JZ", l_same, NULL, NULL);

    emit_mov(isel, "A", lhi, NULL);
    isel_emit(isel, "ANL", "A", "#128", NULL);
    if (is_gt) {
        {
            char* ssa = instr_to_ssa_str(ins);
            emit_far_cond_jump1(isel, "JZ", true_id, false_id, ins, ssa);
            free(ssa);
        }
    } else {
        {
            char* ssa = instr_to_ssa_str(ins);
            emit_far_cond_jump1(isel, "JZ", false_id, true_id, ins, ssa);
            free(ssa);
        }
    }

    isel_emit_label(isel, l_same);
    isel_emit(isel, "CLR", "C", NULL, NULL);
    emit_mov(isel, "A", lhi, NULL);
    isel_emit(isel, "SUBB", "A", rhi, NULL);
    if (is_gt) {
        char* l_false = isel_new_label(isel, "Lcmp_far_false");
        isel_emit(isel, "JC", l_false, NULL, NULL);
        isel_emit(isel, "JZ", l_check_low, NULL, NULL);
        emit_phi_copies_for_edge(isel, isel->current_block_id, true_id, ins);
        isel_emit(isel, "LJMP", target_t, NULL, NULL);
        isel_emit_label(isel, l_false);
        emit_phi_copies_for_edge(isel, isel->current_block_id, false_id, ins);
        isel_emit(isel, "LJMP", target_f, NULL, NULL);
        free(l_false);
    } else {
        char* l_true = isel_new_label(isel, "Lcmp_far_true");
        isel_emit(isel, "JC", l_true, NULL, NULL);
        isel_emit(isel, "JZ", l_check_low, NULL, NULL);
        emit_phi_copies_for_edge(isel, isel->current_block_id, false_id, ins);
        isel_emit(isel, "LJMP", target_f, NULL, NULL);
        isel_emit_label(isel, l_true);
        emit_phi_copies_for_edge(isel, isel->current_block_id, true_id, ins);
        isel_emit(isel, "LJMP", target_t, NULL, NULL);
        free(l_true);
    }

    isel_emit_label(isel, l_check_low);
    isel_emit(isel, "CLR", "C", NULL, NULL);
    emit_mov(isel, "A", llo, NULL);
    isel_emit(isel, "SUBB", "A", rlo, NULL);
    if (is_gt) {
        emit_far_cond_jump2_same(isel, "JC", "JZ", false_id, true_id, ins, NULL);
    } else {
        emit_far_cond_jump1(isel, "JC", true_id, false_id, ins, NULL);
    }

    free_saved_cmp_operand(isel, rhi_tmp);
    free_saved_cmp_operand(isel, rlo_tmp);
    free(l_same);
    free(l_check_low);
}

bool is_unsigned_compare(ISelContext* isel, ValueName a, ValueName b) {
    /* heuristic—assume unsigned compare for now if types indicate so; fallback false */
    (void)isel; (void)a; (void)b;
    return false;
}

void emit_cmp_lt_gt(ISelContext* isel, Instr* ins, Instr* next, bool is_gt) {
    ValueName a = get_src1_value(ins);
    ValueName b = get_src2_value(ins);
    ValueName lhs = a;
    ValueName rhs = b;
    bool unsigned_cmp = is_unsigned_compare(isel, lhs, rhs);

    int size = ins && ins->type ? c51_abi_type_size(ins->type) : get_value_size(isel, ins->dest);
    if (size < 1) size = 1;
    int dst_reg = alloc_reg_for_value(isel, ins->dest, size);
    bool temp_result = false;
    if (dst_reg < 0 || dst_reg + size - 1 > 7) {
        dst_reg = alloc_temp_reg(isel, ins ? ins->dest : -1, size);
        temp_result = dst_reg >= 0;
    }
    if (dst_reg < 0) dst_reg = 0;
    int w = (get_value_size(isel, lhs) == 2 || get_value_size(isel, rhs) == 2) ? 2 : 1;

    if (!unsigned_cmp && next && next->op == IROP_BR && next->args && next->args->len > 0) {
        ValueName cond = *(ValueName*)list_get(next->args, 0);
        if (cond == ins->dest) {
            int id_t = parse_block_id((const char*)list_get(next->labels, 0));
            int id_f = parse_block_id((const char*)list_get(next->labels, 1));
            if (w == 1) {
                emit_signed_cmp8_branch(isel, ins, lhs, rhs, is_gt ? SIGNED_CMP_GT : SIGNED_CMP_LT, id_t, id_f);
            } else {
                emit_signed_cmp16_branch(isel, ins, lhs, rhs, is_gt, id_t, id_f);
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
                    char target_t[32]; char target_f[32];
                    block_label_name(target_t, sizeof(target_t), id_t);
                    block_label_name(target_f, sizeof(target_f), id_f);

                    if (w == 1) {
                        const char* llo = isel_get_lo_reg(isel, lhs);
                        const char* rlo = save_acc_operand_in_b(isel, isel_get_lo_reg(isel, rhs));
                        char* l_same = isel_new_label(isel, "Lscmp_same_tmp");

                        emit_mov(isel, "A", llo, ins);
                        isel_emit(isel, "XRL", "A", rlo, NULL);
                        isel_emit(isel, "ANL", "A", "#128", NULL);
                        isel_emit(isel, "JZ", l_same, NULL, NULL);

                        emit_mov(isel, "A", llo, NULL);
                        isel_emit(isel, "ANL", "A", "#128", NULL);
                        if (!is_gt) {
                            emit_phi_copies_for_edge(isel, isel->current_block_id, id_t, ins);
                            isel_emit(isel, "JNZ", target_t, NULL, instr_to_ssa_str(ins));
                            emit_phi_copies_for_edge(isel, isel->current_block_id, id_f, ins);
                            isel_emit(isel, "LJMP", target_f, NULL, NULL);
                        } else {
                            emit_phi_copies_for_edge(isel, isel->current_block_id, id_f, ins);
                            isel_emit(isel, "JZ", target_t, NULL, instr_to_ssa_str(ins));
                            emit_phi_copies_for_edge(isel, isel->current_block_id, id_f, ins);
                            isel_emit(isel, "LJMP", target_f, NULL, NULL);
                        }

                        isel_emit(isel, l_same, NULL, NULL, NULL);
                        isel_emit(isel, "CLR", "C", NULL, NULL);
                        emit_mov(isel, "A", llo, NULL);
                        isel_emit(isel, "SUBB", "A", rlo, NULL);

                        if (!is_gt) {
                            emit_phi_copies_for_edge(isel, isel->current_block_id, id_t, ins);
                            isel_emit(isel, "JC", target_t, NULL, NULL);
                            emit_phi_copies_for_edge(isel, isel->current_block_id, id_f, ins);
                            isel_emit(isel, "LJMP", target_f, NULL, NULL);
                        } else {
                            emit_phi_copies_for_edge(isel, isel->current_block_id, id_f, ins);
                            isel_emit(isel, "JC", target_f, NULL, NULL);
                            isel_emit(isel, "JZ", target_f, NULL, NULL);
                            emit_phi_copies_for_edge(isel, isel->current_block_id, id_t, ins);
                            isel_emit(isel, "LJMP", target_t, NULL, NULL);
                        }

                        free(l_same);
                        next->op = IROP_NOP;
                        return;
                    } else {
                        const char* lhi = get_cmp_hi_reg(isel, lhs, 2);
                        const char* llo = get_cmp_lo_reg(isel, lhs, 2);
                        int rhi_tmp = -1;
                        int rlo_tmp = -1;
                        const char* rhi = save_acc_operand_for_cmp(isel, get_cmp_hi_reg(isel, rhs, 2), &rhi_tmp);
                        const char* rlo = save_acc_operand_for_cmp(isel, get_cmp_lo_reg(isel, rhs, 2), &rlo_tmp);
                        char* l_same = isel_new_label(isel, "Lscmp16_same_tmp");
                        char* l_check_low = isel_new_label(isel, "Lscmp16_low_tmp");

                        emit_mov(isel, "A", lhi, ins);
                        isel_emit(isel, "XRL", "A", rhi, NULL);
                        isel_emit(isel, "ANL", "A", "#128", NULL);
                        isel_emit(isel, "JZ", l_same, NULL, NULL);

                        emit_mov(isel, "A", lhi, NULL);
                        isel_emit(isel, "ANL", "A", "#128", NULL);
                        if (is_gt) {
                            emit_phi_copies_for_edge(isel, isel->current_block_id, id_t, ins);
                            isel_emit(isel, "JZ", target_t, NULL, instr_to_ssa_str(ins));
                            emit_phi_copies_for_edge(isel, isel->current_block_id, id_f, ins);
                            isel_emit(isel, "SJMP", target_f, NULL, NULL);
                        } else {
                            emit_phi_copies_for_edge(isel, isel->current_block_id, id_f, ins);
                            isel_emit(isel, "JZ", target_f, NULL, instr_to_ssa_str(ins));
                            emit_phi_copies_for_edge(isel, isel->current_block_id, id_t, ins);
                            isel_emit(isel, "LJMP", target_t, NULL, NULL);
                        }

                        isel_emit(isel, l_same, NULL, NULL, NULL);
                        isel_emit(isel, "CLR", "C", NULL, NULL);
                        emit_mov(isel, "A", lhi, NULL);
                        isel_emit(isel, "SUBB", "A", rhi, NULL);
                        if (is_gt) {
                            emit_phi_copies_for_edge(isel, isel->current_block_id, id_f, ins);
                            isel_emit(isel, "JC", target_f, NULL, NULL);
                            isel_emit(isel, "JZ", l_check_low, NULL, NULL);
                            emit_phi_copies_for_edge(isel, isel->current_block_id, id_t, ins);
                            isel_emit(isel, "SJMP", target_t, NULL, NULL);
                        } else {
                            emit_phi_copies_for_edge(isel, isel->current_block_id, id_t, ins);
                            isel_emit(isel, "JC", target_t, NULL, NULL);
                            isel_emit(isel, "JZ", l_check_low, NULL, NULL);
                            emit_phi_copies_for_edge(isel, isel->current_block_id, id_f, ins);
                            isel_emit(isel, "LJMP", target_f, NULL, NULL);
                        }

                        isel_emit(isel, l_check_low, NULL, NULL, NULL);
                        isel_emit(isel, "CLR", "C", NULL, NULL);
                        emit_mov(isel, "A", llo, NULL);
                        isel_emit(isel, "SUBB", "A", rlo, NULL);
                        if (is_gt) {
                            emit_phi_copies_for_edge(isel, isel->current_block_id, id_f, ins);
                            isel_emit(isel, "JC", target_f, NULL, NULL);
                            isel_emit(isel, "JZ", target_f, NULL, NULL);
                            emit_phi_copies_for_edge(isel, isel->current_block_id, id_t, ins);
                            isel_emit(isel, "SJMP", target_t, NULL, NULL);
                        } else {
                            emit_phi_copies_for_edge(isel, isel->current_block_id, id_t, ins);
                            isel_emit(isel, "JC", target_t, NULL, NULL);
                            emit_phi_copies_for_edge(isel, isel->current_block_id, id_f, ins);
                            isel_emit(isel, "SJMP", target_f, NULL, NULL);
                        }

                        free(l_same);
                        free(l_check_low);
                        free_saved_cmp_operand(isel, rhi_tmp);
                        free_saved_cmp_operand(isel, rlo_tmp);
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
                const char* llo = isel_get_lo_reg(isel, lhs);
                const char* rlo = save_acc_operand_in_b(isel, isel_get_lo_reg(isel, rhs));
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

        const char* rlo = save_acc_operand_in_b(isel, isel_get_lo_reg(isel, rhs));
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
            emit_signed_cmp16_result(isel, ins, dst_reg, size, lhs, rhs, is_gt);
            free(l_true); free(l_end);
            if (temp_result) {
                free_temp_reg(isel, dst_reg, size);
            }
            return;
        }

        int rlo_tmp = -1;
        int rhi_tmp = -1;
        const char* rlo = save_acc_operand_for_cmp(isel, get_cmp_lo_reg(isel, rhs, 2), &rlo_tmp);
        const char* rhi = save_acc_operand_for_cmp(isel, get_cmp_hi_reg(isel, rhs, 2), &rhi_tmp);
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

    int size = ins && ins->type ? c51_abi_type_size(ins->type) : get_value_size(isel, ins->dest);
    if (size < 1) size = 1;
    int dst_reg = alloc_reg_for_value(isel, ins->dest, size);
    bool temp_result = false;
    if (dst_reg < 0 || dst_reg + size - 1 > 7) {
        dst_reg = alloc_temp_reg(isel, ins ? ins->dest : -1, size);
        temp_result = dst_reg >= 0;
    }
    if (dst_reg < 0) dst_reg = 0;
    int w = (get_value_size(isel, lhs) == 2 || get_value_size(isel, rhs) == 2) ? 2 : 1;

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
                const char* llo = isel_get_lo_reg(isel, lhs);
                const char* rlo = save_acc_operand_in_b(isel, isel_get_lo_reg(isel, rhs));
                isel_emit(isel, "CLR", "C", NULL, NULL);
                emit_mov(isel, "A", llo, ins);
                isel_emit(isel, "SUBB", "A", rlo, NULL);

                char* ssa = instr_to_ssa_str(ins);
                emit_far_cond_jump1(isel, "JNC", id_t, id_f, ins, ssa);
                free(ssa);

                next->op = IROP_NOP;
                return;
            } else {
                const char* rhi = save_acc_operand_in_b(isel, isel_get_extended_hi_reg(isel, rhs, 2));
                const char* lhi = isel_get_extended_hi_reg(isel, lhs, 2);

                isel_emit(isel, "CLR", "C", NULL, NULL);
                emit_mov(isel, "A", lhi, ins);
                isel_emit(isel, "SUBB", "A", rhi, NULL);

                if (is_ge) {
                    char* l_true = isel_new_label(isel, "Lcmp_far_true");
                    char* l_false = isel_new_label(isel, "Lcmp_far_false");
                    char* ssa = instr_to_ssa_str(ins);
                    isel_emit(isel, "JNC", l_true, NULL, ssa);
                    free(ssa);
                    isel_emit(isel, "JZ", l_false, NULL, NULL);
                    emit_phi_copies_for_edge(isel, isel->current_block_id, id_t, ins);
                    isel_emit(isel, "LJMP", target_t, NULL, NULL);
                    isel_emit_label(isel, l_false);
                    emit_phi_copies_for_edge(isel, isel->current_block_id, id_f, ins);
                    isel_emit(isel, "LJMP", target_f, NULL, NULL);
                    isel_emit_label(isel, l_true);
                    emit_phi_copies_for_edge(isel, isel->current_block_id, id_t, ins);
                    isel_emit(isel, "LJMP", target_t, NULL, NULL);
                    free(l_true);
                    free(l_false);
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
            if (w == 1) {
                emit_signed_cmp8_branch(isel, ins, a, b, is_ge ? SIGNED_CMP_GE : SIGNED_CMP_LE, id_t, id_f);
            } else {
                emit_signed_cmp16_branch(isel, ins, lhs, rhs, is_ge, id_t, id_f);
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

        const char* rlo = save_acc_operand_in_b(isel, isel_get_lo_reg(isel, rhs));
        const char* llo = isel_get_lo_reg(isel, lhs);
        isel_emit(isel, "CLR", "C", NULL, NULL);
        emit_mov(isel, "A", llo, ins);
        isel_emit(isel, "SUBB", "A", rlo, NULL);
    } else {
        int rlo_tmp = -1;
        int rhi_tmp = -1;
        const char* rlo = save_acc_operand_for_cmp(isel, isel_get_extended_lo_reg(isel, rhs, 2), &rlo_tmp);
        const char* rhi = save_acc_operand_for_cmp(isel, isel_get_extended_hi_reg(isel, rhs, 2), &rhi_tmp);
        const char* llo = isel_get_extended_lo_reg(isel, lhs, 2);
        const char* lhi = isel_get_extended_hi_reg(isel, lhs, 2);
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
