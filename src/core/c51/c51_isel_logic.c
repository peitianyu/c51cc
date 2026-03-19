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

void emit_bitwise(ISelContext* isel, Instr* ins, Instr* next, const char* op_mnem) {
    ValueName src1 = get_src1_value(ins);
    int size = ins->type ? ins->type->size : 1;
    int64_t imm_val;
    bool src2_is_imm = is_imm_operand(ins, &imm_val);
    ValueName src2 = get_src2_value(ins);

    int reg = alloc_dest_reg(isel, ins, next, size, true);
    const char* dst_lo = isel_reg_name(reg + (size == 2 ? 1 : 0));
    const char* dst_hi = isel_reg_name(reg);

    const char* src1_lo = isel_get_lo_reg(isel, src1);
    const char* src1_hi = isel_get_hi_reg(isel, src1);

    emit_mov(isel, "A", src1_lo, ins);
    if (src2_is_imm) {
        char imm_str[16];
        snprintf(imm_str, sizeof(imm_str), "#%d", (int)(imm_val & 0xFF));
        isel_emit(isel, op_mnem, "A", imm_str, NULL);
    } else {
        const char* src2_lo = save_acc_operand_in_b(isel, isel_get_lo_reg(isel, src2));
        isel_emit(isel, op_mnem, "A", src2_lo, NULL);
    }
    emit_mov(isel, dst_lo, "A", ins);

    if (size == 2) {
        emit_mov(isel, "A", src1_hi, ins);
        if (src2_is_imm) {
            char imm_str[16];
            snprintf(imm_str, sizeof(imm_str), "#%d", (int)((imm_val >> 8) & 0xFF));
            isel_emit(isel, op_mnem, "A", imm_str, NULL);
        } else {
            const char* src2_hi = save_acc_operand_in_b(isel, isel_get_hi_reg(isel, src2));
            isel_emit(isel, op_mnem, "A", src2_hi, NULL);
        }
        emit_mov(isel, dst_hi, "A", ins);
    }

    emit_store_spilled_result(isel, ins->dest, reg, size, ins);
}

void emit_not(ISelContext* isel, Instr* ins, Instr* next) {
    ValueName src1 = get_src1_value(ins);
    int src_size = get_value_size(isel, src1);
    int dst_size = ins->type ? ins->type->size : 1;

    int reg = safe_alloc_reg_for_value(isel, ins->dest, dst_size);
    int try_reg = try_bind_result_to_phi_target(isel, ins, next, dst_size);
    if (try_reg >= 0 && try_reg + dst_size - 1 < 8) {
        reg = try_reg;
    }

    const char* dst_lo = NULL;
    const char* dst_hi = NULL;
    if (reg >= 0) {
        dst_lo = isel_reg_name(reg + (dst_size == 2 ? 1 : 0));
        dst_hi = isel_reg_name(reg);
    } else if (reg == -2) {
        dst_lo = "A";
        dst_hi = NULL;
    }

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

    emit_store_spilled_result(isel, ins->dest, reg, dst_size, ins);
}

void emit_ne(ISelContext* isel, Instr* ins, Instr* next) {
    ValueName src1 = get_src1_value(ins);
    int size = ins->type ? ins->type->size : 1;
    int64_t imm_val;
    bool src2_is_imm = is_imm_operand(ins, &imm_val);
    ValueName src2 = get_src2_value(ins);

    int reg = alloc_reg_for_value(isel, ins->dest, size);
    const char* dst_lo = isel_reg_name(reg + (size == 2 ? 1 : 0));
    const char* dst_hi = isel_reg_name(reg);

    char* l_true = isel_new_label(isel, "Lne_true");
    char* l_end = isel_new_label(isel, "Lne_end");
    char lbuf_true[64];
    char lbuf_end[64];
    snprintf(lbuf_true, sizeof(lbuf_true), "%s:", l_true);
    snprintf(lbuf_end, sizeof(lbuf_end), "%s:", l_end);

    if (size == 2) {
        const char* src1_lo = isel_get_lo_reg(isel, src1);
        const char* src1_hi = isel_get_hi_reg(isel, src1);
        const char* src2_lo = NULL;
        const char* src2_hi = NULL;

        if (!src2_is_imm) {
            src2_lo = save_acc_operand_in_b(isel, isel_get_lo_reg(isel, src2));
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
            src2_hi = save_acc_operand_in_b(isel, isel_get_hi_reg(isel, src2));
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
    } else {
        const char* src1_lo = isel_get_lo_reg(isel, src1);
        const char* src2_lo = NULL;
        if (!src2_is_imm) {
            src2_lo = save_acc_operand_in_b(isel, isel_get_lo_reg(isel, src2));
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
    }

    isel_emit(isel, "MOV", "A", "#0", NULL);
    isel_emit(isel, "SJMP", l_end, NULL, NULL);
    isel_emit(isel, lbuf_true, NULL, NULL, NULL);
    isel_emit(isel, "MOV", "A", "#1", NULL);
    isel_emit(isel, lbuf_end, NULL, NULL, NULL);

    emit_mov(isel, dst_lo, "A", ins);
    if (size == 2) {
        emit_mov(isel, dst_hi, "#00H", ins);
    }

    emit_store_spilled_result(isel, ins->dest, reg, size, ins);

    free(l_true);
    free(l_end);
}

void emit_lnot(ISelContext* isel, Instr* ins, Instr* next) {
    ValueName src = get_src1_value(ins);
    int size = ins->type ? ins->type->size : 1;

    int reg = alloc_reg_for_value(isel, ins->dest, size);
    const char* dst_lo = isel_reg_name(reg + (size == 2 ? 1 : 0));
    const char* dst_hi = isel_reg_name(reg);

    char* l_true = isel_new_label(isel, "Lnot_true");
    char* l_end = isel_new_label(isel, "Lnot_end");
    char lbuf_true[64];
    char lbuf_end[64];
    snprintf(lbuf_true, sizeof(lbuf_true), "%s:", l_true);
    snprintf(lbuf_end, sizeof(lbuf_end), "%s:", l_end);

    if (size == 2) {
        const char* lo = save_acc_operand_in_b(isel, isel_get_lo_reg(isel, src));
        const char* hi = isel_get_hi_reg(isel, src);
        emit_mov(isel, "A", hi, ins);
        isel_emit(isel, "ORL", "A", lo, NULL);
    } else {
        isel_ensure_in_acc(isel, src);
    }

    isel_emit(isel, "JZ", l_true, NULL, NULL);
    isel_emit(isel, "MOV", "A", "#0", NULL);
    isel_emit(isel, "SJMP", l_end, NULL, NULL);
    isel_emit(isel, lbuf_true, NULL, NULL, NULL);
    isel_emit(isel, "MOV", "A", "#1", NULL);
    isel_emit(isel, lbuf_end, NULL, NULL, NULL);

    emit_mov(isel, dst_lo, "A", ins);
    if (size == 2) {
        emit_mov(isel, dst_hi, "#0", ins);
    }

    emit_store_spilled_result(isel, ins->dest, reg, size, ins);

    free(l_true);
    free(l_end);
}

void emit_cmp_eq(ISelContext* isel, Instr* ins, Instr* next) {
    ValueName src1 = get_src1_value(ins);
    ValueName src2 = get_src2_value(ins);
    int size = ins->type ? ins->type->size : 1;
    int dst_reg = alloc_reg_for_value(isel, ins->dest, size);

    char* l_true = isel_new_label(isel, "Leq_true");
    char* l_false = isel_new_label(isel, "Leq_false");
    char* l_end = isel_new_label(isel, "Leq_end");
    char lb_true[64], lb_false[64], lb_end[64];
    snprintf(lb_true, sizeof(lb_true), "%s:", l_true);
    snprintf(lb_false, sizeof(lb_false), "%s:", l_false);
    snprintf(lb_end, sizeof(lb_end), "%s:", l_end);

    const char* s2_lo = save_acc_operand_in_b(isel, isel_get_lo_reg(isel, src2));
    const char* s1_lo = isel_get_lo_reg(isel, src1);
    emit_mov(isel, "A", s1_lo, ins);
    {
        char arg2[64];
        snprintf(arg2, sizeof(arg2), "%s, %s", s2_lo, l_false);
        isel_emit(isel, "CJNE", "A", arg2, NULL);
    }

    if (get_value_size(isel, src1) == 2 || get_value_size(isel, src2) == 2) {
        const char* s2_hi = save_acc_operand_in_b(isel, isel_get_hi_reg(isel, src2));
        const char* s1_hi = isel_get_hi_reg(isel, src1);
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
}

void emit_signed_cmp8_result(ISelContext* isel, Instr* ins, int dst_reg, int size, ValueName lhs, ValueName rhs, int cmp_type) {
    /* Re-implementing helper moved from original file: compare signed 8-bit values and set bool result */
    char* l_true = isel_new_label(isel, "Lscmp_true");
    char* l_end = isel_new_label(isel, "Lscmp_end");
    char lb_true[64], lb_end[64];
    snprintf(lb_true, sizeof(lb_true), "%s:", l_true);
    snprintf(lb_end, sizeof(lb_end), "%s:", l_end);

    const char* llo = isel_get_lo_reg(isel, lhs);
    const char* rlo = save_acc_operand_in_b(isel, isel_get_lo_reg(isel, rhs));

    emit_mov(isel, "A", llo, NULL);
    isel_emit(isel, "ANL", "A", "#128", NULL);
    isel_emit(isel, "JZ", l_true, NULL, NULL);

    isel_emit(isel, lb_true, NULL, NULL, NULL);
    emit_mov(isel, "A", llo, NULL);
    isel_emit(isel, "SUBB", "A", rlo, NULL);

    if (cmp_type == SIGNED_CMP_LT) {
        isel_emit(isel, "JC", lb_true, NULL, NULL);
    } else {
        isel_emit(isel, "JNC", lb_true, NULL, NULL);
    }

    emit_set_bool_result(isel, ins, dst_reg, size, false);
    isel_emit(isel, "SJMP", lb_end, NULL, NULL);
    isel_emit(isel, lb_true, NULL, NULL, NULL);
    emit_set_bool_result(isel, ins, dst_reg, size, true);
    isel_emit(isel, lb_end, NULL, NULL, NULL);

    free(l_true); free(l_end);
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

    int size = ins->type ? ins->type->size : 1;
    int dst_reg = alloc_reg_for_value(isel, ins->dest, size);
    int w = (get_value_size(isel, lhs) == 2 || get_value_size(isel, rhs) == 2) ? 2 : 1;

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
                            isel_emit(isel, "SJMP", target_f, NULL, NULL);
                        } else {
                            emit_phi_copies_for_edge(isel, isel->current_block_id, id_f, ins);
                            isel_emit(isel, "JZ", target_t, NULL, instr_to_ssa_str(ins));
                            emit_phi_copies_for_edge(isel, isel->current_block_id, id_f, ins);
                            isel_emit(isel, "SJMP", target_f, NULL, NULL);
                        }

                        isel_emit(isel, l_same, NULL, NULL, NULL);
                        isel_emit(isel, "CLR", "C", NULL, NULL);
                        emit_mov(isel, "A", llo, NULL);
                        isel_emit(isel, "SUBB", "A", rlo, NULL);

                        if (!is_gt) {
                            emit_phi_copies_for_edge(isel, isel->current_block_id, id_t, ins);
                            isel_emit(isel, "JC", target_t, NULL, NULL);
                            emit_phi_copies_for_edge(isel, isel->current_block_id, id_f, ins);
                            isel_emit(isel, "SJMP", target_f, NULL, NULL);
                        } else {
                            emit_phi_copies_for_edge(isel, isel->current_block_id, id_f, ins);
                            isel_emit(isel, "JC", target_f, NULL, NULL);
                            isel_emit(isel, "JZ", target_f, NULL, NULL);
                            emit_phi_copies_for_edge(isel, isel->current_block_id, id_t, ins);
                            isel_emit(isel, "SJMP", target_t, NULL, NULL);
                        }

                        free(l_same);
                        next->op = IROP_NOP;
                        return;
                    } else {
                        /* signed 16-bit compare: check high then low */
                        const char* lhi = isel_get_hi_reg(isel, lhs);
                        const char* rhi = save_acc_operand_in_b(isel, isel_get_hi_reg(isel, rhs));
                        const char* llo = isel_get_lo_reg(isel, lhs);
                        const char* rlo = save_acc_operand_in_b(isel, isel_get_lo_reg(isel, rhs));

                        isel_emit(isel, "CLR", "C", NULL, NULL);
                        emit_mov(isel, "A", lhi, ins);
                        isel_emit(isel, "SUBB", "A", rhi, NULL);

                        if (!is_gt) {
                            char* l_check_low = isel_new_label(isel, "Lcheck_low_tmp");
                            isel_emit(isel, "JC", target_f, NULL, NULL);
                            isel_emit(isel, "JZ", l_check_low, NULL, NULL);
                            emit_phi_copies_for_edge(isel, isel->current_block_id, id_f, ins);
                            isel_emit(isel, "SJMP", target_f, NULL, NULL);

                            isel_emit(isel, l_check_low, NULL, NULL, NULL);
                            isel_emit(isel, "CLR", "C", NULL, NULL);
                            emit_mov(isel, "A", llo, NULL);
                            isel_emit(isel, "SUBB", "A", rlo, NULL);
                            emit_phi_copies_for_edge(isel, isel->current_block_id, id_t, ins);
                            isel_emit(isel, "JC", target_t, NULL, NULL);
                            emit_phi_copies_for_edge(isel, isel->current_block_id, id_f, ins);
                            isel_emit(isel, "SJMP", target_f, NULL, NULL);
                            free(l_check_low);
                        } else {
                            char* l_check_low = isel_new_label(isel, "Lcheck_low_tmp");
                            isel_emit(isel, "JC", target_f, NULL, NULL);
                            isel_emit(isel, "JZ", l_check_low, NULL, NULL);
                            emit_phi_copies_for_edge(isel, isel->current_block_id, id_t, ins);
                            isel_emit(isel, "SJMP", target_t, NULL, NULL);

                            isel_emit(isel, l_check_low, NULL, NULL, NULL);
                            isel_emit(isel, "CLR", "C", NULL, NULL);
                            emit_mov(isel, "A", llo, NULL);
                            isel_emit(isel, "SUBB", "A", rlo, NULL);
                            emit_phi_copies_for_edge(isel, isel->current_block_id, id_f, ins);
                            isel_emit(isel, "JC", target_f, NULL, NULL);
                            isel_emit(isel, "JZ", target_f, NULL, NULL);
                            emit_phi_copies_for_edge(isel, isel->current_block_id, id_t, ins);
                            isel_emit(isel, "SJMP", target_t, NULL, NULL);
                            free(l_check_low);
                        }

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
                    emit_phi_copies_for_edge(isel, isel->current_block_id, id_t, ins);
                    char* ssa = instr_to_ssa_str(ins);
                    isel_emit(isel, "JC", target_t, NULL, ssa);
                    free(ssa);
                    emit_phi_copies_for_edge(isel, isel->current_block_id, id_f, ins);
                    isel_emit(isel, "SJMP", target_f, NULL, NULL);
                } else {
                    emit_phi_copies_for_edge(isel, isel->current_block_id, id_f, ins);
                    char* ssa = instr_to_ssa_str(ins);
                    isel_emit(isel, "JC", target_f, NULL, ssa);
                    free(ssa);
                    emit_phi_copies_for_edge(isel, isel->current_block_id, id_f, ins);
                    isel_emit(isel, "JZ", target_f, NULL, NULL);
                    emit_phi_copies_for_edge(isel, isel->current_block_id, id_t, ins);
                    isel_emit(isel, "SJMP", target_t, NULL, NULL);
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
        const char* rlo = save_acc_operand_in_b(isel, isel_get_lo_reg(isel, rhs));
        const char* rhi = save_acc_operand_in_b(isel, isel_get_hi_reg(isel, rhs));
        const char* llo = isel_get_lo_reg(isel, lhs);
        const char* lhi = isel_get_hi_reg(isel, lhs);

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
    }

    free(l_true); free(l_end);
}

void emit_cmp_le_ge(ISelContext* isel, Instr* ins, Instr* next, bool is_ge) {
    ValueName a = get_src1_value(ins);
    ValueName b = get_src2_value(ins);
    ValueName lhs = is_ge ? a : b;
    ValueName rhs = is_ge ? b : a;
    bool unsigned_cmp = is_unsigned_compare(isel, lhs, rhs);

    int size = ins->type ? ins->type->size : 1;
    int dst_reg = alloc_reg_for_value(isel, ins->dest, size);
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

                emit_phi_copies_for_edge(isel, isel->current_block_id, id_t, ins);
                char* ssa = instr_to_ssa_str(ins);
                isel_emit(isel, "JNC", target_t, NULL, ssa);
                free(ssa);
                emit_phi_copies_for_edge(isel, isel->current_block_id, id_f, ins);
                isel_emit(isel, "SJMP", target_f, NULL, NULL);

                next->op = IROP_NOP;
                return;
            } else {
                const char* rhi = save_acc_operand_in_b(isel, isel_get_hi_reg(isel, rhs));
                const char* lhi = isel_get_hi_reg(isel, lhs);

                isel_emit(isel, "CLR", "C", NULL, NULL);
                emit_mov(isel, "A", lhi, ins);
                isel_emit(isel, "SUBB", "A", rhi, NULL);

                if (is_ge) {
                    emit_phi_copies_for_edge(isel, isel->current_block_id, id_t, ins);
                    char* ssa = instr_to_ssa_str(ins);
                    isel_emit(isel, "JNC", target_t, NULL, ssa);
                    free(ssa);
                    emit_phi_copies_for_edge(isel, isel->current_block_id, id_f, ins);
                    isel_emit(isel, "JZ", target_f, NULL, NULL);
                    isel_emit(isel, "SJMP", target_t, NULL, NULL);
                } else {
                    emit_phi_copies_for_edge(isel, isel->current_block_id, id_t, ins);
                    char* ssa = instr_to_ssa_str(ins);
                    isel_emit(isel, "JC", target_t, NULL, ssa);
                    free(ssa);
                    emit_phi_copies_for_edge(isel, isel->current_block_id, id_f, ins);
                    isel_emit(isel, "SJMP", target_f, NULL, NULL);
                }

                next->op = IROP_NOP;
                return;
            }
        }
    }

    if (w == 1) {
        if (!unsigned_cmp) {
            emit_signed_cmp8_result(isel, ins, dst_reg, size, a, b,
                                    is_ge ? SIGNED_CMP_GE : SIGNED_CMP_LE);
            free(l_true); free(l_end);
            return;
        }

        const char* rlo = save_acc_operand_in_b(isel, isel_get_lo_reg(isel, rhs));
        const char* llo = isel_get_lo_reg(isel, lhs);
        isel_emit(isel, "CLR", "C", NULL, NULL);
        emit_mov(isel, "A", llo, ins);
        isel_emit(isel, "SUBB", "A", rlo, NULL);
    } else {
        const char* rlo = save_acc_operand_in_b(isel, isel_get_lo_reg(isel, rhs));
        const char* rhi = save_acc_operand_in_b(isel, isel_get_hi_reg(isel, rhs));
        const char* llo = isel_get_lo_reg(isel, lhs);
        const char* lhi = isel_get_hi_reg(isel, lhs);
        isel_emit(isel, "CLR", "C", NULL, NULL);
        emit_mov(isel, "A", llo, ins);
        isel_emit(isel, "SUBB", "A", rlo, NULL);
        emit_mov(isel, "A", lhi, NULL);
        isel_emit(isel, "SUBB", "A", rhi, NULL);
    }

    isel_emit(isel, "JNC", l_true, NULL, NULL);
    emit_set_bool_result(isel, ins, dst_reg, size, false);
    isel_emit(isel, "SJMP", l_end, NULL, NULL);
    isel_emit(isel, lb_true, NULL, NULL, NULL);
    emit_set_bool_result(isel, ins, dst_reg, size, true);
    isel_emit(isel, lb_end, NULL, NULL, NULL);

    free(l_true); free(l_end);
}
