#include "c51_isel_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "c51_isel_regalloc.h"

void emit_const(ISelContext* isel, Instr* ins) {
    int size = ins->type ? ins->type->size : 1;
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

    if (size == 1) {
        char imm_str[16];
        snprintf(imm_str, sizeof(imm_str), "#%d", val & 0xFF);
        emit_mov(isel, isel_reg_name(reg), imm_str, ins);
    } else if (size == 2) {
        char imm_high[16], imm_low[16];
        snprintf(imm_high, sizeof(imm_high), "#%d", (val >> 8) & 0xFF);
        snprintf(imm_low, sizeof(imm_low), "#%d", val & 0xFF);

        emit_mov(isel, isel_reg_name(reg), imm_high, ins);
        emit_mov(isel, isel_reg_name(reg + 1), imm_low, ins);
    }

    if (isel) {
        isel->last_const_reg = reg;
        isel->last_const_val = val;
        isel->last_const_size = size;
    }
}

void emit_add(ISelContext* isel, Instr* ins, Instr* next) {
    ValueName src1 = get_src1_value(ins);
    int size = ins->type ? ins->type->size : 1;
    int64_t imm_val;
    bool src2_is_imm = is_imm_operand(ins, &imm_val);

    int dst_reg = alloc_dest_reg(isel, ins, next, size, true);

    if (isel && isel->ctx && isel->ctx->value_to_addr) {
        char* k = int_to_key(src1);
        const char* addrname = (const char*)dict_get(isel->ctx->value_to_addr, k);
        free(k);
        if (addrname && src2_is_imm) {
            int addr_dst = alloc_reg_for_value(isel, ins->dest, 2);
            if (addr_dst < 0) addr_dst = 0;
            const char* dst_hi = isel_reg_name(addr_dst);
            const char* dst_lo = isel_reg_name(addr_dst + 1);
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
            return;
        }
    }
    if (dst_reg < 0) dst_reg = 0;

    const char* src1_lo = isel_get_lo_reg(isel, src1);
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
        ValueName src2 = get_src2_value(ins);
        const char* src2_lo = isel_get_lo_reg(isel, src2);
        isel_emit(isel, "ADD", "A", src2_lo, NULL);
    }

    const char* dst_lo = isel_reg_name(dst_reg + (size == 2 ? 1 : 0));
    emit_mov(isel, dst_lo, "A", NULL);

    if (size == 2) {
        const char* src1_hi = isel_get_hi_reg(isel, src1);
        const char* dst_hi = isel_reg_name(dst_reg);

        emit_mov(isel, "A", src1_hi, NULL);

        if (src2_is_imm) {
            char imm_str[16];
            snprintf(imm_str, sizeof(imm_str), "#%d", (int)((imm_val >> 8) & 0xFF));
            isel_emit(isel, "ADDC", "A", imm_str, NULL);
        } else {
            ValueName src2 = get_src2_value(ins);
            const char* src2_hi = isel_get_hi_reg(isel, src2);
            isel_emit(isel, "ADDC", "A", src2_hi, NULL);
        }

        emit_mov(isel, dst_hi, "A", NULL);
    }

    if (next && next->op == IROP_RET) {
        const char* ret_lo = isel_reg_name(dst_reg + (size == 2 ? 1 : 0));
        const char* ret_hi = isel_reg_name(dst_reg);
        int ret_size = next->type ? next->type->size : 1;

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

        if (isel->ctx && isel->ctx->value_to_reg) {
            int* reg_num = malloc(sizeof(int));
            *reg_num = (ret_size == 2) ? 6 : 7;
            char* key = int_to_key(ins->dest);
            dict_put(isel->ctx->value_to_reg, key, reg_num);
        }
    }
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
        const char* src2_lo = isel_get_lo_reg(isel, src2);
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
            const char* src2_hi = isel_get_hi_reg(isel, src2);
            isel_emit(isel, op_mnem, "A", src2_hi, NULL);
        }
        emit_mov(isel, dst_hi, "A", ins);
    }
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
}

void emit_ne(ISelContext* isel, Instr* ins) {
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

        emit_mov(isel, "A", src1_lo, ins);
        if (src2_is_imm) {
            char imm_str[32];
            snprintf(imm_str, sizeof(imm_str), "#%d, %s", (int)(imm_val & 0xFF), l_true);
            isel_emit(isel, "CJNE", "A", imm_str, NULL);
        } else {
            const char* src2_lo = isel_get_lo_reg(isel, src2);
            char arg2[64];
            snprintf(arg2, sizeof(arg2), "%s, %s", src2_lo, l_true);
            isel_emit(isel, "CJNE", "A", arg2, NULL);
        }

        emit_mov(isel, "A", src1_hi, NULL);
        if (src2_is_imm) {
            char imm_str[32];
            snprintf(imm_str, sizeof(imm_str), "#%d, %s", (int)((imm_val >> 8) & 0xFF), l_true);
            isel_emit(isel, "CJNE", "A", imm_str, NULL);
        } else {
            const char* src2_hi = isel_get_hi_reg(isel, src2);
            char arg2[64];
            snprintf(arg2, sizeof(arg2), "%s, %s", src2_hi, l_true);
            isel_emit(isel, "CJNE", "A", arg2, NULL);
        }
    } else {
        const char* src1_lo = isel_get_lo_reg(isel, src1);
        emit_mov(isel, "A", src1_lo, ins);
        if (src2_is_imm) {
            char imm_str[32];
            snprintf(imm_str, sizeof(imm_str), "#%d, %s", (int)(imm_val & 0xFF), l_true);
            isel_emit(isel, "CJNE", "A", imm_str, NULL);
        } else {
            const char* src2_lo = isel_get_lo_reg(isel, src2);
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

    free(l_true);
    free(l_end);
}

void emit_lnot(ISelContext* isel, Instr* ins) {
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
        const char* hi = isel_get_hi_reg(isel, src);
        const char* lo = isel_get_lo_reg(isel, src);
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

    free(l_true);
    free(l_end);
}

void emit_cmp_eq(ISelContext* isel, Instr* ins) {
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

    const char* s1_lo = isel_get_lo_reg(isel, src1);
    const char* s2_lo = isel_get_lo_reg(isel, src2);
    emit_mov(isel, "A", s1_lo, ins);
    {
        char arg2[64];
        snprintf(arg2, sizeof(arg2), "%s, %s", s2_lo, l_false);
        isel_emit(isel, "CJNE", "A", arg2, NULL);
    }

    if (get_value_size(isel, src1) == 2 || get_value_size(isel, src2) == 2) {
        const char* s1_hi = isel_get_hi_reg(isel, src1);
        const char* s2_hi = isel_get_hi_reg(isel, src2);
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

void emit_cmp_lt_gt(ISelContext* isel, Instr* ins, Instr* next, bool is_gt) {
    ValueName a = get_src1_value(ins);
    ValueName b = get_src2_value(ins);
    ValueName lhs = a;
    ValueName rhs = b;

    int size = ins->type ? ins->type->size : 1;
    int dst_reg = alloc_reg_for_value(isel, ins->dest, size);
    int w = (get_value_size(isel, lhs) == 2 || get_value_size(isel, rhs) == 2) ? 2 : 1;

    char* l_true = isel_new_label(isel, "Lcmp_true");
    char* l_end = isel_new_label(isel, "Lcmp_end");
    char lb_true[64], lb_end[64];
    snprintf(lb_true, sizeof(lb_true), "%s:", l_true);
    snprintf(lb_end, sizeof(lb_end), "%s:", l_end);

    if (next && next->op == IROP_BR && next->args && next->args->len > 0) {
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
                const char* rlo = isel_get_lo_reg(isel, rhs);
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
        const char* llo = isel_get_lo_reg(isel, lhs);
        const char* rlo = isel_get_lo_reg(isel, rhs);

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
        const char* llo = isel_get_lo_reg(isel, lhs);
        const char* lhi = isel_get_hi_reg(isel, lhs);
        const char* rlo = isel_get_lo_reg(isel, rhs);
        const char* rhi = isel_get_hi_reg(isel, rhs);

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

    int size = ins->type ? ins->type->size : 1;
    int dst_reg = alloc_reg_for_value(isel, ins->dest, size);
    int w = (get_value_size(isel, lhs) == 2 || get_value_size(isel, rhs) == 2) ? 2 : 1;

    char* l_true = isel_new_label(isel, "Lcmp_true");
    char* l_end = isel_new_label(isel, "Lcmp_end");
    char lb_true[64], lb_end[64];
    snprintf(lb_true, sizeof(lb_true), "%s:", l_true);
    snprintf(lb_end, sizeof(lb_end), "%s:", l_end);

    if (next && next->op == IROP_BR && next->args && next->args->len > 0) {
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
                const char* rlo = isel_get_lo_reg(isel, rhs);
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
                const char* lhi = isel_get_hi_reg(isel, lhs);
                const char* rhi = isel_get_hi_reg(isel, rhs);

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
        const char* llo = isel_get_lo_reg(isel, lhs);
        const char* rlo = isel_get_lo_reg(isel, rhs);
        isel_emit(isel, "CLR", "C", NULL, NULL);
        emit_mov(isel, "A", llo, ins);
        isel_emit(isel, "SUBB", "A", rlo, NULL);
    } else {
        const char* llo = isel_get_lo_reg(isel, lhs);
        const char* lhi = isel_get_hi_reg(isel, lhs);
        const char* rlo = isel_get_lo_reg(isel, rhs);
        const char* rhi = isel_get_hi_reg(isel, rhs);
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

void emit_neg(ISelContext* isel, Instr* ins) {
    ValueName src = get_src1_value(ins);
    int size = ins->type ? ins->type->size : 1;
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
}

void emit_shift(ISelContext* isel, Instr* ins, bool is_shr) {
    ValueName src = get_src1_value(ins);
    int size = ins->type ? ins->type->size : 1;
    int dst_reg = alloc_dest_reg(isel, ins, NULL, size, true);
    const char* dst_lo = isel_reg_name(dst_reg + (size == 2 ? 1 : 0));
    const char* dst_hi = isel_reg_name(dst_reg);
    emit_copy_value(isel, ins, src, dst_reg, size);

    int64_t imm = 0;
    if (is_imm_operand(ins, &imm)) {
        int cnt = (int)(imm & 0x1F);
        for (int i = 0; i < cnt; i++) {
            if (size == 1) {
                emit_mov(isel, "A", dst_lo, ins);
                if (is_shr) {
                    isel_emit(isel, "CLR", "C", NULL, NULL);
                    isel_emit(isel, "RRC", "A", NULL, NULL);
                } else {
                    isel_emit(isel, "ADD", "A", dst_lo, NULL);
                }
                emit_mov(isel, dst_lo, "A", NULL);
            } else {
                if (is_shr) {
                    isel_emit(isel, "CLR", "C", NULL, NULL);
                    emit_mov(isel, "A", dst_hi, NULL);
                    isel_emit(isel, "RRC", "A", NULL, NULL);
                    emit_mov(isel, dst_hi, "A", NULL);
                    emit_mov(isel, "A", dst_lo, NULL);
                    isel_emit(isel, "RRC", "A", NULL, NULL);
                    emit_mov(isel, dst_lo, "A", NULL);
                } else {
                    isel_emit(isel, "CLR", "C", NULL, NULL);
                    emit_mov(isel, "A", dst_lo, NULL);
                    isel_emit(isel, "RLC", "A", NULL, NULL);
                    emit_mov(isel, dst_lo, "A", NULL);
                    emit_mov(isel, "A", dst_hi, NULL);
                    isel_emit(isel, "RLC", "A", NULL, NULL);
                    emit_mov(isel, dst_hi, "A", NULL);
                }
            }
        }
        return;
    }

    ValueName cntv = get_src2_value(ins);
    const char* tcnt = isel_get_lo_reg(isel, cntv);

    char* l_loop = isel_new_label(isel, "Lsh_loop");
    char* l_end = isel_new_label(isel, "Lsh_end");
    char lb_loop[64], lb_end[64];
    snprintf(lb_loop, sizeof(lb_loop), "%s:", l_loop);
    snprintf(lb_end, sizeof(lb_end), "%s:", l_end);

    isel_emit(isel, lb_loop, NULL, NULL, NULL);
    emit_mov(isel, "A", tcnt, NULL);
    isel_emit(isel, "JZ", l_end, NULL, NULL);

    if (size == 1) {
        emit_mov(isel, "A", dst_lo, NULL);
        if (is_shr) {
            isel_emit(isel, "CLR", "C", NULL, NULL);
            isel_emit(isel, "RRC", "A", NULL, NULL);
        } else {
            isel_emit(isel, "ADD", "A", dst_lo, NULL);
        }
        emit_mov(isel, dst_lo, "A", NULL);
    } else {
        if (is_shr) {
            isel_emit(isel, "CLR", "C", NULL, NULL);
            emit_mov(isel, "A", dst_hi, NULL);
            isel_emit(isel, "RRC", "A", NULL, NULL);
            emit_mov(isel, dst_hi, "A", NULL);
            emit_mov(isel, "A", dst_lo, NULL);
            isel_emit(isel, "RRC", "A", NULL, NULL);
            emit_mov(isel, dst_lo, "A", NULL);
        } else {
            isel_emit(isel, "CLR", "C", NULL, NULL);
            emit_mov(isel, "A", dst_lo, NULL);
            isel_emit(isel, "RLC", "A", NULL, NULL);
            emit_mov(isel, dst_lo, "A", NULL);
            emit_mov(isel, "A", dst_hi, NULL);
            isel_emit(isel, "RLC", "A", NULL, NULL);
            emit_mov(isel, dst_hi, "A", NULL);
        }
    }

    emit_mov(isel, "A", tcnt, NULL);
    isel_emit(isel, "DEC", "A", NULL, NULL);
    emit_mov(isel, tcnt, "A", NULL);
    isel_emit(isel, "SJMP", l_loop, NULL, NULL);
    isel_emit(isel, lb_end, NULL, NULL, NULL);

    free(l_loop); free(l_end);
}

void emit_mul(ISelContext* isel, Instr* ins, Instr* next) {
    ValueName a = get_src1_value(ins);
    ValueName b = get_src2_value(ins);
    int size = ins->type ? ins->type->size : 1;
    int dst_reg = alloc_dest_reg(isel, ins, next, size, true);
    const char* dst_lo = isel_reg_name(dst_reg + (size == 2 ? 1 : 0));
    const char* dst_hi = isel_reg_name(dst_reg);

    emit_mov(isel, dst_lo, "#0", ins);
    if (size == 2) emit_mov(isel, dst_hi, "#0", NULL);

    int t = alloc_temp_reg(isel, -1, size == 2 ? 2 : 1);
    const char* t_lo = (t >= 0) ? isel_reg_name(t + (size == 2 ? 1 : 0)) : "A";
    const char* t_hi = (t >= 0) ? isel_reg_name(t) : "A";
    emit_mov(isel, t_lo, isel_get_lo_reg(isel, b), NULL);
    if (size == 2) emit_mov(isel, t_hi, isel_get_hi_reg(isel, b), NULL);

    if (size == 1) {
        if (t >= 0) {
            emit_mov(isel, "B", t_lo, NULL);
            free_temp_reg(isel, t, 1);
        } else {
            emit_mov(isel, "B", isel_get_lo_reg(isel, b), NULL);
        }
        emit_mov(isel, "A", isel_get_lo_reg(isel, a), ins);
        isel_emit(isel, "MUL", "AB", NULL, NULL);
        emit_mov(isel, dst_lo, "A", ins);
        return;
    }

    char* l_loop = isel_new_label(isel, "Lmul_loop");
    char* l_end = isel_new_label(isel, "Lmul_end");
    char lb_loop[64], lb_end[64];
    snprintf(lb_loop, sizeof(lb_loop), "%s:", l_loop);
    snprintf(lb_end, sizeof(lb_end), "%s:", l_end);

    isel_emit(isel, lb_loop, NULL, NULL, NULL);
    emit_mov(isel, "A", t_hi, NULL);
    isel_emit(isel, "ORL", "A", t_lo, NULL);
    isel_emit(isel, "JZ", l_end, NULL, NULL);
    emit_add16_regs(isel, dst_hi, dst_lo, isel_get_hi_reg(isel, a), isel_get_lo_reg(isel, a), ins);

    isel_emit(isel, "CLR", "C", NULL, NULL);
    emit_mov(isel, "A", t_lo, NULL);
    isel_emit(isel, "SUBB", "A", "#1", NULL);
    emit_mov(isel, t_lo, "A", NULL);
    emit_mov(isel, "A", t_hi, NULL);
    isel_emit(isel, "SUBB", "A", "#0", NULL);
    emit_mov(isel, t_hi, "A", NULL);

    isel_emit(isel, "SJMP", l_loop, NULL, NULL);
    isel_emit(isel, lb_end, NULL, NULL, NULL);

    free(l_loop); free(l_end);
    if (t >= 0) free_temp_reg(isel, t, size == 2 ? 2 : 1);
}

void emit_div_mod(ISelContext* isel, Instr* ins, bool want_mod) {
    ValueName num = get_src1_value(ins);
    ValueName den = get_src2_value(ins);
    int size = ins->type ? ins->type->size : 1;
    int dst_reg = alloc_reg_for_value(isel, ins->dest, size);
    const char* dst_lo = isel_reg_name(dst_reg + (size == 2 ? 1 : 0));
    const char* dst_hi = isel_reg_name(dst_reg);

    int tr = alloc_temp_reg(isel, -1, size == 2 ? 2 : 1);
    const char* rem_lo = (tr >= 0) ? isel_reg_name(tr + (size == 2 ? 1 : 0)) : "R1";
    const char* rem_hi = (tr >= 0) ? isel_reg_name(tr) : "R0";
    emit_mov(isel, rem_lo, isel_get_lo_reg(isel, num), ins);
    if (size == 2) emit_mov(isel, rem_hi, isel_get_hi_reg(isel, num), NULL);

    emit_mov(isel, dst_lo, "#0", NULL);
    if (size == 2) emit_mov(isel, dst_hi, "#0", NULL);

    char* l_end = isel_new_label(isel, "Ldiv_end");
    char* l_loop = isel_new_label(isel, "Ldiv_loop");
    char* l_body = isel_new_label(isel, "Ldiv_body");
    char lb_end[64], lb_loop[64], lb_body[64];
    snprintf(lb_end, sizeof(lb_end), "%s:", l_end);
    snprintf(lb_loop, sizeof(lb_loop), "%s:", l_loop);
    snprintf(lb_body, sizeof(lb_body), "%s:", l_body);
    if (size == 1) {
        (void)get_value_type(isel, ins->dest);
        bool is_unsigned = true;

        int td = alloc_temp_reg(isel, -1, 1);
        const char* den_tmp = (td >= 0) ? isel_reg_name(td) : "R2";
        emit_mov(isel, den_tmp, isel_get_lo_reg(isel, den), NULL);

        char *l_nodiv = isel_new_label(isel, "Ldiv_skip");
        char lb_nodiv[64];
        snprintf(lb_nodiv, sizeof(lb_nodiv), "%s:", l_nodiv);
        emit_mov(isel, "A", den_tmp, NULL);
        isel_emit(isel, "JZ", l_nodiv, NULL, NULL);

        if (is_unsigned) {
            emit_mov(isel, "A", rem_lo, ins);
            emit_mov(isel, "B", den_tmp, NULL);
            isel_emit(isel, "DIV", "AB", NULL, NULL);
            if (want_mod) {
                emit_mov(isel, dst_lo, "B", ins);
            } else {
                emit_mov(isel, dst_lo, "A", ins);
            }
            isel_emit(isel, lb_nodiv, NULL, NULL, NULL);
            free(l_nodiv);
            if (td >= 0) free_temp_reg(isel, td, 1);
            free(l_loop); free(l_body); free(l_end);
            if (tr >= 0) free_temp_reg(isel, tr, 1);
            return;
        }

        int tsn = alloc_temp_reg(isel, -1, 1);
        int tsd = alloc_temp_reg(isel, -1, 1);
        const char* s_num = (tsn >= 0) ? isel_reg_name(tsn) : "R3";
        const char* s_den = (tsd >= 0) ? isel_reg_name(tsd) : "R4";
        isel_emit(isel, "MOV", s_num, "#0", NULL);
        isel_emit(isel, "MOV", s_den, "#0", NULL);

        char *l_num_pos = isel_new_label(isel, "Lnum_pos");
        char *l_den_pos = isel_new_label(isel, "Lden_pos");
        char *l_after_fix = isel_new_label(isel, "Ldiv_after_fix");

        emit_mov(isel, "A", rem_lo, NULL);
        isel_emit(isel, "ANL", "A", "#128", NULL);
        isel_emit(isel, "JZ", l_num_pos, NULL, NULL);
        emit_mov(isel, "A", rem_lo, NULL);
        isel_emit(isel, "CPL", "A", NULL, NULL);
        isel_emit(isel, "INC", "A", NULL, NULL);
        emit_mov(isel, rem_lo, "A", NULL);
        isel_emit(isel, "MOV", s_num, "#1", NULL);
        isel_emit(isel, "SJMP", l_den_pos, NULL, NULL);
        isel_emit(isel, l_num_pos, NULL, NULL, NULL);

        emit_mov(isel, "A", den_tmp, NULL);
        isel_emit(isel, "ANL", "A", "#128", NULL);
        isel_emit(isel, "JZ", l_den_pos, NULL, NULL);
        emit_mov(isel, "A", den_tmp, NULL);
        isel_emit(isel, "CPL", "A", NULL, NULL);
        isel_emit(isel, "INC", "A", NULL, NULL);
        emit_mov(isel, den_tmp, "A", NULL);
        isel_emit(isel, "MOV", s_den, "#1", NULL);
        isel_emit(isel, l_den_pos, NULL, NULL, NULL);

        emit_mov(isel, "A", rem_lo, ins);
        emit_mov(isel, "B", den_tmp, NULL);
        isel_emit(isel, "DIV", "AB", NULL, NULL);

        emit_mov(isel, "A", s_num, NULL);
        isel_emit(isel, "XRL", "A", s_den, NULL);
        char *l_no_negq = isel_new_label(isel, "Lno_negq");
        isel_emit(isel, "JZ", l_no_negq, NULL, NULL);
        isel_emit(isel, "CPL", "A", NULL, NULL);
        isel_emit(isel, "INC", "A", NULL, NULL);
        emit_mov(isel, dst_lo, "A", ins);
        isel_emit(isel, "SJMP", l_after_fix, NULL, NULL);
        isel_emit(isel, l_no_negq, NULL, NULL, NULL);
        if (want_mod) {
            emit_mov(isel, "A", "B", NULL);
            isel_emit(isel, "ANL", "A", "#0", NULL);
        }
        isel_emit(isel, l_after_fix, NULL, NULL, NULL);

        if (want_mod) {
            emit_mov(isel, "A", s_num, NULL);
            char *l_no_reml_neg = isel_new_label(isel, "Lno_reml_neg");
            isel_emit(isel, "JZ", l_no_reml_neg, NULL, NULL);
            emit_mov(isel, "A", "B", NULL);
            isel_emit(isel, "CPL", "A", NULL, NULL);
            isel_emit(isel, "INC", "A", NULL, NULL);
            emit_mov(isel, "B", "A", NULL);
            isel_emit(isel, l_no_reml_neg, NULL, NULL, NULL);
            emit_mov(isel, dst_lo, "B", ins);
            free(l_no_reml_neg);
        } else {
            emit_mov(isel, dst_lo, "A", ins);
        }

        if (td >= 0) free_temp_reg(isel, td, 1);
        if (tsn >= 0) free_temp_reg(isel, tsn, 1);
        if (tsd >= 0) free_temp_reg(isel, tsd, 1);
        free(l_num_pos); free(l_den_pos); free(l_after_fix); free(l_no_negq);
        free(l_loop); free(l_body); free(l_end);
        if (tr >= 0) free_temp_reg(isel, tr, 1);
        return;
    } else {
        emit_sub16_regs(isel, rem_hi, rem_lo, isel_get_hi_reg(isel, den), isel_get_lo_reg(isel, den), ins);
        if (!want_mod) {
            emit_mov(isel, "A", dst_lo, NULL);
            isel_emit(isel, "INC", "A", NULL, NULL);
            emit_mov(isel, dst_lo, "A", NULL);
            isel_emit(isel, "JNZ", l_loop, NULL, NULL);
            emit_mov(isel, "A", dst_hi, NULL);
            isel_emit(isel, "INC", "A", NULL, NULL);
            emit_mov(isel, dst_hi, "A", NULL);
            isel_emit(isel, "SJMP", l_loop, NULL, NULL);
        }
    }

    if (size == 1 && !want_mod) {
        isel_emit(isel, "SJMP", l_loop, NULL, NULL);
    } else if (size == 1 && want_mod) {
        isel_emit(isel, "SJMP", l_loop, NULL, NULL);
    } else if (size == 2 && want_mod) {
        isel_emit(isel, "SJMP", l_loop, NULL, NULL);
    }

    isel_emit(isel, lb_end, NULL, NULL, NULL);
    if (want_mod) {
        emit_mov(isel, dst_lo, rem_lo, ins);
        if (size == 2) emit_mov(isel, dst_hi, rem_hi, NULL);
    }

    free(l_end); free(l_loop); free(l_body);
    if (tr >= 0) free_temp_reg(isel, tr, size == 2 ? 2 : 1);
}

void emit_select(ISelContext* isel, Instr* ins) {
    if (!ins->args || ins->args->len < 3) return;
    ValueName cond = *(ValueName*)list_get(ins->args, 0);
    ValueName tv = *(ValueName*)list_get(ins->args, 1);
    ValueName fv = *(ValueName*)list_get(ins->args, 2);

    int size = ins->type ? ins->type->size : 1;
    int dst_reg = alloc_reg_for_value(isel, ins->dest, size);
    const char* dst_lo = isel_reg_name(dst_reg + (size == 2 ? 1 : 0));
    const char* dst_hi = isel_reg_name(dst_reg);

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

    const char* src_tv_lo = isel_get_lo_reg(isel, tv);
    const char* src_tv_hi = isel_get_hi_reg(isel, tv);
    const char* src_fv_lo = isel_get_lo_reg(isel, fv);
    const char* src_fv_hi = isel_get_hi_reg(isel, fv);

    bool need_temp_tv = (strcmp(src_tv_lo, "A") == 0) || (strcmp(src_tv_lo, dst_lo) == 0);
    bool need_temp_fv = (strcmp(src_fv_lo, "A") == 0) || (strcmp(src_fv_lo, dst_lo) == 0);

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

    if (tr_tv >= 0) free_temp_reg(isel, tr_tv, size);
    if (tr_fv >= 0) free_temp_reg(isel, tr_fv, size);

    free(l_true); free(l_end);
}

void emit_simple_cast(ISelContext* isel, Instr* ins, bool sign_extend) {
    ValueName src = get_src1_value(ins);
    int src_size = get_value_size(isel, src);
    int dst_size = ins->type ? ins->type->size : src_size;
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
}

void emit_sub(ISelContext* isel, Instr* ins, Instr* next) {
    ValueName src1 = get_src1_value(ins);
    int size = ins->type ? ins->type->size : 1;
    int64_t imm_val;
    bool src2_is_imm = is_imm_operand(ins, &imm_val);

    const char* src1_lo = isel_get_lo_reg(isel, src1);
    int dst_reg = alloc_dest_reg(isel, ins, next, size, true);
    const char* dst_lo = isel_reg_name(dst_reg + (size == 2 ? 1 : 0));

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
            ValueName src2 = get_src2_value(ins);
            const char* src2_lo = isel_get_lo_reg(isel, src2);
            char* ssa = instr_to_ssa_str(ins);
            isel_emit(isel, "SUBB", "A", src2_lo, ssa);
            free(ssa);
        }
    } else {
        isel_emit(isel, "CLR", "C", NULL, NULL);
        ValueName src2 = get_src2_value(ins);
        const char* src2_lo = isel_get_lo_reg(isel, src2);
        char* ssa = instr_to_ssa_str(ins);
        isel_emit(isel, "SUBB", "A", src2_lo, ssa);
        free(ssa);
    }

    emit_mov(isel, dst_lo, "A", ins);

    if (size == 2) {
        const char* src1_hi = isel_get_hi_reg(isel, src1);
        const char* dst_hi = isel_reg_name(dst_reg);

        emit_mov(isel, "A", src1_hi, ins);

        if (src2_is_imm) {
            char imm_str[16];
            snprintf(imm_str, sizeof(imm_str), "#%d", (int)((imm_val >> 8) & 0xFF));
            isel_emit(isel, "SUBB", "A", imm_str, NULL);
        } else {
            ValueName src2 = get_src2_value(ins);
            const char* src2_hi = isel_get_hi_reg(isel, src2);
            isel_emit(isel, "SUBB", "A", src2_hi, NULL);
        }

        emit_mov(isel, dst_hi, "A", ins);
    }

    if (next && next->op == IROP_RET) {
        const char* ret_lo = NULL;
        const char* ret_hi = NULL;
        if (dst_reg >= 0) {
            ret_lo = isel_reg_name(dst_reg + (size == 2 ? 1 : 0));
            ret_hi = isel_reg_name(dst_reg);
        } else {
            ret_lo = isel_get_lo_reg(isel, ins->dest);
            ret_hi = isel_get_hi_reg(isel, ins->dest);
        }
        int ret_size = next->type ? next->type->size : 1;
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

        if (isel->ctx && isel->ctx->value_to_reg) {
            int* reg_num = malloc(sizeof(int));
            *reg_num = (ret_size == 2) ? 6 : 7;
            char* key = int_to_key(ins->dest);
            dict_put(isel->ctx->value_to_reg, key, reg_num);
        }
    }
}

void emit_trunc(ISelContext* isel, Instr* ins) {
    ValueName src = get_src1_value(ins);
    int src_size = get_value_size(isel, src);

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
            }
        }
    } else {
        int* reg_num = malloc(sizeof(int));
        *reg_num = isel_get_value_reg(isel, src);
        char* key = int_to_key(ins->dest);
        dict_put(isel->ctx->value_to_reg, key, reg_num);
    }
}
