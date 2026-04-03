#include "c51_isel_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "c51_isel_regalloc.h"

static void emit_load_save_byte(ISelContext* isel, int dst_reg, int size, bool high_byte, const char* ssa) {
    if (!isel || dst_reg < 0) return;
    const char* dst = NULL;
    if (size == 2) {
        dst = high_byte ? isel_reg_name(dst_reg) : isel_reg_name(dst_reg + 1);
    } else {
        dst = isel_reg_name(dst_reg);
    }
    if (dst && strcmp(dst, "A") != 0) {
        isel_emit(isel, "MOV", dst, "A", ssa);
    }
}

static void store_spilled_mem_result(ISelContext* isel, Instr* ins, int reg, int size) {
    if (!ins) return;
    emit_store_spilled_result(isel, ins->dest, reg, size, ins);
}

static bool addr_value_needs_materialization(ISelContext* isel, ValueName value) {
    if (!isel || !isel->ctx || !isel->ctx->current_func || value <= 0) return true;
    bool has_use = false;
    Func *func = isel->ctx->current_func;
    for (Iter bit = list_iter(func->blocks); !iter_end(bit);) {
        Block *block = iter_next(&bit);
        if (!block || !block->instrs) continue;
        for (Iter iit = list_iter(block->instrs); !iter_end(iit);) {
            Instr *user = iter_next(&iit);
            if (!user || !user->args) continue;
            bool uses_value = false;
            for (int index = 0; index < user->args->len; index++) {
                ValueName *arg = list_get(user->args, index);
                if (arg && *arg == value) {
                    uses_value = true;
                    has_use = true;
                    if ((user->op == IROP_LOAD || user->op == IROP_STORE) && index == 0) {
                        /* Direct load/store use: OK, no materialization needed for this use */
                    } else if (user->op == IROP_OFFSET && index == 0
                               && user->args->len >= 2) {
                        /* OFFSET(value, const, scale): foldable if OFFSET result itself
                           is only used by LOAD/STORE as pointer */
                        ValueName offidx = *(ValueName*)list_get(user->args, 1);
                        int64_t dummy = 0;
                        bool idx_const = try_get_value_const(isel, offidx, &dummy);
                        if (idx_const && !addr_value_needs_materialization(isel, user->dest)) {
                            /* OFFSET result only used by load/store â†?foldable */
                        } else {
                            return true;
                        }
                    } else {
                        return true;
                    }
                }
            }
            if (uses_value) continue;
        }
    }
    return !has_use;
}

static const char* preserve_offset_operand(ISelContext* isel, const char* src) {
    if (src && strcmp(src, "A") == 0) {
        isel_emit(isel, "MOV", "B", "A", NULL);
        return "B";
    }
    return src;
}

static int alloc_indirect_scratch_reg(ISelContext* isel) {
    if (!isel) return -1;
    for (int reg = 0; reg <= 1; reg++) {
        if (isel->reg_busy[reg]) continue;
        isel->reg_busy[reg] = true;
        isel->reg_val[reg] = -1;
        return reg;
    }
    return -1;
}

static void emit_materialize_pointer_symbol(ISelContext* isel, const char* sym,
                                            int ptr_size,
                                            const char* dst_lo,
                                            const char* dst_hi,
                                            const char* dst_tag,
                                            Instr* ins) {
    if (!isel || !sym || !dst_lo) return;

    SectionKind sym_sec = get_symbol_section_kind(isel, sym);
    if (ptr_size == 1) {
        char imm[256];
        snprintf(imm, sizeof(imm), "#%s", sym);
        emit_mov(isel, dst_lo, imm, ins);
        return;
    }

    char dptr_val[256];
    snprintf(dptr_val, sizeof(dptr_val), "#%s", sym);
    isel_emit(isel, "MOV", "DPTR", dptr_val, NULL);

    if (dst_lo) emit_mov(isel, dst_lo, "DPL", ins);
    if (dst_hi) emit_mov(isel, dst_hi, "DPH", NULL);
    if (ptr_size >= 3 && dst_tag) {
        const char* tag_imm = "#0";
        if (sym_sec == SEC_XDATA) tag_imm = "#1";
        else if (sym_sec == SEC_CODE) tag_imm = "#255";
        emit_mov(isel, dst_tag, tag_imm, NULL);
    }
}

static bool emit_load_from_pointer_value(ISelContext* isel, Instr* ins, ValueName ptr) {
    Ctype* ptr_type = get_value_type(isel, ptr);
    if (!ptr_type || ptr_type->type != CTYPE_PTR) return false;

    int ptr_abi_size = c51_abi_type_size(ptr_type);
    int load_size = ins->type ? c51_abi_type_size(ins->type) : 1;
    int ptr_reg = isel_get_value_reg(isel, ptr);
    if (ptr_reg == SPILL_REG) {
        ptr_reg = isel_reload_spill(isel, ptr, ptr_abi_size, ins);
    }
    if (ptr_reg < 0 || load_size < 1 || load_size > 2) return false;

    int ptr_space = get_mem_space(ptr_type);
    int dst_reg = alloc_reg_for_value(isel, ins->dest, load_size);
    int phys_dst_reg = dst_reg;
    if (phys_dst_reg < 0) {
        phys_dst_reg = alloc_temp_reg(isel, ins->dest, load_size);
    }
    if (ptr_reg >= 0 && phys_dst_reg >= 0) {
        int ptr_begin = ptr_reg;
        int ptr_end = ptr_reg + ptr_abi_size - 1;
        int dst_begin = phys_dst_reg;
        int dst_end = phys_dst_reg + load_size - 1;
        bool overlaps = !(dst_end < ptr_begin || dst_begin > ptr_end);
        if (overlaps) {
            int alt_reg = alloc_temp_reg(isel, ins->dest, load_size);
            if (alt_reg >= 0) {
                phys_dst_reg = alt_reg;
                dst_reg = alt_reg;
            }
        }
    }
    if (phys_dst_reg < 0) {
        phys_dst_reg = 0;
    }
    if (isel && isel->ctx && isel->ctx->value_to_reg && ins && ins->dest > 0 && phys_dst_reg >= 0) {
        int* reg_num = malloc(sizeof(int));
        if (reg_num) {
            *reg_num = phys_dst_reg;
            char* key = int_to_key(ins->dest);
            dict_put(isel->ctx->value_to_reg, key, reg_num);
        }
        dst_reg = phys_dst_reg;
    }
    if (dst_reg < 0 && dst_reg != SPILL_REG && isel && isel->ctx && isel->ctx->value_to_reg) {
        int* reg_num = malloc(sizeof(int));
        *reg_num = phys_dst_reg;
        char* key = int_to_key(ins->dest);
        dict_put(isel->ctx->value_to_reg, key, reg_num);
        dst_reg = phys_dst_reg;
    }
    char* ssa = instr_to_ssa_str(ins);
    int scratch_reg = -1;
    const char* scratch = NULL;

    if (ptr_abi_size == 1 || ptr_abi_size == 3 || ((ptr_space == 1 || ptr_space == 2 || ptr_space == 3) && ptr_abi_size == 2)) {
        scratch_reg = alloc_indirect_scratch_reg(isel);
        scratch = (scratch_reg >= 0) ? isel_reg_name(scratch_reg) : "R0";
    }

    if (ptr_abi_size == 1) {
        const char* ptr_lo = isel_reg_name(ptr_reg);
        isel_emit(isel, "MOV", scratch, ptr_lo, NULL);
        if (ptr_space == 3) {
            char ref[16];
            snprintf(ref, sizeof(ref), "@%s", scratch);
            isel_emit(isel, "MOVX", "A", ref, ssa);
        } else {
            char ref[16];
            snprintf(ref, sizeof(ref), "@%s", scratch);
            isel_emit(isel, "MOV", "A", ref, ssa);
        }
        emit_load_save_byte(isel, phys_dst_reg, load_size, false, NULL);
        if (load_size == 2) {
            isel_emit(isel, "INC", scratch, NULL, NULL);
            if (ptr_space == 3) {
                char ref[16];
                snprintf(ref, sizeof(ref), "@%s", scratch);
                isel_emit(isel, "MOVX", "A", ref, NULL);
            } else {
                char ref[16];
                snprintf(ref, sizeof(ref), "@%s", scratch);
                isel_emit(isel, "MOV", "A", ref, NULL);
            }
            emit_load_save_byte(isel, phys_dst_reg, load_size, true, NULL);
        }
        store_spilled_mem_result(isel, ins, phys_dst_reg, load_size);
        if (scratch_reg >= 0) free_temp_reg(isel, scratch_reg, 1);
        free(ssa);
        return true;
    }

    if (ptr_abi_size == 2) {
        const char* ptr_lo = isel_get_lo_reg(isel, ptr);
        const char* ptr_hi = isel_get_hi_reg(isel, ptr);
        if (ptr_space == 1 || ptr_space == 2 || ptr_space == 3) {
            char ref[16];
            isel_emit(isel, "MOV", scratch, ptr_lo, NULL);
            snprintf(ref, sizeof(ref), "@%s", scratch);
            if (ptr_space == 3) {
                isel_emit(isel, "MOVX", "A", ref, ssa);
            } else {
                isel_emit(isel, "MOV", "A", ref, ssa);
            }
            emit_load_save_byte(isel, phys_dst_reg, load_size, false, NULL);
            if (load_size == 2) {
                isel_emit(isel, "INC", scratch, NULL, NULL);
                snprintf(ref, sizeof(ref), "@%s", scratch);
                if (ptr_space == 3) {
                    isel_emit(isel, "MOVX", "A", ref, NULL);
                } else {
                    isel_emit(isel, "MOV", "A", ref, NULL);
                }
                emit_load_save_byte(isel, phys_dst_reg, load_size, true, NULL);
            }
            store_spilled_mem_result(isel, ins, phys_dst_reg, load_size);
            if (scratch_reg >= 0) free_temp_reg(isel, scratch_reg, 1);
            free(ssa);
            return true;
        }

        isel_emit(isel, "MOV", "DPL", ptr_lo, NULL);
        isel_emit(isel, "MOV", "DPH", ptr_hi, NULL);
        if (ptr_space == 6) {
            isel_emit(isel, "CLR", "A", NULL, NULL);
            isel_emit(isel, "MOVC", "A", "@A+DPTR", ssa);
        } else {
            isel_emit(isel, "MOVX", "A", "@DPTR", ssa);
        }
        emit_load_save_byte(isel, phys_dst_reg, load_size, false, NULL);
        if (load_size == 2) {
            isel_emit(isel, "INC", "DPTR", NULL, NULL);
            if (ptr_space == 6) {
                isel_emit(isel, "CLR", "A", NULL, NULL);
                isel_emit(isel, "MOVC", "A", "@A+DPTR", NULL);
            } else {
                isel_emit(isel, "MOVX", "A", "@DPTR", NULL);
            }
            emit_load_save_byte(isel, phys_dst_reg, load_size, true, NULL);
        }
        store_spilled_mem_result(isel, ins, phys_dst_reg, load_size);
        free(ssa);
        return true;
    }

    if (ptr_abi_size == 3 && ptr_reg + 2 < 8) {
        const char* ptr_lo = isel_reg_name(ptr_reg);
        const char* ptr_hi = isel_reg_name(ptr_reg + 1);
        const char* ptr_tag = isel_reg_name(ptr_reg + 2);
        char *l_data = isel_new_label(isel, "Lgptr_data");
        char *l_xdata = isel_new_label(isel, "Lgptr_xdata");
        char *l_pdata = isel_new_label(isel, "Lgptr_pdata");
        char *l_code = isel_new_label(isel, "Lgptr_code");
        char *l_done = isel_new_label(isel, "Lgptr_done");
        char lb_data[64], lb_xdata[64], lb_pdata[64], lb_code[64], lb_done[64];

        snprintf(lb_data, sizeof(lb_data), "%s:", l_data);
        snprintf(lb_xdata, sizeof(lb_xdata), "%s:", l_xdata);
        snprintf(lb_pdata, sizeof(lb_pdata), "%s:", l_pdata);
        snprintf(lb_code, sizeof(lb_code), "%s:", l_code);
        snprintf(lb_done, sizeof(lb_done), "%s:", l_done);

        isel_emit(isel, "MOV", "A", ptr_tag, NULL);
        isel_emit(isel, "JZ", l_data, NULL, NULL);
        isel_emit(isel, "MOV", "A", ptr_tag, NULL);
        isel_emit(isel, "XRL", "A", "#1", NULL);
        isel_emit(isel, "JZ", l_xdata, NULL, NULL);
        isel_emit(isel, "MOV", "A", ptr_tag, NULL);
        isel_emit(isel, "XRL", "A", "#254", NULL);
        isel_emit(isel, "JZ", l_pdata, NULL, NULL);
        isel_emit(isel, "MOV", "A", ptr_tag, NULL);
        isel_emit(isel, "XRL", "A", "#255", NULL);
        isel_emit(isel, "JZ", l_code, NULL, NULL);
        isel_emit(isel, "SJMP", l_data, NULL, NULL);

        isel_emit(isel, lb_data, NULL, NULL, NULL);
        isel_emit(isel, "MOV", scratch, ptr_lo, NULL);
        {
            char ref[16];
            snprintf(ref, sizeof(ref), "@%s", scratch);
            isel_emit(isel, "MOV", "A", ref, ssa);
        }
        isel_emit(isel, "SJMP", l_done, NULL, NULL);

        isel_emit(isel, lb_xdata, NULL, NULL, NULL);
        isel_emit(isel, "MOV", "DPL", ptr_lo, NULL);
        isel_emit(isel, "MOV", "DPH", ptr_hi, NULL);
        isel_emit(isel, "MOVX", "A", "@DPTR", ssa);
        isel_emit(isel, "SJMP", l_done, NULL, NULL);

        isel_emit(isel, lb_pdata, NULL, NULL, NULL);
        isel_emit(isel, "MOV", scratch, ptr_lo, NULL);
        {
            char ref[16];
            snprintf(ref, sizeof(ref), "@%s", scratch);
            isel_emit(isel, "MOVX", "A", ref, ssa);
        }
        isel_emit(isel, "SJMP", l_done, NULL, NULL);

        isel_emit(isel, lb_code, NULL, NULL, NULL);
        isel_emit(isel, "MOV", "DPL", ptr_lo, NULL);
        isel_emit(isel, "MOV", "DPH", ptr_hi, NULL);
        isel_emit(isel, "CLR", "A", NULL, NULL);
        isel_emit(isel, "MOVC", "A", "@A+DPTR", ssa);

        isel_emit(isel, lb_done, NULL, NULL, NULL);
        if (load_size == 2) {
            isel_emit(isel, "MOV", "B", "A", NULL);
        } else {
            emit_load_save_byte(isel, phys_dst_reg, load_size, false, NULL);
        }

        if (load_size == 2) {
            char *l_data_hi = isel_new_label(isel, "Lgptr_data_hi");
            char *l_xdata_hi = isel_new_label(isel, "Lgptr_xdata_hi");
            char *l_pdata_hi = isel_new_label(isel, "Lgptr_pdata_hi");
            char *l_code_hi = isel_new_label(isel, "Lgptr_code_hi");
            char *l_done_hi = isel_new_label(isel, "Lgptr_done_hi");
            char lb_data_hi[64], lb_xdata_hi[64], lb_pdata_hi[64], lb_code_hi[64], lb_done_hi[64];

            snprintf(lb_data_hi, sizeof(lb_data_hi), "%s:", l_data_hi);
            snprintf(lb_xdata_hi, sizeof(lb_xdata_hi), "%s:", l_xdata_hi);
            snprintf(lb_pdata_hi, sizeof(lb_pdata_hi), "%s:", l_pdata_hi);
            snprintf(lb_code_hi, sizeof(lb_code_hi), "%s:", l_code_hi);
            snprintf(lb_done_hi, sizeof(lb_done_hi), "%s:", l_done_hi);

            isel_emit(isel, "MOV", "A", ptr_tag, NULL);
            isel_emit(isel, "JZ", l_data_hi, NULL, NULL);
            isel_emit(isel, "MOV", "A", ptr_tag, NULL);
            isel_emit(isel, "XRL", "A", "#1", NULL);
            isel_emit(isel, "JZ", l_xdata_hi, NULL, NULL);
            isel_emit(isel, "MOV", "A", ptr_tag, NULL);
            isel_emit(isel, "XRL", "A", "#254", NULL);
            isel_emit(isel, "JZ", l_pdata_hi, NULL, NULL);
            isel_emit(isel, "MOV", "A", ptr_tag, NULL);
            isel_emit(isel, "XRL", "A", "#255", NULL);
            isel_emit(isel, "JZ", l_code_hi, NULL, NULL);
            isel_emit(isel, "SJMP", l_data_hi, NULL, NULL);

            isel_emit(isel, lb_data_hi, NULL, NULL, NULL);
            isel_emit(isel, "MOV", scratch, ptr_lo, NULL);
            isel_emit(isel, "INC", scratch, NULL, NULL);
            {
                char ref[16];
                snprintf(ref, sizeof(ref), "@%s", scratch);
                isel_emit(isel, "MOV", "A", ref, NULL);
            }
            isel_emit(isel, "SJMP", l_done_hi, NULL, NULL);

            isel_emit(isel, lb_xdata_hi, NULL, NULL, NULL);
            isel_emit(isel, "MOV", "DPL", ptr_lo, NULL);
            isel_emit(isel, "MOV", "DPH", ptr_hi, NULL);
            isel_emit(isel, "INC", "DPTR", NULL, NULL);
            isel_emit(isel, "MOVX", "A", "@DPTR", NULL);
            isel_emit(isel, "SJMP", l_done_hi, NULL, NULL);

            isel_emit(isel, lb_pdata_hi, NULL, NULL, NULL);
            isel_emit(isel, "MOV", scratch, ptr_lo, NULL);
            isel_emit(isel, "INC", scratch, NULL, NULL);
            {
                char ref[16];
                snprintf(ref, sizeof(ref), "@%s", scratch);
                isel_emit(isel, "MOVX", "A", ref, NULL);
            }
            isel_emit(isel, "SJMP", l_done_hi, NULL, NULL);

            isel_emit(isel, lb_code_hi, NULL, NULL, NULL);
            isel_emit(isel, "MOV", "DPL", ptr_lo, NULL);
            isel_emit(isel, "MOV", "DPH", ptr_hi, NULL);
            isel_emit(isel, "INC", "DPTR", NULL, NULL);
            isel_emit(isel, "CLR", "A", NULL, NULL);
            isel_emit(isel, "MOVC", "A", "@A+DPTR", NULL);

            isel_emit(isel, lb_done_hi, NULL, NULL, NULL);
            if (phys_dst_reg >= 0) {
                const char* dst_hi = isel_reg_name(phys_dst_reg);
                const char* dst_lo = isel_reg_name(phys_dst_reg + 1);
                if (strcmp(dst_hi, "A") != 0) {
                    isel_emit(isel, "MOV", dst_hi, "A", NULL);
                }
                if (strcmp(dst_lo, "B") != 0) {
                    isel_emit(isel, "MOV", dst_lo, "B", NULL);
                }
            }

            free(l_data_hi);
            free(l_xdata_hi);
            free(l_pdata_hi);
            free(l_code_hi);
            free(l_done_hi);
        }

        store_spilled_mem_result(isel, ins, phys_dst_reg, load_size);
        if (scratch_reg >= 0) free_temp_reg(isel, scratch_reg, 1);
        free(l_data);
        free(l_xdata);
        free(l_pdata);
        free(l_code);
        free(l_done);
        free(ssa);
        return true;
    }

    if (scratch_reg >= 0) free_temp_reg(isel, scratch_reg, 1);

    free(ssa);
    return false;
}

static bool emit_store_to_pointer_value(ISelContext* isel, Instr* ins, ValueName ptr, ValueName val) {
    Ctype* ptr_type = get_value_type(isel, ptr);
    if (!ptr_type || ptr_type->type != CTYPE_PTR) return false;

    int ptr_abi_size = c51_abi_type_size(ptr_type);
    int store_size = ins->mem_type ? c51_abi_type_size(ins->mem_type)
                                   : (ptr_type->ptr ? c51_abi_type_size(ptr_type->ptr) : get_value_size(isel, val));
    if (store_size < 1) store_size = 1;
    if (store_size > 2) store_size = 2;

    int ptr_reg = isel_get_value_reg(isel, ptr);
    if (ptr_reg == SPILL_REG) {
        ptr_reg = isel_reload_spill(isel, ptr, ptr_abi_size, ins);
    }
    if (ptr_reg < 0) return false;

    int ptr_space = get_mem_space(ptr_type);
    const char* val_lo = isel_get_extended_lo_reg(isel, val, store_size);
    const char* val_hi = (store_size == 2) ? isel_get_extended_hi_reg(isel, val, store_size) : NULL;
    int scratch_reg = -1;
    const char* scratch = NULL;

    if (ptr_abi_size == 1 || ptr_abi_size == 3 || ((ptr_space == 1 || ptr_space == 2 || ptr_space == 3) && ptr_abi_size == 2)) {
        scratch_reg = alloc_indirect_scratch_reg(isel);
        scratch = (scratch_reg >= 0) ? isel_reg_name(scratch_reg) : "R0";
    }

    if (ptr_abi_size == 1) {
        const char* ptr_lo = isel_reg_name(ptr_reg);
        char ref[16];

        isel_emit(isel, "MOV", scratch, ptr_lo, NULL);
        if (strcmp(val_lo, "A") != 0) emit_mov(isel, "A", val_lo, ins);
        snprintf(ref, sizeof(ref), "@%s", scratch);
        if (ptr_space == 3) isel_emit(isel, "MOVX", ref, "A", instr_to_ssa_str(ins));
        else isel_emit(isel, "MOV", ref, "A", instr_to_ssa_str(ins));

        if (store_size == 2 && val_hi) {
            isel_emit(isel, "INC", scratch, NULL, NULL);
            if (strcmp(val_hi, "A") != 0) emit_mov(isel, "A", val_hi, NULL);
            snprintf(ref, sizeof(ref), "@%s", scratch);
            if (ptr_space == 3) isel_emit(isel, "MOVX", ref, "A", NULL);
            else isel_emit(isel, "MOV", ref, "A", NULL);
        }

        if (scratch_reg >= 0) free_temp_reg(isel, scratch_reg, 1);
        return true;
    }

    if (ptr_abi_size == 2) {
        const char* ptr_lo = isel_get_lo_reg(isel, ptr);
        const char* ptr_hi = isel_get_hi_reg(isel, ptr);
        if (ptr_space == 6) return false;

        if (ptr_space == 1 || ptr_space == 2 || ptr_space == 3) {
            char ref[16];
            isel_emit(isel, "MOV", scratch, ptr_lo, NULL);
            if (strcmp(val_lo, "A") != 0) emit_mov(isel, "A", val_lo, ins);
            snprintf(ref, sizeof(ref), "@%s", scratch);
            if (ptr_space == 3) isel_emit(isel, "MOVX", ref, "A", instr_to_ssa_str(ins));
            else isel_emit(isel, "MOV", ref, "A", instr_to_ssa_str(ins));

            if (store_size == 2 && val_hi) {
                isel_emit(isel, "INC", scratch, NULL, NULL);
                if (strcmp(val_hi, "A") != 0) emit_mov(isel, "A", val_hi, NULL);
                snprintf(ref, sizeof(ref), "@%s", scratch);
                if (ptr_space == 3) isel_emit(isel, "MOVX", ref, "A", NULL);
                else isel_emit(isel, "MOV", ref, "A", NULL);
            }

            if (scratch_reg >= 0) free_temp_reg(isel, scratch_reg, 1);
            return true;
        }

        isel_emit(isel, "MOV", "DPL", ptr_lo, NULL);
        isel_emit(isel, "MOV", "DPH", ptr_hi, NULL);
        if (strcmp(val_lo, "A") != 0) emit_mov(isel, "A", val_lo, ins);
        isel_emit(isel, "MOVX", "@DPTR", "A", instr_to_ssa_str(ins));

        if (store_size == 2 && val_hi) {
            isel_emit(isel, "INC", "DPTR", NULL, NULL);
            if (strcmp(val_hi, "A") != 0) emit_mov(isel, "A", val_hi, NULL);
            isel_emit(isel, "MOVX", "@DPTR", "A", NULL);
        }

        return true;
    }

    if (ptr_abi_size == 3 && ptr_reg + 2 < 8) {
        const char* ptr_lo = isel_reg_name(ptr_reg);
        const char* ptr_hi = isel_reg_name(ptr_reg + 1);
        const char* ptr_tag = isel_reg_name(ptr_reg + 2);
        char *l_data = isel_new_label(isel, "Lsptr_data");
        char *l_xdata = isel_new_label(isel, "Lsptr_xdata");
        char *l_pdata = isel_new_label(isel, "Lsptr_pdata");
        char *l_done = isel_new_label(isel, "Lsptr_done");
        char lb_data[64], lb_xdata[64], lb_pdata[64], lb_done[64];

        snprintf(lb_data, sizeof(lb_data), "%s:", l_data);
        snprintf(lb_xdata, sizeof(lb_xdata), "%s:", l_xdata);
        snprintf(lb_pdata, sizeof(lb_pdata), "%s:", l_pdata);
        snprintf(lb_done, sizeof(lb_done), "%s:", l_done);

        isel_emit(isel, "MOV", "A", ptr_tag, NULL);
        isel_emit(isel, "JZ", l_data, NULL, NULL);
        isel_emit(isel, "MOV", "A", ptr_tag, NULL);
        isel_emit(isel, "XRL", "A", "#1", NULL);
        isel_emit(isel, "JZ", l_xdata, NULL, NULL);
        isel_emit(isel, "MOV", "A", ptr_tag, NULL);
        isel_emit(isel, "XRL", "A", "#254", NULL);
        isel_emit(isel, "JZ", l_pdata, NULL, NULL);
        isel_emit(isel, "SJMP", l_done, NULL, NULL);

        isel_emit(isel, lb_data, NULL, NULL, NULL);
        isel_emit(isel, "MOV", scratch, ptr_lo, NULL);
        if (strcmp(val_lo, "A") != 0) emit_mov(isel, "A", val_lo, ins);
        {
            char ref[16];
            snprintf(ref, sizeof(ref), "@%s", scratch);
            isel_emit(isel, "MOV", ref, "A", instr_to_ssa_str(ins));
        }
        if (store_size == 2 && val_hi) {
            isel_emit(isel, "INC", scratch, NULL, NULL);
            if (strcmp(val_hi, "A") != 0) emit_mov(isel, "A", val_hi, NULL);
            {
                char ref[16];
                snprintf(ref, sizeof(ref), "@%s", scratch);
                isel_emit(isel, "MOV", ref, "A", NULL);
            }
        }
        isel_emit(isel, "SJMP", l_done, NULL, NULL);

        isel_emit(isel, lb_xdata, NULL, NULL, NULL);
        isel_emit(isel, "MOV", "DPL", ptr_lo, NULL);
        isel_emit(isel, "MOV", "DPH", ptr_hi, NULL);
        if (strcmp(val_lo, "A") != 0) emit_mov(isel, "A", val_lo, ins);
        isel_emit(isel, "MOVX", "@DPTR", "A", instr_to_ssa_str(ins));
        if (store_size == 2 && val_hi) {
            isel_emit(isel, "INC", "DPTR", NULL, NULL);
            if (strcmp(val_hi, "A") != 0) emit_mov(isel, "A", val_hi, NULL);
            isel_emit(isel, "MOVX", "@DPTR", "A", NULL);
        }
        isel_emit(isel, "SJMP", l_done, NULL, NULL);

        isel_emit(isel, lb_pdata, NULL, NULL, NULL);
        isel_emit(isel, "MOV", scratch, ptr_lo, NULL);
        if (strcmp(val_lo, "A") != 0) emit_mov(isel, "A", val_lo, ins);
        {
            char ref[16];
            snprintf(ref, sizeof(ref), "@%s", scratch);
            isel_emit(isel, "MOVX", ref, "A", instr_to_ssa_str(ins));
        }
        if (store_size == 2 && val_hi) {
            isel_emit(isel, "INC", scratch, NULL, NULL);
            if (strcmp(val_hi, "A") != 0) emit_mov(isel, "A", val_hi, NULL);
            {
                char ref[16];
                snprintf(ref, sizeof(ref), "@%s", scratch);
                isel_emit(isel, "MOVX", ref, "A", NULL);
            }
        }

        isel_emit(isel, lb_done, NULL, NULL, NULL);

        if (scratch_reg >= 0) free_temp_reg(isel, scratch_reg, 1);
        free(l_data);
        free(l_xdata);
        free(l_pdata);
        free(l_done);
        return true;
    }

    if (scratch_reg >= 0) free_temp_reg(isel, scratch_reg, 1);
    return false;
}

void emit_offset(ISelContext* isel, Instr* ins) {
    if (!ins->args || ins->args->len < 2) return;
    ValueName base = *(ValueName*)list_get(ins->args, 0);
    ValueName idx = *(ValueName*)list_get(ins->args, 1);

    /* Optimization: OFFSET(ADDR(sym)/direct-DATA-sym, const) where result only
       used as ptr in LOAD/STORE â†?skip code generation entirely.
       emit_load/emit_store already handle OFFSET(ADDR(sym), const) via their
       look-through logic, so the pointer value never needs to be in a register. */
    if (isel && isel->ctx && isel->ctx->current_func) {
        int64_t idx_imm = 0;
        bool idx_is_imm_early = try_get_value_const(isel, idx, &idx_imm);
        if (idx_is_imm_early) {
            /* Resolve base symbol */
            const char *osym = NULL;
            Func *f = isel->ctx->current_func;
            Instr *bdef = find_def_instr_in_func(f, base);
            if (bdef && bdef->op == IROP_ADDR) {
                if (isel->ctx->value_to_addr) {
                    char *bk = int_to_key(bdef->dest);
                    osym = (const char*)dict_get(isel->ctx->value_to_addr, bk);
                    free(bk);
                }
            } else if (bdef && bdef->op == IROP_LOAD
                       && bdef->args && bdef->args->len >= 1) {
                ValueName inner = *(ValueName*)list_get(bdef->args, 0);
                Instr *idef2 = find_def_instr_in_func(f, inner);
                if (idef2 && idef2->op == IROP_ADDR && isel->ctx->value_to_addr) {
                    char *bk = int_to_key(idef2->dest);
                    osym = (const char*)dict_get(isel->ctx->value_to_addr, bk);
                    free(bk);
                }
            } else if (isel->ctx->value_to_addr) {
                char *bk = int_to_key(base);
                osym = (const char*)dict_get(isel->ctx->value_to_addr, bk);
                free(bk);
            }
            if (osym) {
                SectionKind osec = get_symbol_section_kind(isel, osym);
                if (osec == SEC_DATA || osec == SEC_IDATA || osec == SEC_XDATA) {
                    /* Result value only used as LOAD/STORE pointer â†?no register needed */
                    if (!addr_value_needs_materialization(isel, ins->dest)) {
                        return;
                    }
                }
                /* CODE segment with constant offset â‰?255: emit_load handles this via
                 * MOV DPTR,#sym; MOV A,#off; MOVC A,@A+DPTR directly, so no register
                 * materialization is needed. */
                if (osec == SEC_CODE) {
                    int total = (int)(idx_imm * (int)(ins->imm.ival ? ins->imm.ival : 1));
                    if (total >= 0 && total <= 255 && !addr_value_needs_materialization(isel, ins->dest)) {
                        return;
                    }
                }
            }
        }
    }

    int ptr_size = get_value_size(isel, ins->dest);
    if (ptr_size < 2) ptr_size = 2;

    int dst_reg = alloc_reg_for_value(isel, ins->dest, ptr_size);
    bool temp_dst = false;
    if (dst_reg < 0) {
        dst_reg = alloc_temp_reg(isel, ins->dest, ptr_size);
        temp_dst = dst_reg >= 0;
    }
    if (dst_reg < 0) return;

    const char* dst_regs[3] = {
        isel_reg_name(dst_reg),
        isel_reg_name(dst_reg + 1),
        (ptr_size >= 3) ? isel_reg_name(dst_reg + 2) : NULL
    };
    const char* dst_lo = (ptr_size == 2) ? isel_reg_name(dst_reg + 1) : isel_reg_name(dst_reg);
    const char* dst_hi = isel_reg_name(dst_reg + (ptr_size == 2 ? 0 : 1));
    const char* dst_tag = (ptr_size >= 3) ? isel_reg_name(dst_reg + 2) : NULL;

    int scale = (int)(ins->imm.ival ? ins->imm.ival : 1);
    int64_t idx_imm = 0;
    bool idx_is_imm = try_get_value_const(isel, idx, &idx_imm);
    const char* idx_lo = NULL;
    const char* idx_hi = NULL;
    int scaled_reg = -1;
    const char* scaled_lo = NULL;
    const char* scaled_hi = NULL;

    if (!idx_is_imm) {
        idx_lo = preserve_offset_operand(isel, isel_get_extended_lo_reg(isel, idx, 2));
        idx_hi = preserve_offset_operand(isel, isel_get_extended_hi_reg(isel, idx, 2));

        bool overlap_dst = (strcmp(idx_lo, dst_lo) == 0) || (strcmp(idx_lo, dst_hi) == 0) ||
                           (strcmp(idx_hi, dst_lo) == 0) || (strcmp(idx_hi, dst_hi) == 0);
        if (scale != 1 || overlap_dst) {
            scaled_reg = alloc_temp_reg(isel, -1, 2);
            if (scaled_reg >= 0) {
                scaled_hi = isel_reg_name(scaled_reg);
                scaled_lo = isel_reg_name(scaled_reg + 1);
                emit_mov(isel, scaled_lo, idx_lo, ins);
                emit_mov(isel, scaled_hi, idx_hi, NULL);
            }
        }

        if (!scaled_lo) {
            scaled_lo = idx_lo;
            scaled_hi = idx_hi;
        }

        for (int i = 1; scaled_reg >= 0 && i < scale; i++) {
            emit_mov(isel, "A", scaled_lo, NULL);
            isel_emit(isel, "ADD", "A", preserve_offset_operand(isel, idx_lo), NULL);
            emit_mov(isel, scaled_lo, "A", NULL);
            emit_mov(isel, "A", scaled_hi, NULL);
            isel_emit(isel, "ADDC", "A", preserve_offset_operand(isel, idx_hi), NULL);
            emit_mov(isel, scaled_hi, "A", NULL);
        }
    }

    int base_reg = isel_get_value_reg(isel, base);
    if (base_reg == SPILL_REG) {
        base_reg = isel_reload_spill(isel, base, ptr_size, ins);
    }
    if (base_reg >= 0) {
        if (ptr_size == 2) {
            emit_mov(isel, dst_hi, isel_reg_name(base_reg), ins);
            emit_mov(isel, dst_lo, isel_reg_name(base_reg + 1), NULL);
        } else {
            emit_mov(isel, dst_lo, isel_reg_name(base_reg), ins);
            emit_mov(isel, dst_hi, isel_reg_name(base_reg + 1), NULL);
            emit_mov(isel, dst_tag, isel_reg_name(base_reg + 2), NULL);
        }
    } else {
        const char* sym = lookup_value_addr_symbol(isel, base);
        if (!sym) {
            if (scaled_reg >= 0) free_temp_reg(isel, scaled_reg, 2);
            if (temp_dst) free_temp_reg(isel, dst_reg, ptr_size);
            return;
        }
        emit_materialize_pointer_symbol(isel, sym, ptr_size, dst_lo, dst_hi, dst_tag, ins);
    }

    if (idx_is_imm) {
        int total = (int)(idx_imm * scale);
        if (total != 0) {
            char imm_lo[32], imm_hi[32];
            snprintf(imm_lo, sizeof(imm_lo), "#%d", total & 0xFF);
            snprintf(imm_hi, sizeof(imm_hi), "#%d", (total >> 8) & 0xFF);
            if ((total & 0xFF) != 0) {
                /* low byte: MOV A, dst_lo; ADD A, #lo; MOV dst_lo, A */
                emit_mov(isel, "A", dst_lo, NULL);
                isel_emit(isel, "ADD", "A", imm_lo, NULL);
                emit_mov(isel, dst_lo, "A", NULL);
            }
            /* high byte: MOV A, dst_hi; ADDC A, #hi; MOV dst_hi, A
             * When low byte was 0 we skipped the ADD, so carry is clear â†?
             * use ADD instead of ADDC to avoid spurious carry dependency. */
            int hi_byte = (total >> 8) & 0xFF;
            bool low_was_skipped = ((total & 0xFF) == 0);
            if (hi_byte != 0) {
                emit_mov(isel, "A", dst_hi, NULL);
                if (low_was_skipped) {
                    isel_emit(isel, "ADD", "A", imm_hi, NULL);
                } else {
                    isel_emit(isel, "ADDC", "A", imm_hi, NULL);
                }
                emit_mov(isel, dst_hi, "A", NULL);
            } else if (!low_was_skipped) {
                /* hi imm == 0 but low was non-zero: still need ADDC A, #0 to
                 * propagate carry into the high byte */
                emit_mov(isel, "A", dst_hi, NULL);
                isel_emit(isel, "ADDC", "A", "#0", NULL);
                emit_mov(isel, dst_hi, "A", NULL);
            }
        }
    } else {
        emit_mov(isel, "A", dst_lo, NULL);
        isel_emit(isel, "ADD", "A", preserve_offset_operand(isel, scaled_lo), NULL);
        emit_mov(isel, dst_lo, "A", NULL);

        emit_mov(isel, "A", dst_hi, NULL);
        isel_emit(isel, "ADDC", "A", preserve_offset_operand(isel, scaled_hi), NULL);
        emit_mov(isel, dst_hi, "A", NULL);

        if (scaled_reg >= 0) free_temp_reg(isel, scaled_reg, 2);
    }

    store_spilled_mem_result(isel, ins, dst_reg, ptr_size);
    if (temp_dst) free_temp_reg(isel, dst_reg, ptr_size);

}

void emit_store(ISelContext* isel, Instr* ins) {
    ValueName ptr = -1, val = -1;
    if (ins->args && ins->args->len > 0) {
        ptr = *(ValueName*)list_get(ins->args, 0);
    }
    if (ins->args && ins->args->len > 1) {
        val = *(ValueName*)list_get(ins->args, 1);
    }

    const char* var_name = NULL;
    if (isel->ctx && isel->ctx->value_to_addr) {
        char* key = int_to_key(ptr);
        var_name = (const char*)dict_get(isel->ctx->value_to_addr, key);
        free(key);
    }

    const char* label = NULL;
    if (!var_name && ins->labels && ins->labels->len > 0) {
        label = list_get(ins->labels, 0);
        if (label && label[0] == '@') {
            var_name = label + 1;
        } else {
            var_name = label;
        }
    }

    if ((!ins->labels || ins->labels->len == 0) && ptr > 0) {
        bool allow_pointer_store = true;
        if (isel->ctx && isel->ctx->current_func) {
            Instr *def = find_def_instr_in_func(isel->ctx->current_func, ptr);
            if (def && def->op == IROP_ADDR) {
                allow_pointer_store = false;
            }
            /* Optimization: STORE through OFFSET(ADDR(sym)/LOAD(ADDR(sym)), const) â†?direct sym+off store */
            if (allow_pointer_store && def && def->op == IROP_OFFSET
                    && def->args && def->args->len >= 2) {
                ValueName base = *(ValueName*)list_get(def->args, 0);
                ValueName offv = *(ValueName*)list_get(def->args, 1);
                /* Resolve base: may be ADDR(sym) or LOAD(ADDR(sym)) */
                const char *sym = NULL;
                Instr *bdef = find_def_instr_in_func(isel->ctx->current_func, base);
                if (bdef && bdef->op == IROP_ADDR) {
                    /* OFFSET(ADDR(sym), k) */
                    if (isel->ctx->value_to_addr) {
                        char *bkey = int_to_key(bdef->dest);
                        sym = (const char*)dict_get(isel->ctx->value_to_addr, bkey);
                        free(bkey);
                    }
                } else if (bdef && bdef->op == IROP_LOAD
                           && bdef->args && bdef->args->len >= 1) {
                    /* OFFSET(LOAD(ADDR(sym)), k) */
                    ValueName inner = *(ValueName*)list_get(bdef->args, 0);
                    Instr *idef = find_def_instr_in_func(isel->ctx->current_func, inner);
                    if (idef && idef->op == IROP_ADDR && isel->ctx->value_to_addr) {
                        char *bkey = int_to_key(idef->dest);
                        sym = (const char*)dict_get(isel->ctx->value_to_addr, bkey);
                        free(bkey);
                    }
                } else {
                    /* direct lookup in value_to_addr */
                    if (isel->ctx->value_to_addr) {
                        char *bkey = int_to_key(base);
                        sym = (const char*)dict_get(isel->ctx->value_to_addr, bkey);
                        free(bkey);
                    }
                }
                if (sym) {
                    Instr *cdef = find_def_instr_in_func(isel->ctx->current_func, offv);
                    if (cdef && cdef->op == IROP_CONST) {
                        int64_t idx_imm = cdef->imm.ival;
                        int scale = (int)(def->imm.ival ? def->imm.ival : 1);
                        int off = (int)(idx_imm * scale);
                        SectionKind sym_sec = get_symbol_section_kind(isel, sym);
                        if (sym_sec == SEC_DATA || sym_sec == SEC_IDATA || sym_sec == SEC_XDATA) {
                            int store_size = ins->mem_type ? c51_abi_type_size(ins->mem_type) : 1;
                            if (store_size < 1) store_size = 1;
                            if (store_size > 2) store_size = 2;
                            const char* vlo = isel_get_extended_lo_reg(isel, val, store_size);
                            const char* vhi = (store_size == 2) ? isel_get_extended_hi_reg(isel, val, store_size) : NULL;
                            emit_store_symbol_byte(isel, sym, off, vlo, ins);
                            if (store_size == 2 && vhi) {
                                emit_store_symbol_byte(isel, sym, off + 1, vhi, NULL);
                            }
                            return;
                        }
                    }
                }
            }
        }
        if (allow_pointer_store && emit_store_to_pointer_value(isel, ins, ptr, val)) {
            return;
        }
    }

    if (!var_name) return;

    if (label && label[0] == '@' && (!ins->args || ins->args->len == 0)) {
        if (is_sbit_type(ins->mem_type)) {
            if (ins->imm.ival) {
                isel_emit(isel, "SETB", var_name, NULL, instr_to_ssa_str(ins));
            } else {
                isel_emit(isel, "CLR", var_name, NULL, instr_to_ssa_str(ins));
            }
        } else {
            int store_size = (ins->mem_type && ins->mem_type->size > 1) ? ins->mem_type->size : 1;
            emit_store_symbol_imm_byte(isel, var_name, 0, (int)(ins->imm.ival & 0xFF), ins);
            if (store_size >= 2) {
                emit_store_symbol_imm_byte(isel, var_name, 1, (int)((ins->imm.ival >> 8) & 0xFF), NULL);
            }
        }
        return;
    }

    int space = get_mem_space(ins->mem_type);
    int val_size = ins->mem_type ? c51_abi_type_size(ins->mem_type) : get_value_size(isel, val);
    if (val_size < 1) val_size = 1;
    if (val_size > 2) val_size = 2;
    if (var_name && isel->ctx && isel->ctx->obj) {
        SectionKind sym_sec = get_symbol_section_kind(isel, var_name);
        if (sym_sec == SEC_XDATA) space = 4;
        else if (sym_sec == SEC_IDATA) space = 2;
        else if (sym_sec == SEC_CODE) space = 6;
        else space = 1;
    }

    if (is_sbit_type(ins->mem_type)) {
        const char* val_reg = isel_get_lo_reg(isel, val);
        if (strcmp(val_reg, "A") != 0) {
            isel_emit(isel, "MOV", "A", val_reg, NULL);
        }
        isel_emit(isel, "MOV", "C", "ACC.0", NULL);
        isel_emit(isel, "MOV", var_name, "C", instr_to_ssa_str(ins));
        return;
    }

    const char* val_lo = isel_get_extended_lo_reg(isel, val, val_size);
    emit_store_symbol_byte(isel, var_name, 0, val_lo, ins);
    if (val_size == 2) {
        const char* val_hi = isel_get_extended_hi_reg(isel, val, val_size);
        emit_store_symbol_byte(isel, var_name, 1, val_hi, NULL);
    }
}

void emit_addr(ISelContext* isel, Instr* ins) {
    const char* var_name = NULL;
    if (ins->labels && ins->labels->len > 0) {
        var_name = list_get(ins->labels, 0);
    }

    if (!var_name) return;

    if (isel->ctx && isel->ctx->value_to_addr) {
        char* key = int_to_key(ins->dest);
        dict_put(isel->ctx->value_to_addr, key, strdup(var_name));
    }

    if (ins->mem_type) {
        CtypeAttr attr = get_attr(ins->mem_type->attr);
        if (attr.ctype_register) {
            return;
        }
    }

    if (!addr_value_needs_materialization(isel, ins->dest)) {
        /* Skip materialization for symbols whose address is only used as a
           base in OFFSET(addr, const) chains â†?downstream emit_load/emit_store
           already fold those patterns directly.
           For CODE symbols this holds too, since emit_offset now skips
           CODE-segment OFFSET materialization and emit_load handles it. */
        return;
    }

    int ptr_size = ins->type ? c51_abi_type_size(ins->type) : get_value_size(isel, ins->dest);
    if (ptr_size < 2) ptr_size = 2;

    int reg = safe_alloc_reg_for_value(isel, ins->dest, ptr_size);
    int phys_reg = reg;
    bool temp_result = false;
    if (phys_reg < 0 || phys_reg + ptr_size - 1 > 7) {
        phys_reg = alloc_temp_reg(isel, ins ? ins->dest : -1, ptr_size);
        temp_result = phys_reg >= 0;
    }
    if (phys_reg < 0) phys_reg = 0;

    const char* dst_lo = (ptr_size == 2) ? isel_reg_name(phys_reg + 1) : isel_reg_name(phys_reg);
    const char* dst_hi = (ptr_size >= 2) ? isel_reg_name(phys_reg + (ptr_size == 2 ? 0 : 1)) : NULL;
    const char* dst_tag = (ptr_size >= 3) ? isel_reg_name(phys_reg + 2) : NULL;
    emit_materialize_pointer_symbol(isel, var_name, ptr_size, dst_lo, dst_hi, dst_tag, ins);
    store_spilled_mem_result(isel, ins, phys_reg, ptr_size);
    if (temp_result) {
        free_temp_reg(isel, phys_reg, ptr_size);
    }
}

void emit_load(ISelContext* isel, Instr* ins) {
    ValueName ptr = -1;
    if (ins->args && ins->args->len > 0) {
        ptr = *(ValueName*)list_get(ins->args, 0);
    }

    if ((!ins->labels || ins->labels->len == 0) && ptr > 0) {
        bool allow_pointer_deref = true;
        if (isel->ctx && isel->ctx->current_func) {
            Instr* def = find_def_instr_in_func(isel->ctx->current_func, ptr);
            if (def && def->op == IROP_ADDR) {
                allow_pointer_deref = false;
                /* Optimization: load(addr(sym)) where result only used as base in
                   offset(result, const, scale) and all those offsets are only used
                   by load/store â†?skip emitting this load entirely.
                   emit_load/emit_store already look through LOAD(ADDR(sym)) chains. */
                if (ins->dest > 0) {
                    const char *sym_early = NULL;
                    if (isel->ctx->value_to_addr) {
                        char *bk = int_to_key(def->dest);
                        sym_early = (const char*)dict_get(isel->ctx->value_to_addr, bk);
                        free(bk);
                    }
                    if (sym_early) {
                        SectionKind sec_early = get_symbol_section_kind(isel, sym_early);
                        if (sec_early == SEC_DATA || sec_early == SEC_IDATA || sec_early == SEC_XDATA) {
                            /* Check all uses of ins->dest are OFFSET with const idx,
                               and all those OFFSET results only used by LOAD/STORE */
                            bool all_uses_foldable = true;
                            bool has_any_use = false;
                            Func *f = isel->ctx->current_func;
                            for (Iter bbit = list_iter(f->blocks); !iter_end(bbit) && all_uses_foldable;) {
                                Block *blk = iter_next(&bbit);
                                if (!blk || !blk->instrs) continue;
                                for (Iter iit2 = list_iter(blk->instrs); !iter_end(iit2) && all_uses_foldable;) {
                                    Instr *user = iter_next(&iit2);
                                    if (!user || !user->args) continue;
                                    for (int ai = 0; ai < user->args->len; ai++) {
                                        ValueName *av = list_get(user->args, ai);
                                        if (!av || *av != ins->dest) continue;
                                        has_any_use = true;
                                        /* Must be OFFSET(dest, const, scale) */
                                        if (user->op != IROP_OFFSET || ai != 0) {
                                            all_uses_foldable = false; break;
                                        }
                                        /* idx (arg 1) must be const */
                                        if (user->args->len < 2) { all_uses_foldable = false; break; }
                                        ValueName offidx = *(ValueName*)list_get(user->args, 1);
                                        int64_t dummy = 0;
                                        if (!try_get_value_const(isel, offidx, &dummy)) {
                                            all_uses_foldable = false; break;
                                        }
                                        /* OFFSET result only used by LOAD/STORE */
                                        if (!addr_value_needs_materialization(isel, user->dest)) {
                                            /* already confirmed: only used as ptr in load/store */
                                        } else {
                                            all_uses_foldable = false; break;
                                        }
                                    }
                                    if (!all_uses_foldable) break;
                                }
                            }
                            if (all_uses_foldable && has_any_use) {
                                return; /* skip: downstream load/store will fold via LOAD(ADDR(sym)) look-through */
                            }
                        }
                    }
                }
            }
            /* Optimization: LOAD through OFFSET(ADDR(sym)/LOAD(ADDR(sym)), const) â†?direct sym+off load */
            if (allow_pointer_deref && def && def->op == IROP_OFFSET
                    && def->args && def->args->len >= 2) {
                ValueName obase = *(ValueName*)list_get(def->args, 0);
                ValueName ooffv = *(ValueName*)list_get(def->args, 1);
                const char *osym = NULL;
                Instr *obdef = find_def_instr_in_func(isel->ctx->current_func, obase);
                if (obdef && obdef->op == IROP_ADDR) {
                    if (isel->ctx->value_to_addr) {
                        char *bk = int_to_key(obdef->dest);
                        osym = (const char*)dict_get(isel->ctx->value_to_addr, bk);
                        free(bk);
                    }
                } else if (obdef && obdef->op == IROP_LOAD
                           && obdef->args && obdef->args->len >= 1) {
                    ValueName inner = *(ValueName*)list_get(obdef->args, 0);
                    Instr *idef2 = find_def_instr_in_func(isel->ctx->current_func, inner);
                    if (idef2 && idef2->op == IROP_ADDR && isel->ctx->value_to_addr) {
                        char *bk = int_to_key(idef2->dest);
                        osym = (const char*)dict_get(isel->ctx->value_to_addr, bk);
                        free(bk);
                    }
                } else if (isel->ctx->value_to_addr) {
                    char *bk = int_to_key(obase);
                    osym = (const char*)dict_get(isel->ctx->value_to_addr, bk);
                    free(bk);
                }
                if (osym) {
                    Instr *ocdef = find_def_instr_in_func(isel->ctx->current_func, ooffv);
                    if (ocdef && ocdef->op == IROP_CONST) {
                        int64_t oidx = ocdef->imm.ival;
                        int oscale = (int)(def->imm.ival ? def->imm.ival : 1);
                        int ooff = (int)(oidx * oscale);
                        SectionKind osec = get_symbol_section_kind(isel, osym);
                        if (osec == SEC_DATA || osec == SEC_IDATA || osec == SEC_XDATA) {
                            int size = ins->type ? c51_abi_type_size(ins->type) : 1;
                            if (size < 1) size = 1;
                            if (size > 2) size = 2;
                            int reg = safe_alloc_reg_for_value(isel, ins->dest, size);
                            bool temp_r = false;
                            if (reg < 0 || reg + size - 1 > 7) {
                                reg = alloc_temp_reg(isel, ins->dest, size);
                                temp_r = reg >= 0;
                            }
                            if (reg < 0) reg = 0;
                            const char* dst_lo_r = isel_reg_name(reg + (size == 2 ? 1 : 0));
                            const char* dst_hi_r = (size == 2) ? isel_reg_name(reg) : NULL;
                            emit_load_symbol_byte(isel, osym, ooff, dst_lo_r, ins);
                            if (size == 2) {
                                emit_load_symbol_byte(isel, osym, ooff + 1, dst_hi_r ? dst_hi_r : "A", NULL);
                            }
                            store_spilled_mem_result(isel, ins, reg, size);
                            if (temp_r) free_temp_reg(isel, reg, size);
                            return;
                        }
                        /* CODE segment: use MOV DPTR, #sym; MOV A, #off; MOVC A, @A+DPTR
                         * This avoids materializing the pointer into Rx:Ry and then
                         * MOV DPL/DPH back from those registers. */
                        if (osec == SEC_CODE && ooff >= 0 && ooff <= 255) {
                            int size = ins->type ? c51_abi_type_size(ins->type) : 1;
                            if (size < 1) size = 1;
                            /* Only single-byte CODE loads are handled here (MOVC reads 1 byte) */
                            if (size == 1) {
                                char dptr_val[256];
                                snprintf(dptr_val, sizeof(dptr_val), "#%s", osym);
                                isel_emit(isel, "MOV", "DPTR", dptr_val, NULL);
                                char* ssa_str = instr_to_ssa_str(ins);
                                if (ooff == 0) {
                                    isel_emit(isel, "CLR", "A", NULL, ssa_str);
                                } else {
                                    char offstr[16];
                                    snprintf(offstr, sizeof(offstr), "#%d", ooff);
                                    isel_emit(isel, "MOV", "A", offstr, ssa_str);
                                }
                                free(ssa_str);
                                isel_emit(isel, "MOVC", "A", "@A+DPTR", NULL);
                                int reg = safe_alloc_reg_for_value(isel, ins->dest, 1);
                                const char* dst_r = (reg >= 0) ? isel_reg_name(reg) : "A";
                                if (dst_r && strcmp(dst_r, "A") != 0) {
                                    isel_emit(isel, "MOV", dst_r, "A", NULL);
                                }
                                store_spilled_mem_result(isel, ins, reg >= 0 ? reg : 0, 1);
                                return;
                            }
                        }
                    }
                }
            }
        }
        if (allow_pointer_deref && emit_load_from_pointer_value(isel, ins, ptr)) return;
    }

    const char* var_name = NULL;
    if (isel->ctx && isel->ctx->value_to_addr && ptr > 0) {
        char* key = int_to_key(ptr);
        var_name = (const char*)dict_get(isel->ctx->value_to_addr, key);
        free(key);
    }

    if (!var_name && ins->labels && ins->labels->len > 0) {
        const char* label = list_get(ins->labels, 0);
        if (label && label[0] == '@') var_name = label + 1;
        else var_name = label;
    }

    if (!var_name && ptr > 0 && isel->ctx && isel->ctx->current_func) {
        Func *f = isel->ctx->current_func;
        Instr *def = find_def_instr_in_func(f, ptr);
        if (def && def->op == IROP_OFFSET && def->args && def->args->len >= 2) {
            ValueName base = *(ValueName*)list_get(def->args, 0);
            ValueName offv = *(ValueName*)list_get(def->args, 1);
            /* Resolve base: ADDR(sym) or LOAD(ADDR(sym)) or direct lookup */
            const char *sym = NULL;
            Instr *bdef = find_def_instr_in_func(f, base);
            if (bdef && bdef->op == IROP_ADDR) {
                if (isel->ctx->value_to_addr) {
                    char *bk = int_to_key(bdef->dest);
                    sym = (const char*)dict_get(isel->ctx->value_to_addr, bk);
                    free(bk);
                }
            } else if (bdef && bdef->op == IROP_LOAD
                       && bdef->args && bdef->args->len >= 1) {
                ValueName inner = *(ValueName*)list_get(bdef->args, 0);
                Instr *idef2 = find_def_instr_in_func(f, inner);
                if (idef2 && idef2->op == IROP_ADDR && isel->ctx->value_to_addr) {
                    char *bk = int_to_key(idef2->dest);
                    sym = (const char*)dict_get(isel->ctx->value_to_addr, bk);
                    free(bk);
                }
            } else {
                if (isel->ctx->value_to_addr) {
                    char *bk = int_to_key(base);
                    sym = (const char*)dict_get(isel->ctx->value_to_addr, bk);
                    free(bk);
                }
            }
            if (sym) {
                Instr *cdef = find_def_instr_in_func(f, offv);
                if (cdef && cdef->op == IROP_CONST) {
                    int64_t idx_imm = cdef->imm.ival;
                    int scale_f = (int)(def->imm.ival ? def->imm.ival : 1);
                    int off = (int)(idx_imm * scale_f);
                    int size = ins->type ? c51_abi_type_size(ins->type) : 1;
                    if (size < 1) size = 1;
                    if (size > 2) size = 2;
                    SectionKind sym_sec = get_symbol_section_kind(isel, sym);
                    /* DATA / IDATA / XDATA: load sym+off directly */
                    if (sym_sec == SEC_DATA || sym_sec == SEC_IDATA || sym_sec == SEC_XDATA) {
                        int reg = safe_alloc_reg_for_value(isel, ins->dest, size);
                        bool temp_result = false;
                        if (reg < 0 || reg + size - 1 > 7) {
                            reg = alloc_temp_reg(isel, ins->dest, size);
                            temp_result = reg >= 0;
                        }
                        if (reg < 0) reg = 0;
                        const char* dst_lo_r = isel_reg_name(reg + (size == 2 ? 1 : 0));
                        const char* dst_hi_r = (size == 2) ? isel_reg_name(reg) : NULL;
                        emit_load_symbol_byte(isel, sym, off, dst_lo_r, ins);
                        if (size == 2) {
                            emit_load_symbol_byte(isel, sym, off + 1, dst_hi_r ? dst_hi_r : "A", NULL);
                        }
                        store_spilled_mem_result(isel, ins, reg, size);
                        if (temp_result) free_temp_reg(isel, reg, size);
                        return;
                    }
                    /* CODE segment: use MOVC */
                    if (sym_sec == SEC_CODE) {
                        char dptr_val[256];
                        snprintf(dptr_val, sizeof(dptr_val), "#%s", sym);
                        isel_emit(isel, "MOV", "DPTR", dptr_val, NULL);
                        if (off == 0) {
                            isel_emit(isel, "CLR", "A", NULL, instr_to_ssa_str(ins));
                        } else if (off >= 0 && off <= 255) {
                            char offvstr[32]; snprintf(offvstr, sizeof(offvstr), "#%d", off);
                            isel_emit(isel, "MOV", "A", offvstr, instr_to_ssa_str(ins));
                        }
                        isel_emit(isel, "MOVC", "A", "@A+DPTR", instr_to_ssa_str(ins));
                        int reg = safe_alloc_reg_for_value(isel, ins->dest, size);
                        const char* dst_lo = (reg >= 0) ? isel_reg_name(reg + (size == 2 ? 1 : 0)) : "A";
                        if (dst_lo && strcmp(dst_lo, "A") != 0) {
                            isel_emit(isel, "MOV", dst_lo, "A", NULL);
                        }
                        store_spilled_mem_result(isel, ins, reg, size);
                        return;
                    }
                }
            }
        }
    }

    if (!var_name) {
        if (emit_load_from_pointer_value(isel, ins, ptr)) return;
        return;
    }

    int space = get_mem_space(ins->mem_type);
    int size = ins->type ? c51_abi_type_size(ins->type) : 1;
    if (var_name && isel->ctx && isel->ctx->obj) {
        SectionKind sym_sec = get_symbol_section_kind(isel, var_name);
        if (sym_sec == SEC_XDATA) space = 4;
        else if (sym_sec == SEC_IDATA) space = 2;
        else if (sym_sec == SEC_CODE) space = 6;
        else space = 1;
    }
    int reg = alloc_reg_for_value(isel, ins->dest, size);
    int phys_reg = reg;
    bool temp_result = false;
    if (phys_reg < 0 || phys_reg + size - 1 > 7) {
        phys_reg = alloc_temp_reg(isel, ins ? ins->dest : -1, size);
        temp_result = phys_reg >= 0;
    }
    if (phys_reg < 0) phys_reg = 0;

    if (is_sbit_type(ins->mem_type)) {
        isel_emit(isel, "MOV", "C", var_name, instr_to_ssa_str(ins));
        isel_emit(isel, "CLR", "A", NULL, NULL);
        isel_emit(isel, "RLC", "A", NULL, NULL);
    } else if (space == 4) {
        char dptr_val[256];
        snprintf(dptr_val, sizeof(dptr_val), "#%s", var_name);
        isel_emit(isel, "MOV", "DPTR", dptr_val, NULL);
        isel_emit(isel, "MOVX", "A", "@DPTR", instr_to_ssa_str(ins));
    } else if (space == 6) {
        char dptr_val[256];
        snprintf(dptr_val, sizeof(dptr_val), "#%s", var_name);
        isel_emit(isel, "MOV", "DPTR", dptr_val, NULL);
        isel_emit(isel, "CLR", "A", NULL, NULL);
        isel_emit(isel, "MOVC", "A", "@A+DPTR", instr_to_ssa_str(ins));
    } else {
        emit_load_symbol_byte(isel, var_name, 0, "A", ins);
    }

    if (phys_reg >= 0) {
        const char* dst_reg = isel_reg_name(phys_reg + (size == 2 ? 1 : 0));
        if (dst_reg && strcmp(dst_reg, "A") != 0) {
            char* ssa = instr_to_ssa_str(ins);
            isel_emit(isel, "MOV", dst_reg, "A", ssa);
            free(ssa);
        }
    }

    if (size == 2 && phys_reg >= 0) {
        emit_load_symbol_byte(isel, var_name, 1, "A", NULL);
        const char* dst_reg_hi = isel_reg_name(phys_reg);
        if (dst_reg_hi && strcmp(dst_reg_hi, "A") != 0) {
            isel_emit(isel, "MOV", dst_reg_hi, "A", NULL);
        }
    }

    store_spilled_mem_result(isel, ins, phys_reg, size);
    if (temp_result) {
        free_temp_reg(isel, phys_reg, size);
    }
}
