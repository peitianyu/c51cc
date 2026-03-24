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

static const char* preserve_offset_operand(ISelContext* isel, const char* src) {
    if (src && strcmp(src, "A") == 0) {
        isel_emit(isel, "MOV", "B", "A", NULL);
        return "B";
    }
    return src;
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
    if (ptr_reg == -3) {
        ptr_reg = isel_reload_spill(isel, ptr, ptr_abi_size, ins);
    }
    if (ptr_reg < 0 || load_size < 1 || load_size > 2) return false;

    int ptr_space = get_mem_space(ptr_type);
    int dst_reg = alloc_reg_for_value(isel, ins->dest, load_size);
    int phys_dst_reg = dst_reg;
    if (phys_dst_reg < 0) {
        phys_dst_reg = alloc_temp_reg(isel, ins->dest, load_size);
    }
    if (phys_dst_reg < 0) {
        phys_dst_reg = 0;
    }
    if (dst_reg < 0 && dst_reg != -3 && isel && isel->ctx && isel->ctx->value_to_reg) {
        int* reg_num = malloc(sizeof(int));
        *reg_num = phys_dst_reg;
        char* key = int_to_key(ins->dest);
        dict_put(isel->ctx->value_to_reg, key, reg_num);
        dst_reg = phys_dst_reg;
    }
    char* ssa = instr_to_ssa_str(ins);
    int scratch_reg = -1;
    const char* scratch = NULL;

    if (ptr_abi_size == 1 || ptr_abi_size == 3) {
        scratch_reg = alloc_temp_reg(isel, -1, 1);
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

void emit_offset(ISelContext* isel, Instr* ins) {
    if (!ins->args || ins->args->len < 2) return;
    ValueName base = *(ValueName*)list_get(ins->args, 0);
    ValueName idx = *(ValueName*)list_get(ins->args, 1);

    int ptr_size = get_value_size(isel, ins->dest);
    if (ptr_size < 2) ptr_size = 2;

    int dst_reg = alloc_reg_for_value(isel, ins->dest, ptr_size);
    if (dst_reg < 0) dst_reg = alloc_temp_reg(isel, ins->dest, ptr_size);
    if (dst_reg < 0) return;

    const char* dst_regs[3] = {
        isel_reg_name(dst_reg),
        isel_reg_name(dst_reg + 1),
        (ptr_size >= 3) ? isel_reg_name(dst_reg + 2) : NULL
    };
    const char* dst_lo = (ptr_size == 2) ? isel_reg_name(dst_reg + 1) : isel_reg_name(dst_reg);
    const char* dst_hi = isel_reg_name(dst_reg + (ptr_size == 2 ? 0 : 1));
    const char* dst_tag = (ptr_size >= 3) ? isel_reg_name(dst_reg + 2) : NULL;

    int base_reg = isel_get_value_reg(isel, base);
    if (base_reg == -3) {
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
        if (!sym) return;
        emit_materialize_pointer_symbol(isel, sym, ptr_size, dst_lo, dst_hi, dst_tag, ins);
    }

    int scale = (int)(ins->imm.ival ? ins->imm.ival : 1);
    int64_t idx_imm = 0;
    bool idx_is_imm = try_get_value_const(isel, idx, &idx_imm);

    if (idx_is_imm) {
        int total = (int)(idx_imm * scale);
        char imm_lo[32], imm_hi[32];
        snprintf(imm_lo, sizeof(imm_lo), "#%d", total & 0xFF);
        snprintf(imm_hi, sizeof(imm_hi), "#%d", (total >> 8) & 0xFF);
        emit_mov(isel, "A", dst_lo, NULL);
        isel_emit(isel, "ADD", "A", imm_lo, NULL);
        emit_mov(isel, dst_lo, "A", NULL);
        emit_mov(isel, "A", dst_hi, NULL);
        isel_emit(isel, "ADDC", "A", imm_hi, NULL);
        emit_mov(isel, dst_hi, "A", NULL);
    } else {
        const char* idx_lo = isel_get_lo_reg(isel, idx);
        const char* idx_hi = isel_get_hi_reg(isel, idx);
        int scaled_reg = alloc_temp_reg(isel, -1, 2);
        const char* scaled_lo = idx_lo;
        const char* scaled_hi = idx_hi;

        if (scaled_reg >= 0) {
            scaled_hi = isel_reg_name(scaled_reg);
            scaled_lo = isel_reg_name(scaled_reg + 1);
            emit_mov(isel, scaled_lo, idx_lo, ins);
            emit_mov(isel, scaled_hi, idx_hi, NULL);

            for (int i = 1; i < scale; i++) {
                emit_mov(isel, "A", scaled_lo, NULL);
                isel_emit(isel, "ADD", "A", idx_lo, NULL);
                emit_mov(isel, scaled_lo, "A", NULL);
                emit_mov(isel, "A", scaled_hi, NULL);
                isel_emit(isel, "ADDC", "A", idx_hi, NULL);
                emit_mov(isel, scaled_hi, "A", NULL);
            }
        }

        emit_mov(isel, "A", dst_lo, NULL);
        isel_emit(isel, "ADD", "A", scaled_lo, NULL);
        emit_mov(isel, dst_lo, "A", NULL);

        emit_mov(isel, "A", dst_hi, NULL);
        isel_emit(isel, "ADDC", "A", scaled_hi, NULL);
        emit_mov(isel, dst_hi, "A", NULL);

        if (scaled_reg >= 0) {
            free_temp_reg(isel, scaled_reg, 2);
        }
    }

    store_spilled_mem_result(isel, ins, dst_reg, ptr_size);

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

    if (!var_name) return;

    if (label && label[0] == '@' && (!ins->args || ins->args->len == 0)) {
        if (is_sbit_type(ins->mem_type)) {
            if (ins->imm.ival) {
                isel_emit(isel, "SETB", var_name, NULL, instr_to_ssa_str(ins));
            } else {
                isel_emit(isel, "CLR", var_name, NULL, instr_to_ssa_str(ins));
            }
        } else {
            char imm_str[16];
            snprintf(imm_str, sizeof(imm_str), "#%d", (int)(ins->imm.ival & 0xFF));
            isel_emit(isel, "MOV", var_name, imm_str, instr_to_ssa_str(ins));
        }
        return;
    }

    int space = get_mem_space(ins->mem_type);
    if (var_name && isel->ctx && isel->ctx->obj) {
        SectionKind sym_sec = get_symbol_section_kind(isel, var_name);
        if (sym_sec == SEC_XDATA) space = 4;
        else if (sym_sec == SEC_IDATA) space = 2;
        else if (sym_sec == SEC_CODE) space = 6;
        else space = 1;
    }

    const char* val_reg = isel_get_lo_reg(isel, val);
    if (strcmp(val_reg, "A") != 0) {
        isel_emit(isel, "MOV", "A", val_reg, NULL);
    }

    if (is_sbit_type(ins->mem_type)) {
        isel_emit(isel, "MOV", "C", "ACC.0", NULL);
        isel_emit(isel, "MOV", var_name, "C", instr_to_ssa_str(ins));
        return;
    }

    if (space == 4) {
        char dptr_val[256];
        snprintf(dptr_val, sizeof(dptr_val), "#%s", var_name);
        isel_emit(isel, "MOV", "DPTR", dptr_val, NULL);
        isel_emit(isel, "MOVX", "@DPTR", "A", instr_to_ssa_str(ins));
    } else if (space == 2) {
        isel_emit(isel, "MOV", "R0", var_name, NULL);
        isel_emit(isel, "MOV", "@R0", "A", instr_to_ssa_str(ins));
    } else {
        isel_emit(isel, "MOV", var_name, "A", instr_to_ssa_str(ins));
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
            char *key = int_to_key(base);
            const char *sym = NULL;
            if (isel->ctx->value_to_addr) sym = (const char*)dict_get(isel->ctx->value_to_addr, key);
            free(key);
            if (sym) {
                Instr *cdef = find_def_instr_in_func(f, offv);
                if (cdef && cdef->op == IROP_CONST) {
                    int off = (int)cdef->imm.ival;
                    Instr *basedef = find_def_instr_in_func(f, base);
                    int space = basedef && basedef->mem_type ? get_mem_space(basedef->mem_type) : 0;
                    if (space == 6) {
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
                        const char* dst_lo = NULL;
                        int size = ins->type ? c51_abi_type_size(ins->type) : 1;
                        int reg = safe_alloc_reg_for_value(isel, ins->dest, size);
                        if (reg >= 0) dst_lo = isel_reg_name(reg + (size == 2 ? 1 : 0));
                        else dst_lo = "A";
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
    int reg = safe_alloc_reg_for_value(isel, ins->dest, size);

    if (ins->type && ins->type->type == CTYPE_PTR) {
        SectionKind sym_sec = get_symbol_section_kind(isel, var_name);
        if (size == 1) {
            char imm[256];
            snprintf(imm, sizeof(imm), "#%s", var_name);
            if (reg >= 0) emit_mov(isel, isel_reg_name(reg), imm, ins);
            store_spilled_mem_result(isel, ins, reg, size);
            return;
        }

        char dptr_val[256];
        snprintf(dptr_val, sizeof(dptr_val), "#%s", var_name);
        isel_emit(isel, "MOV", "DPTR", dptr_val, NULL);

        if (size == 2 && reg >= 0) {
            isel_emit(isel, "MOV", isel_reg_name(reg + 1), "DPL", instr_to_ssa_str(ins));
            isel_emit(isel, "MOV", isel_reg_name(reg), "DPH", NULL);
            store_spilled_mem_result(isel, ins, reg, size);
            return;
        }

        if (size == 3 && reg >= 0) {
            const char* tag_imm = "#0";
            if (sym_sec == SEC_XDATA) tag_imm = "#1";
            else if (sym_sec == SEC_CODE) tag_imm = "#255";
            else if (sym_sec == SEC_IDATA) tag_imm = "#0";
            emit_mov(isel, isel_reg_name(reg), "DPL", ins);
            emit_mov(isel, isel_reg_name(reg + 1), "DPH", NULL);
            emit_mov(isel, isel_reg_name(reg + 2), tag_imm, NULL);
            store_spilled_mem_result(isel, ins, reg, size);
            return;
        }
    }

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
    } else if (space == 2) {
        isel_emit(isel, "MOV", "R0", var_name, NULL);
        isel_emit(isel, "MOV", "A", "@R0", instr_to_ssa_str(ins));
    } else {
        isel_emit(isel, "MOV", "A", var_name, instr_to_ssa_str(ins));
    }

    if (reg >= 0) {
        const char* dst_reg = isel_reg_name(reg + (size == 2 ? 1 : 0));
        if (dst_reg && strcmp(dst_reg, "A") != 0) {
            char* ssa = instr_to_ssa_str(ins);
            isel_emit(isel, "MOV", dst_reg, "A", ssa);
            free(ssa);
        }
    }

    if (size == 2 && reg >= 0) {
        if (space == 4) {
            char dptr_val[256];
            snprintf(dptr_val, sizeof(dptr_val), "#(%s + 1)", var_name);
            isel_emit(isel, "MOV", "DPTR", dptr_val, NULL);
            isel_emit(isel, "MOVX", "A", "@DPTR", NULL);
        } else if (space == 6) {
            char dptr_val[256];
            snprintf(dptr_val, sizeof(dptr_val), "#(%s + 1)", var_name);
            isel_emit(isel, "MOV", "DPTR", dptr_val, NULL);
            isel_emit(isel, "CLR", "A", NULL, NULL);
            isel_emit(isel, "MOVC", "A", "@A+DPTR", NULL);
        } else {
            char source_hi[256];
            snprintf(source_hi, sizeof(source_hi), "(%s + 1)", var_name);
            isel_emit(isel, "MOV", "A", source_hi, NULL);
        }
        const char* dst_reg_hi = isel_reg_name(reg);
        if (dst_reg_hi && strcmp(dst_reg_hi, "A") != 0) {
            isel_emit(isel, "MOV", dst_reg_hi, "A", NULL);
        }
    }

    store_spilled_mem_result(isel, ins, reg, size);
}
