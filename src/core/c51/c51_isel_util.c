#include "c51_isel_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* no debug */

#include "c51_isel_regalloc.h"

static char* instr_ptr_key(const Instr* ins) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%p", (const void*)ins);
    return strdup(buf);
}

void free_br_bitinfo(void* p) {
    BrBitInfo* info = (BrBitInfo*)p;
    if (!info) return;
    free(info->bit);
    free(info);
}

void br_invert_put(ISelContext* isel, Instr* br, bool invert) {
    if (!isel || !isel->br_invert || !br) return;
    bool* v = malloc(sizeof(bool));
    if (!v) return;
    *v = invert;
    char* key = instr_ptr_key(br);
    dict_put(isel->br_invert, key, v);
}

bool br_invert_get(ISelContext* isel, Instr* br, bool* out_invert) {
    if (!isel || !isel->br_invert || !br) return false;
    char* key = instr_ptr_key(br);
    bool* v = (bool*)dict_get(isel->br_invert, key);
    free(key);
    if (!v) return false;
    if (out_invert) *out_invert = *v;
    return true;
}

void br_bitinfo_put(ISelContext* isel, Instr* br, const char* bit, bool invert) {
    if (!isel || !isel->br_bitinfo || !br || !bit) return;
    BrBitInfo* info = malloc(sizeof(BrBitInfo));
    if (!info) return;
    info->bit = strdup(bit);
    info->invert = invert;
    char* key = instr_ptr_key(br);
    dict_put(isel->br_bitinfo, key, info);
}

BrBitInfo* br_bitinfo_get(ISelContext* isel, Instr* br) {
    if (!isel || !isel->br_bitinfo || !br) return NULL;
    char buf[32];
    snprintf(buf, sizeof(buf), "%p", (const void*)br);
    return (BrBitInfo*)dict_get(isel->br_bitinfo, buf);
}

int reg_index_from_name(const char* s) {
    if (!s) return -1;
    if (s[0] == 'R' && s[1] >= '0' && s[1] <= '7' && s[2] == '\0') {
        return s[1] - '0';
    }
    return -1;
}

int alloc_temp_reg(ISelContext* isel, ValueName val, int size) {
    if (!isel) return ACC_REG;
    for (int r = C51_ALLOCATABLE_REG_MIN; r <= C51_ALLOCATABLE_REG_MAX; r++) {
        if (r + size - 1 > C51_ALLOCATABLE_REG_MAX) continue;
        bool ok = true;
        for (int j = 0; j < size; j++) {
            if (isel->reg_busy[r + j]) { ok = false; break; }
        }
        if (!ok) continue;
        for (int j = 0; j < size; j++) {
            isel->reg_busy[r + j] = true;
            isel->reg_val[r + j] = val;
        }
        return r;
    }
    return ACC_REG;
}

void free_temp_reg(ISelContext* isel, int reg, int size) {
    if (!isel || reg < 0) return;
    for (int j = 0; j < size; j++) {
        if (reg + j >= 0 && reg + j < 8) {
            isel->reg_busy[reg + j] = false;
            isel->reg_val[reg + j] = -1;
        }
    }
}

/* 直接用立即数写 IDATA/DATA spill（不需要通过 A 和 Rn 中转）
 * 用于 emit_set_bool_result 的优化路径：避免多余的 MOV A,#imm + MOV Rn,A + MOV A,Rn + MOV spill,A
 */
static void emit_store_spill_imm(ISelContext* isel, ValueName val, int size,
                                  const char* lo_imm, const char* hi_imm, Instr* ins) {
    if (!isel || !isel->ctx || val < 0 || !isel_value_is_spilled(isel, val)) return;
    char* key = int_to_key(val);
    const char* var_name = isel->ctx->value_to_addr ?
                           (const char*)dict_get(isel->ctx->value_to_addr, key) : NULL;
    free(key);
    if (!var_name) return;

    SectionKind sym_sec = get_symbol_section_kind(isel, var_name);
    if (sym_sec == SEC_IDATA) {
        /* MOV direct, #imm: 合法 8051 指令，直接写 IDATA，不需要 A */
        char* ssa = instr_to_ssa_str(ins);
        isel_emit(isel, "MOV", var_name, lo_imm, ssa);
        if (size == 2) {
            char off1[256];
            snprintf(off1, sizeof(off1), "(%s + 1)", var_name);
            isel_emit(isel, "MOV", off1, hi_imm, NULL);
        }
        free(ssa);
    } else if (sym_sec == SEC_DATA) {
        /* DATA section: 直接 MOV direct, #imm */
        char* ssa = instr_to_ssa_str(ins);
        isel_emit(isel, "MOV", var_name, lo_imm, ssa);
        if (size == 2) {
            char off1[256];
            snprintf(off1, sizeof(off1), "(%s + 1)", var_name);
            isel_emit(isel, "MOV", off1, hi_imm, NULL);
        }
        free(ssa);
    } else {
        /* XDATA 或其他：退回到用立即数通过 A 写，比 Rn 中转少一条 */
        /* 先设 A = lo_imm，再走通常路径；这里直接用 isel_store_spill_from_reg 的逻辑 */
        /* 简单起见：这里不处理 XDATA，让调用方 fallback 到老路径 */
    }
}

void emit_set_bool_result(ISelContext* isel, Instr* ins, int dst_reg, int size, bool one) {
    int phys_reg = dst_reg;
    if (phys_reg < 0 && ins) {
        phys_reg = alloc_temp_reg(isel, ins->dest, size);
    }
    if (phys_reg < 0) {
        phys_reg = 0;
    }

    const char* dst_lo = isel_reg_name(phys_reg + (size == 2 ? 1 : 0));
    const char* dst_hi = isel_reg_name(phys_reg);
    const char* imm_val = one ? "#1" : "#0";

    /* 直接用立即数写寄存器，不通过 A（省去 MOV A,#imm + MOV Rn,A = 1条） */
    emit_mov(isel, dst_lo, imm_val, ins);
    if (size == 2) {
        emit_mov(isel, dst_hi, "#0", ins);
    }

    /* 对于 IDATA/DATA spill：直接用立即数写，不通过 A（省去 MOV A,Rn + MOV spill,A = 1条） */
    ValueName dest_val = ins ? ins->dest : -1;
    if (dest_val >= 0 && isel_value_is_spilled(isel, dest_val)) {
        char* key2 = int_to_key(dest_val);
        const char* var_name2 = isel->ctx && isel->ctx->value_to_addr ?
                                (const char*)dict_get(isel->ctx->value_to_addr, key2) : NULL;
        free(key2);
        SectionKind sec2 = var_name2 ? get_symbol_section_kind(isel, var_name2) : SEC_XDATA;
        if (sec2 == SEC_IDATA || sec2 == SEC_DATA) {
            emit_store_spill_imm(isel, dest_val, size, imm_val, "#0", ins);
            return;
        }
    }
    /* 非 IDATA/DATA spill（XDATA 等）：退回到通过 A 中转的老路 */
    /* 先把 A 设为立即数，再走 isel_store_spill_from_reg */
    if (dest_val >= 0 && isel_value_is_spilled(isel, dest_val)) {
        isel_emit(isel, "MOV", "A", imm_val, NULL);
        emit_store_spilled_result(isel, dest_val, phys_reg, size, ins);
    }
}

void emit_store_spilled_result(ISelContext* isel, ValueName val, int reg, int size, Instr* ins) {
    if (reg < 0 || size < 1 || !ins || val < 0) return;
    isel_store_spill_from_reg(isel, val, reg, size, ins);
}

void emit_copy_value(ISelContext* isel, Instr* ins, ValueName src, int dst_reg, int size) {
    const char* src_lo = isel_get_lo_reg(isel, src);
    const char* dst_lo = isel_reg_name(dst_reg + (size == 2 ? 1 : 0));
    if (size == 2) {
        const char* src_hi = isel_get_hi_reg(isel, src);
        const char* dst_hi = isel_reg_name(dst_reg);
        int src_hi_tmp = -1;
        const char* src_hi_safe = src_hi;

        if (src_hi && dst_lo && strcmp(dst_lo, src_hi) == 0 && strcmp(dst_hi, src_hi) != 0) {
            src_hi_tmp = alloc_temp_reg(isel, -1, 1);
            if (src_hi_tmp >= 0) {
                src_hi_safe = isel_reg_name(src_hi_tmp);
                emit_mov(isel, src_hi_safe, src_hi, NULL);
            }
        }

        emit_mov(isel, dst_lo, src_lo, ins);
        emit_mov(isel, dst_hi, src_hi_safe, ins);

        if (src_hi_tmp >= 0) {
            free_temp_reg(isel, src_hi_tmp, 1);
        }
        return;
    }

    emit_mov(isel, dst_lo, src_lo, ins);
}

void emit_add16_regs(ISelContext* isel,
                     const char* dst_hi, const char* dst_lo,
                     const char* src_hi, const char* src_lo,
                     Instr* ins) {
    emit_mov(isel, "A", dst_lo, ins);
    isel_emit(isel, "ADD", "A", src_lo, NULL);
    emit_mov(isel, dst_lo, "A", NULL);
    emit_mov(isel, "A", dst_hi, NULL);
    isel_emit(isel, "ADDC", "A", src_hi, NULL);
    emit_mov(isel, dst_hi, "A", NULL);
}

void emit_sub16_regs(ISelContext* isel,
                     const char* dst_hi, const char* dst_lo,
                     const char* src_hi, const char* src_lo,
                     Instr* ins) {
    isel_emit(isel, "CLR", "C", NULL, NULL);
    emit_mov(isel, "A", dst_lo, ins);
    isel_emit(isel, "SUBB", "A", src_lo, NULL);
    emit_mov(isel, dst_lo, "A", NULL);
    emit_mov(isel, "A", dst_hi, NULL);
    isel_emit(isel, "SUBB", "A", src_hi, NULL);
    emit_mov(isel, dst_hi, "A", NULL);
}

bool is_memory_operand_local(const char* op) {
    if (!op) return false;
    if (strcmp(op, "A") == 0) return false;
    if (op[0] == 'R' && op[1] >= '0' && op[1] <= '7' && op[2] == '\0') return false;
    if (op[0] == '#') return false;
    return true;
}

SectionKind get_symbol_section_kind(ISelContext* isel, const char* var_name) {
    if (!isel || !isel->ctx || !isel->ctx->obj || !var_name) return SEC_DATA;
    for (Iter it = list_iter(isel->ctx->obj->symbols); !iter_end(it);) {
        Symbol *sym = iter_next(&it);
        if (sym && sym->name && strcmp(sym->name, var_name) == 0) {
            Section *s = obj_get_section(isel->ctx->obj, sym->section);
            if (s) return s->kind;
            break;
        }
    }
    return SEC_DATA;
}

const char* lookup_value_addr_symbol(ISelContext* isel, ValueName val) {
    if (!isel || !isel->ctx || !isel->ctx->value_to_addr || val <= 0) return NULL;
    char* key = int_to_key(val);
    const char* sym = (const char*)dict_get(isel->ctx->value_to_addr, key);
    free(key);
    return sym;
}

static void format_symbol_byte_ref(char* out, size_t out_size, const char* sym, int offset) {
    if (!out || out_size == 0 || !sym) return;
    if (offset <= 0) snprintf(out, out_size, "%s", sym);
    else snprintf(out, out_size, "(%s + %d)", sym, offset);
}

void emit_load_symbol_byte(ISelContext* isel, const char* sym, int offset, const char* dst, Instr* ins) {
    if (!isel || !sym || !dst) return;

    SectionKind sym_sec = get_symbol_section_kind(isel, sym);
    char ref[256];
    char* ssa = instr_to_ssa_str(ins);
    format_symbol_byte_ref(ref, sizeof(ref), sym, offset);

    if (sym_sec == SEC_XDATA) {
        char dptr_val[256];
        snprintf(dptr_val, sizeof(dptr_val), "#%s", ref);
        isel_emit(isel, "MOV", "DPTR", dptr_val, NULL);
        isel_emit(isel, "MOVX", "A", "@DPTR", ssa);
        if (strcmp(dst, "A") != 0) {
            isel_emit(isel, "MOV", dst, "A", NULL);
        }
        free(ssa);
        return;
    }

    if (sym_sec == SEC_IDATA) {
        isel_emit(isel, "MOV", "A", ref, ssa);
        if (strcmp(dst, "A") != 0) {
            isel_emit(isel, "MOV", dst, "A", NULL);
        }
        free(ssa);
        return;
    }

    if (sym_sec == SEC_CODE) {
        char dptr_val[256];
        snprintf(dptr_val, sizeof(dptr_val), "#%s", ref);
        isel_emit(isel, "MOV", "DPTR", dptr_val, NULL);
        isel_emit(isel, "CLR", "A", NULL, NULL);
        isel_emit(isel, "MOVC", "A", "@A+DPTR", ssa);
        if (strcmp(dst, "A") != 0) {
            isel_emit(isel, "MOV", dst, "A", NULL);
        }
        free(ssa);
        return;
    }

    emit_mov(isel, dst, ref, ins);
    free(ssa);
}

void emit_store_symbol_byte(ISelContext* isel, const char* sym, int offset, const char* src, Instr* ins) {
    if (!isel || !sym || !src) return;

    SectionKind sym_sec = get_symbol_section_kind(isel, sym);
    char ref[256];
    format_symbol_byte_ref(ref, sizeof(ref), sym, offset);

    if (sym_sec == SEC_XDATA) {
        char dptr_val[256];
        snprintf(dptr_val, sizeof(dptr_val), "#%s", ref);
        isel_emit(isel, "MOV", "DPTR", dptr_val, NULL);
        if (strcmp(src, "A") != 0) emit_mov(isel, "A", src, ins);
        else {
            char* ssa = instr_to_ssa_str(ins);
            free(ssa);
        }
        isel_emit(isel, "MOVX", "@DPTR", "A", NULL);
        return;
    }

    if (sym_sec == SEC_IDATA) {
        if (strcmp(src, "A") != 0) emit_mov(isel, "A", src, ins);
        else {
            char* ssa = instr_to_ssa_str(ins);
            free(ssa);
        }
        isel_emit(isel, "MOV", ref, "A", NULL);
        return;
    }

    emit_mov(isel, ref, src, ins);
}

void emit_store_symbol_imm_byte(ISelContext* isel, const char* sym, int offset, int value, Instr* ins) {
    char imm[32];
    snprintf(imm, sizeof(imm), "#%d", value & 0xFF);
    emit_store_symbol_byte(isel, sym, offset, imm, ins);
}

int isel_reload_spill(ISelContext* isel, ValueName val, int size, Instr* ins) {
    if (!isel || !isel->ctx) return -2;
    char* key = int_to_key(val);
    char* var_name = NULL;
    if (isel->ctx->value_to_addr) {
        var_name = (char*)dict_get(isel->ctx->value_to_addr, key);
    }
    free(key);

    if (!var_name) return -2;

    if (isel->acc_busy && isel->acc_val == val) {
        return -2;
    }

    if (isel->ctx && isel->ctx->value_to_reg) {
        char* k = int_to_key(val);
        int* existing = (int*)dict_get(isel->ctx->value_to_reg, k);
        free(k);
        if (existing && *existing != SPILL_REG) return *existing;
    }

    int reg = alloc_temp_reg(isel, val, size);
    const char* ssa = ins ? instr_to_ssa_str(ins) : NULL;

    if (reg >= 0) {
        const char* dst_lo = isel_reg_name(reg + (size == 2 ? 1 : 0));
        emit_load_symbol_byte(isel, var_name, 0, dst_lo, ins);
        if (ssa) { free((void*)ssa); ssa = NULL; }

        if (size == 2) {
            const char* dst_hi = isel_reg_name(reg);
            emit_load_symbol_byte(isel, var_name, 1, dst_hi, NULL);
        } else if (size >= 3) {
            const char* dst_hi = isel_reg_name(reg + 1);
            const char* dst_tag = isel_reg_name(reg + 2);
            emit_load_symbol_byte(isel, var_name, 1, dst_hi, NULL);
            emit_load_symbol_byte(isel, var_name, 2, dst_tag, NULL);
        }
        return reg;
    } else {
        if (isel->acc_busy && isel->acc_val == val) {
            if (ssa) free((void*)ssa);
            return -2;
        }
        if (ssa) free((void*)ssa);
        return -2;
    }
}

bool isel_value_is_spilled(ISelContext* isel, ValueName val) {
    if (!isel || !isel->ctx || !isel->ctx->value_to_reg) return false;
    char* key = int_to_key(val);
    int* reg_ptr = (int*)dict_get(isel->ctx->value_to_reg, key);
    free(key);
    return reg_ptr && *reg_ptr == SPILL_REG;
}

void isel_store_spill_from_reg(ISelContext* isel, ValueName val, int reg, int size, Instr* ins) {
    if (!isel || !isel->ctx || reg < 0 || !isel_value_is_spilled(isel, val)) return;

    char* key = int_to_key(val);
    const char* var_name = isel->ctx->value_to_addr ? (const char*)dict_get(isel->ctx->value_to_addr, key) : NULL;
    free(key);
    if (!var_name) return;

    SectionKind sym_sec = get_symbol_section_kind(isel, var_name);
    const char* src_lo = isel_reg_name(reg + (size == 2 ? 1 : 0));
    const char* src_hi = isel_reg_name(reg);
    const char* src_ptr_hi = (size >= 3) ? isel_reg_name(reg + 1) : NULL;
    const char* src_tag = (size >= 3) ? isel_reg_name(reg + 2) : NULL;

    if (sym_sec == SEC_XDATA) {
        char dptr_val[256];
        snprintf(dptr_val, sizeof(dptr_val), "#%s", var_name);
        isel_emit(isel, "MOV", "DPTR", dptr_val, NULL);
        emit_mov(isel, "A", src_lo, ins);
        isel_emit(isel, "MOVX", "@DPTR", "A", NULL);
        if (size == 2) {
            snprintf(dptr_val, sizeof(dptr_val), "#(%s + 1)", var_name);
            isel_emit(isel, "MOV", "DPTR", dptr_val, NULL);
            emit_mov(isel, "A", src_hi, NULL);
            isel_emit(isel, "MOVX", "@DPTR", "A", NULL);
        } else if (size >= 3) {
            snprintf(dptr_val, sizeof(dptr_val), "#(%s + 1)", var_name);
            isel_emit(isel, "MOV", "DPTR", dptr_val, NULL);
            emit_mov(isel, "A", src_ptr_hi, NULL);
            isel_emit(isel, "MOVX", "@DPTR", "A", NULL);
            snprintf(dptr_val, sizeof(dptr_val), "#(%s + 2)", var_name);
            isel_emit(isel, "MOV", "DPTR", dptr_val, NULL);
            emit_mov(isel, "A", src_tag, NULL);
            isel_emit(isel, "MOVX", "@DPTR", "A", NULL);
        }
        return;
    }

    if (sym_sec == SEC_IDATA) {
        char off1[256];
        emit_mov(isel, "A", src_lo, ins);
        isel_emit(isel, "MOV", var_name, "A", NULL);
        if (size == 2) {
            snprintf(off1, sizeof(off1), "(%s + 1)", var_name);
            emit_mov(isel, "A", src_hi, NULL);
            isel_emit(isel, "MOV", off1, "A", NULL);
        } else if (size >= 3) {
            char off2[256];
            snprintf(off1, sizeof(off1), "(%s + 1)", var_name);
            snprintf(off2, sizeof(off2), "(%s + 2)", var_name);
            emit_mov(isel, "A", src_ptr_hi, NULL);
            isel_emit(isel, "MOV", off1, "A", NULL);
            emit_mov(isel, "A", src_tag, NULL);
            isel_emit(isel, "MOV", off2, "A", NULL);
        }
        return;
    }

    emit_mov(isel, var_name, src_lo, ins);
    if (size == 2) {
        char var_hi[256];
        snprintf(var_hi, sizeof(var_hi), "(%s + 1)", var_name);
        emit_mov(isel, var_hi, src_hi, NULL);
    } else if (size >= 3) {
        char var_hi[256];
        char var_tag[256];
        snprintf(var_hi, sizeof(var_hi), "(%s + 1)", var_name);
        snprintf(var_tag, sizeof(var_tag), "(%s + 2)", var_name);
        emit_mov(isel, var_hi, src_ptr_hi, NULL);
        emit_mov(isel, var_tag, src_tag, NULL);
    }
}

void emit_parallel_reg_moves(ISelContext* isel, RegMove* moves, int n, Instr* ins) {
    if (!isel || !moves || n <= 0) return;

    bool done[64] = {0};
    int remaining = n;

    while (remaining > 0) {
        bool progressed = false;

        for (int i = 0; i < n; i++) {
            if (done[i]) continue;

            if (moves[i].dst == moves[i].src) {
                done[i] = true;
                remaining--;
                progressed = true;
                continue;
            }

            bool dst_used_as_src = false;
            for (int j = 0; j < n; j++) {
                if (j == i || done[j]) continue;
                if (moves[j].src == moves[i].dst) {
                    dst_used_as_src = true;
                    break;
                }
            }

            if (!dst_used_as_src) {
                const char* dst = isel_reg_name(moves[i].dst);
                const char* src = (moves[i].src == ACC_REG) ? "A" : isel_reg_name(moves[i].src);
                emit_mov(isel, dst, src, ins);
                done[i] = true;
                remaining--;
                progressed = true;
            }
        }

        if (progressed) continue;

        int cyc = -1;
        for (int i = 0; i < n; i++) {
            if (!done[i] && moves[i].src >= 0) {
                cyc = i;
                break;
            }
        }
        if (cyc < 0) break;

        int saved_src = moves[cyc].src;
        emit_mov(isel, "A", isel_reg_name(saved_src), ins);

        for (int j = 0; j < n; j++) {
            if (!done[j] && moves[j].src == saved_src) {
                moves[j].src = -2;
            }
        }
    }
}

int get_value_size(ISelContext* isel, ValueName val) {
    if (!isel || !isel->ctx || !isel->ctx->value_type) return 1;
    char* key = int_to_key(val);
    Ctype* type = (Ctype*)dict_get(isel->ctx->value_type, key);
    free(key);
    if (type) return c51_abi_type_size(type);
    return 1;
}

const char* isel_get_extended_lo_reg(ISelContext* isel, ValueName val, int width) {
    int actual_size = get_value_size(isel, val);
    if (width <= 1 || actual_size <= 1) return isel_get_lo_reg(isel, val);

    int base_reg = isel_get_value_reg(isel, val);
    if (base_reg == ACC_REG) return "A";
    if (base_reg == SPILL_REG) {
        int reg = isel_reload_spill(isel, val, width, NULL);
        if (reg >= 0) return isel_reg_name(reg + 1);
        {
            const char* sym = lookup_value_addr_symbol(isel, val);
            if (sym) {
                emit_load_symbol_byte(isel, sym, 0, "A", NULL);
                return "A";
            }
        }
        return "A";
    }
    if (base_reg < 0) return "R7";
    return isel_reg_name(base_reg + 1);
}

const char* isel_get_extended_hi_reg(ISelContext* isel, ValueName val, int width) {
    int actual_size = get_value_size(isel, val);
    if (width <= 1) return isel_get_hi_reg(isel, val);

    if (actual_size <= 1) {
        Ctype* type = get_value_type(isel, val);
        if (type) {
            CtypeAttr attr = get_attr(type->attr);
            if (attr.ctype_unsigned || type->type == CTYPE_BOOL) return "#0";
        }
        return "#0";
    }

    int base_reg = isel_get_value_reg(isel, val);
    if (base_reg == ACC_REG) return "A";
    if (base_reg == SPILL_REG) {
        int reg = isel_reload_spill(isel, val, width, NULL);
        if (reg >= 0) return isel_reg_name(reg);
        {
            const char* sym = lookup_value_addr_symbol(isel, val);
            if (sym) {
                emit_load_symbol_byte(isel, sym, 1, "A", NULL);
                return "A";
            }
        }
        return "A";
    }
    if (base_reg < 0) return "R6";
    return isel_reg_name(base_reg);
}

Ctype* get_value_type(ISelContext* isel, ValueName val) {
    if (!isel || !isel->ctx || !isel->ctx->value_type) return NULL;
    char* key = int_to_key(val);
    Ctype* type = (Ctype*)dict_get(isel->ctx->value_type, key);
    free(key);
    return type;
}

int get_mem_space(Ctype* mem_type) {
    if (!mem_type) return 0;
    return (mem_type->attr >> 7) & 0x7;
}

bool is_sbit_type(Ctype* mem_type) {
    if (!mem_type) return false;
    CtypeAttr a = get_attr(mem_type->attr);
    return a.ctype_register && mem_type->type == CTYPE_BOOL;
}

const char* get_sbit_var_name(ISelContext* isel, Instr* ins) {
    if (!isel || !ins) return NULL;
    ValueName ptr = -1;
    if (ins->args && ins->args->len > 0) {
        ptr = *(ValueName*)list_get(ins->args, 0);
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

    return var_name;
}

const char* resolve_addr_symbol_in_block(Instr** instrs, int n, ValueName ptr) {
    if (!instrs || n <= 0 || ptr <= 0) return NULL;
    for (int i = 0; i < n; i++) {
        Instr* ins = instrs[i];
        if (!ins || ins->op != IROP_ADDR || ins->dest != ptr) continue;
        if (ins->labels && ins->labels->len > 0) {
            const char* label = list_get(ins->labels, 0);
            if (label && label[0] == '@') return label + 1;
            return label;
        }
    }
    return NULL;
}

bool instr_uses_value(Instr* ins, ValueName v) {
    if (!ins || !ins->args) return false;
    for (int i = 0; i < ins->args->len; i++) {
        ValueName* p = list_get(ins->args, i);
        if (p && *p == v) return true;
    }
    return false;
}

int count_value_uses(Instr** instrs, int n, ValueName v) {
    int count = 0;
    for (int i = 0; i < n; i++) {
        if (!instrs[i]) continue;
        if (instr_uses_value(instrs[i], v)) count++;
    }
    return count;
}

bool find_const_in_block(Instr** instrs, int n, ValueName v, int64_t* out_val) {
    bool found = false;
    int64_t val = 0;
    for (int i = 0; i < n; i++) {
        Instr* ins = instrs[i];
        if (!ins || ins->op != IROP_CONST) continue;
        if (ins->dest == v) {
            if (found) return false;
            found = true;
            val = ins->imm.ival;
        }
    }
    if (found && out_val) *out_val = val;
    return found;
}

bool ne_is_compare_zero(Instr** instrs, int n, Instr* ne, ValueName* out_other) {
    if (!ne) return false;
    int64_t imm = 0;
    if (is_imm_operand(ne, &imm)) {
        if (imm == 0) {
            if (out_other) *out_other = get_src1_value(ne);
            return true;
        }
        return false;
    }

    ValueName a = get_src1_value(ne);
    ValueName b = get_src2_value(ne);
    int64_t v = 0;
    if (find_const_in_block(instrs, n, b, &v) && v == 0) {
        if (out_other) *out_other = a;
        return true;
    }
    if (find_const_in_block(instrs, n, a, &v) && v == 0) {
        if (out_other) *out_other = b;
        return true;
    }
    return false;
}

Instr* find_def_instr_in_func(Func* f, ValueName v) {
    if (!f || v <= 0) return NULL;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block* b = iter_next(&it);
        if (!b) continue;
        for (Iter jt = list_iter(b->instrs); !iter_end(jt);) {
            Instr* ins = iter_next(&jt);
            if (ins && ins->dest == v) return ins;
        }
        for (Iter jt = list_iter(b->phis); !iter_end(jt);) {
            Instr* ins = iter_next(&jt);
            if (ins && ins->dest == v) return ins;
        }
    }
    return NULL;
}

bool try_get_value_const(ISelContext* isel, ValueName val, int64_t* out_val) {
    if (!isel || !isel->ctx || !isel->ctx->current_func || val <= 0) return false;
    Instr* def = find_def_instr_in_func(isel->ctx->current_func, val);
    if (!def || def->op != IROP_CONST) return false;
    if (out_val) *out_val = def->imm.ival;
    return true;
}

bool is_const_zero_def(Func* f, ValueName v) {
    Instr* def = find_def_instr_in_func(f, v);
    return def && def->op == IROP_CONST && def->imm.ival == 0;
}

bool ne_is_compare_zero_def(Func* f, Instr* ne, ValueName* out_other) {
    if (!ne) return false;
    int64_t imm = 0;
    if (is_imm_operand(ne, &imm)) {
        if (imm == 0) {
            if (out_other) *out_other = get_src1_value(ne);
            return true;
        }
        return false;
    }

    ValueName a = get_src1_value(ne);
    ValueName b = get_src2_value(ne);
    if (is_const_zero_def(f, b)) {
        if (out_other) *out_other = a;
        return true;
    }
    if (is_const_zero_def(f, a)) {
        if (out_other) *out_other = b;
        return true;
    }
    return false;
}

int parse_block_id(const char* label) {
    if (!label) return -1;
    int id = -1;
    if (sscanf(label, "block%d", &id) == 1) return id;
    return -1;
}

void block_label_name(char* out, size_t out_len, int id) {
    snprintf(out, out_len, "L%d", id);
}

int safe_alloc_reg_for_value(ISelContext* isel, ValueName val, int size) {
    int reg = alloc_reg_for_value(isel, val, size);
    if (reg < 0) {
        if (isel->ctx && isel->ctx->value_to_reg) {
            int* reg_num = malloc(sizeof(int));
            *reg_num = -2;
            char* key = int_to_key(val);
            dict_put(isel->ctx->value_to_reg, key, reg_num);
        }
        return -2;
    }
    return reg;
}

void emit_mov(ISelContext* isel, const char* dst, const char* src, Instr* ins) {
    if (!dst || !src || strcmp(dst, src) == 0) return;
    if (isel && isel->ctx && isel->ctx->obj) {
        SectionKind sym_sec = get_symbol_section_kind(isel, src);
        if (sym_sec != SEC_DATA) {
            char* ssa = instr_to_ssa_str(ins);
            if (sym_sec == SEC_XDATA) {
                char dptr_val[256];
                snprintf(dptr_val, sizeof(dptr_val), "#%s", src);
                isel_emit(isel, "MOV", "DPTR", dptr_val, NULL);
                isel_emit(isel, "MOVX", "A", "@DPTR", NULL);
                isel_emit(isel, "MOV", dst, "A", ssa);
            } else if (sym_sec == SEC_IDATA) {
                isel_emit(isel, "MOV", "R0", src, NULL);
                isel_emit(isel, "MOV", "A", "@R0", NULL);
                isel_emit(isel, "MOV", dst, "A", ssa);
            } else if (sym_sec == SEC_CODE) {
                char dptr_val[256];
                snprintf(dptr_val, sizeof(dptr_val), "#%s", src);
                isel_emit(isel, "MOV", "DPTR", dptr_val, NULL);
                isel_emit(isel, "CLR", "A", NULL, NULL);
                isel_emit(isel, "MOVC", "A", "@A+DPTR", NULL);
                isel_emit(isel, "MOV", dst, "A", ssa);
            } else {
                isel_emit(isel, "MOV", dst, src, ssa);
            }
            free(ssa);
            return;
        }
    }

    char* ssa = instr_to_ssa_str(ins);
    isel_emit(isel, "MOV", dst, src, ssa);
    free(ssa);
}

ValueName get_src1_value(Instr* ins) {
    if (ins && ins->args && ins->args->len > 0) {
        ValueName* p = list_get(ins->args, 0);
        if (p) return *p;
    }
    return -1;
}

ValueName get_src2_value(Instr* ins) {
    if (ins && ins->args && ins->args->len > 1) {
        ValueName* p = list_get(ins->args, 1);
        if (p) return *p;
    }
    return -1;
}

bool is_imm_operand(Instr* ins, int64_t* out_val) {
    if (ins->labels && ins->labels->len > 0) {
        char* tag = (char*)list_get(ins->labels, 0);
        if (tag && strcmp(tag, "imm") == 0) {
            if (out_val) *out_val = ins->imm.ival;
            return true;
        }
    }
    return false;
}
