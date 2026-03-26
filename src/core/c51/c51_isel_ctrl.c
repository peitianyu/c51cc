#include "c51_isel_internal.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "c51_isel_regalloc.h"

Block* find_block_by_id(Func* f, int id) {
    if (!f || id < 0) return NULL;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block* b = iter_next(&it);
        if (b && (int)b->id == id) return b;
    }
    return NULL;
}

static bool reg_range_used_by_moves(RegMove* moves, int move_count, int reg) {
    for (int i = 0; i < move_count; i++) {
        if (moves[i].dst == reg) return true;
    }
    return false;
}

static int rebind_phi_dest_reg(ISelContext* isel, ValueName val, int size, RegMove* moves, int move_count) {
    if (!isel || !isel->ctx || !isel->ctx->value_to_reg) return -1;
    for (int base = 7 - size + 1; base >= 0; base--) {
        bool ok = true;
        for (int offset = 0; offset < size; offset++) {
            if (reg_range_used_by_moves(moves, move_count, base + offset)) {
                ok = false;
                break;
            }
        }
        if (!ok) continue;

        int* reg_num = malloc(sizeof(int));
        if (!reg_num) return -1;
        *reg_num = base;
        char* key = int_to_key(val);
        dict_put(isel->ctx->value_to_reg, key, reg_num);
        return base;
    }
    return -1;
}

int try_bind_result_to_phi_target(ISelContext* isel, Instr* ins, Instr* next, int size) {
    if (!isel || !ins || !next || next->op != IROP_JMP || !next->labels || next->labels->len == 0) return -1;
    const char* lbl = list_get(next->labels, 0);
    int succ_id = parse_block_id(lbl);
    if (succ_id < 0 || !isel->ctx || !isel->ctx->current_func) return -1;

    Func* f = isel->ctx->current_func;
    Block* succ = find_block_by_id(f, succ_id);
    if (!succ || !succ->phis) return -1;

    char pred_lbl[32]; snprintf(pred_lbl, sizeof(pred_lbl), "block%d", isel->current_block_id);

    for (Iter it = list_iter(succ->phis); !iter_end(it);) {
        Instr* phi = iter_next(&it);
        if (!phi || phi->op != IROP_PHI || !phi->args || !phi->labels) continue;
        int n = phi->labels->len;
        for (int i = 0; i < n; i++) {
            const char* l = (const char*)list_get(phi->labels, i);
            if (!l || strcmp(l, pred_lbl) != 0) continue;
            if (i >= phi->args->len) continue;
            ValueName arg = *(ValueName*)list_get(phi->args, i);
            if (arg != ins->dest) continue;
            int phi_dst_reg = isel_get_value_reg(isel, phi->dest);
            int phi_size = phi->type ? c51_abi_type_size(phi->type) : get_value_size(isel, phi->dest);
            if (phi_size < size) phi_size = size;
            if (phi_dst_reg >= 0 && phi_dst_reg + phi_size - 1 < 8) {
                if (isel->ctx && isel->ctx->value_to_reg) {
                    int* reg_num = malloc(sizeof(int));
                    *reg_num = phi_dst_reg;
                    char* k = int_to_key(ins->dest);
                    dict_put(isel->ctx->value_to_reg, k, reg_num);
                }
                return phi_dst_reg;
            }
        }
    }
    return -1;
}

void emit_phi_copies_for_edge(ISelContext* isel, int pred_id, int succ_id, Instr* ins) {
    if (!isel || !isel->ctx || !isel->ctx->current_func) return;
    Func* f = isel->ctx->current_func;
    Block* succ = find_block_by_id(f, succ_id);
    if (!succ || !succ->phis) return;

    RegMove moves[64];
    int move_count = 0;
    char pred_label[32];
    snprintf(pred_label, sizeof(pred_label), "block%d", pred_id);

    char* mem_srcs[64];
    int mem_src_cnt = 0;
    const char* mem_dsts[64][8];
    int mem_dst_cnt[64];

    for (Iter it = list_iter(succ->phis); !iter_end(it);) {
        Instr* phi = iter_next(&it);
        if (!phi || phi->op != IROP_PHI || !phi->args || !phi->labels) continue;
        int idx = -1;
        int n = phi->labels->len;
        for (int i = 0; i < n; i++) {
            const char* lbl = (const char*)list_get(phi->labels, i);
            if (lbl && strcmp(lbl, pred_label) == 0) { idx = i; break; }
        }
        if (idx < 0 || idx >= phi->args->len) continue;

        ValueName src = *(ValueName*)list_get(phi->args, idx);
        ValueName dst = phi->dest;
        int size = phi->type ? c51_abi_type_size(phi->type) : get_value_size(isel, dst);
        int src_size = get_value_size(isel, src);
        int dst_size = get_value_size(isel, dst);
        if (src_size > size) size = src_size;
        if (dst_size > size) size = dst_size;
        if (size < 1) size = 1;

        int dst_base = isel_get_value_reg(isel, dst);
        if (dst_base >= 0 && dst_base + size - 1 > 7) {
            dst_base = rebind_phi_dest_reg(isel, dst, size, moves, move_count);
        }
        if (dst_base < 0) continue;

        Instr* src_def = find_def_instr_in_func(f, src);
        if (src_def && src_def->op == IROP_CONST) {
            int imm = (int)(src_def->imm.ival & 0xFFFF);
            char imm_lo[32];
            snprintf(imm_lo, sizeof(imm_lo), "#%d", imm & 0xFF);
            emit_mov(isel, isel_reg_name(dst_base + (size == 2 ? 1 : 0)), imm_lo, ins);
            if (size == 2) {
                char imm_hi[32];
                snprintf(imm_hi, sizeof(imm_hi), "#%d", (imm >> 8) & 0xFF);
                emit_mov(isel, isel_reg_name(dst_base), imm_hi, NULL);
            }
            continue;
        }

        const char* dst_lo = isel_reg_name(dst_base + (size == 2 ? 1 : 0));
        const char* src_lo = isel_get_lo_reg(isel, src);
        int src_lo_reg = reg_index_from_name(src_lo);
        int dst_lo_reg = reg_index_from_name(dst_lo);

        if (src_lo_reg >= 0 && dst_lo_reg >= 0) {
            if (move_count < 64) moves[move_count++] = (RegMove){ .dst = dst_lo_reg, .src = src_lo_reg };
        } else if (src_lo && strcmp(src_lo, dst_lo) != 0) {
            if (is_memory_operand_local(src_lo)) {
                int found = -1;
                for (int m = 0; m < mem_src_cnt; m++) {
                    if (strcmp(mem_srcs[m], src_lo) == 0) { found = m; break; }
                }
                if (found < 0 && mem_src_cnt < 64) {
                    mem_srcs[mem_src_cnt] = strdup(src_lo);
                    mem_dst_cnt[mem_src_cnt] = 0;
                    found = mem_src_cnt++;
                }
                if (found >= 0 && mem_dst_cnt[found] < 8) mem_dsts[found][mem_dst_cnt[found]++] = dst_lo;
            } else {
                emit_mov(isel, dst_lo, src_lo, ins);
            }
        }

        if (size == 2) {
            const char* dst_hi = isel_reg_name(dst_base);
            const char* src_hi = isel_get_hi_reg(isel, src);
            int src_hi_reg = reg_index_from_name(src_hi);
            int dst_hi_reg = reg_index_from_name(dst_hi);

            if (src_hi_reg >= 0 && dst_hi_reg >= 0) {
                if (move_count < 64) moves[move_count++] = (RegMove){ .dst = dst_hi_reg, .src = src_hi_reg };
            } else if (src_hi && strcmp(src_hi, dst_hi) != 0) {
                if (is_memory_operand_local(src_hi)) {
                    int found = -1;
                    for (int m = 0; m < mem_src_cnt; m++) {
                        if (strcmp(mem_srcs[m], src_hi) == 0) { found = m; break; }
                    }
                    if (found < 0 && mem_src_cnt < 64) {
                        mem_srcs[mem_src_cnt] = strdup(src_hi);
                        mem_dst_cnt[mem_src_cnt] = 0;
                        found = mem_src_cnt++;
                    }
                    if (found >= 0 && mem_dst_cnt[found] < 8) mem_dsts[found][mem_dst_cnt[found]++] = dst_hi;
                } else {
                    emit_mov(isel, dst_hi, src_hi, ins);
                }
            }
        }
    }

    if (move_count > 0) {
        emit_parallel_reg_moves(isel, moves, move_count, ins);
    }

    for (int m = 0; m < mem_src_cnt; m++) {
        if (!mem_srcs[m]) continue;
        char* ssa = instr_to_ssa_str(ins);
        isel_emit(isel, "MOV", "A", mem_srcs[m], ssa);
        free(ssa);
        for (int d = 0; d < mem_dst_cnt[m]; d++) {
            const char* dst = mem_dsts[m][d];
            if (dst && strcmp(dst, "A") != 0) emit_mov(isel, dst, "A", ins);
        }
        free(mem_srcs[m]);
    }
}

void emit_jmp(ISelContext* isel, Instr* ins) {
    if (!ins->labels || ins->labels->len < 1) return;
    const char* lbl = (const char*)list_get(ins->labels, 0);
    int id = parse_block_id(lbl);
    if (id < 0) return;
    char target[32];
    block_label_name(target, sizeof(target), id);

    emit_phi_copies_for_edge(isel, isel->current_block_id, id, ins);
    isel_emit(isel, "SJMP", target, NULL, instr_to_ssa_str(ins));
}

void emit_br(ISelContext* isel, Instr* ins) {
    if (!ins->args || ins->args->len < 1) return;
    if (!ins->labels || ins->labels->len < 2) return;

    if (isel && isel->ctx && isel->ctx->current_func) {
        ValueName cond0 = *(ValueName*)list_get(ins->args, 0);
        ValueName base = cond0;
        bool invert = false;

        Instr* def = find_def_instr_in_func(isel->ctx->current_func, base);
        if (def && def->op == IROP_NE) {
            ValueName other = -1;
            if (ne_is_compare_zero_def(isel->ctx->current_func, def, &other)) {
                base = other;
                def = find_def_instr_in_func(isel->ctx->current_func, base);
            }
        }

        if (def && def->op == IROP_LNOT) {
            base = get_src1_value(def);
            invert = !invert;
            def = find_def_instr_in_func(isel->ctx->current_func, base);
        }

        if (def && def->op == IROP_LOAD && is_sbit_type(def->mem_type)) {
            const char* bit = get_sbit_var_name(isel, def);
            if (!bit && def->args && def->args->len > 0) {
                ValueName ptr = *(ValueName*)list_get(def->args, 0);
                Instr* addr = find_def_instr_in_func(isel->ctx->current_func, ptr);
                if (addr && addr->op == IROP_ADDR && addr->labels && addr->labels->len > 0) {
                    const char* label = list_get(addr->labels, 0);
                    if (label && label[0] == '@') bit = label + 1;
                    else bit = label;
                }
            }

            if (bit) {
                const char* lbl_t = (const char*)list_get(ins->labels, 0);
                const char* lbl_f = (const char*)list_get(ins->labels, 1);
                int id_t = parse_block_id(lbl_t);
                int id_f = parse_block_id(lbl_f);
                if (id_t >= 0 && id_f >= 0) {
                    char target_t[32];
                    char target_f[32];
                    block_label_name(target_t, sizeof(target_t), id_t);
                    block_label_name(target_f, sizeof(target_f), id_f);

                    if (invert) {
                        isel_emit(isel, "JNB", bit, target_t, instr_to_ssa_str(ins));
                    } else {
                        isel_emit(isel, "JB", bit, target_t, instr_to_ssa_str(ins));
                    }
                    isel_emit(isel, "SJMP", target_f, NULL, NULL);
                    return;
                }
            }
        }
    }

    BrBitInfo* bitinfo = br_bitinfo_get(isel, ins);
    if (bitinfo && bitinfo->bit) {
        const char* lbl_t = (const char*)list_get(ins->labels, 0);
        const char* lbl_f = (const char*)list_get(ins->labels, 1);
        int id_t = parse_block_id(lbl_t);
        int id_f = parse_block_id(lbl_f);
        if (id_t < 0 || id_f < 0) return;

        char target_t[32];
        char target_f[32];
        block_label_name(target_t, sizeof(target_t), id_t);
        block_label_name(target_f, sizeof(target_f), id_f);

        if (bitinfo->invert) {
            isel_emit(isel, "JNB", bitinfo->bit, target_t, instr_to_ssa_str(ins));
        } else {
            isel_emit(isel, "JB", bitinfo->bit, target_t, instr_to_ssa_str(ins));
        }
        isel_emit(isel, "SJMP", target_f, NULL, NULL);
        return;
    }

    ValueName cond = *(ValueName*)list_get(ins->args, 0);
    const char* lbl_t = (const char*)list_get(ins->labels, 0);
    const char* lbl_f = (const char*)list_get(ins->labels, 1);
    int id_t = parse_block_id(lbl_t);
    int id_f = parse_block_id(lbl_f);
    if (id_t < 0 || id_f < 0) return;

    char target_t[32];
    char target_f[32];
    block_label_name(target_t, sizeof(target_t), id_t);
    block_label_name(target_f, sizeof(target_f), id_f);

    int size = get_value_size(isel, cond);
    if (size == 2) {
        const char* hi = isel_get_hi_reg(isel, cond);
        const char* lo = isel_get_lo_reg(isel, cond);
        if (hi && strcmp(hi, "A") != 0) isel_emit(isel, "MOV", "A", hi, NULL);
        if (lo) isel_emit(isel, "ORL", "A", lo, NULL);
    } else {
        isel_ensure_in_acc(isel, cond);
    }

    bool invert = false;
    bool has_invert = br_invert_get(isel, ins, &invert);
    if (has_invert && invert) {
        isel_emit(isel, "JZ", target_t, NULL, instr_to_ssa_str(ins));
    } else {
        isel_emit(isel, "JNZ", target_t, NULL, instr_to_ssa_str(ins));
    }
    isel_emit(isel, "SJMP", target_f, NULL, NULL);
}

void precompute_sbit_br(ISelContext* isel, Instr** instrs, int n) {
    if (!isel || !instrs || n <= 0) return;
    for (int i = 0; i < n; i++) {
        Instr* ld = instrs[i];
        if (!ld || ld->op != IROP_LOAD || !is_sbit_type(ld->mem_type)) continue;

        ValueName v0 = ld->dest;
        if (v0 <= 0) continue;

        const char* bit = get_sbit_var_name(isel, ld);
        if (!bit) {
            ValueName ptr = -1;
            if (ld->args && ld->args->len > 0) ptr = *(ValueName*)list_get(ld->args, 0);
            bit = resolve_addr_symbol_in_block(instrs, n, ptr);
        }
        if (!bit) continue;

        if (i + 1 < n) {
            Instr* br = instrs[i + 1];
            if (br && br->op == IROP_BR && instr_uses_value(br, v0)) {
                if (count_value_uses(instrs, n, v0) == 1) {
                    br_bitinfo_put(isel, br, bit, false);
                    ld->op = IROP_NOP;
                    continue;
                }
            }
        }

        if (i + 2 < n) {
            Instr* lnot = instrs[i + 1];
            Instr* br = instrs[i + 2];
            if (lnot && br && lnot->op == IROP_LNOT && br->op == IROP_BR) {
                ValueName v1 = lnot->dest;
                if (get_src1_value(lnot) == v0 && instr_uses_value(br, v1)) {
                    if (count_value_uses(instrs, n, v0) == 1 && count_value_uses(instrs, n, v1) == 1) {
                        br_bitinfo_put(isel, br, bit, true);
                        ld->op = IROP_NOP;
                        lnot->op = IROP_NOP;
                        continue;
                    }
                }
            }
        }

        if (i + 2 < n) {
            Instr* ne = instrs[i + 1];
            Instr* br = instrs[i + 2];
            if (ne && br && ne->op == IROP_NE && br->op == IROP_BR) {
                ValueName other = -1;
                if (ne_is_compare_zero(instrs, n, ne, &other) && other == v0) {
                    ValueName v1 = ne->dest;
                    if (instr_uses_value(br, v1)) {
                        if (count_value_uses(instrs, n, v0) == 1 && count_value_uses(instrs, n, v1) == 1) {
                            br_bitinfo_put(isel, br, bit, false);
                            ld->op = IROP_NOP;
                            ne->op = IROP_NOP;
                            continue;
                        }
                    }
                }
            }
        }

        if (i + 3 < n) {
            Instr* lnot = instrs[i + 1];
            Instr* ne = instrs[i + 2];
            Instr* br = instrs[i + 3];
            if (lnot && ne && br && lnot->op == IROP_LNOT && ne->op == IROP_NE && br->op == IROP_BR) {
                ValueName v1 = lnot->dest;
                ValueName other = -1;
                if (get_src1_value(lnot) == v0 && ne_is_compare_zero(instrs, n, ne, &other) && other == v1) {
                    ValueName v2 = ne->dest;
                    if (instr_uses_value(br, v2)) {
                        if (count_value_uses(instrs, n, v0) == 1 &&
                            count_value_uses(instrs, n, v1) == 1 &&
                            count_value_uses(instrs, n, v2) == 1) {
                            br_bitinfo_put(isel, br, bit, true);
                            ld->op = IROP_NOP;
                            lnot->op = IROP_NOP;
                            ne->op = IROP_NOP;
                            continue;
                        }
                    }
                }
            }
        }
    }

    for (int i = 0; i < n; i++) {
        Instr* br = instrs[i];
        if (!br || br->op != IROP_BR || !br->args || br->args->len < 1) continue;

        ValueName cond = *(ValueName*)list_get(br->args, 0);
        Instr* def_ne = NULL;
        Instr* def_lnot = NULL;
        Instr* def_load = NULL;
        bool invert = false;

        Instr* def = find_def_instr_in_func(isel->ctx->current_func, cond);
        if (def && def->op == IROP_NE) {
            ValueName other = -1;
            if (ne_is_compare_zero_def(isel->ctx->current_func, def, &other)) {
                def_ne = def;
                cond = other;
                def = find_def_instr_in_func(isel->ctx->current_func, cond);
            }
        }

        if (def && def->op == IROP_LNOT) {
            def_lnot = def;
            cond = get_src1_value(def);
            invert = !invert;
            def = find_def_instr_in_func(isel->ctx->current_func, cond);
        }

        if (def && def->op == IROP_LOAD && is_sbit_type(def->mem_type)) {
            def_load = def;
            const char* bit = get_sbit_var_name(isel, def_load);
            if (!bit && def_load->args && def_load->args->len > 0) {
                ValueName ptr = *(ValueName*)list_get(def_load->args, 0);
                bit = resolve_addr_symbol_in_block(instrs, n, ptr);
            }
            if (!bit) continue;

            bool ok = true;
            if (def_ne && count_value_uses(instrs, n, def_ne->dest) != 1) ok = false;
            if (def_lnot && count_value_uses(instrs, n, def_lnot->dest) != 1) ok = false;
            if (def_load && count_value_uses(instrs, n, def_load->dest) != 1) ok = false;
            if (!ok) continue;

            br_bitinfo_put(isel, br, bit, invert);
            if (def_ne) def_ne->op = IROP_NOP;
            if (def_lnot) def_lnot->op = IROP_NOP;
            if (def_load) def_load->op = IROP_NOP;
        }
    }
}

void precompute_br_simplify(ISelContext* isel, Instr** instrs, int n) {
    if (!isel || !instrs || n <= 0) return;
    for (int i = 0; i < n; i++) {
        Instr* ins = instrs[i];
        if (!ins) continue;

        if (ins->op == IROP_LNOT && i + 1 < n) {
            Instr* br = instrs[i + 1];
            if (br && br->op == IROP_BR && instr_uses_value(br, ins->dest)) {
                ValueName v0 = get_src1_value(ins);
                if (count_value_uses(instrs, n, ins->dest) == 1) {
                    ValueName* p = list_get(br->args, 0);
                    if (p) *p = v0;
                    br_invert_put(isel, br, true);
                    ins->op = IROP_NOP;
                    continue;
                }
            }
        }

        if (ins->op == IROP_NE && i + 1 < n) {
            Instr* br = instrs[i + 1];
            ValueName other = -1;
            if (br && br->op == IROP_BR && ne_is_compare_zero(instrs, n, ins, &other)) {
                if (instr_uses_value(br, ins->dest) && count_value_uses(instrs, n, ins->dest) == 1) {
                    ValueName* p = list_get(br->args, 0);
                    if (p) *p = other;
                    ins->op = IROP_NOP;
                    continue;
                }
            }
        }

        if (ins->op == IROP_LNOT && i + 2 < n) {
            Instr* ne = instrs[i + 1];
            Instr* br = instrs[i + 2];
            ValueName other = -1;
            if (ne && br && ne->op == IROP_NE && br->op == IROP_BR && ne_is_compare_zero(instrs, n, ne, &other)) {
                ValueName v1 = ne->dest;
                if (other == ins->dest && instr_uses_value(br, v1)) {
                    if (count_value_uses(instrs, n, ins->dest) == 1 && count_value_uses(instrs, n, v1) == 1) {
                        ValueName v0 = get_src1_value(ins);
                        ValueName* p = list_get(br->args, 0);
                        if (p) *p = v0;
                        br_invert_put(isel, br, true);
                        ins->op = IROP_NOP;
                        ne->op = IROP_NOP;
                        continue;
                    }
                }
            }
        }
    }
}

void emit_inline_asm_instr(ISelContext* isel, Instr* ins) {
    if (!isel || !ins || !ins->labels || ins->labels->len <= 0) return;

    char* asm_text = list_get(ins->labels, 0);
    if (!asm_text) return;
    c51_emit_asm_text(isel->sec, asm_text);
}

static void setup_call_param_u8(ISelContext* isel, Instr* ins, const char* callee_name, int param_pos, int class_index, ValueName v, RegMove* moves, int* move_count) {
    if (class_index >= 6) {
        if (callee_name && isel) {
            char sym[128];
            snprintf(sym, sizeof(sym), "__param_%s_%d", callee_name, param_pos);
            int64_t imm_val = 0;
            if (try_get_value_const(isel, v, &imm_val)) {
                emit_store_symbol_imm_byte(isel, sym, 0, (int)imm_val, ins);
                return;
            }
            const char* src_sym = lookup_value_addr_symbol(isel, v);
            if (src_sym && isel_get_value_reg(isel, v) == -3) {
                emit_load_symbol_byte(isel, src_sym, 0, "A", ins);
                emit_store_symbol_byte(isel, sym, 0, "A", NULL);
                return;
            }
            const char* src_lo = isel_get_lo_reg(isel, v);
            if (src_lo) emit_store_symbol_byte(isel, sym, 0, src_lo, ins);
        }
        return;
    }
    int targ = param_regs_char[class_index];
    const char* dst = isel_reg_name(targ);
    int64_t imm_val = 0;
    if (try_get_value_const(isel, v, &imm_val)) {
        char imm_str[32];
        snprintf(imm_str, sizeof(imm_str), "#%d", (int)(imm_val & 0xFF));
        emit_mov(isel, dst, imm_str, ins);
        return;
    }
    const char* src_sym = lookup_value_addr_symbol(isel, v);
    if (src_sym && isel_get_value_reg(isel, v) == -3) {
        emit_load_symbol_byte(isel, src_sym, 0, dst, ins);
        return;
    }
    const char* src_lo = isel_get_lo_reg(isel, v);

    if (isel_get_value_reg(isel, v) == -3) {
        int r = isel_reload_spill(isel, v, 1, ins);
        if (r >= 0) src_lo = isel_reg_name(r);
        else src_lo = "A";
    } else if (isel->ctx && isel->ctx->value_to_addr) {
        char* ktmp = int_to_key(v);
        const char* sym = (const char*)dict_get(isel->ctx->value_to_addr, ktmp);
        free(ktmp);
        if (sym) {
            int r = isel_reload_spill(isel, v, 1, ins);
            if (r >= 0) src_lo = isel_reg_name(r);
            else src_lo = "A";
        }
    }

    int src_reg = reg_index_from_name(src_lo);
    if (src_reg < 0 && src_lo && is_memory_operand_local(src_lo)) {
        int r = isel_reload_spill(isel, v, 1, ins);
        if (r >= 0) {
            src_lo = isel_reg_name(r);
            src_reg = r;
        } else {
            src_lo = "A";
            src_reg = -2;
        }
    }

    if (src_reg >= 0) {
        if (*move_count < 64) {
            moves[(*move_count)++] = (RegMove){.dst = targ, .src = src_reg};
        }
    } else if (src_lo && strcmp(src_lo, dst) != 0) {
        emit_mov(isel, dst, src_lo, ins);
    }
}

static void setup_call_param_u16(ISelContext* isel, Instr* ins, const char* callee_name, int param_pos, int class_index, ValueName v, RegMove* moves, int* move_count) {
    if (class_index >= 3) {
        if (callee_name && isel) {
            char sym[128];
            snprintf(sym, sizeof(sym), "__param_%s_%d", callee_name, param_pos);
            int64_t imm_val = 0;
            if (try_get_value_const(isel, v, &imm_val)) {
                emit_store_symbol_imm_byte(isel, sym, 0, (int)(imm_val & 0xFF), ins);
                emit_store_symbol_imm_byte(isel, sym, 1, (int)((imm_val >> 8) & 0xFF), NULL);
                return;
            }
            const char* src_sym = lookup_value_addr_symbol(isel, v);
            if (src_sym && isel_get_value_reg(isel, v) == -3) {
                emit_load_symbol_byte(isel, src_sym, 0, "A", ins);
                emit_store_symbol_byte(isel, sym, 0, "A", NULL);
                emit_load_symbol_byte(isel, src_sym, 1, "A", NULL);
                emit_store_symbol_byte(isel, sym, 1, "A", NULL);
                return;
            }
            const char* src_lo = isel_get_lo_reg(isel, v);
            const char* src_hi = isel_get_hi_reg(isel, v);
            if (src_lo) emit_store_symbol_byte(isel, sym, 0, src_lo, ins);
            if (src_hi) emit_store_symbol_byte(isel, sym, 1, src_hi, NULL);
        }
        return;
    }

    int targ_hi = param_regs_int_h[class_index];
    int targ_lo = param_regs_int_l[class_index];
    const char* dst_hi = isel_reg_name(targ_hi);
    const char* dst_lo = isel_reg_name(targ_lo);
    int64_t imm_val = 0;
    if (try_get_value_const(isel, v, &imm_val)) {
        char imm_hi[32], imm_lo[32];
        snprintf(imm_hi, sizeof(imm_hi), "#%d", (int)((imm_val >> 8) & 0xFF));
        snprintf(imm_lo, sizeof(imm_lo), "#%d", (int)(imm_val & 0xFF));
        emit_mov(isel, dst_hi, imm_hi, ins);
        emit_mov(isel, dst_lo, imm_lo, NULL);
        return;
    }
    const char* src_sym = lookup_value_addr_symbol(isel, v);
    if (src_sym && isel_get_value_reg(isel, v) == -3) {
        emit_load_symbol_byte(isel, src_sym, 0, dst_lo, ins);
        emit_load_symbol_byte(isel, src_sym, 1, dst_hi, NULL);
        return;
    }
    const char* src_hi = isel_get_hi_reg(isel, v);
    const char* src_lo = isel_get_lo_reg(isel, v);

    if (isel_get_value_reg(isel, v) == -3) {
        int r = isel_reload_spill(isel, v, 2, ins);
        if (r >= 0) {
            src_hi = isel_reg_name(r);
            src_lo = isel_reg_name(r + 1);
        } else {
            src_hi = "A";
            src_lo = "A";
        }
    } else if (isel->ctx && isel->ctx->value_to_addr) {
        char* ktmp = int_to_key(v);
        const char* sym = (const char*)dict_get(isel->ctx->value_to_addr, ktmp);
        free(ktmp);
        if (sym) {
            int r = isel_reload_spill(isel, v, 2, ins);
            if (r >= 0) {
                src_hi = isel_reg_name(r);
                src_lo = isel_reg_name(r + 1);
            } else {
                src_hi = "A";
                src_lo = "A";
            }
        }
    }

    int src_hi_reg = reg_index_from_name(src_hi);
    int src_lo_reg = reg_index_from_name(src_lo);

    if ((src_hi_reg < 0 && src_hi && is_memory_operand_local(src_hi)) ||
        (src_lo_reg < 0 && src_lo && is_memory_operand_local(src_lo))) {
        int r = isel_reload_spill(isel, v, 2, ins);
        if (r >= 0) {
            src_hi = isel_reg_name(r);
            src_lo = isel_reg_name(r + 1);
            src_hi_reg = r;
            src_lo_reg = r + 1;
        } else {
            src_hi = "A";
            src_lo = "A";
            src_hi_reg = -2;
            src_lo_reg = -2;
        }
    }

    if (src_hi_reg >= 0) {
        if (*move_count < 64) {
            moves[(*move_count)++] = (RegMove){.dst = targ_hi, .src = src_hi_reg};
        }
    } else if (src_hi && strcmp(src_hi, dst_hi) != 0) {
        emit_mov(isel, dst_hi, src_hi, ins);
    }

    if (src_lo_reg >= 0) {
        if (*move_count < 64) {
            moves[(*move_count)++] = (RegMove){.dst = targ_lo, .src = src_lo_reg};
        }
    } else if (src_lo && strcmp(src_lo, dst_lo) != 0) {
        emit_mov(isel, dst_lo, src_lo, ins);
    }
}

static void setup_call_param_u24(ISelContext* isel, Instr* ins, const char* callee_name, int param_pos, int class_index, ValueName v, RegMove* moves, int* move_count) {
    if (class_index != 0) {
        if (callee_name && isel) {
            char sym[128];
            snprintf(sym, sizeof(sym), "__param_%s_%d", callee_name, param_pos);
            char sym1[192], sym2[192];
            snprintf(sym1, sizeof(sym1), "(%s + 1)", sym);
            snprintf(sym2, sizeof(sym2), "(%s + 2)", sym);
            const char* lo = isel_get_lo_reg(isel, v);
            const char* hi = isel_get_hi_reg(isel, v);
            if (lo) emit_mov(isel, sym, lo, ins);
            if (hi) emit_mov(isel, sym1, hi, NULL);
            int base = isel_get_value_reg(isel, v);
            if (base >= 0 && base + 2 < 8) emit_mov(isel, sym2, isel_reg_name(base + 2), NULL);
        }
        return;
    }

    int64_t imm_val = 0;
    if (try_get_value_const(isel, v, &imm_val)) {
        char imm0[32], imm1[32], imm2[32];
        snprintf(imm0, sizeof(imm0), "#%d", (int)((imm_val >> 16) & 0xFF));
        snprintf(imm1, sizeof(imm1), "#%d", (int)((imm_val >> 8) & 0xFF));
        snprintf(imm2, sizeof(imm2), "#%d", (int)(imm_val & 0xFF));
        emit_mov(isel, "R1", imm0, ins);
        emit_mov(isel, "R2", imm1, NULL);
        emit_mov(isel, "R3", imm2, NULL);
        return;
    }

    int base = isel_get_value_reg(isel, v);
    if (base >= 0 && base + 2 < 8) {
        if (*move_count < 64) moves[(*move_count)++] = (RegMove){.dst = 1, .src = base};
        if (*move_count < 64) moves[(*move_count)++] = (RegMove){.dst = 2, .src = base + 1};
        if (*move_count < 64) moves[(*move_count)++] = (RegMove){.dst = 3, .src = base + 2};
        return;
    }

    if (base == -3) {
        int r = isel_reload_spill(isel, v, 3, ins);
        if (r >= 0 && r + 2 < 8) {
            if (*move_count < 64) moves[(*move_count)++] = (RegMove){.dst = 1, .src = r};
            if (*move_count < 64) moves[(*move_count)++] = (RegMove){.dst = 2, .src = r + 1};
            if (*move_count < 64) moves[(*move_count)++] = (RegMove){.dst = 3, .src = r + 2};
        }
    }
}

static void emit_indirect_call(ISelContext* isel, Instr* ins, ValueName callee) {
    const char* callee_lo = isel_get_lo_reg(isel, callee);
    const char* callee_hi = isel_get_hi_reg(isel, callee);

    char* l_cont = isel_new_label(isel, "Lcall_indirect_cont");
    char lbuf_cont[64];
    snprintf(lbuf_cont, sizeof(lbuf_cont), "%s:", l_cont);

    char cont_addr[256];
    snprintf(cont_addr, sizeof(cont_addr), "#%s", l_cont);
    isel_emit(isel, "MOV", "DPTR", cont_addr, NULL);
    isel_emit(isel, "PUSH", "DPH", NULL, NULL);
    isel_emit(isel, "PUSH", "DPL", NULL, NULL);

    emit_mov(isel, "DPL", callee_lo, ins);
    emit_mov(isel, "DPH", callee_hi, NULL);
    isel_emit(isel, "CLR", "A", NULL, NULL);
    isel_emit(isel, "JMP", "@A+DPTR", NULL, instr_to_ssa_str(ins));
    isel_emit(isel, lbuf_cont, NULL, NULL, NULL);

    free(l_cont);
}

static void bind_call_result_to_return_regs(ISelContext* isel, ValueName dest, int size) {
    if (!isel || !isel->ctx || !isel->ctx->value_to_reg || dest <= 0) return;

    int base_reg = -1;
    if (size == 1) base_reg = 7;
    else if (size == 2) base_reg = 6;
    else return;

    int* reg_num = malloc(sizeof(int));
    if (!reg_num) return;
    *reg_num = base_reg;

    char* key = int_to_key(dest);
    dict_put(isel->ctx->value_to_reg, key, reg_num);

    for (int offset = 0; offset < size; offset++) {
        if (base_reg + offset < 8) {
            isel->reg_val[base_reg + offset] = dest;
        }
    }
}

void emit_call_instr(ISelContext* isel, Instr* ins, Instr* next) {
    if (!isel || !ins || !ins->labels || ins->labels->len < 1) return;
    const char* fname = list_get(ins->labels, 0);
    if (!fname) return;

    bool indirect = ins->labels->len > 1 && strcmp((const char*)list_get(ins->labels, 1), "indirect") == 0;
    int arg_start = indirect ? 1 : 0;
    ValueName callee_val = (indirect && ins->args && ins->args->len > 0)
        ? *(ValueName*)list_get(ins->args, 0)
        : -1;
    int size1_index = 0;
    int size2_index = 0;
    int size3_index = 0;
    int size4_index = 0;

    RegMove moves[64];
    int move_count = 0;
    for (int k = arg_start; ins->args && k < ins->args->len; k++) {
        ValueName v = *(ValueName*)list_get(ins->args, k);
        char* key = int_to_key(v);
        Ctype* t = NULL;
        if (isel->ctx && isel->ctx->value_type) {
            t = (Ctype*)dict_get(isel->ctx->value_type, key);
        }
        free(key);

        int size = t ? c51_abi_type_size(t) : 1;
        int param_pos = k - arg_start;
        int class_index = 0;
        if (size == 1) {
            class_index = size1_index++;
        } else if (size == 2) {
            class_index = size2_index++;
        } else if (size == 3) {
            class_index = size3_index++;
        } else if (size == 4) {
            class_index = size4_index++;
        }

        if (size == 1) {
            setup_call_param_u8(isel, ins, fname, param_pos, class_index, v, moves, &move_count);
        } else if (size == 2) {
            setup_call_param_u16(isel, ins, fname, param_pos, class_index, v, moves, &move_count);
        } else if (size == 3) {
            setup_call_param_u24(isel, ins, fname, param_pos, class_index, v, moves, &move_count);
        }
    }

    emit_parallel_reg_moves(isel, moves, move_count, ins);

    if (indirect && callee_val > 0) {
        emit_indirect_call(isel, ins, callee_val);
    } else {
        char callee[256];
        snprintf(callee, sizeof(callee), "_%s", fname);
        isel_emit(isel, "LCALL", callee, NULL, instr_to_ssa_str(ins));
    }

    if (ins->dest > 0) {
        int size = ins->type ? c51_abi_type_size(ins->type) : 1;
        bool spill_dest = isel_value_is_spilled(isel, ins->dest);
        bool skip_copy_back = false;
        if (next && next->op == IROP_RET && next->args && next->args->len > 0) {
            ValueName ret_arg = *(ValueName*)list_get(next->args, 0);
            if (ret_arg == ins->dest) {
                skip_copy_back = true;
            }
        }

        if (skip_copy_back) {
            bind_call_result_to_return_regs(isel, ins->dest, size);
        } else {
            int reg = alloc_reg_for_value(isel, ins->dest, size);
            int phys_reg = reg;
            if (phys_reg < 0) phys_reg = 0;
            if (size == 1) {
                const char* lo = isel_reg_name(phys_reg + (size == 2 ? 1 : 0));
                if (strcmp("R7", lo) != 0) emit_mov(isel, lo, "R7", ins);
            } else if (size == 2) {
                const char* lo = isel_reg_name(phys_reg + 1);
                const char* hi = isel_reg_name(phys_reg);
                if (strcmp("R7", lo) != 0) emit_mov(isel, lo, "R7", ins);
                if (strcmp("R6", hi) != 0) emit_mov(isel, hi, "R6", ins);
            }
            if (spill_dest) {
                isel_store_spill_from_reg(isel, ins->dest, phys_reg, size, ins);
            }
        }
    }
}

void emit_ret(ISelContext* isel, Instr* ins) {
    if (isel && isel->ctx && isel->ctx->current_func && isel->ctx->current_func->is_interrupt) {
        isel_emit(isel, "POP", "DPH", NULL, NULL);
        isel_emit(isel, "POP", "DPL", NULL, NULL);
        isel_emit(isel, "POP", "B", NULL, NULL);
        isel_emit(isel, "POP", "ACC", NULL, NULL);
        isel_emit(isel, "POP", "PSW", NULL, NULL);
        isel_emit(isel, "RETI", NULL, NULL, instr_to_ssa_str(ins));
        return;
    }

    int64_t imm_val = 0;
    if (is_imm_operand(ins, &imm_val)) {
        int ret_size = ins->type ? c51_abi_type_size(ins->type) : 1;
        int lo = (int)(imm_val & 0xFF);
        char imm_lo[32]; snprintf(imm_lo, sizeof(imm_lo), "#%d", lo);
        char* ssa = instr_to_ssa_str(ins);
        isel_emit(isel, "MOV", "R7", imm_lo, ssa);
        if (ret_size == 2) {
            int hi = (int)((imm_val >> 8) & 0xFF);
            char imm_hi[32]; snprintf(imm_hi, sizeof(imm_hi), "#%d", hi);
            isel_emit(isel, "MOV", "R6", imm_hi, NULL);
        }
        isel_emit(isel, "RET", NULL, NULL, ssa);
        if (ssa) free(ssa);
        return;
    }

    if (ins->args && ins->args->len > 0) {
        ValueName ret_val = *(ValueName*)list_get(ins->args, 0);
        int ret_size = ins->type ? c51_abi_type_size(ins->type) : 1;
        int val_size = get_value_size(isel, ret_val);

        const char* ret_lo = isel_get_lo_reg(isel, ret_val);
        if (ret_lo && strcmp(ret_lo, "R7") != 0) {
            emit_mov(isel, "R7", ret_lo, ins);
        }

        if (ret_size == 2) {
            if (val_size == 2) {
                const char* ret_hi = isel_get_hi_reg(isel, ret_val);
                if (ret_hi && strcmp(ret_hi, "R6") != 0) {
                    emit_mov(isel, "R6", ret_hi, ins);
                }
            } else {
                isel_emit(isel, "MOV", "R6", "#0", NULL);
            }
        }
    }

    isel_emit(isel, "RET", NULL, NULL, instr_to_ssa_str(ins));
}
