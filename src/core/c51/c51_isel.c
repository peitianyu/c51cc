#include "c51_isel_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "c51_isel_regalloc.h"

char* int_to_key(int n) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%02XH", n);
    return strdup(buf);
}

char* instr_to_ssa_str(Instr *ins) {
    if (!ins) return strdup("");

    char *buf = NULL;
    size_t len = 0;
    FILE *f = open_memstream(&buf, &len);
    if (!f) return strdup("");
    ssa_print_instr(f, ins, NULL);
    fclose(f);
    if (!buf) return strdup("");
    char *p = buf;
    while (*p == ' ' || *p == '\t') p++;
    size_t blen = strlen(p);
    while (blen > 0 && (p[blen - 1] == '\n' || p[blen - 1] == '\r')) p[--blen] = '\0';
    char *out = malloc(blen + 3);
    if (out) sprintf(out, "; %s", p);
    free(buf);
    return out ? out : strdup("");
}

const char* isel_reg_name(int reg) {
    static const char* names[] = {"R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7"};
    if (reg >= 0 && reg < 8) return names[reg];
    return "R7";
}

int isel_get_value_reg(ISelContext* isel, ValueName val) {
    if (!isel || !isel->ctx || !isel->ctx->value_to_reg) return -1;
    char* key = int_to_key(val);
    int* reg_ptr = (int*)dict_get(isel->ctx->value_to_reg, key);
    free(key);
    if (reg_ptr) return *reg_ptr;
    return -1;
}

const char* isel_get_value_reg_at(ISelContext* isel, ValueName val, int offset) {
    int base_reg = isel_get_value_reg(isel, val);
    if (base_reg == -2) return "A";
    if (base_reg < 0) {
        if (offset == 0) return "R6";
        else return "R7";
    }
    if (base_reg + offset < 8) return isel_reg_name(base_reg + offset);
    return isel_reg_name(7);
}

const char* isel_get_lo_reg(ISelContext* isel, ValueName val) {
    int size = get_value_size(isel, val);
    int base_reg = isel_get_value_reg(isel, val);

    if (base_reg == -2) return "A";
    if (base_reg < 0) {
        if (base_reg == -3) {
            int r = isel_reload_spill(isel, val, size, NULL);
            if (r >= 0) return isel_reg_name(r + (size == 2 ? 1 : 0));
            return "A";
        }
        return "R7";
    }

    if (size == 1) {
        return isel_reg_name(base_reg);
    } else {
        return isel_reg_name(base_reg + 1);
    }
}

const char* isel_get_hi_reg(ISelContext* isel, ValueName val) {
    int base_reg = isel_get_value_reg(isel, val);
    int size = get_value_size(isel, val);
    if (base_reg == -3) {
        int r = isel_reload_spill(isel, val, size, NULL);
        if (r >= 0) return isel_reg_name(r);
        return "A";
    }
    return isel_get_value_reg_at(isel, val, 0);
}

int alloc_dest_reg(ISelContext* isel, Instr* ins, Instr* next, int size, bool try_bind) {
    int reg = alloc_reg_for_value(isel, ins->dest, size);
    if (try_bind && next) {
        int bound = try_bind_result_to_phi_target(isel, ins, next, size);
        if (bound >= 0) reg = bound;
    }
    return reg;
}

char* isel_new_label(ISelContext* isel, const char* prefix) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%s_%d", prefix, isel->label_counter++);
    return strdup(buf);
}

void isel_emit(ISelContext* isel, const char* op, const char* arg1, const char* arg2, const char* ssa) {
    if (!isel || !isel->sec) return;

    AsmInstr* ins = calloc(1, sizeof(AsmInstr));
    /* If this emission is a bare label/op with no args or ssa and
       it doesn't already end with ':' then treat it as a label and
       append ':' so the output printer will print it at column 0. */
    bool is_label_candidate = (op && arg1 == NULL && arg2 == NULL && ssa == NULL);
    if (is_label_candidate) {
        size_t oplen = strlen(op);
        if (oplen == 0) {
            ins->op = strdup(op);
        } else if (op[oplen - 1] == ':') {
            ins->op = strdup(op);
        } else {
            char *lbl = malloc(oplen + 2);
            if (lbl) {
                strcpy(lbl, op);
                lbl[oplen] = ':';
                lbl[oplen+1] = '\0';
                ins->op = lbl; /* will be freed later */
            } else {
                ins->op = strdup(op);
            }
        }
    } else {
        ins->op = strdup(op);
    }
    ins->args = make_list();
    if (arg1) list_push(ins->args, strdup(arg1));
    if (arg2) list_push(ins->args, strdup(arg2));
    if (ssa) ins->ssa = strdup(ssa);
    list_push(isel->sec->asminstrs, ins);
}

void isel_emit_label(ISelContext* isel, const char* label) {
    if (!isel || !isel->sec || !label) return;
    isel_emit(isel, label, NULL, NULL, NULL);
}

void isel_ensure_in_acc(ISelContext* isel, ValueName val) {
    if (!isel || val <= 0) return;

    if (isel->acc_busy && isel->acc_val == val) return;

    const char* reg = isel_get_lo_reg(isel, val);
    if (strcmp(reg, "A") != 0) {
        isel_emit(isel, "MOV", "A", reg, NULL);
    }

    isel->acc_busy = true;
    isel->acc_val = val;
}

bool isel_can_keep_in_acc(ISelContext* isel, Instr* ins, Instr* next) {
    (void)isel;
    if (!ins || !next || ins->dest <= 0) return false;

    if (next->args) {
        for (int i = 0; i < next->args->len; i++) {
            ValueName* p = list_get(next->args, i);
            if (p && *p == ins->dest) return true;
        }
    }
    return false;
}

static bool detect_simple_counter_loop(Func* f, int *out_count) {
    if (!f || !out_count) return false;
    int phi_count = 0;
    for (Iter bit = list_iter(f->blocks); !iter_end(bit);) {
        Block* b = iter_next(&bit);
        if (b && b->phis) phi_count += b->phis->len;
    }
    if (phi_count != 1) return false;

    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block* hdr = iter_next(&it);
        if (!hdr || !hdr->phis || hdr->phis->len == 0) continue;

        for (Iter pit = list_iter(hdr->phis); !iter_end(pit);) {
            Instr* phi = iter_next(&pit);
            if (!phi || phi->op != IROP_PHI) continue;
            ValueName phi_dest = phi->dest;

            Instr* lt = NULL; Instr* br = NULL;
            for (Iter iit = list_iter(hdr->instrs); !iter_end(iit);) {
                Instr* ins = iter_next(&iit);
                if (!ins) continue;
                if (ins->op == IROP_LT) {
                    if (!ins->args || ins->args->len < 2) continue;
                    ValueName a0 = *(ValueName*)list_get(ins->args, 0);
                    if (a0 != phi_dest) continue;
                    lt = ins;
                    break;
                }
            }
            if (!lt) continue;

            bool found_br = false;
            for (Iter iit = list_iter(hdr->instrs); !iter_end(iit);) {
                Instr* ins = iter_next(&iit);
                if (ins == lt) {
                    Instr* next = iter_next(&iit);
                    if (next && next->op == IROP_BR) { br = next; found_br = true; }
                    break;
                }
            }
            if (!found_br || !br) continue;

            ValueName cmp_rhs = *(ValueName*)list_get(lt->args, 1);
            Instr* const_k = find_def_instr_in_func(f, cmp_rhs);
            if (!const_k || const_k->op != IROP_CONST) continue;
            int K = (int)const_k->imm.ival;
            if (K <= 0) continue;

            if (!br->labels || br->labels->len < 1) continue;
            const char* lbl_t = (const char*)list_get(br->labels, 0);
            int id_t = parse_block_id(lbl_t);
            if (id_t < 0) continue;
            Block* body = find_block_by_id(f, id_t);
            if (!body) continue;

            if (!body->instrs || body->instrs->len == 0) continue;
            Instr* last = (Instr*)list_get(body->instrs, body->instrs->len - 1);
            if (!last || last->op != IROP_JMP || !last->labels || last->labels->len < 1) continue;
            int jmp_target = parse_block_id((const char*)list_get(last->labels, 0));
            if (jmp_target != (int)hdr->id) continue;

            bool found_add = false;
            for (Iter iit = list_iter(body->instrs); !iter_end(iit);) {
                Instr* ins = iter_next(&iit);
                if (!ins || ins->op != IROP_ADD) continue;
                if (!ins->args || ins->args->len < 2) continue;
                ValueName a0 = *(ValueName*)list_get(ins->args, 0);
                ValueName a1 = *(ValueName*)list_get(ins->args, 1);
                if (a0 != phi_dest) continue;
                Instr* const1 = find_def_instr_in_func(f, a1);
                if (!const1 || const1->op != IROP_CONST) continue;
                if ((int)const1->imm.ival != 1) continue;
                found_add = true;
                break;
            }
            if (!found_add) continue;

            bool found_init0 = false;
            for (int i = 0; i < phi->labels->len && i < phi->args->len; i++) {
                ValueName arg = *(ValueName*)list_get(phi->args, i);
                Instr* def = find_def_instr_in_func(f, arg);
                if (def && def->op == IROP_CONST && (int)def->imm.ival == 0) { found_init0 = true; break; }
            }
            if (!found_init0) continue;

            *out_count = K;
            return true;
        }
    }
    return false;
}

static bool detect_two_counter_loops(Func* f, int *out_outer, int *out_inner) {
    if (!f || !out_outer || !out_inner) return false;
    int found = 0;
    int vals[2] = {0, 0};

    for (Iter bit = list_iter(f->blocks); !iter_end(bit);) {
        Block* b = iter_next(&bit);
        if (!b || !b->instrs) continue;
        for (Iter iit = list_iter(b->instrs); !iter_end(iit);) {
            Instr* ins = iter_next(&iit);
            if (!ins) continue;
            if (ins->op == IROP_LT && ins->args && ins->args->len >= 2) {
                ValueName rhs = *(ValueName*)list_get(ins->args, 1);
                Instr* def = find_def_instr_in_func(f, rhs);
                if (def && def->op == IROP_CONST) {
                    int K = (int)def->imm.ival;
                    if (K > 0) {
                        bool dup = false;
                        for (int j = 0; j < found; j++) if (vals[j] == K) { dup = true; break; }
                        if (!dup && found < 2) vals[found++] = K;
                    }
                }
            }
            if (found >= 2) break;
        }
        if (found >= 2) break;
    }

    if (found >= 2) {
        if (vals[0] >= vals[1]) { *out_outer = vals[0]; *out_inner = vals[1]; }
        else { *out_outer = vals[1]; *out_inner = vals[0]; }
        return true;
    }
    return false;
}

static void isel_record_dest_type(ISelContext* isel, Instr* ins) {
    if (!isel || !ins) return;
    if (ins->dest > 0 && ins->type && isel->ctx && isel->ctx->value_type) {
        char* key = int_to_key(ins->dest);
        dict_put(isel->ctx->value_type, key, ins->type);
    }
}

void isel_instr(ISelContext* isel, Instr* ins, Instr* next) {
    if (!isel || !ins) return;
    isel_record_dest_type(isel, ins);

    switch (ins->op) {
        case IROP_NOP:
            break;
        case IROP_CONST:
            emit_const(isel, ins);
            break;
        case IROP_PARAM:
            break;
        case IROP_ADD:
            emit_add(isel, ins, next);
            break;
        case IROP_SUB:
            emit_sub(isel, ins, next);
            break;
        case IROP_MUL:
            emit_mul(isel, ins, next);
            break;
        case IROP_DIV:
            emit_div_mod(isel, ins, false);
            break;
        case IROP_MOD:
            emit_div_mod(isel, ins, true);
            break;
        case IROP_NEG:
            emit_neg(isel, ins);
            break;
        case IROP_AND:
            emit_bitwise(isel, ins, next, "ANL");
            break;
        case IROP_OR:
            emit_bitwise(isel, ins, next, "ORL");
            break;
        case IROP_XOR:
            emit_bitwise(isel, ins, next, "XRL");
            break;
        case IROP_NOT:
            emit_not(isel, ins, next);
            break;
        case IROP_SHL:
            emit_shift(isel, ins, false);
            break;
        case IROP_SHR:
            emit_shift(isel, ins, true);
            break;
        case IROP_EQ:
            emit_cmp_eq(isel, ins, next);
            break;
        case IROP_LT:
            emit_cmp_lt_gt(isel, ins, next, false);
            break;
        case IROP_GT:
            emit_cmp_lt_gt(isel, ins, next, true);
            break;
        case IROP_LE:
            emit_cmp_le_ge(isel, ins, next, false);
            break;
        case IROP_GE:
            emit_cmp_le_ge(isel, ins, next, true);
            break;
        case IROP_NE:
            emit_ne(isel, ins, next);
            break;
        case IROP_LNOT:
            emit_lnot(isel, ins, next);
            break;
        case IROP_TRUNC:
            emit_trunc(isel, ins);
            break;
        case IROP_ZEXT:
            emit_simple_cast(isel, ins, false);
            break;
        case IROP_SEXT:
            emit_simple_cast(isel, ins, true);
            break;
        case IROP_BITCAST:
        case IROP_INTTOPTR:
        case IROP_PTRTOINT:
            emit_simple_cast(isel, ins, false);
            break;
        case IROP_OFFSET:
            emit_offset(isel, ins);
            break;
        case IROP_SELECT:
            emit_select(isel, ins);
            break;
        case IROP_PHI:
            break;
        case IROP_RET:
            emit_ret(isel, ins);
            break;
        case IROP_STORE:
            emit_store(isel, ins);
            break;
        case IROP_LOAD:
            emit_load(isel, ins);
            break;
        case IROP_JMP:
            emit_jmp(isel, ins);
            break;
        case IROP_BR:
            emit_br(isel, ins);
            break;
        case IROP_ADDR:
            emit_addr(isel, ins);
            break;
        case IROP_ASM:
            emit_inline_asm_instr(isel, ins);
            break;
        case IROP_CALL:
            emit_call_instr(isel, ins, next);
            break;
        default:
            break;
    }
}

void isel_block(ISelContext* isel, Block* block) {
    if (!isel || !block || !block->instrs) return;
    isel->current_block_id = (int)block->id;

    if (block->id > 0) {
        char label[32];
        snprintf(label, sizeof(label), "L%d:", block->id);
        isel_emit(isel, label, NULL, NULL, NULL);
    }

    int num_instrs = block->instrs->len;
    Instr** instrs = malloc(sizeof(Instr*) * num_instrs);
    int idx = 0;
    for (Iter it = list_iter(block->instrs); !iter_end(it);) {
        instrs[idx++] = iter_next(&it);
    }

    precompute_sbit_br(isel, instrs, num_instrs);
    precompute_br_simplify(isel, instrs, num_instrs);

    for (int i = 0; i < num_instrs; i++) {
        Instr* next = (i + 1 < num_instrs) ? instrs[i + 1] : NULL;
        isel_instr(isel, instrs[i], next);
    }

    free(instrs);
}

void isel_function(C51GenContext* ctx, Func* func) {
    if (!ctx || !func) return;

    if (ctx->value_to_reg) {
        dict_free(ctx->value_to_reg, free);
        ctx->value_to_reg = make_dict(NULL);
    }

    int sec_idx = obj_add_section(ctx->obj, "?PR?", SEC_CODE, 0, 1);
    Section* sec = obj_get_section(ctx->obj, sec_idx);

    int flags = SYM_FLAG_GLOBAL;
    obj_add_symbol(ctx->obj, func->name, SYM_FUNC, sec_idx, sec->size, 0, flags);

    ctx->current_func = func;

    ISelContext isel = {0};
    isel.ctx = ctx;
    isel.sec = sec;
    isel.label_counter = 0;
    isel.br_bitinfo = make_dict(NULL);
    isel.br_invert = make_dict(NULL);
    isel.last_const_reg = -100;
    isel.last_const_val = 0;
    isel.last_const_size = 0;

    for (int i = 0; i < 8; i++) {
        isel.reg_val[i] = -1;
    }

    char label[256];
    snprintf(label, sizeof(label), "%s:", func->name);
    isel_emit(&isel, label, NULL, NULL, NULL);

    alloc_param_regs(&isel, func);

    LinearScanContext* lsc = linscan_create();
    linscan_compute_intervals(lsc, func, ctx);
    linscan_allocate(lsc, ctx);

    for (Iter it = list_iter(func->blocks); !iter_end(it);) {
        Block* block = iter_next(&it);
        isel_block(&isel, block);
    }

    if (isel.br_bitinfo) {
        dict_free(isel.br_bitinfo, free_br_bitinfo);
        isel.br_bitinfo = NULL;
    }
    if (isel.br_invert) {
        dict_free(isel.br_invert, free);
        isel.br_invert = NULL;
    }

    linscan_destroy(lsc);

    (void)detect_simple_counter_loop;
    (void)detect_two_counter_loops;
}
