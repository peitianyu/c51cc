#include "c51_gen.h"

bool is_reg_eq(const char *a, const char *b)
{
    return a && b && !strcmp(a, b);
}

unsigned reg_bit(int r)
{
    if (r < 0 || r > 7) return 0;
    return 1u << r;
}

unsigned reg_mask_from_arg(const char *arg)
{
    int r = parse_reg_rn(arg);
    if (r >= 0) return reg_bit(r);
    r = parse_indirect_rn(arg);
    if (r >= 0) return reg_bit(r);
    return 0;
}

void reg_use_def(const AsmInstr *ins, unsigned *use, unsigned *def)
{
    if (use) *use = 0;
    if (def) *def = 0;
    if (!ins || !ins->op || !ins->args) return;

    const char *op = ins->op;
    char *a0 = (ins->args->len > 0) ? list_get(ins->args, 0) : NULL;
    char *a1 = (ins->args->len > 1) ? list_get(ins->args, 1) : NULL;

    if (!strcmp(op, "mov") && a0 && a1) {
        int rd = parse_reg_rn(a0);
        int rs = parse_reg_rn(a1);
        int id = parse_indirect_rn(a0);
        int is = parse_indirect_rn(a1);
        if (def && rd >= 0) *def |= reg_bit(rd);
        if (use && rs >= 0) *use |= reg_bit(rs);
        if (use && id >= 0) *use |= reg_bit(id);
        if (use && is >= 0) *use |= reg_bit(is);
        return;
    }

    if ((!strcmp(op, "inc") || !strcmp(op, "dec")) && a0) {
        int r = parse_reg_rn(a0);
        int ir = parse_indirect_rn(a0);
        if (r >= 0) {
            if (use) *use |= reg_bit(r);
            if (def) *def |= reg_bit(r);
        } else if (ir >= 0) {
            if (use) *use |= reg_bit(ir);
        }
        return;
    }

    if (!strcmp(op, "djnz") && a0) {
        int r = parse_reg_rn(a0);
        if (r >= 0) {
            if (use) *use |= reg_bit(r);
            if (def) *def |= reg_bit(r);
        }
        return;
    }

    if (!strcmp(op, "cjne") && a0) {
        if (use) {
            *use |= reg_mask_from_arg(a0);
            if (a1) *use |= reg_mask_from_arg(a1);
        }
        return;
    }

    if (!strcmp(op, "push") && a0) {
        if (use) *use |= reg_mask_from_arg(a0);
        return;
    }

    if (!strcmp(op, "pop") && a0) {
        int r = parse_reg_rn(a0);
        if (def && r >= 0) *def |= reg_bit(r);
        return;
    }

    if ((!strcmp(op, "add") || !strcmp(op, "subb") || !strcmp(op, "anl") ||
         !strcmp(op, "orl") || !strcmp(op, "xrl")) && a0 && a1) {
        int r0 = parse_reg_rn(a0);
        if (r0 >= 0) {
            if (use) *use |= reg_bit(r0);
            if (def) *def |= reg_bit(r0);
        } else {
            if (use) *use |= reg_mask_from_arg(a0);
        }
        if (use) *use |= reg_mask_from_arg(a1);
        return;
    }

    if (use) {
        *use |= reg_mask_from_arg(a0);
        *use |= reg_mask_from_arg(a1);
    }
}

void shrink_call_saves(Section *sec)
{
    if (!sec || !sec->asminstrs) return;
    int n = sec->asminstrs->len;
    if (n <= 0) return;

    unsigned *live_after = gen_alloc(sizeof(unsigned) * n);
    unsigned live = 0;
    for (int i = n - 1; i >= 0; --i) {
        live_after[i] = live;
        AsmInstr *ins = list_get(sec->asminstrs, i);
        unsigned use = 0, def = 0;
        reg_use_def(ins, &use, &def);
        live = (live & ~def) | use;
    }

    for (int i = 0; i < n; ++i) {
        AsmInstr *ins = list_get(sec->asminstrs, i);
        if (!ins || !ins->op || strcmp(ins->op, "lcall") != 0) continue;

        unsigned live_regs = live_after[i];
        int push_idx[8];
        int pop_idx[8];
        for (int r = 0; r < 8; ++r) { push_idx[r] = -1; pop_idx[r] = -1; }

        int found = 0;
        for (int j = i - 1; j >= 0 && found < 8; --j) {
            AsmInstr *p = list_get(sec->asminstrs, j);
            if (!p || !p->op) continue;
            if (!strcmp(p->op, ".label")) break;
            if (!strcmp(p->op, "push") && p->args && p->args->len == 1) {
                char *a0 = list_get(p->args, 0);
                int r = parse_reg_rn(a0);
                if (r >= 0 && push_idx[r] < 0) {
                    push_idx[r] = j;
                    ++found;
                }
            }
        }

        int pos = -1;
        for (int j = i + 1; j < n; ++j) {
            AsmInstr *p = list_get(sec->asminstrs, j);
            if (!p || !p->op) continue;
            if (!strcmp(p->op, "pop") && p->args && p->args->len == 1) {
                char *a0 = list_get(p->args, 0);
                int r = parse_reg_rn(a0);
                if (r == 7) { pop_idx[7] = j; pos = j; break; }
            }
            if (!strcmp(p->op, ".label")) break;
        }
        if (pos >= 0) {
            for (int r = 6; r >= 0; --r) {
                for (int j = pos + 1; j < n; ++j) {
                    AsmInstr *p = list_get(sec->asminstrs, j);
                    if (!p || !p->op) continue;
                    if (!strcmp(p->op, "pop") && p->args && p->args->len == 1) {
                        char *a0 = list_get(p->args, 0);
                        int rr = parse_reg_rn(a0);
                        if (rr == r) { pop_idx[r] = j; pos = j; break; }
                    }
                    if (!strcmp(p->op, ".label")) break;
                }
            }
        }

        for (int r = 0; r < 8; ++r) {
            if ((live_regs & reg_bit(r)) != 0) continue;
            if (push_idx[r] >= 0 && pop_idx[r] >= 0) {
                AsmInstr *p = list_get(sec->asminstrs, push_idx[r]);
                AsmInstr *q = list_get(sec->asminstrs, pop_idx[r]);
                free_asminstr(p);
                free_asminstr(q);
                list_set(sec->asminstrs, push_idx[r], NULL);
                list_set(sec->asminstrs, pop_idx[r], NULL);
            }
        }
    }
}

const char *invert_jcc(const char *op)
{
    if (!op) return NULL;
    if (!strcmp(op, "jz")) return "jnz";
    if (!strcmp(op, "jnz")) return "jz";
    if (!strcmp(op, "jc")) return "jnc";
    if (!strcmp(op, "jnc")) return "jc";
    return NULL;
}

void peephole_section_asminstrs(Section *sec)
{
    if (!sec || !sec->asminstrs) return;
    List *out = make_list();

    for (int i = 0; i < sec->asminstrs->len; ++i) {
        AsmInstr *ins = list_get(sec->asminstrs, i);
        AsmInstr *next = (i + 1 < sec->asminstrs->len) ? list_get(sec->asminstrs, i + 1) : NULL;
        AsmInstr *next2 = (i + 2 < sec->asminstrs->len) ? list_get(sec->asminstrs, i + 2) : NULL;
        if (!ins || !ins->op) {
            list_push(out, ins);
            continue;
        }

        if ((ins->op && (!strcmp(ins->op, "sjmp") || !strcmp(ins->op, "ljmp") ||
                         !strcmp(ins->op, "jz") || !strcmp(ins->op, "jnz") ||
                         !strcmp(ins->op, "jc") || !strcmp(ins->op, "jnc"))) &&
            ins->args && ins->args->len == 1 && next && next->op && !strcmp(next->op, ".label") &&
            next->args && next->args->len >= 1) {
            char *t = list_get(ins->args, 0);
            char *lbl = list_get(next->args, 0);
            if (t && lbl && !strcmp(t, lbl)) {
                free_asminstr(ins);
                continue;
            }
        }

        if (!strcmp(ins->op, "push") && ins->args && ins->args->len == 1 &&
            next && next->op && !strcmp(next->op, "pop") && next->args && next->args->len == 1) {
            char *a0 = list_get(ins->args, 0);
            char *b0 = list_get(next->args, 0);
            if (a0 && b0 && !strcmp(a0, b0)) {
                free_asminstr(ins);
                free_asminstr(next);
                ++i;
                continue;
            }
        }

        if ((ins->op && (!strcmp(ins->op, "anl") || !strcmp(ins->op, "orl") || !strcmp(ins->op, "xrl"))) &&
            ins->args && ins->args->len >= 2) {
            char *a0 = list_get(ins->args, 0);
            char *a1 = list_get(ins->args, 1);
            int imm = 0;
            if (a0 && !strcmp(a0, "A") && a1 && parse_immediate(a1, &imm)) {
                if ((!strcmp(ins->op, "anl") && (imm & 0xFF) == 0xFF) ||
                    (!strcmp(ins->op, "orl") && (imm & 0xFF) == 0x00) ||
                    (!strcmp(ins->op, "xrl") && (imm & 0xFF) == 0x00)) {
                    free_asminstr(ins);
                    continue;
                }
            }
        }

        if ((ins->op && (!strcmp(ins->op, "add") || !strcmp(ins->op, "subb"))) &&
            ins->args && ins->args->len >= 2) {
            char *a0 = list_get(ins->args, 0);
            char *a1 = list_get(ins->args, 1);
            int imm = 0;
            if (a0 && !strcmp(a0, "A") && a1 && parse_immediate(a1, &imm)) {
                if (imm == 0) {
                    free_asminstr(ins);
                    continue;
                }
                if (!strcmp(ins->op, "add") && imm == 1) {
                    AsmInstr *inc = gen_instr_new("inc");
                    gen_instr_add_arg(inc, "A");
                    list_push(out, inc);
                    free_asminstr(ins);
                    continue;
                }
            }
        }

        if (ins->op && next && next2 &&
            (!strcmp(ins->op, "jz") || !strcmp(ins->op, "jnz") ||
             !strcmp(ins->op, "jc") || !strcmp(ins->op, "jnc")) &&
            ins->args && ins->args->len == 1 &&
            next->op && !strcmp(next->op, "sjmp") &&
            next->args && next->args->len == 1 &&
            next2->op && !strcmp(next2->op, ".label") &&
            next2->args && next2->args->len >= 1) {
            char *t = list_get(ins->args, 0);
            char *lbl = list_get(next2->args, 0);
            const char *inv = invert_jcc(ins->op);
            if (t && lbl && inv && !strcmp(t, lbl)) {
                AsmInstr *j = gen_instr_new(inv);
                gen_instr_add_arg(j, list_get(next->args, 0));
                list_push(out, j);
                free_asminstr(ins);
                free_asminstr(next);
                ++i;
                continue;
            }
        }

        if (ins->op && next && next2 && !strcmp(ins->op, "cjne") &&
            ins->args && ins->args->len == 3 &&
            next->op && !strcmp(next->op, "sjmp") && next->args && next->args->len == 1 &&
            next2->op && !strcmp(next2->op, ".label") && next2->args && next2->args->len >= 1) {
            char *a0 = list_get(ins->args, 0);
            char *a1 = list_get(ins->args, 1);
            char *a2 = list_get(ins->args, 2);
            char *lbl = list_get(next2->args, 0);
            int imm = 0;
            if (a0 && !strcmp(a0, "A") && a1 && parse_immediate(a1, &imm) && imm == 0 &&
                a2 && lbl && !strcmp(a2, lbl)) {
                AsmInstr *j = gen_instr_new("jz");
                gen_instr_add_arg(j, list_get(next->args, 0));
                list_push(out, j);
                free_asminstr(ins);
                free_asminstr(next);
                ++i;
                continue;
            }
        }

        if (!strcmp(ins->op, "mov") && ins->args && ins->args->len >= 2) {
            char *dst = list_get(ins->args, 0);
            char *src = list_get(ins->args, 1);
            if (is_reg_eq(dst, src)) {
                free_asminstr(ins);
                continue;
            }
            if (next && next->op && !strcmp(next->op, "mov") && next->args && next->args->len >= 2) {
                char *ndst = list_get(next->args, 0);
                char *nsrc = list_get(next->args, 1);
                int imm = 0;
                if (dst && src && ndst && nsrc) {
                    if (!strcmp(dst, "A") && parse_immediate(src, &imm) && !strcmp(nsrc, "A") && parse_reg_rn(ndst) >= 0) {
                        char ibuf[16];
                        snprintf(ibuf, sizeof(ibuf), "#%d", imm);
                        list_set(next->args, 1, gen_strdup(ibuf));
                        free(nsrc);
                        list_push(out, next);
                        free_asminstr(ins);
                        ++i;
                        continue;
                    }
                    if (parse_reg_rn(dst) >= 0 && parse_immediate(src, &imm) && !strcmp(ndst, "A") && !strcmp(nsrc, dst)) {
                        char ibuf[16];
                        snprintf(ibuf, sizeof(ibuf), "#%d", imm);
                        list_set(next->args, 1, gen_strdup(ibuf));
                        free(nsrc);
                        list_push(out, next);
                        free_asminstr(ins);
                        ++i;
                        continue;
                    }
                }
            }
            if (next && next->op && !strcmp(next->op, "mov") && next->args && next->args->len >= 2) {
                char *ndst = list_get(next->args, 0);
                char *nsrc = list_get(next->args, 1);
                if (dst && src && ndst && nsrc) {
                    if (!strcmp(dst, "A") && parse_reg_rn(src) >= 0 && !strcmp(nsrc, "A") && !strcmp(ndst, src)) {
                        list_push(out, ins);
                        free_asminstr(next);
                        ++i;
                        continue;
                    }
                    if (parse_reg_rn(dst) >= 0 && !strcmp(src, "A") && !strcmp(ndst, "A") && !strcmp(nsrc, dst)) {
                        list_push(out, ins);
                        free_asminstr(next);
                        ++i;
                        continue;
                    }
                    if (!strcmp(dst, "A") && parse_reg_rn(src) >= 0 && !strcmp(ndst, "A") && !strcmp(nsrc, src)) {
                        list_push(out, ins);
                        free_asminstr(next);
                        ++i;
                        continue;
                    }
                }
            }
        }

        if (!strcmp(ins->op, "mov") && ins->args && ins->args->len >= 2 &&
            next && next->op && !strcmp(next->op, "add") && next->args && next->args->len >= 2) {
            char *dst = list_get(ins->args, 0);
            char *src = list_get(ins->args, 1);
            char *a0 = list_get(next->args, 0);
            char *a1 = list_get(next->args, 1);
            int imm = 0;
            if (dst && src && a0 && a1 && !strcmp(dst, "A") && !strcmp(a0, "A") && parse_immediate(src, &imm)) {
                if (imm == 0 && parse_immediate(a1, &imm)) {
                    char ibuf[16];
                    snprintf(ibuf, sizeof(ibuf), "#%d", imm);
                    list_set(ins->args, 1, gen_strdup(ibuf));
                    free(src);
                    list_push(out, ins);
                    free_asminstr(next);
                    ++i;
                    continue;
                }
            }
        }

        list_push(out, ins);
    }

    free(sec->asminstrs);
    sec->asminstrs = out;
}
