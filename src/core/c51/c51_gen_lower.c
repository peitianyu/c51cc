#include "c51_gen.h"

/* === Address/Value maps (using types from c51_gen.h) === */
char *vreg_key(ValueName v)
{
    char buf[32];
    snprintf(buf, sizeof(buf), "v%d", v);
    return gen_strdup(buf);
}

void mmio_map_put(const char *name, int addr, bool is_bit)
{
    if (!g_mmio_map || !name) return;
    MmioInfo *info = gen_alloc(sizeof(MmioInfo));
    info->addr = addr;
    info->is_bit = is_bit;
    dict_put(g_mmio_map, gen_strdup(name), info);
}

MmioInfo *mmio_map_get(const char *name)
{
    if (!g_mmio_map || !name) return NULL;
    return (MmioInfo *)dict_get(g_mmio_map, (char *)name);
}

void addr_map_put(ValueName v, const char *label, Ctype *mem_type)
{
    if (!g_addr_map || v <= 0 || !label) return;
    struct AddrInfo *info = gen_alloc(sizeof(struct AddrInfo));
    MmioInfo *mmio = mmio_map_get(label);
    if (mmio) {
        info->label = gen_strdup(label);
    } else {
        info->label = label;
    }
    info->mem_type = mem_type;
    info->is_stack = false;
    info->stack_off = 0;
    dict_put(g_addr_map, vreg_key(v), info);
}

struct AddrInfo *addr_map_get(ValueName v)
{
    if (!g_addr_map || v <= 0) return NULL;
    char buf[32];
    snprintf(buf, sizeof(buf), "v%d", v);
    return (struct AddrInfo *)dict_get(g_addr_map, buf);
}

void addr_map_put_stack(ValueName v, int offset, Ctype *mem_type)
{
    if (!g_addr_map || v <= 0) return;
    struct AddrInfo *info = gen_alloc(sizeof(struct AddrInfo));
    info->label = NULL;
    info->mem_type = mem_type;
    info->is_stack = true;
    info->stack_off = offset;
    dict_put(g_addr_map, vreg_key(v), info);
}

void const_map_put(ValueName v, int val)
{
    if (!g_const_map || v <= 0) return;
    int *p = gen_alloc(sizeof(int));
    *p = val;
    dict_put(g_const_map, vreg_key(v), p);
}

bool const_map_get(ValueName v, int *out)
{
    if (!g_const_map || v <= 0) return false;
    char buf[32];
    snprintf(buf, sizeof(buf), "v%d", v);
    int *p = (int *)dict_get(g_const_map, buf);
    if (!p) return false;
    if (out) *out = *p;
    return true;
}

void val_type_put(ValueName v, Ctype *t)
{
    if (!g_val_type || v <= 0 || !t) return;
    dict_put(g_val_type, vreg_key(v), t);
}

Ctype *val_type_get(ValueName v)
{
    if (!g_val_type || v <= 0) return NULL;
    return (Ctype *)dict_get(g_val_type, vreg_key(v));
}

int val_size(ValueName v)
{
    Ctype *t = val_type_get(v);
    return t ? t->size : 1;
}

static ValueName v16_resolve_alias(ValueName v)
{
    if (!g_v16_alias || v <= 0) return v;
    for (int i = 0; i < 8; ++i) {
        int *p = (int *)dict_get(g_v16_alias, vreg_key(v));
        if (!p || *p == v) break;
        v = *p;
    }
    return v;
}

int v16_addr(ValueName v)
{
    if (!g_v16_map || v <= 0) return -1;
    v = v16_resolve_alias(v);
    int *p = (int *)dict_get(g_v16_map, vreg_key(v));
    if (p) return *p;
    int *np = gen_alloc(sizeof(int));
    *np = g_v16_next;
    g_v16_next += 2;
    dict_put(g_v16_map, vreg_key(v), np);
    return *np;
}

void v16_alias_put(ValueName v, ValueName alias)
{
    if (!g_v16_alias || v <= 0 || alias <= 0 || v == alias) return;
    int *p = gen_alloc(sizeof(int));
    *p = alias;
    dict_put(g_v16_alias, vreg_key(v), p);
}

bool is_v16_value(ValueName v)
{
    if (!g_v16_map || v <= 0) return false;
    return dict_get(g_v16_map, vreg_key(v)) != NULL;
}

void fmt_direct(char *buf, size_t n, int addr)
{
    snprintf(buf, n, "0x%02X", addr & 0xFF);
}

void fmt_v16_direct(char *buf, size_t n, int addr)
{
    if (g_v16_base_label && g_v16_base_label[0]) {
        if (addr == 0) snprintf(buf, n, "%s", g_v16_base_label);
        else snprintf(buf, n, "%s+%d", g_v16_base_label, addr);
    } else {
        fmt_direct(buf, n, addr);
    }
}

void emit_set_v16(Section *sec, int addr, int val)
{
    char buf[16];
    snprintf(buf, sizeof(buf), "#%d", val & 0xFF);
    char dst0[64];
    fmt_v16_direct(dst0, sizeof(dst0), addr);
    emit_ins2(sec, "mov", dst0, buf);
    snprintf(buf, sizeof(buf), "#%d", (val >> 8) & 0xFF);
    char dst1[64];
    fmt_v16_direct(dst1, sizeof(dst1), addr + 1);
    emit_ins2(sec, "mov", dst1, buf);
}

static bool v16_reg_pair(ValueName v, int *lo, int *hi)
{
    if (!g_v16_reg_map || v <= 0) return false;
    ValueName cur = v;
    for (int i = 0; i < 8; ++i) {
        V16RegPair *p = (V16RegPair *)dict_get(g_v16_reg_map, vreg_key(cur));
        if (p) {
            if (lo) *lo = p->lo;
            if (hi) *hi = p->hi;
            return true;
        }
        if (!g_v16_alias) break;
        int *alias = (int *)dict_get(g_v16_alias, vreg_key(cur));
        if (!alias || *alias == cur) break;
        cur = *alias;
    }
    return false;
}

/* === Block analysis === */
List *collect_block_defs(Block *blk)
{
    List *defs = make_list();
    if (!blk) return defs;
    for (Iter it = list_iter(blk->instrs); !iter_end(it);) {
        Instr *ins = iter_next(&it);
        if (!ins || ins->dest <= 0) continue;
        if (ins->op == IROP_NOP || ins->op == IROP_PHI || ins->op == IROP_CONST) continue;
        bool seen = false;
        for (Iter jt = list_iter(defs); !iter_end(jt);) {
            ValueName *p = iter_next(&jt);
            if (p && *p == ins->dest) { seen = true; break; }
        }
        if (!seen) {
            ValueName *p = gen_alloc(sizeof(ValueName));
            *p = ins->dest;
            list_push(defs, p);
        }
    }
    return defs;
}

/* === Phi moves === */
void emit_phi_moves_for_edge(Section *sec, Func *func, Block *from, const char *to_label)
{
    if (!sec || !func || !from || !to_label) return;
    Block *to = find_block_by_label(func, to_label);
    if (!to || !to->phis) return;

    char from_label[32];
    snprintf(from_label, sizeof(from_label), "block%d", from->id);

    for (Iter pit = list_iter(to->phis); !iter_end(pit);) {
        Instr *phi = iter_next(&pit);
        if (!phi || phi->op != IROP_PHI || !phi->labels || !phi->args) continue;

        ValueName src_val = 0;
        for (int i = 0; i < phi->labels->len && i < phi->args->len; ++i) {
            char *lbl = list_get(phi->labels, i);
            if (!lbl || strcmp(lbl, from_label) != 0) continue;
            ValueName *src = list_get(phi->args, i);
            if (!src) continue;
            src_val = *src;
            break;
        }

        if (src_val == 0) {
            const char *var = find_var_for_value(to, phi->dest);
            if (var) {
                ValueName *p = (ValueName *)dict_get(from->var_map, (char *)var);
                if (p) src_val = *p;
            }
        }

        if (src_val == 0 || phi->dest == src_val) continue;

        int phi_size = 1;
        Ctype *pt = phi->type ? phi->type : val_type_get(phi->dest);
        if (pt) {
            phi_size = pt->size;
        } else if (phi->args) {
            for (int k = 0; k < phi->args->len; ++k) {
                ValueName *arg = list_get(phi->args, k);
                if (!arg) continue;
                if (is_v16_value(*arg) || val_size(*arg) >= 2) {
                    phi_size = 2;
                    break;
                }
            }
        }

        int cval = 0;
        if (const_map_get(src_val, &cval)) {
            if (phi_size >= 2 || is_v16_value(phi->dest)) {
                int rlo = -1, rhi = -1;
                if (v16_reg_pair(phi->dest, &rlo, &rhi)) {
                    char buf[16];
                    snprintf(buf, sizeof(buf), "#%d", cval & 0xFF);
                    char rbuf[8];
                    snprintf(rbuf, sizeof(rbuf), "r%d", rlo);
                    emit_ins2(sec, "mov", rbuf, buf);
                    snprintf(buf, sizeof(buf), "#%d", (cval >> 8) & 0xFF);
                    snprintf(rbuf, sizeof(rbuf), "r%d", rhi);
                    emit_ins2(sec, "mov", rbuf, buf);
                } else {
                    emit_set_v16(sec, v16_addr(phi->dest), cval);
                }
            } else {
                char ibuf[16];
                snprintf(ibuf, sizeof(ibuf), "#%d", cval & 0xFF);
                emit_ins2(sec, "mov", vreg(phi->dest), ibuf);
            }
            continue;
        }

        if (phi_size >= 2 || is_v16_value(phi->dest) || is_v16_value(src_val)) {
            int d_lo = -1, d_hi = -1, s_lo = -1, s_hi = -1;
            bool d_reg = v16_reg_pair(phi->dest, &d_lo, &d_hi);
            bool s_reg = v16_reg_pair(src_val, &s_lo, &s_hi);
            if (d_reg && s_reg && d_lo == s_lo && d_hi == s_hi) continue;

            char d0[64], d1[64], s0[64], s1[64];
            if (d_reg) {
                snprintf(d0, sizeof(d0), "r%d", d_lo);
                snprintf(d1, sizeof(d1), "r%d", d_hi);
            } else {
                int dst = v16_addr(phi->dest);
                fmt_v16_direct(d0, sizeof(d0), dst);
                fmt_v16_direct(d1, sizeof(d1), dst + 1);
            }
            if (s_reg) {
                snprintf(s0, sizeof(s0), "r%d", s_lo);
                snprintf(s1, sizeof(s1), "r%d", s_hi);
            } else {
                int src = v16_addr(src_val);
                fmt_v16_direct(s0, sizeof(s0), src);
                fmt_v16_direct(s1, sizeof(s1), src + 1);
            }

            emit_ins2(sec, "mov", "A", s0);
            emit_ins2(sec, "mov", d0, "A");
            emit_ins2(sec, "mov", "A", s1);
            emit_ins2(sec, "mov", d1, "A");
        } else {
            emit_ins2(sec, "mov", vreg(phi->dest), vreg(src_val));
        }
    }
}

/* === Lowering/cleanup passes === */
void lower_section_asminstrs(Section *sec)
{
    if (!sec || !sec->asminstrs) return;
    List *out = make_list();
    for (Iter it = list_iter(sec->asminstrs); !iter_end(it);) {
        AsmInstr *ins = iter_next(&it);
        if (!ins || !ins->op) {
            list_push(out, ins);
            continue;
        }
        if ((!strcmp(ins->op, "push") || !strcmp(ins->op, "pop")) && ins->args && ins->args->len == 1) {
            char *arg = list_get(ins->args, 0);
            int r = parse_reg_rn(arg);
            if (r >= 0) {
                char buf[8];
                snprintf(buf, sizeof(buf), "ar%d", r);
                list_set(ins->args, 0, gen_strdup(buf));
                free(arg);
            }
        }
        if (!strcmp(ins->op, "mov") && ins->args && ins->args->len == 2) {
            char *dst = list_get(ins->args, 0);
            char *src = list_get(ins->args, 1);
            if (dst && src && !strcmp(dst, src)) {
                free_asminstr(ins);
                continue;
            }
            if (parse_reg_rn(dst) >= 0 && parse_reg_rn(src) >= 0) {
                AsmInstr *i1 = gen_instr_new("mov");
                gen_instr_add_arg(i1, "A");
                gen_instr_add_arg(i1, src);
                gen_instr_copy_ssa(i1, ins);
                list_push(out, i1);

                AsmInstr *i2 = gen_instr_new("mov");
                gen_instr_add_arg(i2, dst);
                gen_instr_add_arg(i2, "A");
                list_push(out, i2);

                free_asminstr(ins);
                continue;
            }
            if (parse_direct(dst, NULL) && parse_direct(src, NULL)) {
                AsmInstr *i1 = gen_instr_new("mov");
                gen_instr_add_arg(i1, "A");
                gen_instr_add_arg(i1, src);
                gen_instr_copy_ssa(i1, ins);
                list_push(out, i1);

                AsmInstr *i2 = gen_instr_new("mov");
                gen_instr_add_arg(i2, dst);
                gen_instr_add_arg(i2, "A");
                list_push(out, i2);

                free_asminstr(ins);
                continue;
            }
        }
        list_push(out, ins);
    }
    free(sec->asminstrs);
    sec->asminstrs = out;
}

int instr_estimated_size(const AsmInstr *ins)
{
    if (!ins || !ins->op) return 0;
    if (!strcmp(ins->op, ".label")) return 0;
    if (!strcmp(ins->op, "sjmp") || !strcmp(ins->op, "jnz") || !strcmp(ins->op, "jz") ||
        !strcmp(ins->op, "jc") || !strcmp(ins->op, "jnc")) return 2;
    if (!strcmp(ins->op, "djnz") || !strcmp(ins->op, "cjne")) return 3;
    if (!strcmp(ins->op, "lcall") || !strcmp(ins->op, "ljmp")) return 3;
    if (!strcmp(ins->op, "ret") || !strcmp(ins->op, "reti") || !strcmp(ins->op, "nop")) return 1;
    if (!strcmp(ins->op, "rrc") || !strcmp(ins->op, "rlc") || !strcmp(ins->op, "rr") ||
        !strcmp(ins->op, "rl") || !strcmp(ins->op, "swap") || !strcmp(ins->op, "mul") ||
        !strcmp(ins->op, "div")) return 1;
    if (!strcmp(ins->op, "push") || !strcmp(ins->op, "pop")) return 2;
    if (!strcmp(ins->op, "movx") || !strcmp(ins->op, "movc")) return 1;
    if (!strcmp(ins->op, "add") || !strcmp(ins->op, "addc") || !strcmp(ins->op, "subb") || !strcmp(ins->op, "anl") ||
        !strcmp(ins->op, "orl") || !strcmp(ins->op, "xrl") || !strcmp(ins->op, "clr") ||
        !strcmp(ins->op, "cpl")) return 2;
    if (!strcmp(ins->op, "mov")) return 3;
    return 1;
}

void fixup_short_jumps(Section *sec)
{
    if (!sec || !sec->asminstrs) return;
    bool changed = true;

    while (changed) {
        changed = false;
        Dict *label_offsets = make_dict(NULL);
        int offset = 0;

        for (Iter it = list_iter(sec->asminstrs); !iter_end(it);) {
            AsmInstr *ins = iter_next(&it);
            if (ins && ins->op && !strcmp(ins->op, ".label") && ins->args && ins->args->len > 0) {
                char *name = list_get(ins->args, 0);
                if (name) {
                    int *p = gen_alloc(sizeof(int));
                    *p = offset;
                    dict_put(label_offsets, gen_strdup(name), p);
                }
            } else {
                offset += instr_estimated_size(ins);
            }
        }

        offset = 0;
        for (Iter it = list_iter(sec->asminstrs); !iter_end(it);) {
            AsmInstr *ins = iter_next(&it);
            if (!ins || !ins->op) continue;
            if (!strcmp(ins->op, ".label")) continue;
            if (!strcmp(ins->op, "sjmp") && ins->args && ins->args->len == 1) {
                char *label = list_get(ins->args, 0);
                int *target = label ? (int *)dict_get(label_offsets, label) : NULL;
                if (target) {
                    int rel = *target - (offset + 2);
                    if (rel < -128 || rel > 127) {
                        free(ins->op);
                        ins->op = gen_strdup("ljmp");
                        changed = true;
                    }
                }
            }
            offset += instr_estimated_size(ins);
        }

        if (label_offsets) {
            for (Iter it = list_iter(label_offsets->list); !iter_end(it);) {
                DictEntry *e = iter_next(&it);
                if (!e) continue;
                free(e->key);
                free(e->val);
            }
            dict_clear(label_offsets);
            label_offsets = NULL;
        }
    }
}
