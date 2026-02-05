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
        char buf[32];
        snprintf(buf, sizeof(buf), "0x%02X", mmio->addr & 0xFF);
        info->label = gen_strdup(buf);
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

int v16_addr(ValueName v)
{
    if (!g_v16_map || v <= 0) return -1;
    int *p = (int *)dict_get(g_v16_map, vreg_key(v));
    if (p) return *p;
    int *np = gen_alloc(sizeof(int));
    *np = g_v16_next;
    g_v16_next += 2;
    dict_put(g_v16_map, vreg_key(v), np);
    return *np;
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

void emit_set_v16(Section *sec, int addr, int val)
{
    char buf[16];
    snprintf(buf, sizeof(buf), "#%d", val & 0xFF);
    char dst0[16];
    fmt_direct(dst0, sizeof(dst0), addr);
    emit_ins2(sec, "mov", dst0, buf);
    snprintf(buf, sizeof(buf), "#%d", (val >> 8) & 0xFF);
    char dst1[16];
    fmt_direct(dst1, sizeof(dst1), addr + 1);
    emit_ins2(sec, "mov", dst1, buf);
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
    snprintf(from_label, sizeof(from_label), "block%u", from->id);

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
        Ctype *pt = phi->type ? phi->type : val_type_get(phi->dest);
        int size = pt ? pt->size : val_size(src_val);
        if (size >= 2 || is_v16_value(phi->dest) || is_v16_value(src_val)) {
            int dst = v16_addr(phi->dest);
            int src = v16_addr(src_val);
            char d0[16], d1[16], s0[16], s1[16];
            fmt_direct(d0, sizeof(d0), dst);
            fmt_direct(d1, sizeof(d1), dst + 1);
            fmt_direct(s0, sizeof(s0), src);
            fmt_direct(s1, sizeof(s1), src + 1);
            emit_ins2(sec, "mov", d0, s0);
            emit_ins2(sec, "mov", d1, s1);
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
