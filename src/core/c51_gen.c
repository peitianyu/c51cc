#include "c51_obj.h"
#include "ssa.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct MmioInfo MmioInfo;
static void mmio_map_put(const char *name, int addr, bool is_bit);
static MmioInfo *mmio_map_get(const char *name);
static int parse_reg_rn(const char *s);
static bool parse_immediate(const char *s, int *out);

/* === Core utilities === */
static void *gen_alloc(size_t size)
{
    void *p = calloc(1, size);
    if (!p) {
        fprintf(stderr, "c51_gen: out of memory\n");
        exit(1);
    }
    return p;
}

static char *gen_strdup(const char *s)
{
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char *d = gen_alloc(len);
    memcpy(d, s, len);
    return d;
}

/* === Asm instruction builders === */
static const char *vreg(ValueName v)
{
    static char buf[4][32];
    static int idx = 0;
    idx = (idx + 1) % 4;
    snprintf(buf[idx], sizeof(buf[idx]), "v%d", v);
    return buf[idx];
}

static AsmInstr *gen_instr_new(const char *op)
{
    AsmInstr *ins = gen_alloc(sizeof(AsmInstr));
    ins->op = gen_strdup(op);
    ins->args = make_list();
    return ins;
}

static void gen_instr_add_arg(AsmInstr *ins, const char *arg)
{
    if (!ins || !arg) return;
    list_push(ins->args, gen_strdup(arg));
}

static void emit_ins0(Section *sec, const char *op)
{
    AsmInstr *ins = gen_instr_new(op);
    list_push(sec->asminstrs, ins);
}

static void emit_ins1(Section *sec, const char *op, const char *a0)
{
    AsmInstr *ins = gen_instr_new(op);
    gen_instr_add_arg(ins, a0);
    list_push(sec->asminstrs, ins);
}

static void emit_ins2(Section *sec, const char *op, const char *a0, const char *a1)
{
    AsmInstr *ins = gen_instr_new(op);
    gen_instr_add_arg(ins, a0);
    gen_instr_add_arg(ins, a1);
    list_push(sec->asminstrs, ins);
}

static void emit_ins3(Section *sec, const char *op, const char *a0, const char *a1, const char *a2)
{
    AsmInstr *ins = gen_instr_new(op);
    gen_instr_add_arg(ins, a0);
    gen_instr_add_arg(ins, a1);
    gen_instr_add_arg(ins, a2);
    list_push(sec->asminstrs, ins);
}

static void emit_label(Section *sec, const char *name)
{
    if (!sec || !name) return;
    emit_ins1(sec, ".label", name);
}

static void free_asminstr(AsmInstr *ins)
{
    if (!ins) return;
    if (ins->args) {
        list_free(ins->args);
        free(ins->args);
    }
    free(ins->op);
    free(ins);
}

/* === Type/section helpers === */
static SectionKind map_data_space(Ctype *type)
{
    if (!type) return SEC_DATA;
    CtypeAttr a = get_attr(type->attr);
    switch (a.ctype_data) {
    case 1: return SEC_DATA;
    case 2: return SEC_IDATA;
    case 3: return SEC_PDATA;
    case 4: return SEC_XDATA;
    case 5: return SEC_XDATA;
    case 6: return SEC_CODE;
    default: return SEC_DATA;
    }
}

static bool is_signed_type(Ctype *type)
{
    if (!type) return true;
    CtypeAttr a = get_attr(type->attr);
    if (a.ctype_unsigned) return false;
    return true;
}

static bool is_register_mmio(Ctype *type)
{
    if (!type) return false;
    return get_attr(type->attr).ctype_register != 0;
}

static bool is_register_bit(Ctype *type)
{
    return is_register_mmio(type) && type->type == CTYPE_BOOL;
}

/* === Section management === */
static Section *get_or_create_section(ObjFile *obj, const char *name, SectionKind kind)
{
    int idx = 0;
    for (Iter it = list_iter(obj->sections); !iter_end(it); ++idx) {
        Section *sec = iter_next(&it);
        if (sec && sec->name && !strcmp(sec->name, name))
            return sec;
    }
    idx = objfile_add_section(obj, name, kind, 0, 1);
    return objfile_get_section(obj, idx);
}

static int section_index_from_ptr(ObjFile *obj, Section *sec)
{
    int idx = 0;
    for (Iter it = list_iter(obj->sections); !iter_end(it); ++idx) {
        if (iter_next(&it) == sec)
            return idx;
    }
    return -1;
}

/* === Global data emission === */
static void emit_global_data(ObjFile *obj, GlobalVar *g)
{
    if (!g || !g->name) return;
    if (is_register_mmio(g->type)) {
        if (g->has_init) {
            mmio_map_put(g->name, (int)g->init_value, is_register_bit(g->type));
        }
        return;
    }
    if (g->is_extern) {
        objfile_add_symbol(obj, g->name, SYM_DATA, -1, 0, g->type ? g->type->size : 0, SYM_FLAG_EXTERN);
        return;
    }

    SectionKind kind = map_data_space(g->type);
    const char *sec_name = ".data";
    if (kind == SEC_CODE) {
        sec_name = g->has_init ? ".const" : ".text";
    } else if (kind == SEC_XDATA) {
        sec_name = g->has_init ? ".xdata" : ".xdata_bss";
    } else if (kind == SEC_IDATA) {
        sec_name = g->has_init ? ".idata" : ".idata_bss";
    } else if (kind == SEC_PDATA) {
        sec_name = g->has_init ? ".pdata" : ".pdata_bss";
    } else {
        sec_name = g->has_init ? ".data" : ".bss";
    }
    Section *sec = get_or_create_section(obj, sec_name, kind);
    int offset = sec->bytes_len;
    int size = g->type ? g->type->size : 1;

    if (g->init_instr && g->init_instr->imm.blob.bytes && g->init_instr->imm.blob.len > 0) {
        int copy_len = g->init_instr->imm.blob.len;
        if (copy_len > size) copy_len = size;
        section_append_bytes(sec, g->init_instr->imm.blob.bytes, copy_len);
        if (size > copy_len) section_append_zeros(sec, size - copy_len);
    } else if (g->has_init) {
        long v = g->init_value;
        if (size == 1) {
            unsigned char b = (unsigned char)(v & 0xFF);
            section_append_bytes(sec, &b, 1);
        } else if (size == 2) {
            unsigned char b[2] = {(unsigned char)(v & 0xFF), (unsigned char)((v >> 8) & 0xFF)};
            section_append_bytes(sec, b, 2);
        } else if (size == 4) {
            unsigned char b[4] = {
                (unsigned char)(v & 0xFF),
                (unsigned char)((v >> 8) & 0xFF),
                (unsigned char)((v >> 16) & 0xFF),
                (unsigned char)((v >> 24) & 0xFF)
            };
            section_append_bytes(sec, b, 4);
        } else {
            section_append_zeros(sec, size);
        }
    } else {
        section_append_zeros(sec, size);
    }

    unsigned flags = g->is_static ? SYM_FLAG_LOCAL : SYM_FLAG_GLOBAL;
    objfile_add_symbol(obj, g->name, SYM_DATA, section_index_from_ptr(obj, sec), offset, size, flags);
}

/* === Register allocation === */
static int parse_vreg_id(const char *arg, bool *is_indirect)
{
    if (is_indirect) *is_indirect = false;
    if (!arg) return -1;
    if (arg[0] == 'v' && arg[1] >= '0' && arg[1] <= '9')
        return atoi(arg + 1);
    if (arg[0] == '@' && arg[1] == 'v' && arg[2] >= '0' && arg[2] <= '9') {
        if (is_indirect) *is_indirect = true;
        return atoi(arg + 2);
    }
    return -1;
}

typedef struct {
    int v;
    int start;
    int end;
    bool indir;
} Interval;

static int cmp_interval_start(const void *a, const void *b)
{
    const Interval *ia = (const Interval *)a;
    const Interval *ib = (const Interval *)b;
    if (ia->start != ib->start) return ia->start - ib->start;
    return ia->end - ib->end;
}

static void regalloc_section_asminstrs(Section *sec)
{
    if (!sec || !sec->asminstrs) return;

    int max_v = -1;
    int ins_index = 0;
    for (Iter it = list_iter(sec->asminstrs); !iter_end(it); ++ins_index) {
        AsmInstr *ins = iter_next(&it);
        if (!ins || !ins->args) continue;
        for (Iter ait = list_iter(ins->args); !iter_end(ait);) {
            char *arg = iter_next(&ait);
            int v = parse_vreg_id(arg, NULL);
            if (v > max_v) max_v = v;
        }
    }
    if (max_v < 0) return;

    int count = max_v + 1;
    int *start = gen_alloc(sizeof(int) * count);
    int *end = gen_alloc(sizeof(int) * count);
    bool *need_indirect = gen_alloc(sizeof(bool) * count);
    for (int i = 0; i < count; ++i) { start[i] = -1; end[i] = -1; }

    ins_index = 0;
    for (Iter it = list_iter(sec->asminstrs); !iter_end(it); ++ins_index) {
        AsmInstr *ins = iter_next(&it);
        if (!ins || !ins->args) continue;
        for (Iter ait = list_iter(ins->args); !iter_end(ait);) {
            char *arg = iter_next(&ait);
            bool indir = false;
            int v = parse_vreg_id(arg, &indir);
            if (v < 0 || v >= count) continue;
            if (start[v] < 0) start[v] = ins_index;
            end[v] = ins_index;
            if (indir) need_indirect[v] = true;
        }
    }

    Interval *intervals = gen_alloc(sizeof(Interval) * count);
    int interval_count = 0;
    for (int v = 0; v < count; ++v) {
        if (start[v] < 0) continue;
        intervals[interval_count++] = (Interval){v, start[v], end[v], need_indirect[v]};
    }
    if (interval_count == 0) return;

    qsort(intervals, (size_t)interval_count, sizeof(Interval), cmp_interval_start);

    int *reg_of = gen_alloc(sizeof(int) * count);
    int *spill_addr = gen_alloc(sizeof(int) * count);
    for (int i = 0; i < count; ++i) { reg_of[i] = -1; spill_addr[i] = -1; }

    int active_cap = count;
    int *active = gen_alloc(sizeof(int) * active_cap);
    int active_len = 0;

    for (int i = 0; i < interval_count; ++i) {
        Interval cur = intervals[i];
        for (int j = 0; j < active_len; ) {
            int v = active[j];
            if (end[v] < cur.start) {
                active[j] = active[active_len - 1];
                active_len--;
                continue;
            }
            ++j;
        }

        int reg = -1;
        if (cur.indir) {
            bool r0_used = false, r1_used = false;
            for (int j = 0; j < active_len; ++j) {
                int v = active[j];
                if (reg_of[v] == 0) r0_used = true;
                if (reg_of[v] == 1) r1_used = true;
            }
            if (!r0_used) reg = 0;
            else if (!r1_used) reg = 1;
        } else {
            for (int r = 2; r <= 6; ++r) {
                bool used = false;
                for (int j = 0; j < active_len; ++j) {
                    if (reg_of[active[j]] == r) { used = true; break; }
                }
                if (!used) { reg = r; break; }
            }
        }

        if (reg >= 0) {
            reg_of[cur.v] = reg;
            active[active_len++] = cur.v;
            continue;
        }

        int spill_candidate = -1;
        int spill_end = -1;
        for (int j = 0; j < active_len; ++j) {
            int v = active[j];
            if (cur.indir && reg_of[v] > 1) continue;
            if (!cur.indir && reg_of[v] < 2) continue;
            if (end[v] > spill_end) { spill_end = end[v]; spill_candidate = v; }
        }

        if (spill_candidate >= 0 && spill_end > cur.end) {
            spill_addr[spill_candidate] = 0x30 + spill_candidate;
            reg_of[cur.v] = reg_of[spill_candidate];
            reg_of[spill_candidate] = -1;
            for (int j = 0; j < active_len; ++j) {
                if (active[j] == spill_candidate) {
                    active[j] = active[active_len - 1];
                    active_len--;
                    break;
                }
            }
            active[active_len++] = cur.v;
        } else {
            spill_addr[cur.v] = 0x30 + cur.v;
        }
    }

    List *out = make_list();
    for (Iter it = list_iter(sec->asminstrs); !iter_end(it);) {
        AsmInstr *ins = iter_next(&it);
        if (!ins || !ins->op || !ins->args) {
            list_push(out, ins);
            continue;
        }

        bool need_tmp = false;
        int tmp_spill = -1;
        int idx = 0;
        for (Iter ait = list_iter(ins->args); !iter_end(ait); ++idx) {
            char *arg = iter_next(&ait);
            bool indir = false;
            int v = parse_vreg_id(arg, &indir);
            if (v < 0 || v >= count) continue;

            if (spill_addr[v] >= 0 && indir) {
                need_tmp = true;
                tmp_spill = spill_addr[v];
                char buf[16];
                snprintf(buf, sizeof(buf), "@r0");
                list_set(ins->args, idx, gen_strdup(buf));
                free(arg);
                continue;
            }

            char buf[16];
            if (spill_addr[v] >= 0) {
                snprintf(buf, sizeof(buf), "0x%02X", spill_addr[v] & 0xFF);
            } else if (reg_of[v] >= 0) {
                if (indir) snprintf(buf, sizeof(buf), "@r%d", reg_of[v]);
                else snprintf(buf, sizeof(buf), "r%d", reg_of[v]);
            } else {
                snprintf(buf, sizeof(buf), "r0");
            }
            list_set(ins->args, idx, gen_strdup(buf));
            free(arg);
        }

        if (need_tmp && tmp_spill >= 0) {
            AsmInstr *load = gen_instr_new("mov");
            gen_instr_add_arg(load, "r0");
            char buf[16];
            snprintf(buf, sizeof(buf), "0x%02X", tmp_spill & 0xFF);
            gen_instr_add_arg(load, buf);
            list_push(out, load);
        }

        list_push(out, ins);
    }

    free(sec->asminstrs);
    sec->asminstrs = out;
}

static void regalloc_stub(Func *f)
{
    (void)f;
    /* TODO: linear scan register allocation */
}

/* === Peephole optimization === */
static bool is_reg_eq(const char *a, const char *b)
{
    return a && b && !strcmp(a, b);
}

static void peephole_section_asminstrs(Section *sec)
{
    if (!sec || !sec->asminstrs) return;
    List *out = make_list();

    for (int i = 0; i < sec->asminstrs->len; ++i) {
        AsmInstr *ins = list_get(sec->asminstrs, i);
        AsmInstr *next = (i + 1 < sec->asminstrs->len) ? list_get(sec->asminstrs, i + 1) : NULL;
        if (!ins || !ins->op) {
            list_push(out, ins);
            continue;
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

/* === Symbol helpers === */
static Symbol *find_symbol_by_name(ObjFile *obj, const char *name)
{
    for (Iter it = list_iter(obj->symbols); !iter_end(it);) {
        Symbol *sym = iter_next(&it);
        if (sym && sym->name && name && !strcmp(sym->name, name))
            return sym;
    }
    return NULL;
}

static void define_label_symbol(ObjFile *obj, const char *name, int section, int value)
{
    if (!obj || !name) return;
    Symbol *sym = find_symbol_by_name(obj, name);
    if (!sym) {
        objfile_add_symbol(obj, name, SYM_LABEL, section, value, 0, SYM_FLAG_LOCAL);
        return;
    }
    sym->section = section;
    sym->value = value;
    sym->flags &= ~SYM_FLAG_EXTERN;
}

/* === Parsing helpers === */
static bool is_ident(const char *s)
{
    if (!s || !*s) return false;
    if (!( (*s >= 'A' && *s <= 'Z') || (*s >= 'a' && *s <= 'z') || *s == '_' ))
        return false;
    for (const char *p = s + 1; *p; ++p) {
        if (!( (*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') || *p == '_' ))
            return false;
    }
    return true;
}

static bool parse_int_val(const char *s, int *out)
{
    if (!s || !*s) return false;
    char *end = NULL;
    long v = strtol(s, &end, 0);
    if (end == s || (end && *end != '\0')) return false;
    if (out) *out = (int)v;
    return true;
}

static int parse_reg_rn(const char *s)
{
    if (!s || s[0] != 'r' || s[1] < '0' || s[1] > '7' || s[2] != '\0') return -1;
    return s[1] - '0';
}

static int parse_indirect_rn(const char *s)
{
    if (!s || s[0] != '@' || s[1] != 'r' || s[2] < '0' || s[2] > '7' || s[3] != '\0') return -1;
    return s[2] - '0';
}

static bool parse_immediate(const char *s, int *out)
{
    if (!s || s[0] != '#') return false;
    return parse_int_val(s + 1, out);
}

static bool parse_direct(const char *s, int *out)
{
    if (!s || !*s) return false;
    if (!strcmp(s, "B")) { if (out) *out = 0xF0; return true; }
    if (!strcmp(s, "A")) { if (out) *out = 0xE0; return true; }
    return parse_int_val(s, out);
}

static bool parse_direct_symbol(const char *s, int *out, const char **label)
{
    if (parse_direct(s, out)) {
        if (label) *label = NULL;
        return true;
    }
    if (label && s && is_ident(s)) {
        *label = s;
        if (out) *out = 0;
        return true;
    }
    return false;
}

static bool parse_bit_symbol(const char *s, int *out, const char **label)
{
    if (!s || !*s) return false;
    if (!strcmp(s, "A.0") || !strcmp(s, "ACC.0")) {
        if (out) *out = 0xE0;
        if (label) *label = NULL;
        return true;
    }
    if (!strcmp(s, "A.1") || !strcmp(s, "ACC.1")) {
        if (out) *out = 0xE1;
        if (label) *label = NULL;
        return true;
    }
    if (!strcmp(s, "A.2") || !strcmp(s, "ACC.2")) {
        if (out) *out = 0xE2;
        if (label) *label = NULL;
        return true;
    }
    if (!strcmp(s, "A.3") || !strcmp(s, "ACC.3")) {
        if (out) *out = 0xE3;
        if (label) *label = NULL;
        return true;
    }
    if (!strcmp(s, "A.4") || !strcmp(s, "ACC.4")) {
        if (out) *out = 0xE4;
        if (label) *label = NULL;
        return true;
    }
    if (!strcmp(s, "A.5") || !strcmp(s, "ACC.5")) {
        if (out) *out = 0xE5;
        if (label) *label = NULL;
        return true;
    }
    if (!strcmp(s, "A.6") || !strcmp(s, "ACC.6")) {
        if (out) *out = 0xE6;
        if (label) *label = NULL;
        return true;
    }
    if (!strcmp(s, "A.7") || !strcmp(s, "ACC.7")) {
        if (out) *out = 0xE7;
        if (label) *label = NULL;
        return true;
    }
    if (!strcmp(s, "B.0")) { if (out) *out = 0xF0; if (label) *label = NULL; return true; }
    if (!strcmp(s, "B.1")) { if (out) *out = 0xF1; if (label) *label = NULL; return true; }
    if (!strcmp(s, "B.2")) { if (out) *out = 0xF2; if (label) *label = NULL; return true; }
    if (!strcmp(s, "B.3")) { if (out) *out = 0xF3; if (label) *label = NULL; return true; }
    if (!strcmp(s, "B.4")) { if (out) *out = 0xF4; if (label) *label = NULL; return true; }
    if (!strcmp(s, "B.5")) { if (out) *out = 0xF5; if (label) *label = NULL; return true; }
    if (!strcmp(s, "B.6")) { if (out) *out = 0xF6; if (label) *label = NULL; return true; }
    if (!strcmp(s, "B.7")) { if (out) *out = 0xF7; if (label) *label = NULL; return true; }
    if (parse_int_val(s, out)) {
        if (label) *label = NULL;
        return true;
    }
    if (label && is_ident(s)) {
        *label = s;
        if (out) *out = 0;
        return true;
    }
    return false;
}

static bool parse_immediate_label(const char *s, int *out, const char **label)
{
    if (!s || s[0] != '#') return false;
    if (parse_int_val(s + 1, out)) {
        if (label) *label = NULL;
        return true;
    }
    if (label && is_ident(s + 1)) {
        *label = s + 1;
        if (out) *out = 0;
        return true;
    }
    return false;
}

/* === Encoding helpers === */
static void emit_u8(Section *sec, unsigned char b)
{
    section_append_bytes(sec, &b, 1);
}

static void emit_u16(Section *sec, int v)
{
    unsigned char b[2] = {(unsigned char)(v & 0xFF), (unsigned char)((v >> 8) & 0xFF)};
    section_append_bytes(sec, b, 2);
}

static void emit_rel8(ObjFile *obj, Section *sec, const char *label)
{
    int sec_index = section_index_from_ptr(obj, sec);
    int offset = sec->bytes_len;
    emit_u8(sec, 0);
    if (label && is_ident(label))
        objfile_add_reloc(obj, sec_index, offset, RELOC_REL8, label, 0);
}

static void emit_abs16(ObjFile *obj, Section *sec, const char *label)
{
    int sec_index = section_index_from_ptr(obj, sec);
    int offset = sec->bytes_len;
    emit_u16(sec, 0);
    if (label && is_ident(label))
        objfile_add_reloc(obj, sec_index, offset, RELOC_ABS16, label, 0);
}

static void emit_abs8(ObjFile *obj, Section *sec, const char *label)
{
    int sec_index = section_index_from_ptr(obj, sec);
    int offset = sec->bytes_len;
    emit_u8(sec, 0);
    if (label && is_ident(label))
        objfile_add_reloc(obj, sec_index, offset, RELOC_ABS8, label, 0);
}

    /* === Instruction encoding === */
static void encode_section_bytes(ObjFile *obj, Section *sec)
{
    if (!sec || !sec->asminstrs) return;
    int sec_index = section_index_from_ptr(obj, sec);
    for (Iter it = list_iter(sec->asminstrs); !iter_end(it);) {
        AsmInstr *ins = iter_next(&it);
        if (!ins || !ins->op) continue;

        if (!strcmp(ins->op, ".label")) {
            char *name = (ins->args && ins->args->len > 0) ? list_get(ins->args, 0) : NULL;
            if (name) define_label_symbol(obj, name, sec_index, sec->bytes_len);
            continue;
        }

        if (!strcmp(ins->op, "nop")) {
            emit_u8(sec, 0x00);
            continue;
        }
        if (!strcmp(ins->op, "ret")) {
            emit_u8(sec, 0x22);
            continue;
        }
        if (!strcmp(ins->op, "reti")) {
            emit_u8(sec, 0x32);
            continue;
        }
        if (!strcmp(ins->op, "clr") && ins->args && ins->args->len == 1) {
            char *a0 = list_get(ins->args, 0);
            if (a0 && !strcmp(a0, "C")) {
                emit_u8(sec, 0xC3);
                continue;
            }
            if (a0 && !strcmp(a0, "A")) {
                emit_u8(sec, 0xE4);
                continue;
            }
        }
        if (!strcmp(ins->op, "cpl") && ins->args && ins->args->len == 1) {
            char *a0 = list_get(ins->args, 0);
            if (a0 && !strcmp(a0, "A")) {
                emit_u8(sec, 0xF4);
                continue;
            }
        }
        if (!strcmp(ins->op, "rrc") && (!ins->args || ins->args->len == 0 || (ins->args->len == 1 && !strcmp(list_get(ins->args, 0), "A")))) {
            emit_u8(sec, 0x13);
            continue;
        }
        if (!strcmp(ins->op, "rlc") && (!ins->args || ins->args->len == 0 || (ins->args->len == 1 && !strcmp(list_get(ins->args, 0), "A")))) {
            emit_u8(sec, 0x33);
            continue;
        }
        if (!strcmp(ins->op, "rl") && (!ins->args || ins->args->len == 0 || (ins->args->len == 1 && !strcmp(list_get(ins->args, 0), "A")))) {
            emit_u8(sec, 0x23);
            continue;
        }
        if (!strcmp(ins->op, "rr") && (!ins->args || ins->args->len == 0 || (ins->args->len == 1 && !strcmp(list_get(ins->args, 0), "A")))) {
            emit_u8(sec, 0x03);
            continue;
        }
        if (!strcmp(ins->op, "swap") && ins->args && ins->args->len == 1 && !strcmp(list_get(ins->args, 0), "A")) {
            emit_u8(sec, 0xC4);
            continue;
        }
        if (!strcmp(ins->op, "mul") && ins->args && ins->args->len == 1 && !strcmp(list_get(ins->args, 0), "AB")) {
            emit_u8(sec, 0xA4);
            continue;
        }
        if (!strcmp(ins->op, "div") && ins->args && ins->args->len == 1 && !strcmp(list_get(ins->args, 0), "AB")) {
            emit_u8(sec, 0x84);
            continue;
        }

        if (!strcmp(ins->op, "sjmp") && ins->args && ins->args->len == 1) {
            emit_u8(sec, 0x80);
            emit_rel8(obj, sec, list_get(ins->args, 0));
            continue;
        }
        if (!strcmp(ins->op, "jnz") && ins->args && ins->args->len == 1) {
            emit_u8(sec, 0x70);
            emit_rel8(obj, sec, list_get(ins->args, 0));
            continue;
        }
        if (!strcmp(ins->op, "jz") && ins->args && ins->args->len == 1) {
            emit_u8(sec, 0x60);
            emit_rel8(obj, sec, list_get(ins->args, 0));
            continue;
        }
        if (!strcmp(ins->op, "jc") && ins->args && ins->args->len == 1) {
            emit_u8(sec, 0x40);
            emit_rel8(obj, sec, list_get(ins->args, 0));
            continue;
        }
        if (!strcmp(ins->op, "jnc") && ins->args && ins->args->len == 1) {
            emit_u8(sec, 0x50);
            emit_rel8(obj, sec, list_get(ins->args, 0));
            continue;
        }
        if (!strcmp(ins->op, "lcall") && ins->args && ins->args->len == 1) {
            emit_u8(sec, 0x12);
            emit_abs16(obj, sec, list_get(ins->args, 0));
            continue;
        }
        if (!strcmp(ins->op, "ljmp") && ins->args && ins->args->len == 1) {
            emit_u8(sec, 0x02);
            emit_abs16(obj, sec, list_get(ins->args, 0));
            continue;
        }

        if (!strcmp(ins->op, "djnz") && ins->args && ins->args->len == 2) {
            char *a0 = list_get(ins->args, 0);
            char *a1 = list_get(ins->args, 1);
            int r = parse_reg_rn(a0);
            if (r >= 0) {
                emit_u8(sec, (unsigned char)(0xD8 + r));
                emit_rel8(obj, sec, a1);
                continue;
            }
            int direct = 0;
            if (parse_direct(a0, &direct)) {
                emit_u8(sec, 0xD5);
                emit_u8(sec, (unsigned char)(direct & 0xFF));
                emit_rel8(obj, sec, a1);
                continue;
            }
        }

        if (!strcmp(ins->op, "cjne") && ins->args && ins->args->len == 3) {
            char *a0 = list_get(ins->args, 0);
            char *a1 = list_get(ins->args, 1);
            char *a2 = list_get(ins->args, 2);
            int imm = 0;
            if (a0 && !strcmp(a0, "A")) {
                if (parse_immediate(a1, &imm)) {
                    emit_u8(sec, 0xB4);
                    emit_u8(sec, (unsigned char)(imm & 0xFF));
                    emit_rel8(obj, sec, a2);
                    continue;
                }
                int direct = 0;
                int r = parse_reg_rn(a1);
                if (r >= 0) direct = r;
                else if (!parse_direct(a1, &direct)) direct = -1;
                if (direct >= 0) {
                    emit_u8(sec, 0xB5);
                    emit_u8(sec, (unsigned char)(direct & 0xFF));
                    emit_rel8(obj, sec, a2);
                    continue;
                }
            }
            int r = parse_reg_rn(a0);
            if (r >= 0 && parse_immediate(a1, &imm)) {
                emit_u8(sec, (unsigned char)(0xB8 + r));
                emit_u8(sec, (unsigned char)(imm & 0xFF));
                emit_rel8(obj, sec, a2);
                continue;
            }
            int ir = parse_indirect_rn(a0);
            if ((ir == 0 || ir == 1) && parse_immediate(a1, &imm)) {
                emit_u8(sec, (unsigned char)(ir == 0 ? 0xB6 : 0xB7));
                emit_u8(sec, (unsigned char)(imm & 0xFF));
                emit_rel8(obj, sec, a2);
                continue;
            }
        }

        if ((!strcmp(ins->op, "push") || !strcmp(ins->op, "pop")) && ins->args && ins->args->len == 1) {
            char *a0 = list_get(ins->args, 0);
            int direct = 0;
            int r = parse_reg_rn(a0);
            if (r >= 0) direct = r;
            else if (!parse_direct(a0, &direct)) direct = -1;
            if (direct >= 0) {
                emit_u8(sec, (unsigned char)(!strcmp(ins->op, "push") ? 0xC0 : 0xD0));
                emit_u8(sec, (unsigned char)(direct & 0xFF));
                continue;
            }
        }

        if (!strcmp(ins->op, "mov") && ins->args && ins->args->len == 2) {
            char *dst = list_get(ins->args, 0);
            char *src = list_get(ins->args, 1);
            int imm = 0;
            int rdst = parse_reg_rn(dst);
            int rsrc = parse_reg_rn(src);
            int idst = parse_indirect_rn(dst);
            int isrc = parse_indirect_rn(src);
            int direct_dst = 0;
            int direct_src = 0;
            const char *dst_label = NULL;
            const char *src_label = NULL;
            bool dst_direct_ok = parse_direct_symbol(dst, &direct_dst, &dst_label);
            bool src_direct_ok = parse_direct_symbol(src, &direct_src, &src_label);

            if (dst && !strcmp(dst, "C")) {
                int bit = 0;
                const char *bit_label = NULL;
                if (parse_bit_symbol(src, &bit, &bit_label)) {
                    emit_u8(sec, 0xA2);
                    if (bit_label) emit_abs8(obj, sec, bit_label);
                    else emit_u8(sec, (unsigned char)(bit & 0xFF));
                    continue;
                }
            }
            if (src && !strcmp(src, "C")) {
                int bit = 0;
                const char *bit_label = NULL;
                if (parse_bit_symbol(dst, &bit, &bit_label)) {
                    emit_u8(sec, 0x92);
                    if (bit_label) emit_abs8(obj, sec, bit_label);
                    else emit_u8(sec, (unsigned char)(bit & 0xFF));
                    continue;
                }
            }

            if (dst && !strcmp(dst, "DPTR")) {
                const char *imm_label = NULL;
                if (parse_immediate_label(src, &imm, &imm_label)) {
                    emit_u8(sec, 0x90);
                    if (imm_label) emit_abs16(obj, sec, imm_label);
                    else emit_u16(sec, imm);
                    continue;
                }
            }

            if (dst && !strcmp(dst, "A")) {
                if (parse_immediate(src, &imm)) {
                    emit_u8(sec, 0x74);
                    emit_u8(sec, (unsigned char)(imm & 0xFF));
                    continue;
                }
                if (rsrc >= 0) {
                    emit_u8(sec, (unsigned char)(0xE8 + rsrc));
                    continue;
                }
                if (isrc == 0 || isrc == 1) {
                    emit_u8(sec, (unsigned char)(isrc == 0 ? 0xE6 : 0xE7));
                    continue;
                }
                if (src_direct_ok) {
                    emit_u8(sec, 0xE5);
                    if (src_label) emit_abs8(obj, sec, src_label);
                    else emit_u8(sec, (unsigned char)(direct_src & 0xFF));
                    continue;
                }
            }
            if (rdst >= 0) {
                if (parse_immediate(src, &imm)) {
                    emit_u8(sec, (unsigned char)(0x78 + rdst));
                    emit_u8(sec, (unsigned char)(imm & 0xFF));
                    continue;
                }
                if (src && !strcmp(src, "A")) {
                    emit_u8(sec, (unsigned char)(0xF8 + rdst)); 
                    continue;
                }
                if (src_direct_ok) {
                    emit_u8(sec, (unsigned char)(0xA8 + rdst));
                    if (src_label) emit_abs8(obj, sec, src_label);
                    else emit_u8(sec, (unsigned char)(direct_src & 0xFF));
                    continue;
                }
                if (rsrc >= 0) {
                    emit_u8(sec, (unsigned char)(0xE8 + rsrc));
                    emit_u8(sec, (unsigned char)(0xF8 + rdst));
                    continue;
                }
                if (isrc == 0 || isrc == 1) {
                    emit_u8(sec, (unsigned char)(isrc == 0 ? 0xE6 : 0xE7));
                    emit_u8(sec, (unsigned char)(0xF8 + rdst));
                    continue;
                }
            }
            if (idst == 0 || idst == 1) {
                if (src && !strcmp(src, "A")) {
                    emit_u8(sec, (unsigned char)(idst == 0 ? 0xF6 : 0xF7));
                    continue;
                }
                if (parse_immediate(src, &imm)) {
                    emit_u8(sec, (unsigned char)(idst == 0 ? 0x76 : 0x77));
                    emit_u8(sec, (unsigned char)(imm & 0xFF));
                    continue;
                }
                if (src_direct_ok) {
                    emit_u8(sec, (unsigned char)(idst == 0 ? 0xA6 : 0xA7));
                    if (src_label) emit_abs8(obj, sec, src_label);
                    else emit_u8(sec, (unsigned char)(direct_src & 0xFF));
                    continue;
                }
                if (rsrc >= 0) {
                    emit_u8(sec, (unsigned char)(0xE8 + rsrc));
                    emit_u8(sec, (unsigned char)(idst == 0 ? 0xF6 : 0xF7));
                    continue;
                }
            }
            if (dst_direct_ok) {
                if (parse_immediate(src, &imm)) {
                    emit_u8(sec, 0x75);
                    if (dst_label) emit_abs8(obj, sec, dst_label);
                    else emit_u8(sec, (unsigned char)(direct_dst & 0xFF));
                    emit_u8(sec, (unsigned char)(imm & 0xFF));
                    continue;
                }
                if (src && !strcmp(src, "A")) {
                    emit_u8(sec, 0xF5);
                    if (dst_label) emit_abs8(obj, sec, dst_label);
                    else emit_u8(sec, (unsigned char)(direct_dst & 0xFF));
                    continue;
                }
                if (rsrc >= 0) {
                    emit_u8(sec, (unsigned char)(0x88 + rsrc));
                    if (dst_label) emit_abs8(obj, sec, dst_label);
                    else emit_u8(sec, (unsigned char)(direct_dst & 0xFF));
                    continue;
                }
                if (src_direct_ok) {
                    emit_u8(sec, 0xE5);
                    if (src_label) emit_abs8(obj, sec, src_label);
                    else emit_u8(sec, (unsigned char)(direct_src & 0xFF));
                    emit_u8(sec, 0xF5);
                    if (dst_label) emit_abs8(obj, sec, dst_label);
                    else emit_u8(sec, (unsigned char)(direct_dst & 0xFF));
                    continue;
                }
                if (isrc == 0 || isrc == 1) {
                    emit_u8(sec, (unsigned char)(isrc == 0 ? 0x86 : 0x87));
                    if (dst_label) emit_abs8(obj, sec, dst_label);
                    else emit_u8(sec, (unsigned char)(direct_dst & 0xFF));
                    continue;
                }
            }
        }

        if (!strcmp(ins->op, "movx") && ins->args && ins->args->len == 2) {
            char *dst = list_get(ins->args, 0);
            char *src = list_get(ins->args, 1);
            if (dst && src && !strcmp(dst, "A") && !strcmp(src, "@DPTR")) {
                emit_u8(sec, 0xE0);
                continue;
            }
            if (dst && src && !strcmp(dst, "@DPTR") && !strcmp(src, "A")) {
                emit_u8(sec, 0xF0);
                continue;
            }
        }

        if (!strcmp(ins->op, "movc") && ins->args && ins->args->len == 2) {
            char *dst = list_get(ins->args, 0);
            char *src = list_get(ins->args, 1);
            if (dst && src && !strcmp(dst, "A") && !strcmp(src, "@A+DPTR")) {
                emit_u8(sec, 0x93);
                continue;
            }
        }

        if (!strcmp(ins->op, "add") && ins->args && ins->args->len == 2) {
            char *a0 = list_get(ins->args, 0);
            char *a1 = list_get(ins->args, 1);
            if (a0 && !strcmp(a0, "A")) {
                int imm = 0;
                int r = parse_reg_rn(a1);
                int ir = parse_indirect_rn(a1);
                int direct = 0;
                if (parse_immediate(a1, &imm)) {
                    emit_u8(sec, 0x24); emit_u8(sec, (unsigned char)(imm & 0xFF)); continue;
                }
                if (r >= 0) { emit_u8(sec, (unsigned char)(0x28 + r)); continue; }
                if (ir == 0 || ir == 1) { emit_u8(sec, (unsigned char)(ir == 0 ? 0x26 : 0x27)); continue; }
                if (parse_direct(a1, &direct)) { emit_u8(sec, 0x25); emit_u8(sec, (unsigned char)(direct & 0xFF)); continue; }
            }
        }
        if (!strcmp(ins->op, "subb") && ins->args && ins->args->len == 2) {
            char *a0 = list_get(ins->args, 0);
            char *a1 = list_get(ins->args, 1);
            if (a0 && !strcmp(a0, "A")) {
                int imm = 0;
                int r = parse_reg_rn(a1);
                int ir = parse_indirect_rn(a1);
                int direct = 0;
                if (parse_immediate(a1, &imm)) { emit_u8(sec, 0x94); emit_u8(sec, (unsigned char)(imm & 0xFF)); continue; }
                if (r >= 0) { emit_u8(sec, (unsigned char)(0x98 + r)); continue; }
                if (ir == 0 || ir == 1) { emit_u8(sec, (unsigned char)(ir == 0 ? 0x96 : 0x97)); continue; }
                if (parse_direct(a1, &direct)) { emit_u8(sec, 0x95); emit_u8(sec, (unsigned char)(direct & 0xFF)); continue; }
            }
        }
        if (!strcmp(ins->op, "anl") && ins->args && ins->args->len == 2) {
            char *a0 = list_get(ins->args, 0);
            char *a1 = list_get(ins->args, 1);
            if (a0 && !strcmp(a0, "A")) {
                int imm = 0;
                int r = parse_reg_rn(a1);
                int ir = parse_indirect_rn(a1);
                int direct = 0;
                if (parse_immediate(a1, &imm)) { emit_u8(sec, 0x54); emit_u8(sec, (unsigned char)(imm & 0xFF)); continue; }
                if (r >= 0) { emit_u8(sec, (unsigned char)(0x58 + r)); continue; }
                if (ir == 0 || ir == 1) { emit_u8(sec, (unsigned char)(ir == 0 ? 0x56 : 0x57)); continue; }
                if (parse_direct(a1, &direct)) { emit_u8(sec, 0x55); emit_u8(sec, (unsigned char)(direct & 0xFF)); continue; }
            }
        }
        if (!strcmp(ins->op, "orl") && ins->args && ins->args->len == 2) {
            char *a0 = list_get(ins->args, 0);
            char *a1 = list_get(ins->args, 1);
            if (a0 && !strcmp(a0, "A")) {
                int imm = 0;
                int r = parse_reg_rn(a1);
                int ir = parse_indirect_rn(a1);
                int direct = 0;
                if (parse_immediate(a1, &imm)) { emit_u8(sec, 0x44); emit_u8(sec, (unsigned char)(imm & 0xFF)); continue; }
                if (r >= 0) { emit_u8(sec, (unsigned char)(0x48 + r)); continue; }
                if (ir == 0 || ir == 1) { emit_u8(sec, (unsigned char)(ir == 0 ? 0x46 : 0x47)); continue; }
                if (parse_direct(a1, &direct)) { emit_u8(sec, 0x45); emit_u8(sec, (unsigned char)(direct & 0xFF)); continue; }
            }
        }
        if (!strcmp(ins->op, "xrl") && ins->args && ins->args->len == 2) {
            char *a0 = list_get(ins->args, 0);
            char *a1 = list_get(ins->args, 1);
            if (a0 && !strcmp(a0, "A")) {
                int imm = 0;
                int r = parse_reg_rn(a1);
                int ir = parse_indirect_rn(a1);
                int direct = 0;
                if (parse_immediate(a1, &imm)) { emit_u8(sec, 0x64); emit_u8(sec, (unsigned char)(imm & 0xFF)); continue; }
                if (r >= 0) { emit_u8(sec, (unsigned char)(0x68 + r)); continue; }
                if (ir == 0 || ir == 1) { emit_u8(sec, (unsigned char)(ir == 0 ? 0x66 : 0x67)); continue; }
                if (parse_direct(a1, &direct)) { emit_u8(sec, 0x65); emit_u8(sec, (unsigned char)(direct & 0xFF)); continue; }
            }
        }
        if (!strcmp(ins->op, "inc") && ins->args && ins->args->len == 1) {
            char *a0 = list_get(ins->args, 0);
            int r = parse_reg_rn(a0);
            int ir = parse_indirect_rn(a0);
            int direct = 0;
            if (a0 && !strcmp(a0, "A")) { emit_u8(sec, 0x04); continue; }
            if (r >= 0) { emit_u8(sec, (unsigned char)(0x08 + r)); continue; }
            if (ir == 0 || ir == 1) { emit_u8(sec, (unsigned char)(ir == 0 ? 0x06 : 0x07)); continue; }
            if (parse_direct(a0, &direct)) { emit_u8(sec, 0x05); emit_u8(sec, (unsigned char)(direct & 0xFF)); continue; }
        }
        if (!strcmp(ins->op, "dec") && ins->args && ins->args->len == 1) {
            char *a0 = list_get(ins->args, 0);
            int r = parse_reg_rn(a0);
            int ir = parse_indirect_rn(a0);
            int direct = 0;
            if (a0 && !strcmp(a0, "A")) { emit_u8(sec, 0x14); continue; }
            if (r >= 0) { emit_u8(sec, (unsigned char)(0x18 + r)); continue; }
            if (ir == 0 || ir == 1) { emit_u8(sec, (unsigned char)(ir == 0 ? 0x16 : 0x17)); continue; }
            if (parse_direct(a0, &direct)) { emit_u8(sec, 0x15); emit_u8(sec, (unsigned char)(direct & 0xFF)); continue; }
        }
    }
}

/* === SSA lowering helpers === */
static int g_lower_id = 0;

static char *new_label(const char *prefix)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "L%s_%d", prefix, g_lower_id++);
    return gen_strdup(buf);
}

static const char *map_block_label(const char *func_name, const char *label)
{
    if (!label) return "<null>";
    if (strncmp(label, "block", 5) == 0) {
        int id = atoi(label + 5);
        static char buf[96];
        snprintf(buf, sizeof(buf), "L%s_%d", func_name ? func_name : "fn", id);
        return buf;
    }
    return label;
}

static int param_index(Func *f, const char *name)
{
    if (!f || !f->params || !name) return -1;
    int idx = 0;
    for (Iter it = list_iter(f->params); !iter_end(it); ++idx) {
        char *p = iter_next(&it);
        if (p && !strcmp(p, name)) return idx;
    }
    return -1;
}

static Block *find_block_by_label(Func *f, const char *label)
{
    if (!f || !label) return NULL;
    int id = -1;
    if (strncmp(label, "block", 5) == 0)
        id = atoi(label + 5);
    if (id < 0) return NULL;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (b && (int)b->id == id) return b;
    }
    return NULL;
}

static const char *find_var_for_value(Block *blk, ValueName v)
{
    if (!blk || !blk->var_map || v == 0) return NULL;
    for (Iter it = list_iter(blk->var_map->list); !iter_end(it);) {
        DictEntry *e = iter_next(&it);
        if (!e || !e->val) continue;
        ValueName *val = (ValueName *)e->val;
        if (*val == v) return e->key;
    }
    return NULL;
}

static bool value_defined_in_block(Block *blk, ValueName v)
{
    if (!blk || v == 0) return false;
    for (Iter it = list_iter(blk->instrs); !iter_end(it);) {
        Instr *ins = iter_next(&it);
        if (ins && ins->dest == v && ins->op != IROP_NOP && ins->op != IROP_PHI)
            return true;
    }
    return false;
}

typedef struct {
    const char *label;
    Ctype *mem_type;
    bool is_stack;
    int stack_off;
} AddrInfo;

static Dict *g_addr_map = NULL;
static Dict *g_const_map = NULL;
static Dict *g_mmio_map = NULL;

struct MmioInfo {
    int addr;
    bool is_bit;
};

static char *vreg_key(ValueName v)
{
    char buf[32];
    snprintf(buf, sizeof(buf), "v%d", v);
    return gen_strdup(buf);
}

static void mmio_map_put(const char *name, int addr, bool is_bit)
{
    if (!g_mmio_map || !name) return;
    MmioInfo *info = gen_alloc(sizeof(MmioInfo));
    info->addr = addr;
    info->is_bit = is_bit;
    dict_put(g_mmio_map, gen_strdup(name), info);
}

static MmioInfo *mmio_map_get(const char *name)
{
    if (!g_mmio_map || !name) return NULL;
    return (MmioInfo *)dict_get(g_mmio_map, (char *)name);
}

static void addr_map_put(ValueName v, const char *label, Ctype *mem_type)
{
    if (!g_addr_map || v <= 0 || !label) return;
    AddrInfo *info = gen_alloc(sizeof(AddrInfo));
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

static AddrInfo *addr_map_get(ValueName v)
{
    if (!g_addr_map || v <= 0) return NULL;
    char buf[32];
    snprintf(buf, sizeof(buf), "v%d", v);
    return (AddrInfo *)dict_get(g_addr_map, buf);
}

static void addr_map_put_stack(ValueName v, int offset, Ctype *mem_type)
{
    if (!g_addr_map || v <= 0) return;
    AddrInfo *info = gen_alloc(sizeof(AddrInfo));
    info->label = NULL;
    info->mem_type = mem_type;
    info->is_stack = true;
    info->stack_off = offset;
    dict_put(g_addr_map, vreg_key(v), info);
}

static void const_map_put(ValueName v, int val)
{
    if (!g_const_map || v <= 0) return;
    int *p = gen_alloc(sizeof(int));
    *p = val;
    dict_put(g_const_map, vreg_key(v), p);
}

static bool const_map_get(ValueName v, int *out)
{
    if (!g_const_map || v <= 0) return false;
    char buf[32];
    snprintf(buf, sizeof(buf), "v%d", v);
    int *p = (int *)dict_get(g_const_map, buf);
    if (!p) return false;
    if (out) *out = *p;
    return true;
}

static int data_space_kind(Ctype *type)
{
    if (!type) return 1;
    int d = get_attr(type->attr).ctype_data;
    return d ? d : 1;
}

static bool func_stack_offset(Func *f, const char *name, int *out)
{
    if (!f || !name || !f->stack_offsets) return false;
    int *p = (int *)dict_get(f->stack_offsets, (char *)name);
    if (!p) return false;
    if (out) *out = *p;
    return true;
}

static List *collect_block_defs(Block *blk)
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

static void emit_phi_moves_for_edge(Section *sec, Func *func, Block *from, const char *to_label)
{
    if (!sec || !func || !from || !to_label) return;
    Block *to = find_block_by_label(func, to_label);
    if (!to || !to->phis) return;

    char from_label[32];
    snprintf(from_label, sizeof(from_label), "block%u", from->id);

    List *fallbacks = collect_block_defs(from);
    int fallback_idx = fallbacks->len - 1;

    for (Iter pit = list_iter(to->phis); !iter_end(pit);) {
        Instr *phi = iter_next(&pit);
        if (!phi || phi->op != IROP_PHI || !phi->labels || !phi->args) continue;

        ValueName src_val = 0;
        const char *var = find_var_for_value(to, phi->dest);
        if (var) {
            ValueName *p = (ValueName *)dict_get(from->var_map, (char *)var);
            if (p) src_val = *p;
        }

        if (src_val == 0) {
            for (int i = 0; i < phi->labels->len && i < phi->args->len; ++i) {
                char *lbl = list_get(phi->labels, i);
                if (!lbl || strcmp(lbl, from_label) != 0) continue;
                ValueName *src = list_get(phi->args, i);
                if (!src) continue;
                src_val = *src;
                break;
            }
        }

        if (src_val == 0 || !value_defined_in_block(from, src_val)) {
            while (fallback_idx >= 0) {
                ValueName *p = list_get(fallbacks, fallback_idx--);
                if (p && *p != phi->dest) { src_val = *p; break; }
            }
        }

        if (src_val == 0 || phi->dest == src_val) continue;
        emit_ins2(sec, "mov", vreg(phi->dest), vreg(src_val));
    }

    list_free(fallbacks);
    free(fallbacks);
}

static void emit_load_stack_param(Section *sec, int offset, const char *dst, bool use_fp)
{
    if (!sec || !dst) return;
    char buf[16];
    emit_ins2(sec, "mov", "A", use_fp ? "0x2E" : "0x81");
    snprintf(buf, sizeof(buf), "#0x%02X", (unsigned char)(0 - offset));
    emit_ins2(sec, "add", "A", buf);
    emit_ins2(sec, "mov", "r0", "A");
    emit_ins2(sec, "mov", "A", "@r0");
    emit_ins2(sec, "mov", dst, "A");
}

static void emit_stack_addr(Section *sec, int offset)
{
    char buf[16];
    emit_ins2(sec, "mov", "A", "0x2E");
    snprintf(buf, sizeof(buf), "#%d", offset + 1);
    emit_ins2(sec, "add", "A", buf);
    emit_ins2(sec, "mov", "r0", "A");
}

static void emit_frame_prologue(Section *sec, int stack_size)
{
    if (!sec || stack_size <= 0) return;
    char buf[16];
    emit_ins2(sec, "mov", "0x2E", "0x81");
    emit_ins2(sec, "mov", "A", "0x81");
    snprintf(buf, sizeof(buf), "#%d", stack_size);
    emit_ins2(sec, "add", "A", buf);
    emit_ins2(sec, "mov", "0x81", "A");
}

static void emit_frame_epilogue(Section *sec, int stack_size)
{
    if (!sec || stack_size <= 0) return;
    emit_ins2(sec, "mov", "0x81", "0x2E");
}

static void emit_interrupt_prologue(Section *sec)
{
    if (!sec) return;
    emit_ins1(sec, "push", "A");
    emit_ins1(sec, "push", "0xD0");
    emit_ins1(sec, "push", "0x82");
    emit_ins1(sec, "push", "0x83");
}

static void emit_interrupt_epilogue(Section *sec)
{
    if (!sec) return;
    emit_ins1(sec, "pop", "0x83");
    emit_ins1(sec, "pop", "0x82");
    emit_ins1(sec, "pop", "0xD0");
    emit_ins1(sec, "pop", "A");
}

/* === Instruction selection === */
static void emit_instr(Section *sec, Instr *ins, Func *func, Block *cur_block)
{
    if (!ins) return;
    char buf[64];
    const char *func_name = func ? func->name : NULL;

    switch (ins->op) {
    case IROP_NOP:
        return;
    case IROP_PARAM:
        if (ins->labels && ins->labels->len > 0) {
            char *pname = list_get(ins->labels, 0);
            int idx = param_index(func, pname);
            if (idx >= 0 && idx < 8) {
                char regbuf[8];
                snprintf(regbuf, sizeof(regbuf), "r%d", 7 - idx);
                emit_ins2(sec, "mov", vreg(ins->dest), regbuf);
            } else if (idx >= 8) {
                int offset = 2 + (idx - 8);
                emit_load_stack_param(sec, offset, vreg(ins->dest), func && func->stack_size > 0);
            }
        }
        return;
    case IROP_CONST:
        snprintf(buf, sizeof(buf), "#%lld", (long long)ins->imm.ival);
        emit_ins2(sec, "mov", vreg(ins->dest), buf);
        if (g_const_map)
            const_map_put(ins->dest, (int)ins->imm.ival);
        break;
    case IROP_ADD:
        emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins2(sec, "add", "A", vreg(*(ValueName *)list_get(ins->args, 1)));
        emit_ins2(sec, "mov", vreg(ins->dest), "A");
        break;
    case IROP_SUB:
        emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins1(sec, "clr", "C");
        emit_ins2(sec, "subb", "A", vreg(*(ValueName *)list_get(ins->args, 1)));
        emit_ins2(sec, "mov", vreg(ins->dest), "A");
        break;
    case IROP_MUL:
        emit_ins2(sec, "mov", "B", vreg(*(ValueName *)list_get(ins->args, 1)));
        emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins1(sec, "mul", "AB");
        emit_ins2(sec, "mov", vreg(ins->dest), "A");
        break;
    case IROP_DIV:
        emit_ins2(sec, "mov", "B", vreg(*(ValueName *)list_get(ins->args, 1)));
        emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins1(sec, "div", "AB");
        emit_ins2(sec, "mov", vreg(ins->dest), "A");
        break;
    case IROP_MOD:
        emit_ins2(sec, "mov", "B", vreg(*(ValueName *)list_get(ins->args, 1)));
        emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins1(sec, "div", "AB");
        emit_ins2(sec, "mov", vreg(ins->dest), "B");
        break;
    case IROP_AND:
        emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins2(sec, "anl", "A", vreg(*(ValueName *)list_get(ins->args, 1)));
        emit_ins2(sec, "mov", vreg(ins->dest), "A");
        break;
    case IROP_OR:
        emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins2(sec, "orl", "A", vreg(*(ValueName *)list_get(ins->args, 1)));
        emit_ins2(sec, "mov", vreg(ins->dest), "A");
        break;
    case IROP_XOR:
        emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins2(sec, "xrl", "A", vreg(*(ValueName *)list_get(ins->args, 1)));
        emit_ins2(sec, "mov", vreg(ins->dest), "A");
        break;
    case IROP_SHL: {
        char *l_loop = new_label("shl_loop");
        char *l_end = new_label("shl_end");
        emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins2(sec, "mov", "r7", vreg(*(ValueName *)list_get(ins->args, 1)));
        emit_ins3(sec, "cjne", "r7", "#0", l_loop);
        emit_ins1(sec, "sjmp", l_end);
        emit_label(sec, l_loop);
        emit_ins2(sec, "add", "A", "A");
        emit_ins2(sec, "djnz", "r7", l_loop);
        emit_label(sec, l_end);
        emit_ins2(sec, "mov", vreg(ins->dest), "A");
        free(l_loop);
        free(l_end);
        break;
    }
    case IROP_SHR: {
        char *l_loop = new_label("shr_loop");
        char *l_end = new_label("shr_end");
        emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins2(sec, "mov", "r7", vreg(*(ValueName *)list_get(ins->args, 1)));
        emit_ins3(sec, "cjne", "r7", "#0", l_loop);
        emit_ins1(sec, "sjmp", l_end);
        emit_label(sec, l_loop);
        if (is_signed_type(ins->type)) {
            char *l_pos = new_label("shr_pos");
            char *l_cont = new_label("shr_cont");
            emit_ins2(sec, "mov", "r6", "A");
            emit_ins2(sec, "mov", "A", "r6");
            emit_ins2(sec, "anl", "A", "#0x80");
            emit_ins1(sec, "jz", l_pos);
            emit_ins2(sec, "mov", "A", "r6");
            emit_ins1(sec, "clr", "C");
            emit_ins1(sec, "rrc", "A");
            emit_ins2(sec, "orl", "A", "#0x80");
            emit_ins1(sec, "sjmp", l_cont);
            emit_label(sec, l_pos);
            emit_ins2(sec, "mov", "A", "r6");
            emit_ins1(sec, "clr", "C");
            emit_ins1(sec, "rrc", "A");
            emit_label(sec, l_cont);
            free(l_pos);
            free(l_cont);
        } else {
            emit_ins1(sec, "clr", "C");
            emit_ins1(sec, "rrc", "A");
        }
        emit_ins2(sec, "djnz", "r7", l_loop);
        emit_label(sec, l_end);
        emit_ins2(sec, "mov", vreg(ins->dest), "A");
        free(l_loop);
        free(l_end);
        break;
    }
    case IROP_NEG:
        emit_ins1(sec, "clr", "C");
        emit_ins2(sec, "mov", "A", "#0");
        emit_ins2(sec, "subb", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins2(sec, "mov", vreg(ins->dest), "A");
        break;
    case IROP_NOT:
        emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins1(sec, "cpl", "A");
        emit_ins2(sec, "mov", vreg(ins->dest), "A");
        break;
    case IROP_EQ: {
        char *l_false = new_label("eq_false");
        char *l_end = new_label("eq_end");
        emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins3(sec, "cjne", "A", vreg(*(ValueName *)list_get(ins->args, 1)), l_false);
        emit_ins2(sec, "mov", vreg(ins->dest), "#1");
        emit_ins1(sec, "sjmp", l_end);
        emit_label(sec, l_false);
        emit_ins2(sec, "mov", vreg(ins->dest), "#0");
        emit_label(sec, l_end);
        free(l_false);
        free(l_end);
        break;
    }
    case IROP_NE: {
        char *l_true = new_label("ne_true");
        char *l_end = new_label("ne_end");
        emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins3(sec, "cjne", "A", vreg(*(ValueName *)list_get(ins->args, 1)), l_true);
        emit_ins2(sec, "mov", vreg(ins->dest), "#0");
        emit_ins1(sec, "sjmp", l_end);
        emit_label(sec, l_true);
        emit_ins2(sec, "mov", vreg(ins->dest), "#1");
        emit_label(sec, l_end);
        free(l_true);
        free(l_end);
        break;
    }
    case IROP_LT: {
        char *l_true = new_label("lt_true");
        char *l_false = new_label("lt_false");
        char *l_same = new_label("lt_same");
        char *l_end = new_label("lt_end");
        emit_ins2(sec, "mov", "r6", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins2(sec, "mov", "r7", vreg(*(ValueName *)list_get(ins->args, 1)));
        if (is_signed_type(ins->type)) {
            emit_ins2(sec, "mov", "A", "r6");
            emit_ins2(sec, "xrl", "A", "r7");
            emit_ins2(sec, "anl", "A", "#0x80");
            emit_ins1(sec, "jz", l_same);
            emit_ins2(sec, "mov", "A", "r6");
            emit_ins2(sec, "anl", "A", "#0x80");
            emit_ins1(sec, "jz", l_false);
            emit_ins1(sec, "sjmp", l_true);
            emit_label(sec, l_same);
        }
        emit_ins2(sec, "mov", "A", "r6");
        emit_ins1(sec, "clr", "C");
        emit_ins2(sec, "subb", "A", "r7");
        emit_ins1(sec, "jc", l_true);
        emit_label(sec, l_false);
        emit_ins2(sec, "mov", vreg(ins->dest), "#0");
        emit_ins1(sec, "sjmp", l_end);
        emit_label(sec, l_true);
        emit_ins2(sec, "mov", vreg(ins->dest), "#1");
        emit_label(sec, l_end);
        free(l_true);
        free(l_false);
        free(l_same);
        free(l_end);
        break;
    }
    case IROP_LE: {
        char *l_true = new_label("le_true");
        char *l_false = new_label("le_false");
        char *l_same = new_label("le_same");
        char *l_end = new_label("le_end");
        emit_ins2(sec, "mov", "r6", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins2(sec, "mov", "r7", vreg(*(ValueName *)list_get(ins->args, 1)));
        if (is_signed_type(ins->type)) {
            emit_ins2(sec, "mov", "A", "r6");
            emit_ins2(sec, "xrl", "A", "r7");
            emit_ins2(sec, "anl", "A", "#0x80");
            emit_ins1(sec, "jz", l_same);
            emit_ins2(sec, "mov", "A", "r6");
            emit_ins2(sec, "anl", "A", "#0x80");
            emit_ins1(sec, "jz", l_false);
            emit_ins1(sec, "sjmp", l_true);
            emit_label(sec, l_same);
        }
        emit_ins2(sec, "mov", "A", "r6");
        emit_ins1(sec, "clr", "C");
        emit_ins2(sec, "subb", "A", "r7");
        emit_ins1(sec, "jc", l_true);
        emit_ins1(sec, "jz", l_true);
        emit_label(sec, l_false);
        emit_ins2(sec, "mov", vreg(ins->dest), "#0");
        emit_ins1(sec, "sjmp", l_end);
        emit_label(sec, l_true);
        emit_ins2(sec, "mov", vreg(ins->dest), "#1");
        emit_label(sec, l_end);
        free(l_true);
        free(l_false);
        free(l_same);
        free(l_end);
        break;
    }
    case IROP_GT: {
        char *l_true = new_label("gt_true");
        char *l_false = new_label("gt_false");
        char *l_same = new_label("gt_same");
        char *l_end = new_label("gt_end");
        emit_ins2(sec, "mov", "r6", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins2(sec, "mov", "r7", vreg(*(ValueName *)list_get(ins->args, 1)));
        if (is_signed_type(ins->type)) {
            emit_ins2(sec, "mov", "A", "r6");
            emit_ins2(sec, "xrl", "A", "r7");
            emit_ins2(sec, "anl", "A", "#0x80");
            emit_ins1(sec, "jz", l_same);
            emit_ins2(sec, "mov", "A", "r6");
            emit_ins2(sec, "anl", "A", "#0x80");
            emit_ins1(sec, "jz", l_true);
            emit_ins1(sec, "sjmp", l_false);
            emit_label(sec, l_same);
        }
        emit_ins2(sec, "mov", "A", "r6");
        emit_ins1(sec, "clr", "C");
        emit_ins2(sec, "subb", "A", "r7");
        emit_ins1(sec, "jc", l_false);
        emit_ins1(sec, "jz", l_false);
        emit_label(sec, l_true);
        emit_ins2(sec, "mov", vreg(ins->dest), "#1");
        emit_ins1(sec, "sjmp", l_end);
        emit_label(sec, l_false);
        emit_ins2(sec, "mov", vreg(ins->dest), "#0");
        emit_label(sec, l_end);
        free(l_true);
        free(l_false);
        free(l_same);
        free(l_end);
        break;
    }
    case IROP_GE: {
        char *l_true = new_label("ge_true");
        char *l_false = new_label("ge_false");
        char *l_same = new_label("ge_same");
        char *l_end = new_label("ge_end");
        emit_ins2(sec, "mov", "r6", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins2(sec, "mov", "r7", vreg(*(ValueName *)list_get(ins->args, 1)));
        if (is_signed_type(ins->type)) {
            emit_ins2(sec, "mov", "A", "r6");
            emit_ins2(sec, "xrl", "A", "r7");
            emit_ins2(sec, "anl", "A", "#0x80");
            emit_ins1(sec, "jz", l_same);
            emit_ins2(sec, "mov", "A", "r6");
            emit_ins2(sec, "anl", "A", "#0x80");
            emit_ins1(sec, "jz", l_true);
            emit_ins1(sec, "sjmp", l_false);
            emit_label(sec, l_same);
        }
        emit_ins2(sec, "mov", "A", "r6");
        emit_ins1(sec, "clr", "C");
        emit_ins2(sec, "subb", "A", "r7");
        emit_ins1(sec, "jnc", l_true);
        emit_label(sec, l_false);
        emit_ins2(sec, "mov", vreg(ins->dest), "#0");
        emit_ins1(sec, "sjmp", l_end);
        emit_label(sec, l_true);
        emit_ins2(sec, "mov", vreg(ins->dest), "#1");
        emit_label(sec, l_end);
        free(l_true);
        free(l_false);
        free(l_same);
        free(l_end);
        break;
    }
    case IROP_LNOT: {
        char *l_true = new_label("lnot_true");
        char *l_end = new_label("lnot_end");
        emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins1(sec, "jz", l_true);
        emit_ins2(sec, "mov", vreg(ins->dest), "#0");
        emit_ins1(sec, "sjmp", l_end);
        emit_label(sec, l_true);
        emit_ins2(sec, "mov", vreg(ins->dest), "#1");
        emit_label(sec, l_end);
        free(l_true);
        free(l_end);
        break;
    }
    case IROP_ADDR: {
        if (ins->labels && ins->labels->len > 0) {
            const char *name = list_get(ins->labels, 0);
            int off = 0;
            if (func_stack_offset(func, name, &off)) {
                char obuf[16];
                emit_ins2(sec, "mov", "A", "0x2E");
                snprintf(obuf, sizeof(obuf), "#%d", off + 1);
                emit_ins2(sec, "add", "A", obuf);
                emit_ins2(sec, "mov", vreg(ins->dest), "A");
            } else {
                addr_map_put(ins->dest, name, ins->mem_type);
            }
        }
        return;
    }
    case IROP_OFFSET: {
        ValueName base = *(ValueName *)list_get(ins->args, 0);
        ValueName idx = *(ValueName *)list_get(ins->args, 1);
        int elem = (int)ins->imm.ival;
        int cidx = 0;
        if (const_map_get(idx, &cidx)) {
            int off = cidx * elem;
            char obuf[16];
            emit_ins2(sec, "mov", "A", vreg(base));
            snprintf(obuf, sizeof(obuf), "#%d", off);
            emit_ins2(sec, "add", "A", obuf);
            emit_ins2(sec, "mov", vreg(ins->dest), "A");
        } else {
            emit_ins2(sec, "mov", "A", vreg(idx));
            if (elem != 1) {
                char ebuf[16];
                snprintf(ebuf, sizeof(ebuf), "#%d", elem);
                emit_ins2(sec, "mov", "B", ebuf);
                emit_ins1(sec, "mul", "AB");
            }
            emit_ins2(sec, "mov", "r6", "A");
            emit_ins2(sec, "mov", "A", vreg(base));
            emit_ins2(sec, "add", "A", "r6");
            emit_ins2(sec, "mov", vreg(ins->dest), "A");
        }
        return;
    }
    case IROP_LOAD:
    {
        ValueName ptr = *(ValueName *)list_get(ins->args, 0);
        AddrInfo *info = addr_map_get(ptr);
        Ctype *mtype = ins->mem_type ? ins->mem_type : (info ? info->mem_type : NULL);
        int space = data_space_kind(mtype);
        if (info && info->is_stack) {
            emit_stack_addr(sec, info->stack_off);
            emit_ins2(sec, "mov", "A", "@r0");
            emit_ins2(sec, "mov", vreg(ins->dest), "A");
            break;
        }
        if (info && info->label && is_register_bit(mtype)) {
            emit_ins2(sec, "mov", "C", info->label);
            emit_ins2(sec, "mov", "A", "#0");
            emit_ins1(sec, "rlc", "A");
            emit_ins2(sec, "mov", vreg(ins->dest), "A");
            break;
        }
        if (info && info->label) {
            if (space == 6) {
                char imm[128];
                snprintf(imm, sizeof(imm), "#%s", info->label);
                emit_ins2(sec, "mov", "DPTR", imm);
                emit_ins2(sec, "mov", "A", "#0");
                emit_ins2(sec, "movc", "A", "@A+DPTR");
            } else if (space == 4 || space == 5) {
                char imm[128];
                snprintf(imm, sizeof(imm), "#%s", info->label);
                emit_ins2(sec, "mov", "DPTR", imm);
                emit_ins2(sec, "movx", "A", "@DPTR");
            } else {
                emit_ins2(sec, "mov", "A", info->label);
            }
        } else if (space == 6) {
            emit_ins2(sec, "mov", "0x82", vreg(ptr));
            emit_ins2(sec, "mov", "0x83", "#0");
            emit_ins2(sec, "mov", "A", "#0");
            emit_ins2(sec, "movc", "A", "@A+DPTR");
        } else if (space == 4 || space == 5) {
            emit_ins2(sec, "mov", "0x82", vreg(ptr));
            emit_ins2(sec, "mov", "0x83", "#0");
            emit_ins2(sec, "movx", "A", "@DPTR");
        } else {
            snprintf(buf, sizeof(buf), "@%s", vreg(ptr));
            emit_ins2(sec, "mov", "A", buf);
        }
        emit_ins2(sec, "mov", vreg(ins->dest), "A");
        break;
    }
    case IROP_STORE:
    {
        ValueName ptr = *(ValueName *)list_get(ins->args, 0);
        ValueName val = *(ValueName *)list_get(ins->args, 1);
        AddrInfo *info = addr_map_get(ptr);
        Ctype *mtype = ins->mem_type ? ins->mem_type : (info ? info->mem_type : NULL);
        int space = data_space_kind(mtype);
        emit_ins2(sec, "mov", "A", vreg(val));
        if (info && info->is_stack) {
            emit_stack_addr(sec, info->stack_off);
            emit_ins2(sec, "mov", "@r0", "A");
            break;
        }
        if (info && info->label && is_register_bit(mtype)) {
            emit_ins2(sec, "mov", "C", "ACC.0");
            emit_ins2(sec, "mov", info->label, "C");
            break;
        }
        if (info && info->label) {
            if (space == 4 || space == 5) {
                char imm[128];
                snprintf(imm, sizeof(imm), "#%s", info->label);
                emit_ins2(sec, "mov", "DPTR", imm);
                emit_ins2(sec, "movx", "@DPTR", "A");
            } else if (space != 6) {
                emit_ins2(sec, "mov", info->label, "A");
            }
        } else if (space == 4 || space == 5) {
            emit_ins2(sec, "mov", "0x82", vreg(ptr));
            emit_ins2(sec, "mov", "0x83", "#0");
            emit_ins2(sec, "movx", "@DPTR", "A");
        } else if (space != 6) {
            snprintf(buf, sizeof(buf), "@%s", vreg(ptr));
            emit_ins2(sec, "mov", buf, "A");
        }
        break;
    }
    case IROP_JMP: {
        char *label = list_get(ins->labels, 0);
        emit_phi_moves_for_edge(sec, func, cur_block, label);
        emit_ins1(sec, "sjmp", map_block_label(func_name, label));
        break;
    }
    case IROP_BR: {
        char *t = list_get(ins->labels, 0);
        char *f = list_get(ins->labels, 1);
        char *l_true = new_label("phi_true");
        emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins1(sec, "jnz", l_true);
        emit_phi_moves_for_edge(sec, func, cur_block, f);
        emit_ins1(sec, "sjmp", map_block_label(func_name, f));
        emit_label(sec, l_true);
        emit_phi_moves_for_edge(sec, func, cur_block, t);
        emit_ins1(sec, "sjmp", map_block_label(func_name, t));
        free(l_true);
        break;
    }
    case IROP_CALL: {
        char *fname = list_get(ins->labels, 0);
        int nargs = ins->args ? ins->args->len : 0;
        int extra = nargs > 8 ? (nargs - 8) : 0;

        for (int r = 0; r <= 7; ++r) {
            char regbuf[8];
            snprintf(regbuf, sizeof(regbuf), "r%d", r);
            emit_ins1(sec, "push", regbuf);
        }

        if (ins->args && nargs > 8) {
            for (int idx = nargs - 1; idx >= 8; --idx) {
                ValueName v = *(ValueName *)list_get(ins->args, idx);
                emit_ins2(sec, "mov", "A", vreg(v));
                emit_ins1(sec, "push", "A");
            }
        }

        if (ins->args && nargs > 0) {
            for (int idx = 0; idx < nargs && idx < 8; ++idx) {
                ValueName v = *(ValueName *)list_get(ins->args, idx);
                char regbuf[8];
                snprintf(regbuf, sizeof(regbuf), "r%d", 7 - idx);
                emit_ins2(sec, "mov", regbuf, vreg(v));
            }
        }
        emit_ins1(sec, "lcall", fname ? fname : "<null>");

        for (int i = 0; i < extra; ++i)
            emit_ins1(sec, "pop", "r0");

        for (int r = 7; r >= 0; --r) {
            char regbuf[8];
            snprintf(regbuf, sizeof(regbuf), "r%d", r);
            emit_ins1(sec, "pop", regbuf);
        }

        if (ins->dest != 0)
            emit_ins2(sec, "mov", vreg(ins->dest), "A");
        break;
    }
    case IROP_RET:
        if (ins->args && ins->args->len > 0)
            emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        if (func && func->stack_size > 0)
            emit_frame_epilogue(sec, func->stack_size);
        if (func && func->is_interrupt) {
            emit_interrupt_epilogue(sec);
            emit_ins0(sec, "reti");
        } else {
            emit_ins0(sec, "ret");
        }
        break;
    case IROP_PHI:
        return;
    default:
        return;
    }
}

/* === Lowering/cleanup passes === */
static void lower_section_asminstrs(Section *sec)
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

static int instr_estimated_size(const AsmInstr *ins)
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
    if (!strcmp(ins->op, "add") || !strcmp(ins->op, "subb") || !strcmp(ins->op, "anl") ||
        !strcmp(ins->op, "orl") || !strcmp(ins->op, "xrl") || !strcmp(ins->op, "clr") ||
        !strcmp(ins->op, "cpl")) return 2;
    if (!strcmp(ins->op, "mov")) return 3;
    return 1;
}

/* === Short jump fixups === */
static void fixup_short_jumps(Section *sec)
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

/* === Entry point === */
ObjFile *c51_gen_from_ssa(void *ssa)
{
    SSAUnit *unit = (SSAUnit *)ssa;
    if (!unit) return NULL;

    ObjFile *obj = objfile_new();

    g_mmio_map = make_dict(NULL);

    for (Iter git = list_iter(unit->globals); !iter_end(git);) {
        GlobalVar *g = iter_next(&git);
        emit_global_data(obj, g);
    }

    for (Iter fit = list_iter(unit->funcs); !iter_end(fit);) {
        Func *f = iter_next(&fit);
        if (!f || !f->name) continue;
        regalloc_stub(f);
        g_addr_map = make_dict(NULL);
        g_const_map = make_dict(NULL);
        char sec_name[128];
        snprintf(sec_name, sizeof(sec_name), ".text.%s", f->name);
        Section *sec = get_or_create_section(obj, sec_name, SEC_CODE);

        objfile_add_symbol(obj, (char *)f->name, SYM_FUNC, section_index_from_ptr(obj, sec), 0, 0, SYM_FLAG_GLOBAL);
        emit_label(sec, f->name);
        if (f->is_interrupt) {
            char buf[16];
            snprintf(buf, sizeof(buf), "%d", f->interrupt_id);
            emit_ins1(sec, ".interrupt", buf);
            if (f->bank_id >= 0) {
                char bbuf[16];
                snprintf(bbuf, sizeof(bbuf), "%d", f->bank_id);
                emit_ins1(sec, ".using", bbuf);
            }
            emit_interrupt_prologue(sec);
        }
        if (f->stack_size > 0)
            emit_frame_prologue(sec, f->stack_size);

        for (Iter bit = list_iter(f->blocks); !iter_end(bit);) {
            Block *b = iter_next(&bit);
            if (!b) continue;
            char label[64];
            snprintf(label, sizeof(label), "L%s_%u", f->name, b->id);
            emit_label(sec, label);

            for (Iter it = list_iter(b->instrs); !iter_end(it);) {
                Instr *ins = iter_next(&it);
                emit_instr(sec, ins, f, b);
            }
        }

        regalloc_section_asminstrs(sec);
        lower_section_asminstrs(sec);
        peephole_section_asminstrs(sec);
        fixup_short_jumps(sec);
        encode_section_bytes(obj, sec);

        if (g_addr_map) {
            for (Iter it = list_iter(g_addr_map->list); !iter_end(it);) {
                DictEntry *e = iter_next(&it);
                if (!e) continue;
                free(e->key);
                free(e->val);
            }
            dict_clear(g_addr_map);
            g_addr_map = NULL;
        }
        if (g_const_map) {
            for (Iter it = list_iter(g_const_map->list); !iter_end(it);) {
                DictEntry *e = iter_next(&it);
                if (!e) continue;
                free(e->key);
                free(e->val);
            }
            dict_clear(g_const_map);
            g_const_map = NULL;
        }
    }

    if (g_mmio_map) {
        for (Iter it = list_iter(g_mmio_map->list); !iter_end(it);) {
            DictEntry *e = iter_next(&it);
            if (!e) continue;
            free(e->key);
            free(e->val);
        }
        dict_clear(g_mmio_map);
        g_mmio_map = NULL;
    }

    return obj;
}

#ifdef MINITEST_IMPLEMENTATION
#include "minitest.h"

TEST(test, c51_gen) {
    char infile[256];
    printf("file path for C51 gen test: ");
    if (!fgets(infile, sizeof infile, stdin) || !freopen(strtok(infile, "\n"), "r", stdin))
        puts("open fail"), exit(1);

    set_current_filename(infile);

    SSABuild *b = ssa_build_create();
    List *toplevels = read_toplevels();
    for (Iter i = list_iter(toplevels); !iter_end(i);) {
        Ast *v = iter_next(&i);
        ssa_convert_ast(b, v);
    }

    ObjFile *obj = c51_gen_from_ssa(b->unit);
    Section *code_sec = NULL;
    for (Iter it = list_iter(obj->sections); !iter_end(it);) {
        Section *sec = iter_next(&it);
        if (sec && sec->kind == SEC_CODE) { code_sec = sec; break; }
    }
    if (code_sec && code_sec->asminstrs) {
        for (Iter it = list_iter(code_sec->asminstrs); !iter_end(it);)
            (void)iter_next(&it);
    }
    c51_write_asm(stdout, obj);

    objfile_free(obj);
    ssa_build_destroy(b);
    list_free(strings);
    list_free(ctypes);
}
#endif
