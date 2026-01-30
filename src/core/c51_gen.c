#include "c51_obj.h"
#include "ssa.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static void emit_global_data(ObjFile *obj, GlobalVar *g)
{
    if (!g || !g->name) return;
    if (g->is_extern) {
        objfile_add_symbol(obj, g->name, SYM_DATA, -1, 0, g->type ? g->type->size : 0, SYM_FLAG_EXTERN);
        return;
    }

    SectionKind kind = map_data_space(g->type);
    const char *sec_name = g->has_init ? ".data" : ".bss";
    Section *sec = get_or_create_section(obj, sec_name, kind);
    int offset = sec->bytes_len;
    int size = g->type ? g->type->size : 1;

    if (g->has_init) {
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

static void regalloc_stub(Func *f)
{
    (void)f;
    /* TODO: linear scan register allocation */
}

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

static bool is_mov_def(const AsmInstr *ins, int arg_idx, const char *arg)
{
    if (!ins || !ins->op || !arg) return false;
    if (strcmp(ins->op, "mov") != 0) return false;
    if (arg_idx != 0) return false;
    if (arg[0] == 'v') return true;
    return false;
}

static int alloc_reg(bool prefer_r01, bool used[8])
{
    if (prefer_r01) {
        if (!used[0]) { used[0] = true; return 0; }
        if (!used[1]) { used[1] = true; return 1; }
    }
    for (int i = 0; i < 7; ++i) {
        if (!used[i]) { used[i] = true; return i; }
    }
    return -1;
}

static void regalloc_section_asminstrs(Section *sec)
{
    if (!sec || !sec->asminstrs) return;

    int max_v = -1;
    for (Iter it = list_iter(sec->asminstrs); !iter_end(it);) {
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
    bool *need_indirect = gen_alloc(sizeof(bool) * count);

    for (Iter it = list_iter(sec->asminstrs); !iter_end(it);) {
        AsmInstr *ins = iter_next(&it);
        if (!ins || !ins->args) continue;
        int idx = 0;
        for (Iter ait = list_iter(ins->args); !iter_end(ait); ++idx) {
            char *arg = iter_next(&ait);
            bool indir = false;
            int v = parse_vreg_id(arg, &indir);
            if (v < 0 || v >= count) continue;
            if (indir) need_indirect[v] = true;
        }
    }

    int *map = gen_alloc(sizeof(int) * count);
    int *spill = gen_alloc(sizeof(int) * count);
    for (int i = 0; i < count; ++i) { map[i] = -1; spill[i] = -1; }

    for (Iter it = list_iter(sec->asminstrs); !iter_end(it);) {
        AsmInstr *ins = iter_next(&it);
        if (!ins || !ins->args) continue;

        int idx = 0;
        for (Iter ait = list_iter(ins->args); !iter_end(ait); ++idx) {
            char *arg = iter_next(&ait);
            bool indir = false;
            int v = parse_vreg_id(arg, &indir);
            if (v < 0 || v >= count) continue;

            if (map[v] < 0 && spill[v] < 0) {
                if (need_indirect[v]) {
                    map[v] = (v % 2);
                } else {
                    spill[v] = 0x30 + v;
                }
            }

            char buf[16];
            if (spill[v] >= 0 && !indir) {
                snprintf(buf, sizeof(buf), "0x%02X", spill[v] & 0xFF);
            } else {
                if (map[v] < 0) map[v] = 0;
                if (indir) snprintf(buf, sizeof(buf), "@r%d", map[v]);
                else snprintf(buf, sizeof(buf), "r%d", map[v]);
            }
            list_set(ins->args, idx, gen_strdup(buf));
            free(arg);
        }
    }
}

static bool is_reg_eq(const char *a, const char *b)
{
    return a && b && !strcmp(a, b);
}

static void peephole_section_asminstrs(Section *sec)
{
    if (!sec || !sec->asminstrs) return;
    List *out = make_list();

    for (Iter it = list_iter(sec->asminstrs); !iter_end(it);) {
        AsmInstr *ins = iter_next(&it);
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
        }

        list_push(out, ins);
    }

    free(sec->asminstrs);
    sec->asminstrs = out;
}

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
            bool dst_direct_ok = parse_direct(dst, &direct_dst);
            bool src_direct_ok = parse_direct(src, &direct_src);

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
                    emit_u8(sec, (unsigned char)(direct_src & 0xFF));
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
                    emit_u8(sec, (unsigned char)(direct_src & 0xFF));
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
                    emit_u8(sec, (unsigned char)(direct_src & 0xFF));
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
                    emit_u8(sec, (unsigned char)(direct_dst & 0xFF));
                    emit_u8(sec, (unsigned char)(imm & 0xFF));
                    continue;
                }
                if (src && !strcmp(src, "A")) {
                    emit_u8(sec, 0xF5);
                    emit_u8(sec, (unsigned char)(direct_dst & 0xFF));
                    continue;
                }
                if (rsrc >= 0) {
                    emit_u8(sec, (unsigned char)(0x88 + rsrc));
                    emit_u8(sec, (unsigned char)(direct_dst & 0xFF));
                    continue;
                }
                if (src_direct_ok) {
                    emit_u8(sec, 0xE5);
                    emit_u8(sec, (unsigned char)(direct_src & 0xFF));
                    emit_u8(sec, 0xF5);
                    emit_u8(sec, (unsigned char)(direct_dst & 0xFF));
                    continue;
                }
                if (isrc == 0 || isrc == 1) {
                    emit_u8(sec, (unsigned char)(isrc == 0 ? 0x86 : 0x87));
                    emit_u8(sec, (unsigned char)(direct_dst & 0xFF));
                    continue;
                }
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
            }
        }
        return;
    case IROP_CONST:
        snprintf(buf, sizeof(buf), "#%lld", (long long)ins->imm.ival);
        emit_ins2(sec, "mov", vreg(ins->dest), buf);
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
        emit_ins1(sec, "clr", "C");
        emit_ins1(sec, "rrc", "A");
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
        char *l_end = new_label("lt_end");
        emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins1(sec, "clr", "C");
        emit_ins2(sec, "subb", "A", vreg(*(ValueName *)list_get(ins->args, 1)));
        emit_ins1(sec, "jc", l_true);
        emit_ins2(sec, "mov", vreg(ins->dest), "#0");
        emit_ins1(sec, "sjmp", l_end);
        emit_label(sec, l_true);
        emit_ins2(sec, "mov", vreg(ins->dest), "#1");
        emit_label(sec, l_end);
        free(l_true);
        free(l_end);
        break;
    }
    case IROP_LE: {
        char *l_true = new_label("le_true");
        char *l_end = new_label("le_end");
        emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins1(sec, "clr", "C");
        emit_ins2(sec, "subb", "A", vreg(*(ValueName *)list_get(ins->args, 1)));
        emit_ins1(sec, "jc", l_true);
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
    case IROP_GT: {
        char *l_true = new_label("gt_true");
        char *l_false = new_label("gt_false");
        char *l_end = new_label("gt_end");
        emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins1(sec, "clr", "C");
        emit_ins2(sec, "subb", "A", vreg(*(ValueName *)list_get(ins->args, 1)));
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
        free(l_end);
        break;
    }
    case IROP_GE: {
        char *l_true = new_label("ge_true");
        char *l_end = new_label("ge_end");
        emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins1(sec, "clr", "C");
        emit_ins2(sec, "subb", "A", vreg(*(ValueName *)list_get(ins->args, 1)));
        emit_ins1(sec, "jnc", l_true);
        emit_ins2(sec, "mov", vreg(ins->dest), "#0");
        emit_ins1(sec, "sjmp", l_end);
        emit_label(sec, l_true);
        emit_ins2(sec, "mov", vreg(ins->dest), "#1");
        emit_label(sec, l_end);
        free(l_true);
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
    case IROP_LOAD:
        snprintf(buf, sizeof(buf), "@%s", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins2(sec, "mov", "A", buf);
        emit_ins2(sec, "mov", vreg(ins->dest), "A");
        break;
    case IROP_STORE:
        snprintf(buf, sizeof(buf), "@%s", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 1)));
        emit_ins2(sec, "mov", buf, "A");
        break;
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
        if (ins->args && ins->args->len > 0) {
            int idx = 0;
            for (Iter ait = list_iter(ins->args); !iter_end(ait) && idx < 8; ++idx) {
                ValueName v = *(ValueName *)iter_next(&ait);
                char regbuf[8];
                snprintf(regbuf, sizeof(regbuf), "r%d", 7 - idx);
                emit_ins2(sec, "mov", regbuf, vreg(v));
            }
        }
        emit_ins1(sec, "lcall", fname ? fname : "<null>");
        if (ins->dest != 0)
            emit_ins2(sec, "mov", vreg(ins->dest), "A");
        break;
    }
    case IROP_RET:
        if (ins->args && ins->args->len > 0)
            emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins0(sec, "ret");
        break;
    case IROP_PHI:
        return;
    default:
        return;
    }
}

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

ObjFile *c51_gen_from_ssa(void *ssa)
{
    SSAUnit *unit = (SSAUnit *)ssa;
    if (!unit) return NULL;

    ObjFile *obj = objfile_new();

    for (Iter git = list_iter(unit->globals); !iter_end(git);) {
        GlobalVar *g = iter_next(&git);
        emit_global_data(obj, g);
    }

    for (Iter fit = list_iter(unit->funcs); !iter_end(fit);) {
        Func *f = iter_next(&fit);
        if (!f || !f->name) continue;
        regalloc_stub(f);
        char sec_name[128];
        snprintf(sec_name, sizeof(sec_name), ".text.%s", f->name);
        Section *sec = get_or_create_section(obj, sec_name, SEC_CODE);

        objfile_add_symbol(obj, (char *)f->name, SYM_FUNC, section_index_from_ptr(obj, sec), 0, 0, SYM_FLAG_GLOBAL);
        emit_label(sec, f->name);

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
        encode_section_bytes(obj, sec);
    }

    return obj;
}

#ifdef MINITEST_IMPLEMENTATION
#include "minitest.h"

extern List *ctypes;
extern List *strings;
extern List *read_toplevels(void);
extern void set_current_filename(const char *filename);
extern char *ast_to_string(Ast *ast);

TEST(test, c51_gen) {
    char infile[256];
    printf("file path for C51 gen test: ");
    if (!fgets(infile, sizeof infile, stdin) || !freopen(strtok(infile, "\n"), "r", stdin))
        puts("open fail"), exit(1);

    set_current_filename(infile);

    SSABuild *b = ssa_build_create();
    List *toplevels = read_toplevels();

    printf("\n=== Parsing AST ===\n");
    for (Iter i = list_iter(toplevels); !iter_end(i);) {
        Ast *v = iter_next(&i);
        printf("ast: %s\n", ast_to_string(v));
        ssa_convert_ast(b, v);
    }

    ObjFile *obj = c51_gen_from_ssa(b->unit);
    ASSERT(obj);
    ASSERT(obj->sections && obj->sections->len > 0);
    Section *code_sec = NULL;
    for (Iter it = list_iter(obj->sections); !iter_end(it);) {
        Section *sec = iter_next(&it);
        if (sec && sec->kind == SEC_CODE) { code_sec = sec; break; }
    }
    ASSERT(code_sec);
    ASSERT(code_sec->asminstrs && code_sec->asminstrs->len > 0);
    ASSERT(code_sec->bytes_len > 0);

    for (Iter it = list_iter(code_sec->asminstrs); !iter_end(it);) {
        AsmInstr *ins = iter_next(&it);
        if (ins && ins->op) {
            ASSERT(strcmp(ins->op, "br") != 0);
            ASSERT(strcmp(ins->op, ".warn") != 0);
            ASSERT(strcmp(ins->op, "gt") != 0);
            ASSERT(strcmp(ins->op, "ne") != 0);
            ASSERT(strcmp(ins->op, "lnot") != 0);
            ASSERT(strcmp(ins->op, "param") != 0);
            ASSERT(strcmp(ins->op, "phi") != 0);
        }
        if (ins && ins->args) {
            for (Iter ait = list_iter(ins->args); !iter_end(ait);) {
                char *arg = iter_next(&ait);
                if (arg && arg[0] == 'v')
                    ASSERT(0);
                if (arg && arg[0] == '[' && arg[1] == 'v')
                    ASSERT(0);
            }
        }
        if (ins && ins->op && !strcmp(ins->op, "mov") && ins->args && ins->args->len >= 2) {
            char *dst = list_get(ins->args, 0);
            char *src = list_get(ins->args, 1);
            ASSERT(!(dst && src && !strcmp(dst, src)));
        }
    }

    printf("\n=== ASM Output (gen) ===\n");
    ASSERT_EQ(c51_write_asm(stdout, obj), 0);

    objfile_free(obj);
    ssa_build_destroy(b);
    list_free(strings);
    list_free(ctypes);
}
#endif
