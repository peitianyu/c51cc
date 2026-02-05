#include "obj.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void *link_alloc(size_t size)
{
    void *p = calloc(1, size);
    if (!p) {
        fprintf(stderr, "obj_link: out of memory\n");
        exit(1);
    }
    return p;
}

static char *link_strdup(const char *s)
{
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char *d = link_alloc(len);
    memcpy(d, s, len);
    return d;
}

static const char *section_default_name(SectionKind kind)
{
    switch (kind) {
    case SEC_CODE:  return ".text";
    case SEC_DATA:  return ".data";
    case SEC_IDATA: return ".idata";
    case SEC_XDATA: return ".xdata";
    case SEC_BIT:   return ".bit";
    case SEC_BDATA: return ".bdata";
    case SEC_PDATA: return ".pdata";
    default:        return ".text";
    }
}

static int align_up(int value, int align)
{
    if (align <= 1) return value;
    int mod = value % align;
    if (mod == 0) return value;
    return value + (align - mod);
}

static Section *ensure_out_section(ObjFile *out, SectionKind kind)
{
    for (Iter it = list_iter(out->sections); !iter_end(it);) {
        Section *sec = iter_next(&it);
        if (sec && sec->kind == kind)
            return sec;
    }
    int idx = objfile_add_section(out, section_default_name(kind), kind, 0, 1);
    return objfile_get_section(out, idx);
}

static int section_index(ObjFile *out, Section *sec)
{
    int idx = 0;
    for (Iter it = list_iter(out->sections); !iter_end(it); ++idx) {
        if (iter_next(&it) == sec)
            return idx;
    }
    return -1;
}

typedef struct {
    ObjFile *obj;
    int in_sec;
    int out_sec;
    int base;
} SectionMap;

static SectionMap *find_map(List *maps, ObjFile *obj, int in_sec)
{
    for (Iter it = list_iter(maps); !iter_end(it);) {
        SectionMap *m = iter_next(&it);
        if (m && m->obj == obj && m->in_sec == in_sec)
            return m;
    }
    return NULL;
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

static int apply_relocs(ObjFile *out)
{
    if (!out) return -1;
    for (Iter it = list_iter(out->relocs); !iter_end(it);) {
        Reloc *rel = iter_next(&it);
        if (!rel) continue;
        Section *sec = objfile_get_section(out, rel->section);
        if (!sec || !sec->bytes) {
            fprintf(stderr, "obj_link: reloc into empty section\n");
            return -1;
        }
        Symbol *sym = find_symbol_by_name(out, rel->symbol);
        /* section=-1: undefined/external symbol
         * section=-2: absolute address symbol
         */
        if (!sym || sym->section == -1) {
            fprintf(stderr, "obj_link: undefined symbol: %s\n", rel->symbol ? rel->symbol : "<null>");
            return -1;
        }
        int sym_addr = sym->value + rel->addend;
        int offset = rel->offset;
        if (offset < 0 || offset >= sec->bytes_len) {
            fprintf(stderr, "obj_link: reloc offset out of range\n");
            return -1;
        }

        switch (rel->kind) {
        case RELOC_ABS8: {
            if (offset + 1 > sec->bytes_len) return -1;
            sec->bytes[offset] = (unsigned char)(sym_addr & 0xFF);
            break;
        }
        case RELOC_ABS16: {
            if (offset + 2 > sec->bytes_len) return -1;
            sec->bytes[offset] = (unsigned char)(sym_addr & 0xFF);
            sec->bytes[offset + 1] = (unsigned char)((sym_addr >> 8) & 0xFF);
            break;
        }
        case RELOC_REL8: {
            if (offset + 1 > sec->bytes_len) return -1;
            int pc = offset + 1;
            int relv = sym_addr - pc;
            sec->bytes[offset] = (unsigned char)(relv & 0xFF);
            break;
        }
        case RELOC_REL16: {
            if (offset + 2 > sec->bytes_len) return -1;
            int pc = offset + 2;
            int relv = sym_addr - pc;
            sec->bytes[offset] = (unsigned char)(relv & 0xFF);
            sec->bytes[offset + 1] = (unsigned char)((relv >> 8) & 0xFF);
            break;
        }
        default:
            fprintf(stderr, "obj_link: unknown reloc kind\n");
            return -1;
        }
    }
    return 0;
}

ObjFile *obj_link(List *objs)
{
    if (!objs) return NULL;

    ObjFile *out = objfile_new();
    List *maps = make_list();

    for (Iter oit = list_iter(objs); !iter_end(oit);) {
        ObjFile *obj = iter_next(&oit);
        if (!obj) continue;

        int sec_index = 0;
        for (Iter sit = list_iter(obj->sections); !iter_end(sit); ++sec_index) {
            Section *in = iter_next(&sit);
            if (!in) continue;
            Section *out_sec = ensure_out_section(out, in->kind);

            int align = in->align > 0 ? in->align : 1;
            int base = align_up(out_sec->bytes_len, align);
            if (base > out_sec->bytes_len)
                section_append_zeros(out_sec, base - out_sec->bytes_len);
            if (out_sec->align < align)
                out_sec->align = align;

            if (in->bytes && in->bytes_len > 0)
                section_append_bytes(out_sec, in->bytes, in->bytes_len);
            else if (in->size > 0)
                section_append_zeros(out_sec, in->size);

            if (in->asminstrs && in->asminstrs->len > 0) {
                for (Iter ait = list_iter(in->asminstrs); !iter_end(ait);) {
                    AsmInstr *ins = iter_next(&ait);
                    if (!ins) continue;
                    AsmInstr *copy = link_alloc(sizeof(AsmInstr));
                    copy->op = link_strdup(ins->op);
                    copy->args = make_list();
                    copy->ssa = ins->ssa ? link_strdup(ins->ssa) : NULL;
                    if (ins->args) {
                        for (Iter ait2 = list_iter(ins->args); !iter_end(ait2);) {
                            char *arg = iter_next(&ait2);
                            list_push(copy->args, link_strdup(arg));
                        }
                    }
                    list_push(out_sec->asminstrs, copy);
                }
            }

            SectionMap *m = link_alloc(sizeof(SectionMap));
            m->obj = obj;
            m->in_sec = sec_index;
            m->out_sec = section_index(out, out_sec);
            m->base = base;
            list_push(maps, m);
        }

        for (Iter sit = list_iter(obj->symbols); !iter_end(sit);) {
            Symbol *sym = iter_next(&sit);
            if (!sym) continue;
            if (sym->section == -1) {
                /* undefined/external symbol */
                objfile_add_symbol(out, sym->name, sym->kind, -1, 0, sym->size, sym->flags);
                continue;
            }
            if (sym->section == -2) {
                /* absolute address symbol */
                objfile_add_symbol(out, sym->name, sym->kind, -2, sym->value, sym->size, sym->flags);
                continue;
            }
            SectionMap *m = find_map(maps, obj, sym->section);
            if (!m) continue;
            int out_value = m->base + sym->value;
            objfile_add_symbol(out, sym->name, sym->kind, m->out_sec, out_value, sym->size, sym->flags);
        }

        for (Iter rit = list_iter(obj->relocs); !iter_end(rit);) {
            Reloc *rel = iter_next(&rit);
            if (!rel) continue;
            SectionMap *m = find_map(maps, obj, rel->section);
            if (!m) continue;
            int out_offset = m->base + rel->offset;
            objfile_add_reloc(out, m->out_sec, out_offset, rel->kind, rel->symbol, rel->addend);
        }
    }

    list_free(maps);
    free(maps);

    if (apply_relocs(out) != 0) {
        objfile_free(out);
        return NULL;
    }
    return out;
}

void print_link_summary(const ObjFile *out)
{
    if (!out) return;
    fprintf(stderr, "\n==== Link Map ====\n");
    /* 1. sections */
    for (Iter it = list_iter(out->sections); !iter_end(it);) {
        Section *sec = iter_next(&it);
        if (!sec) continue;
        fprintf(stderr, "section %-6s  addr=0x%04X  size=%-4d  align=%d\n",
                sec->name, 0, sec->bytes_len, sec->align);
    }
    /* 2. symbols */
    for (Iter it = list_iter(out->symbols); !iter_end(it);) {
        Symbol *sym = iter_next(&it);
        if (!sym || !sym->name) continue;
        const char *sec = sym->section == -2 ? "abs" :
                          sym->section == -1 ? "ext" :
                          objfile_get_section_const(out, sym->section)->name;
        fprintf(stderr, "symbol %-16s  sec=%-6s  value=0x%04X  size=%-3d\n",
                sym->name, sec, sym->value, sym->size);
    }
    /* 3. relocs */
    for (Iter it = list_iter(out->relocs); !iter_end(it);) {
        Reloc *r = iter_next(&it);
        if (!r) continue;
        const Section *sec = objfile_get_section_const(out, r->section);
        fprintf(stderr, "reloc  off=0x%04X  kind=%d  sym=%-16s  addend=%d  → %s\n",
                r->offset, r->kind, r->symbol, r->addend,
                sec ? sec->name : "?");
    }
    fprintf(stderr, "==== End Link Map ====\n");
}
