#include "c51_obj.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void *c51_alloc(size_t size)
{
    void *p = calloc(1, size);
    if (!p) {
        fprintf(stderr, "c51_link: out of memory\n");
        exit(1);
    }
    return p;
}

static char *c51_strdup(const char *s)
{
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char *d = c51_alloc(len);
    memcpy(d, s, len);
    return d;
}

ObjFile *objfile_new(void)
{
    ObjFile *obj = c51_alloc(sizeof(ObjFile));
    obj->sections = make_list();
    obj->symbols = make_list();
    obj->relocs = make_list();
    return obj;
}

static void free_section(Section *sec)
{
    if (!sec) return;
    free(sec->name);
    free(sec->bytes);
    if (sec->asminstrs) {
        for (Iter it = list_iter(sec->asminstrs); !iter_end(it);) {
            AsmInstr *ins = iter_next(&it);
            if (!ins) continue;
            if (ins->args) {
                list_free(ins->args);
                free(ins->args);
            }
            free(ins->op);
            free(ins);
        }
        free(sec->asminstrs);
    }
    free(sec);
}

static void free_symbol(Symbol *sym)
{
    if (!sym) return;
    free(sym->name);
    free(sym);
}

static void free_reloc(Reloc *rel)
{
    if (!rel) return;
    free(rel->symbol);
    free(rel);
}

void objfile_free(ObjFile *obj)
{
    if (!obj) return;
    for (Iter it = list_iter(obj->sections); !iter_end(it);)
        free_section(iter_next(&it));
    for (Iter it = list_iter(obj->symbols); !iter_end(it);)
        free_symbol(iter_next(&it));
    for (Iter it = list_iter(obj->relocs); !iter_end(it);)
        free_reloc(iter_next(&it));
    free(obj->sections);
    free(obj->symbols);
    free(obj->relocs);
    free(obj);
}

int objfile_add_section(ObjFile *obj, const char *name, SectionKind kind, int size, int align)
{
    if (!obj || !name) return -1;
    Section *sec = c51_alloc(sizeof(Section));
    sec->name = c51_strdup(name);
    sec->kind = kind;
    sec->size = size;
    sec->align = align;
    sec->bytes = NULL;
    sec->bytes_len = 0;
    sec->asminstrs = make_list();
    if (size > 0) {
        sec->bytes = c51_alloc((size_t)size);
        sec->bytes_len = size;
    }
    list_push(obj->sections, sec);
    return obj->sections->len - 1;
}

Section *objfile_get_section(ObjFile *obj, int index)
{
    if (!obj) return NULL;
    return list_get(obj->sections, index);
}

const Section *objfile_get_section_const(const ObjFile *obj, int index)
{
    if (!obj) return NULL;
    return list_get(obj->sections, index);
}

int objfile_add_symbol(ObjFile *obj, const char *name, SymbolKind kind, int section, int value, int size, unsigned flags)
{
    if (!obj || !name) return -1;
    Symbol *sym = c51_alloc(sizeof(Symbol));
    sym->name = c51_strdup(name);
    sym->kind = kind;
    sym->section = section;
    sym->value = value;
    sym->size = size;
    sym->flags = flags;
    list_push(obj->symbols, sym);
    return obj->symbols->len - 1;
}

int objfile_add_reloc(ObjFile *obj, int section, int offset, RelocKind kind, const char *symbol, int addend)
{
    if (!obj || !symbol) return -1;
    Reloc *rel = c51_alloc(sizeof(Reloc));
    rel->section = section;
    rel->offset = offset;
    rel->kind = kind;
    rel->symbol = c51_strdup(symbol);
    rel->addend = addend;
    list_push(obj->relocs, rel);
    return obj->relocs->len - 1;
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

void section_append_zeros(Section *sec, int count)
{
    if (!sec || count <= 0) return;
    int new_len = sec->bytes_len + count;
    sec->bytes = realloc(sec->bytes, (size_t)new_len);
    if (!sec->bytes) {
        fprintf(stderr, "c51_link: out of memory\n");
        exit(1);
    }
    memset(sec->bytes + sec->bytes_len, 0, (size_t)count);
    sec->bytes_len = new_len;
    sec->size = sec->bytes_len;
}

void section_append_bytes(Section *sec, const unsigned char *bytes, int len)
{
    if (!sec || !bytes || len <= 0) return;
    int new_len = sec->bytes_len + len;
    sec->bytes = realloc(sec->bytes, (size_t)new_len);
    if (!sec->bytes) {
        fprintf(stderr, "c51_link: out of memory\n");
        exit(1);
    }
    memcpy(sec->bytes + sec->bytes_len, bytes, (size_t)len);
    sec->bytes_len = new_len;
    sec->size = sec->bytes_len;
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
            fprintf(stderr, "c51_link: reloc into empty section\n");
            return -1;
        }
        Symbol *sym = find_symbol_by_name(out, rel->symbol);
        /* section=-1: undefined/external symbol
         * section=-2: absolute address symbol (SFR register like P1=0x90)
         */
        if (!sym || sym->section == -1) {
            fprintf(stderr, "c51_link: undefined symbol: %s\n", rel->symbol ? rel->symbol : "<null>");
            return -1;
        }
        /* section=-2 是绝对地址符号（SFR），直接使用 value */
        int sym_addr = (sym->section == -2) ? (sym->value + rel->addend) : (sym->value + rel->addend);
        int offset = rel->offset;
        if (offset < 0 || offset >= sec->bytes_len) {
            fprintf(stderr, "c51_link: reloc offset out of range\n");
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
            fprintf(stderr, "c51_link: unknown reloc kind\n");
            return -1;
        }
    }
    return 0;
}

static void hex_record(FILE *fp, unsigned char type, unsigned short addr, const unsigned char *data, int len)
{
    unsigned char sum = (unsigned char)(len + (addr >> 8) + (addr & 0xFF) + type);
    fprintf(fp, ":%02X%04X%02X", len, addr, type);
    for (int i = 0; i < len; ++i) {
        sum += data[i];
        fprintf(fp, "%02X", data[i]);
    }
    sum = (unsigned char)(~sum + 1);
    fprintf(fp, "%02X\n", sum);
}

int c51_write_hex(FILE *fp, const ObjFile *obj)
{
    if (!fp || !obj) return -1;
    Section *code = NULL;
    for (Iter it = list_iter(obj->sections); !iter_end(it);) {
        Section *sec = iter_next(&it);
        if (sec && sec->kind == SEC_CODE) { code = sec; break; }
    }
    if (!code || !code->bytes || code->bytes_len == 0) {
        hex_record(fp, 0x01, 0, NULL, 0);
        return 0;
    }

    unsigned short addr = 0;
    int i = 0;
    while (i < code->bytes_len) {
        int chunk = code->bytes_len - i;
        if (chunk > 16) chunk = 16;
        hex_record(fp, 0x00, addr, code->bytes + i, chunk);
        addr += (unsigned short)chunk;
        i += chunk;
    }
    hex_record(fp, 0x01, 0, NULL, 0);
    return 0;
}

/*
 * Linker skeleton.
 * TODO: implement section layout, symbol resolution, and relocation.
 */
ObjFile *c51_link(List *objs)
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
                    AsmInstr *copy = c51_alloc(sizeof(AsmInstr));
                    copy->op = c51_strdup(ins->op);
                    copy->args = make_list();
                    if (ins->args) {
                        for (Iter ait2 = list_iter(ins->args); !iter_end(ait2);) {
                            char *arg = iter_next(&ait2);
                            list_push(copy->args, c51_strdup(arg));
                        }
                    }
                    list_push(out_sec->asminstrs, copy);
                }
            }

            SectionMap *m = c51_alloc(sizeof(SectionMap));
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
                /* 未定义/外部符号 */
                objfile_add_symbol(out, sym->name, sym->kind, -1, 0, sym->size, sym->flags);
                continue;
            }
            if (sym->section == -2) {
                /* 绝对地址符号（SFR 寄存器，如 P1=0x90）*/
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
    /* 1. 段信息 */
    for (Iter it = list_iter(out->sections); !iter_end(it);) {
        Section *sec = iter_next(&it);
        if (!sec) continue;
        fprintf(stderr, "section %-6s  addr=0x%04X  size=%-4d  align=%d\n",
                sec->name, 0, sec->bytes_len, sec->align);
    }
    /* 2. 符号信息 */
    for (Iter it = list_iter(out->symbols); !iter_end(it);) {
        Symbol *sym = iter_next(&it);
        if (!sym || !sym->name) continue;
        const char *sec = sym->section == -2 ? "abs" :
                          sym->section == -1 ? "ext" :
                          objfile_get_section_const(out, sym->section)->name;
        fprintf(stderr, "symbol %-16s  sec=%-6s  value=0x%04X  size=%-3d\n",
                sym->name, sec, sym->value, sym->size);
    }
    /* 3. 重定位信息 */
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

#ifdef MINITEST_IMPLEMENTATION
#include "../minitest.h"
#include "../ssa.h"

extern List *ctypes;
extern List *strings;
extern void parser_reset(void);
extern List *read_toplevels(void);
extern void set_current_filename(const char *filename);
extern char *ast_to_string(Ast *ast);
ObjFile *c51_gen_from_ssa(void *ssa);

TEST(test, c51_link) {
    char line[256];
    List *files = make_list();
    printf("file path(s) for C51 link test (empty line to end): ");
    while (fgets(line, sizeof line, stdin)) {
        char *path = strtok(line, "\n");
        if (!path || !*path) break;
        list_push(files, c51_strdup(path));
    }
    if (files->len == 0)
        puts("open fail"), exit(1);

    List *objs = make_list();
    for (Iter fit = list_iter(files); !iter_end(fit);) {
        char *infile = iter_next(&fit);
        if (!freopen(infile, "r", stdin))
            puts("open fail"), exit(1);
        set_current_filename(infile);
        parser_reset();

        SSABuild *b = ssa_build_create();
        List *toplevels = read_toplevels();

        printf("\n=== Parsing AST (%s) ===\n", infile);
        for (Iter i = list_iter(toplevels); !iter_end(i);) {
            Ast *v = iter_next(&i);
            printf("ast: %s\n", ast_to_string(v));
            ssa_convert_ast(b, v);
        }

        ssa_optimize(b->unit, OPT_O1);

        ObjFile *obj = c51_gen_from_ssa(b->unit);
        ASSERT(obj);
        list_push(objs, obj);
        ssa_build_destroy(b);
        parser_reset();
    }

    ObjFile *out = c51_link(objs);
    
    print_link_summary(out);
    
    ASSERT(out);

    printf("\n=== ASM Output (link) ===\n");
    ASSERT_EQ(c51_write_asm(stdout, out), 0);

    printf("\n=== HEX Output (link) ===\n");
    ASSERT_EQ(c51_write_hex(stdout, out), 0);

    objfile_free(out);
    list_free(files);
    free(files);
    list_free(objs);
    free(objs);
}
#endif
