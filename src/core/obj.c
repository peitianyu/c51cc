#include "obj.h"
#include <stdlib.h>
#include <string.h>

static void *obj_alloc(size_t size)
{
    void *p = calloc(1, size);
    if (!p) {
        fprintf(stderr, "obj: out of memory\n");
        exit(1);
    }
    return p;
}

static char *obj_strdup(const char *s)
{
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char *d = obj_alloc(len);
    memcpy(d, s, len);
    return d;
}

ObjFile *objfile_new(void)
{
    ObjFile *obj = obj_alloc(sizeof(ObjFile));
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
            free(ins->ssa);
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
    Section *sec = obj_alloc(sizeof(Section));
    sec->name = obj_strdup(name);
    sec->kind = kind;
    sec->size = size;
    sec->align = align;
    sec->bytes = NULL;
    sec->bytes_len = 0;
    sec->asminstrs = make_list();
    if (size > 0) {
        sec->bytes = obj_alloc((size_t)size);
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
    Symbol *sym = obj_alloc(sizeof(Symbol));
    sym->name = obj_strdup(name);
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
    Reloc *rel = obj_alloc(sizeof(Reloc));
    rel->section = section;
    rel->offset = offset;
    rel->kind = kind;
    rel->symbol = obj_strdup(symbol);
    rel->addend = addend;
    list_push(obj->relocs, rel);
    return obj->relocs->len - 1;
}

void section_append_zeros(Section *sec, int count)
{
    if (!sec || count <= 0) return;
    int new_len = sec->bytes_len + count;
    sec->bytes = realloc(sec->bytes, (size_t)new_len);
    if (!sec->bytes) {
        fprintf(stderr, "obj: out of memory\n");
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
        fprintf(stderr, "obj: out of memory\n");
        exit(1);
    }
    memcpy(sec->bytes + sec->bytes_len, bytes, (size_t)len);
    sec->bytes_len = new_len;
    sec->size = sec->bytes_len;
}
