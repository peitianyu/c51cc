#include "c51_gen.h"

/* === Section management === */
Section *get_or_create_section(ObjFile *obj, const char *name, SectionKind kind)
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

int section_index_from_ptr(ObjFile *obj, Section *sec)
{
    int idx = 0;
    for (Iter it = list_iter(obj->sections); !iter_end(it); ++idx) {
        if (iter_next(&it) == sec)
            return idx;
    }
    return -1;
}

/* === Global data emission === */
void emit_global_data(ObjFile *obj, GlobalVar *g)
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

/* === Symbol helpers === */
Symbol *find_symbol_by_name(ObjFile *obj, const char *name)
{
    for (Iter it = list_iter(obj->symbols); !iter_end(it);) {
        Symbol *sym = iter_next(&it);
        if (sym && sym->name && name && !strcmp(sym->name, name))
            return sym;
    }
    return NULL;
}

void define_label_symbol(ObjFile *obj, const char *name, int section, int value)
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
