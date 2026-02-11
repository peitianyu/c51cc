#ifndef C51_GEN_GLOBAL_VAR_H
#define C51_GEN_GLOBAL_VAR_H

#include "c51_gen_internal.h"

enum {
    CTYPE_DATA_NONE = 0,
    CTYPE_DATA_DATA = 1,
    CTYPE_DATA_IDATA = 2,
    CTYPE_DATA_PDATA = 3,
    CTYPE_DATA_XDATA = 4,
    CTYPE_DATA_EDATA = 5,
    CTYPE_DATA_CODE = 6,
};

static inline void append_init_bytes_safe(Section *sec, GlobalVar *g)
{
    if (g->init_instr && g->init_instr->op == IROP_CONST &&
        g->init_instr->imm.blob.bytes) {
        section_append_bytes(sec, g->init_instr->imm.blob.bytes,
                             g->init_instr->imm.blob.len);
        return;
    }

    unsigned char bytes[4] = {0};
    int len = (g->type->size > (int)sizeof(bytes)) ? (int)sizeof(bytes) : g->type->size;
    for (int i = 0; i < len; i++) {
        bytes[i] = (g->init_value >> (i * 8)) & 0xFF;
    }
    section_append_bytes(sec, bytes, len);
}

static inline void add_data_symbol(C51GenContext *ctx, const char *name,
                                   int sec_idx, unsigned int addr_or_offset,
                                   int size, int flags)
{
    obj_add_symbol(ctx->obj, name, SYM_DATA, sec_idx, addr_or_offset, size, flags);
}

static inline void select_section_kind_and_prefix(CtypeAttr attr, GlobalVar *g,
                                                  SectionKind *out_kind, const char **out_prefix)
{
    switch (attr.ctype_data) {
        case CTYPE_DATA_IDATA:
            *out_kind = SEC_IDATA; *out_prefix = "?ID?"; break;
        case CTYPE_DATA_XDATA:
            *out_kind = SEC_XDATA; *out_prefix = "?XD?"; break;
        case CTYPE_DATA_PDATA:
            *out_kind = SEC_PDATA; *out_prefix = "?PD?"; break;
        case CTYPE_DATA_DATA:
        default:
            *out_kind = SEC_DATA;  *out_prefix = "?DT?"; break;
    }

    if (g->type->type == CTYPE_BOOL || (attr.ctype_data == CTYPE_DATA_NONE && g->type->bit_size > 0)) {
        *out_kind = SEC_BDATA; *out_prefix = "?BA?";
    }
}

static inline bool handle_const_global_var(C51GenContext *ctx, GlobalVar *g)
{
    CtypeAttr attr = get_attr(g->type->attr);

    if (attr.ctype_data == CTYPE_DATA_CODE || (attr.ctype_const && g->type->type != CTYPE_ARRAY)) {
        int sec_idx = obj_add_section(ctx->obj, "?CO?", SEC_CODE, 0, 1);
        Section *sec = obj_get_section(ctx->obj, sec_idx);

        add_data_symbol(ctx, g->name, sec_idx, sec->size, g->type->size, SYM_FLAG_GLOBAL);

        if (g->has_init) {
            append_init_bytes_safe(sec, g);
        }
        return true;
    }
    return false;
}

static inline bool handle_mmio_global_var(C51GenContext *ctx, GlobalVar *g)
{
    CtypeAttr attr = get_attr(g->type->attr);

    bool has_abs_addr = (g->init_instr && g->init_instr->op == IROP_INTTOPTR) || (attr.ctype_register);
    if (!has_abs_addr) return false;

    unsigned int abs_addr = 0;
    if (g->init_instr && g->init_instr->op == IROP_INTTOPTR) {
        abs_addr = (unsigned int)g->init_instr->imm.ival;
    }
    if (attr.ctype_register && abs_addr == 0) {
        abs_addr = (unsigned int)g->init_value;
    }

    if (attr.ctype_register) {
        int flags = SYM_FLAG_GLOBAL;
        if (g->type->type == CTYPE_BOOL) flags |= SYM_FLAG_BIT;
        add_data_symbol(ctx, g->name, -1, abs_addr, g->type->size, flags);
        return true;
    }

    if (abs_addr > 0) {
        int flags = SYM_FLAG_GLOBAL;
        if (g->is_extern) flags |= SYM_FLAG_EXTERN;
        if (g->type->type == CTYPE_BOOL) flags |= SYM_FLAG_BIT;
        add_data_symbol(ctx, g->name, -1, abs_addr, g->type->size, flags);
        return true;
    }
    return false;
}

static inline bool handle_extern_global_var(C51GenContext *ctx, GlobalVar *g)
{
    if (!g->is_extern) return false;

    add_data_symbol(ctx, g->name, -1, 0, g->type->size, SYM_FLAG_GLOBAL | SYM_FLAG_EXTERN);
    return true;
}

static inline void handle_normal_global_var(C51GenContext *ctx, GlobalVar *g)
{
    CtypeAttr attr = get_attr(g->type->attr);
    
    SectionKind kind;
    const char *prefix;
    select_section_kind_and_prefix(attr, g, &kind, &prefix);
    
    int sec_idx = obj_add_section(ctx->obj, prefix, kind, 0, 1);
    Section *sec = obj_get_section(ctx->obj, sec_idx);
    
    unsigned int offset = sec->size;
    
    int flags = SYM_FLAG_GLOBAL;
    if (g->is_static) flags = SYM_FLAG_LOCAL;
    if (g->type->type == CTYPE_BOOL || g->type->bit_size > 0) flags |= SYM_FLAG_BIT;
    add_data_symbol(ctx, g->name, sec_idx, offset, g->type->size, flags);
    
    if (g->has_init) {
        append_init_bytes_safe(sec, g);
    } else {
        section_append_zeros(sec, g->type->size);
    }
}

#endif
