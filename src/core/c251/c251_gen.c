#include "c251_gen.h"
#include "c251_isel.h"
#include "c251_encode.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

C251GenContext* c251_ctx_new(void) {
    C251GenContext* ctx = calloc(1, sizeof(C251GenContext));
    if (!ctx) return NULL;
    ctx->obj = obj_new();
    ctx->value_to_reg = make_dict(NULL);
    ctx->value_type = make_dict(NULL);
    ctx->value_to_const = make_dict(NULL);
    ctx->temp_values = make_list();
    return ctx;
}

void c251_ctx_free(C251GenContext* ctx) {
    if (!ctx) return;
    if (ctx->value_to_reg)  { dict_free(ctx->value_to_reg, free); }
    if (ctx->value_type)    { dict_free(ctx->value_type, NULL); }
    if (ctx->value_to_const){ dict_free(ctx->value_to_const, free); }
    if (ctx->temp_values)   { list_free(ctx->temp_values); }
    free(ctx);
}

/* M1: 整数全局变量 → SEC_EDATA + 符号 + 初始化字节 */
static void process_global_var(C251GenContext *ctx, GlobalVar *g) {
    if (!g || !g->name) return;
    if (g->is_extern) return;
    int size = g->type ? g->type->size : 1;
    if (size < 1) size = 1;
    int sec_idx = obj_find_or_add_section(ctx->obj, "?ED?", SEC_EDATA, 1);
    Section *sec = obj_get_section(ctx->obj, sec_idx);
    int offset = sec->bytes_len;
    obj_add_symbol(ctx->obj, g->name, SYM_DATA, sec_idx, offset, size, SYM_FLAG_GLOBAL);
    section_append_zeros(sec, size);
    /* 有初始值：写第一个字节（M1 简化，完整初始化在 M3） */
    if (g->has_init && g->init_instr == NULL) {
        unsigned char v = (unsigned char)(g->init_value & 0xFF);
        sec->bytes[offset] = v;
    }
}

static void process_function(C251GenContext *ctx, Func *f) {
    if (f) isel_function(ctx, f);
}

ObjFile *c251_gen(SSAUnit *unit) {
    if (!unit) return NULL;
    C251GenContext *ctx = c251_ctx_new();
    if (!ctx) return NULL;
    ctx->unit = unit;

    for (Iter git = list_iter(unit->globals); !iter_end(git);) {
        GlobalVar *g = iter_next(&git);
        if (g) process_global_var(ctx, g);
    }
    for (Iter fit = list_iter(unit->funcs); !iter_end(fit);) {
        Func *f = iter_next(&fit);
        if (f) process_function(ctx, f);
    }

    c251_encode(ctx, ctx->obj);

    ObjFile* obj = ctx->obj;
    ctx->obj = NULL;
    c251_ctx_free(ctx);
    return obj;
}

ObjFile *c251_link_startup(const char *source_path, ObjFile *main_obj) {
    /* M1: 不注入启动代码；main 作为第一个 CODE section 从 0x0000 起，sim251 reset 后 PC=0 直接执行 */
    (void)source_path;
    return main_obj;
}
