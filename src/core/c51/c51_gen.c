#include "c51_gen.h"
#include "c51_isel.h"
#include "c51_gen_global_var.h"
#include "c51_optimize.h"
#include "c51_encode.h"
#include <stdlib.h>
#include <string.h>

/* 上下文管理 */
C51GenContext* c51_ctx_new(void) {
    C51GenContext* ctx = calloc(1, sizeof(C51GenContext));
    if (!ctx) return NULL;
    
    ctx->obj = obj_new();
    ctx->value_to_reg = make_dict(NULL);
    ctx->value_to_addr = make_dict(NULL);
    ctx->value_type = make_dict(NULL);
    ctx->value_to_const = make_dict(NULL);
    ctx->v16_regs = make_dict(NULL);
    ctx->mmio_map = make_dict(NULL);
    ctx->temp_values = make_list();
    ctx->value_in_acc = -1;
    ctx->label_counter = 0;
    
    return ctx;
}

void c51_ctx_free(C51GenContext* ctx) {
    if (!ctx) return;
    
    // 注意: ctx->obj 由调用者管理
    
    if (ctx->value_to_reg) {
        dict_free(ctx->value_to_reg, free);
        ctx->value_to_reg = NULL;
    }
    if (ctx->value_to_addr) {
        dict_free(ctx->value_to_addr, free);
        ctx->value_to_addr = NULL;
    }
    if (ctx->value_type) {
        dict_free(ctx->value_type, NULL);
        ctx->value_type = NULL;
    }
    if (ctx->value_to_const) {
        dict_free(ctx->value_to_const, free);
        ctx->value_to_const = NULL;
    }
    if (ctx->v16_regs) {
        dict_free(ctx->v16_regs, free);
        ctx->v16_regs = NULL;
    }
    if (ctx->mmio_map) {
        dict_free(ctx->mmio_map, NULL);
        ctx->mmio_map = NULL;
    }
    if (ctx->temp_values) {
        list_free(ctx->temp_values);
        ctx->temp_values = NULL;
    }
    
    free(ctx);
}

/* 处理全局变量 */
static void process_global_var(C51GenContext *ctx, GlobalVar *g)
{
    if (!g || !g->name || !ctx) return;

    if (handle_const_global_var(ctx, g)) return;
    if (handle_mmio_global_var(ctx, g)) return;
    if (handle_extern_global_var(ctx, g)) return;
    handle_normal_global_var(ctx, g);
}

/* 处理函数 */
static void process_function(C51GenContext *ctx, Func *f)
{
    isel_function(ctx, f);
}

/* 代码生成主入口 */
ObjFile *c51_gen(SSAUnit *unit) {
    if(!unit) return NULL;

    C51GenContext *ctx = c51_ctx_new();
    if (!ctx) return NULL;

    for (Iter git = list_iter(unit->globals); !iter_end(git);) {
        GlobalVar *g = iter_next(&git);
        if (g) process_global_var(ctx, g);
    }

    for (Iter fit = list_iter(unit->funcs); !iter_end(fit);) {
        Func *f = iter_next(&fit);
        if (f) process_function(ctx, f);
    }

    c51_optimize(ctx, ctx->obj);
    c51_encode(ctx, ctx->obj);

    ObjFile* obj = ctx->obj;
    ctx->obj = NULL;  // 防止被释放
    c51_ctx_free(ctx);
    
    return obj;
}


#ifdef MINITEST_IMPLEMENTATION
#include "../minitest.h"

static ObjFile *compile_one(const char *path) {
    freopen(path, "r", stdin);
    set_current_filename(path);

    SSABuild *b = ssa_build_create();
    List *tops = read_toplevels();
    for (Iter i = list_iter(tops); !iter_end(i);) {
        Ast *t = iter_next(&i);
        printf("ast: %s\n", ast_to_string(t));
        ast_to_ssa(b, t);
    }
        
    ssa_optimize(b->unit, OPT_O1);
    ssa_print(stdout, b->unit);
    ObjFile *o = c51_gen(b->unit);
    ssa_build_destroy(b);
    list_free(strings);
    list_free(ctypes);
    return o;
}

TEST(test, c51_gen) {
    char f[256];
    fgets(f, sizeof f, stdin);
    *strchr(f, '\n') = 0;
    c51_write_asm(stdout, compile_one(f));
}

TEST(test, c51_link) {
    char f[256];
    List *o = make_list();
    while (fgets(f, sizeof f, stdin)) {
        *strchr(f, '\n') = 0;
        if (!*f) break;
        list_push(o, compile_one(f));
    }

    ObjFile *out = obj_link(o);
    c51_write_asm(stdout, out);
    c51_write_hex(stdout, out);
}
#endif
