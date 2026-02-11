#include "c51_gen_internal.h"

#include "c51_gen_global_var.h"
static void process_global_var(C51GenContext *ctx, GlobalVar *g) 
{
    if (!g || !g->name || !ctx)             return;

    if (handle_const_global_var(ctx, g))    return; 
    if (handle_mmio_global_var(ctx, g))     return;
    if (handle_extern_global_var(ctx, g))   return;
    handle_normal_global_var(ctx, g);
}

#include "c51_gen_function.h"
static void process_function(C51GenContext *ctx, Func *f) 
{
    handle_function_init(ctx, f);
    handle_function_emit(ctx, f);
    handle_function_regalloc(ctx, f);
    handle_function_optimize(ctx, f);
    handle_function_encode(ctx, f);
    handle_function_cleanup(ctx, f);
}

ObjFile *c51_gen(SSAUnit *unit) {
    if(!unit) return NULL;

    C51GenContext *ctx = c51_ctx_new();

    for (Iter git = list_iter(unit->globals); !iter_end(git);) {
        GlobalVar *g = iter_next(&git);
        if (g) process_global_var(ctx, g);
    }

    for (Iter fit = list_iter(unit->funcs); !iter_end(fit);) {
        Func *f = iter_next(&fit);
        if (f) process_function(ctx, f);
    }

    return ctx->obj;
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