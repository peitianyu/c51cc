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
    ctx->value_to_spill = make_dict(NULL);
    ctx->next_spill_id = 0;
    /* 默认 spill 区使用 IDATA，较大（size>1）时使用 XDATA */
    ctx->spill_section = SEC_IDATA;
    ctx->spill_use_xdata_for_large = 1;
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
    if (ctx->value_to_spill) {
        dict_free(ctx->value_to_spill, free);
        ctx->value_to_spill = NULL;
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

static void process_top_level_asm(C51GenContext *ctx, SSAUnit *unit)
{
    if (!ctx || !ctx->obj || !unit || !unit->asm_blocks || unit->asm_blocks->len == 0) return;

    int sec_idx = obj_add_section(ctx->obj, "?ASM?", SEC_CODE, 0, 1);
    Section *sec = obj_get_section(ctx->obj, sec_idx);
    if (!sec) return;

    for (Iter ait = list_iter(unit->asm_blocks); !iter_end(ait);) {
        char *asm_text = iter_next(&ait);
        if (asm_text) c51_emit_asm_text(sec, asm_text);
    }
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

    process_top_level_asm(ctx, unit);

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

static ObjFile *compile_one(const char *path);

static char *obj_to_asm_text(ObjFile *obj) {
    if (!obj) return NULL;

    char *buf = NULL;
    size_t len = 0;
    FILE *fp = open_memstream(&buf, &len);
    if (!fp) return NULL;
    c51_write_asm(fp, obj);
    fclose(fp);
    return buf;
}

static char *compile_one_to_asm(const char *path) {
    ObjFile *obj = compile_one(path);
    char *asm_text = obj_to_asm_text(obj);
    obj_free(obj);
    return asm_text;
}

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
        
    // /* print SSA before optimization for debugging array handling */
    // fprintf(stdout, "=== SSA BEFORE OPT ===\n");
    // ssa_print(stdout, b->unit);

    ssa_optimize(b->unit, OPT_O1);
    fprintf(stdout, "=== SSA AFTER OPT ===\n");
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

TEST(test, c51_inline_asm_output) {
    char *asm_text = compile_one_to_asm("test/test_asm.c");
    ASSERT_TRUE(asm_text != NULL);
    ASSERT_TRUE(strstr(asm_text, "_foo:") != NULL);
    ASSERT_TRUE(strstr(asm_text, "PUSH r7") != NULL);
    ASSERT_TRUE(strstr(asm_text, "MOV A, #0") != NULL);
    ASSERT_TRUE(strstr(asm_text, "POP r7") != NULL);
    ASSERT_TRUE(strstr(asm_text, "        RET") != NULL);
    ASSERT_TRUE(strstr(asm_text, "        NOP") != NULL);
    ASSERT_TRUE(strstr(asm_text, "LCALL _foo") != NULL);
    free(asm_text);
}

TEST(test, c51_special_output) {
    char *asm_text = compile_one_to_asm("test/test_more_functions.c");
    ASSERT_TRUE(asm_text != NULL);
    ASSERT_TRUE(strstr(asm_text, "BOOT_LABEL:") != NULL);
    ASSERT_TRUE(strstr(asm_text, "_read_flag:") != NULL);
    ASSERT_TRUE(strstr(asm_text, "_add1:") != NULL);
    ASSERT_TRUE(strstr(asm_text, "LCALL _read_flag") != NULL);
    ASSERT_TRUE(strstr(asm_text, "LCALL _add1") != NULL);
    ASSERT_TRUE(strstr(asm_text, "ISR_1:") != NULL);
    ASSERT_TRUE(strstr(asm_text, "PUSH PSW") != NULL);
    ASSERT_TRUE(strstr(asm_text, "PUSH ACC") != NULL);
    ASSERT_TRUE(strstr(asm_text, "MOV PSW, #8") != NULL);
    ASSERT_TRUE(strstr(asm_text, "POP PSW") != NULL);
    ASSERT_TRUE(strstr(asm_text, "RETI") != NULL);
    ASSERT_TRUE(strstr(asm_text, "JB EA") != NULL || strstr(asm_text, "JNB EA") != NULL);
    ASSERT_TRUE(strstr(asm_text, "INC R7") != NULL);
    free(asm_text);
}

#endif
