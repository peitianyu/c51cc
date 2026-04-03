#include "c51_gen.h"
#include "c51_isel.h"
#include "c51_gen_global_var.h"
#include "c51_optimize.h"
#include "c51_encode.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 上下文管理 */
C51GenContext* c51_ctx_new(void) {
    C51GenContext* ctx = calloc(1, sizeof(C51GenContext));
    if (!ctx) return NULL;
    
    ctx->obj = obj_new();
    ctx->unit = NULL;
    ctx->value_to_reg = make_dict(NULL);
    ctx->value_to_addr = make_dict(NULL);
    ctx->value_type = make_dict(NULL);
    ctx->value_to_const = make_dict(NULL);
    ctx->value_to_spill = make_dict(NULL);
    ctx->next_spill_id = 0;
    /* spill 区统一使用 IDATA（内部 RAM），用直接寻址 MOV 代替 MOVX，
     * 节省大量指令：每次 16 位 spill 从 6 条 MOVX 指令减为 2 条 MOV 指令。
     * 注意：IDATA 只有 128 字节（0x00-0x7F），如果溢出太多变量，
     * 可能需要回退到 XDATA（由 spill_use_xdata_for_large 控制）。*/
    ctx->spill_section = SEC_IDATA;
    ctx->spill_use_xdata_for_large = 0;
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
    ctx->unit = unit;

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

static char *dup_dirname(const char *path)
{
    const char *slash;
    size_t len;
    char *dir;

    if (!path) return NULL;
    slash = strrchr(path, '/');
    if (!slash) slash = strrchr(path, '\\');
    if (!slash) return strdup(".");

    len = (size_t)(slash - path);
    dir = calloc(len + 1, 1);
    if (!dir) return NULL;
    memcpy(dir, path, len);
    dir[len] = '\0';
    return dir;
}

static char *join_path2(const char *dir, const char *name)
{
    size_t dir_len;
    size_t name_len;
    int needs_sep;
    char *path;

    if (!dir || !name) return NULL;
    dir_len = strlen(dir);
    name_len = strlen(name);
    needs_sep = dir_len > 0 && dir[dir_len - 1] != '/' && dir[dir_len - 1] != '\\';

    path = calloc(dir_len + name_len + (needs_sep ? 2 : 1), 1);
    if (!path) return NULL;
    memcpy(path, dir, dir_len);
    if (needs_sep) path[dir_len++] = '/';
    memcpy(path + dir_len, name, name_len);
    return path;
}

static int file_exists(const char *path)
{
    FILE *fp;

    if (!path) return 0;
    fp = c51cc_fopen(path, "rb");
    if (!fp) return 0;
    fclose(fp);
    return 1;
}

static char *read_text_file(const char *path)
{
    FILE *fp;
    long len;
    char *buf;

    if (!path) return NULL;
    fp = c51cc_fopen(path, "rb");
    if (!fp) return NULL;
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return NULL;
    }
    len = ftell(fp);
    if (len < 0 || fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return NULL;
    }

    buf = calloc((size_t)len + 1, 1);
    if (!buf) {
        fclose(fp);
        return NULL;
    }
    if ((long)fread(buf, 1, (size_t)len, fp) != len) {
        fclose(fp);
        free(buf);
        return NULL;
    }
    fclose(fp);
    return buf;
}

static char *trim_inplace(char *text)
{
    char *end;

    if (!text) return NULL;
    while (*text == ' ' || *text == '\t' || *text == '\r' || *text == '\n') text++;
    end = text + strlen(text);
    while (end > text && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' || end[-1] == '\n')) {
        *--end = '\0';
    }
    return text;
}

static int append_text(char **buf, size_t *len, size_t *cap, const char *text)
{
    size_t add;
    char *next;

    if (!buf || !len || !cap || !text) return 0;
    add = strlen(text);
    if (*len + add + 1 > *cap) {
        size_t next_cap = *cap ? *cap : 128;
        while (*len + add + 1 > next_cap) next_cap *= 2;
        next = realloc(*buf, next_cap);
        if (!next) return 0;
        *buf = next;
        *cap = next_cap;
    }
    memcpy(*buf + *len, text, add);
    *len += add;
    (*buf)[*len] = '\0';
    return 1;
}

static int is_keil_directive(const char *token)
{
    if (!token || !*token) return 0;
    return strcmp(token, "NAME") == 0 || strcmp(token, "RSEG") == 0 ||
           strcmp(token, "SEGMENT") == 0 || strcmp(token, "ORG") == 0 ||
           strcmp(token, "END") == 0;
}

static int tokenize_two_words(const char *line, char *first, size_t first_len,
                              char *second, size_t second_len)
{
    const char *cur = line;
    size_t n = 0;

    if (first && first_len) first[0] = '\0';
    if (second && second_len) second[0] = '\0';
    if (!line) return 0;

    while (*cur == ' ' || *cur == '\t') cur++;
    while (*cur && *cur != ' ' && *cur != '\t') {
        if (first && n + 1 < first_len) first[n] = *cur;
        n++;
        cur++;
    }
    if (first && first_len) first[n < first_len ? n : first_len - 1] = '\0';

    while (*cur == ' ' || *cur == '\t') cur++;
    n = 0;
    while (*cur && *cur != ' ' && *cur != '\t') {
        if (second && n + 1 < second_len) second[n] = *cur;
        n++;
        cur++;
    }
    if (second && second_len) second[n < second_len ? n : second_len - 1] = '\0';
    return 1;
}

static int normalize_startup_stmt(char **buf, size_t *len, size_t *cap, char *stmt)
{
    char first[64];
    char second[64];
    char *colon;
    char *trimmed;

    if (!stmt) return 1;
    trimmed = trim_inplace(stmt);
    if (!trimmed || !*trimmed) return 1;

    colon = strchr(trimmed, ':');
    if (colon) {
        *colon = '\0';
        if (!append_text(buf, len, cap, trim_inplace(trimmed))) return 0;
        if (!append_text(buf, len, cap, ":\n")) return 0;
        return normalize_startup_stmt(buf, len, cap, colon + 1);
    }

    tokenize_two_words(trimmed, first, sizeof(first), second, sizeof(second));
    if (is_keil_directive(first) || strcmp(second, "SEGMENT") == 0) return 1;

    if (!append_text(buf, len, cap, trimmed)) return 0;
    if (!append_text(buf, len, cap, "\n")) return 0;
    return 1;
}

static char *normalize_startup_script(const char *text)
{
    char *copy;
    char *cursor;
    char *out = NULL;
    size_t len = 0;
    size_t cap = 0;

    if (!text) return NULL;
    copy = strdup(text);
    if (!copy) return NULL;

    cursor = copy;
    while (*cursor) {
        char *line = cursor;
        char *comment;
        char *next;

        while (*cursor && *cursor != '\n' && *cursor != '\r') cursor++;
        next = cursor;
        if (*cursor == '\r' && cursor[1] == '\n') cursor += 2;
        else if (*cursor == '\r' || *cursor == '\n') cursor++;
        if (*next) *next = '\0';

        comment = strchr(line, ';');
        if (comment) *comment = '\0';
        if (!normalize_startup_stmt(&out, &len, &cap, line)) {
            free(copy);
            free(out);
            return NULL;
        }
    }

    free(copy);
    return out;
}

static char *find_startup_path(const char *source_path)
{
    char *dir;
    char *path;
    char *fallback;

    dir = dup_dirname(source_path);
    if (!dir) return NULL;
    path = join_path2(dir, "STARTUP.A51");
    free(dir);
    if (!path) return NULL;

    if (file_exists(path)) return path;
    free(path);
    
    fallback = join_path2(".", "STARTUP.A51");
    if (file_exists(fallback)) return fallback;
    free(fallback);
    return NULL;
}

static ObjFile *compile_startup_file(const char *startup_path)
{
    char *raw;
    char *normalized;
    ObjFile *obj;
    Section *sec;
    int sec_idx;

    raw = read_text_file(startup_path);
    if (!raw) return NULL;
    normalized = normalize_startup_script(raw);
    free(raw);
    if (!normalized) return NULL;
    if (!*normalized) {
        free(normalized);
        return NULL;
    }

    obj = obj_new();
    sec_idx = obj_add_section(obj, "?C_STARTUP", SEC_CODE, 0, 1);
    sec = obj_get_section(obj, sec_idx);
    if (!sec) {
        free(normalized);
        obj_free(obj);
        return NULL;
    }

    c51_emit_asm_text(sec, normalized);
    c51_encode(NULL, obj);
    free(normalized);
    return obj;
}

ObjFile *c51_link_startup(const char *source_path, ObjFile *main_obj)
{
    char *startup_path;
    ObjFile *startup_obj;
    ObjFile *linked;
    List objs = EMPTY_LIST;

    if (!main_obj || !source_path) return main_obj;

    startup_path = find_startup_path(source_path);
    if (!startup_path) return main_obj;

    startup_obj = compile_startup_file(startup_path);
    free(startup_path);
    if (!startup_obj) return main_obj;

    list_push(&objs, startup_obj);
    list_push(&objs, main_obj);
    linked = obj_link(&objs);

    while (!list_empty(&objs)) list_shift(&objs);
    obj_free(startup_obj);

    return linked ? linked : main_obj;
}


#ifdef MINITEST_IMPLEMENTATION
#include "../minitest.h"

static ObjFile *compile_one(const char *path) {
    parser_reset();
    if (!pp_preprocess_to_stdin(path)) {
        fprintf(stderr, "preprocess failed: %s\n", path);
        return NULL;
    }
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
    List *paths = make_list();
    List *o = make_list();
    char *startup_path = NULL;
    while (fgets(f, sizeof f, stdin)) {
        *strchr(f, '\n') = 0;
        if (!*f) break;
        list_push(paths, strdup(f));
    }

    if (!list_empty(paths)) {
        startup_path = find_startup_path(list_get(paths, 0));
        if (startup_path) {
            ObjFile *startup_obj = compile_startup_file(startup_path);
            if (startup_obj) list_push(o, startup_obj);
            free(startup_path);
        }
    }

    for (Iter it = list_iter(paths); !iter_end(it);) {
        char *path = iter_next(&it);
        if (!path) continue;
        list_push(o, compile_one(path));
    }

    ObjFile *out = obj_link(o);
    c51_write_asm(stdout, out);
    c51_write_hex(stdout, out);
    list_free(paths);
}

#endif
