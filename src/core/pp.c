/*
 * 预处理器 - C语言预处理实现
 * 支持: #include, #define, #undef, #ifdef, #ifndef, #else, #endif
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include "cc.h"

#define PP_LINE_SIZE 4096
#define PP_BUF_SIZE 65536

/* 宏定义类型 */
typedef enum {
    MACRO_OBJ,      /* 对象式宏 */
    MACRO_FUNC      /* 函数式宏 */
} MacroType;

/* 宏定义结构 */
typedef struct Macro {
    char *name;
    MacroType type;
    char *body;
    List *params;   /* 函数式宏的参数列表 */
} Macro;

/* 输入文件结构 */
typedef struct InputFile {
    FILE *fp;
    char *filename;
    int line;
    char *buf;
    int buf_len;
    struct InputFile *next;
} InputFile;

/* 条件编译状态 */
typedef struct CondState {
    bool active;        /* 当前条件块是否生效 */
    bool taken;         /* 是否有分支已被执行 */
    struct CondState *next;
} CondState;

/* 预处理器上下文 */
typedef struct PPContext {
    Dict *macros;           /* 宏定义表 */
    List *include_paths;    /* 包含路径 */
    InputFile *input;       /* 当前输入文件栈 */
    CondState *cond_stack;  /* 条件编译栈 */
    char *output;           /* 输出缓冲区 */
    int out_pos;
    int out_cap;
    char *line;             /* 当前行缓冲区 */
    char *last_line;        /* 上次返回的行（用于释放） */
} PPContext;

static PPContext *g_pp_ctx = NULL;

/* 前向声明 */
static bool is_pp_macro(PPContext *ctx, const char *name);
static Macro *get_pp_macro(PPContext *ctx, const char *name);
static bool handle_ifdef(PPContext *ctx, const char *args, bool is_ifndef);
static bool handle_else(PPContext *ctx, const char *args);
static bool handle_endif(PPContext *ctx, const char *args);
static char *expand_macro_simple(PPContext *ctx, const char *line);
static bool should_skip(PPContext *ctx);

/* 创建宏定义 - name 会被 dict entry 引用，Macro 内部不单独存储 name */
static Macro *macro_create(const char *name, MacroType type, const char *body)
{
    Macro *m = malloc(sizeof(Macro));
    m->name = (char *)name;  /* 不复制，直接使用传入的指针 */
    m->type = type;
    m->body = strdup(body);
    m->params = NULL;  /* 由调用者设置（如果是函数式宏） */
    return m;
}

/* 销毁宏定义 */
static void macro_free(Macro *m)
{
    if (!m) return;
    /* m->name 由调用者/外部管理 */
    free(m->body);
    if (m->params) {
        /* list_free 释放 nodes 和 elems，然后手动释放 List 结构 */
        list_free(m->params);
        free(m->params);
    }
    free(m);
}

/* 初始化预处理器 */
PPContext *pp_init(void)
{
    PPContext *ctx = calloc(1, sizeof(PPContext));
    ctx->macros = make_dict(NULL);
    ctx->include_paths = make_list();
    ctx->out_cap = PP_BUF_SIZE;
    ctx->output = malloc(ctx->out_cap);
    ctx->line = malloc(PP_LINE_SIZE);
    ctx->last_line = NULL;
    
    /* 添加默认包含路径 */
    list_push(ctx->include_paths, strdup("."));
    list_push(ctx->include_paths, strdup("/usr/include"));
    
    return ctx;
}

/* 销毁预处理器 */
void pp_free(PPContext *ctx)
{
    if (!ctx) return;
    
    /* 释放宏定义 - 手动遍历 list，因为需要特殊处理 Macro 和 DictEntry */
    ListNode *node, *tmp;
    list_for_each_safe(node, tmp, ctx->macros->list) {
        DictEntry *e = (DictEntry *)node->elem;
        Macro *m = e->val;
        /* e->key 和 m->name 是同一个指针，只释放一次 */
        free(e->key);  /* 这也释放了 m->name */
        m->name = NULL;
        macro_free(m);
        free(e);
        free(node);  /* 释放 list node */
    }
    free(ctx->macros->list);  /* 释放 list 结构本身 */
    free(ctx->macros);
    
    /* 释放包含路径 - 手动遍历释放每个元素和 node */
    list_for_each_safe(node, tmp, ctx->include_paths) {
        free(node->elem);
        free(node);
    }
    free(ctx->include_paths);
    
    /* 关闭所有输入文件 */
    while (ctx->input) {
        InputFile *f = ctx->input;
        ctx->input = f->next;
        if (f->fp) fclose(f->fp);
        free(f->filename);
        free(f->buf);
        free(f);
    }
    
    /* 释放条件编译栈 */
    while (ctx->cond_stack) {
        CondState *s = ctx->cond_stack;
        ctx->cond_stack = s->next;
        free(s);
    }
    
    free(ctx->output);
    free(ctx->line);
    free(ctx->last_line);
    free(ctx);
}

/* 跳过空白字符 */
static const char *skip_space(const char *p)
{
    while (*p && isspace((unsigned char)*p)) p++;
    return p;
}

/* 获取标识符 */
static char *pp_get_ident(const char *p, int *len)
{
    const char *start = p;
    if (!isalpha((unsigned char)*p) && *p != '_') return NULL;
    p++;
    while (isalnum((unsigned char)*p) || *p == '_') p++;
    *len = p - start;
    if (*len == 0) return NULL;
    char *s = malloc(*len + 1);
    strncpy(s, start, *len);
    s[*len] = '\0';
    return s;
}

/* 检查是否为宏 */
static bool is_pp_macro(PPContext *ctx, const char *name)
{
    return dict_get(ctx->macros, (char *)name) != NULL;
}

/* 获取宏定义 */
static Macro *get_pp_macro(PPContext *ctx, const char *name)
{
    return dict_get(ctx->macros, (char *)name);
}

/* 定义宏 */
void pp_define(PPContext *ctx, const char *name, const char *body)
{
    char *name_copy = strdup(name);
    Macro *m = macro_create(name_copy, MACRO_OBJ, body);
    dict_put(ctx->macros, name_copy, m);
}

/* 定义函数式宏 */
void pp_define_func(PPContext *ctx, const char *name, List *params, const char *body)
{
    char *name_copy = strdup(name);
    Macro *m = macro_create(name_copy, MACRO_FUNC, body);
    m->params = params;
    dict_put(ctx->macros, name_copy, m);
}

/* 取消宏定义 - dict_remove 会释放 key，然后我们再释放 Macro */
void pp_undef(PPContext *ctx, const char *name)
{
    Macro *m = dict_get(ctx->macros, (char *)name);
    if (m) {
        /* 先保存 name 指针，因为 dict_remove 会释放它 */
        char *saved_name = m->name;
        dict_remove(ctx->macros, (char *)name);
        /* 现在释放 Macro，但不释放 name（已经被 dict_remove 释放了） */
        m->name = NULL;  /* 避免 macro_free 尝试释放 */
        macro_free(m);
    }
}

/* 检查是否应该跳过当前行 */
static bool should_skip(PPContext *ctx)
{
    for (CondState *s = ctx->cond_stack; s; s = s->next) {
        if (!s->active) return true;
    }
    return false;
}

/* 进入条件块 */
static void cond_push(PPContext *ctx, bool active)
{
    CondState *s = malloc(sizeof(CondState));
    s->active = active;
    s->taken = active;
    s->next = ctx->cond_stack;
    ctx->cond_stack = s;
}

/* 退出条件块 */
static void cond_pop(PPContext *ctx)
{
    CondState *s = ctx->cond_stack;
    if (!s) return;
    ctx->cond_stack = s->next;
    free(s);
}

/* 切换到#else分支 */
static void cond_else(PPContext *ctx)
{
    CondState *s = ctx->cond_stack;
    if (!s) return;
    s->active = !s->taken;
    s->taken = true;
}

/* 打开文件 */
static FILE *open_include_file(PPContext *ctx, const char *filename, char **fullpath)
{
    FILE *fp = NULL;
    
    /* 首先尝试作为绝对路径或相对路径打开 */
    fp = fopen(filename, "r");
    if (fp) {
        *fullpath = strdup(filename);
        return fp;
    }
    
    /* 在包含路径中搜索 */
    for (Iter i = list_iter(ctx->include_paths); !iter_end(i);) {
        char *path = iter_next(&i);
        char buf[1024];
        snprintf(buf, sizeof(buf), "%s/%s", path, filename);
        fp = fopen(buf, "r");
        if (fp) {
            *fullpath = strdup(buf);
            return fp;
        }
    }
    
    return NULL;
}

/* 推入新文件 */
bool pp_push_file(PPContext *ctx, const char *filename)
{
    char *fullpath = NULL;
    FILE *fp = open_include_file(ctx, filename, &fullpath);
    if (!fp) {
        return false;
    }
    
    InputFile *f = malloc(sizeof(InputFile));
    f->fp = fp;
    f->filename = fullpath;
    f->line = 0;
    f->buf = malloc(PP_LINE_SIZE);
    f->buf_len = 0;
    f->next = ctx->input;
    ctx->input = f;
    
    return true;
}

/* 弹出当前文件 */
void pp_pop_file(PPContext *ctx)
{
    if (!ctx->input) return;
    InputFile *f = ctx->input;
    ctx->input = f->next;
    if (f->fp) fclose(f->fp);
    free(f->filename);
    free(f->buf);
    free(f);
}

/* 从当前文件读取一行 */
static char *read_line_from_file(InputFile *f)
{
    if (!f || !f->fp) return NULL;
    if (fgets(f->buf, PP_LINE_SIZE, f->fp)) {
        f->line++;
        /* 去掉换行符 */
        int len = strlen(f->buf);
        if (len > 0 && f->buf[len - 1] == '\n') {
            f->buf[len - 1] = '\0';
        }
        return f->buf;
    }
    return NULL;
}

/* 展开宏 - 简单替换，返回新分配的字符串（调用者需释放） */
static char *expand_macro_simple(PPContext *ctx, const char *line)
{
    String result = make_string();
    const char *p = line;
    
    while (*p) {
        if (isalpha((unsigned char)*p) || *p == '_') {
            int len;
            char *ident = pp_get_ident(p, &len);
            if (ident) {
                Macro *m = get_pp_macro(ctx, ident);
                if (m && m->type == MACRO_OBJ) {
                    /* 替换为宏体 */
                    string_appendf(&result, "%s", m->body);
                } else {
                    string_appendf(&result, "%s", ident);
                }
                free(ident);
                p += len;
                continue;
            }
        }
        string_append(&result, *p);
        p++;
    }
    
    return strdup(get_cstring(result));
}

/* 获取目录部分（不含末尾的/）*/
static void get_dirname(const char *path, char *dir, size_t dir_size)
{
    const char *last_slash = strrchr(path, '/');
    if (!last_slash) {
        /* 没有/，说明是当前目录 */
        strncpy(dir, ".", dir_size);
        dir[dir_size - 1] = '\0';
        return;
    }
    
    size_t len = last_slash - path;
    if (len >= dir_size) len = dir_size - 1;
    strncpy(dir, path, len);
    dir[len] = '\0';
}

/* 打开文件，支持额外的搜索目录 */
static FILE *open_include_file_with_dir(PPContext *ctx, const char *filename,
                                        const char *extra_dir, char **fullpath)
{
    FILE *fp = NULL;
    char buf[1024];
    
    /* 首先尝试作为绝对路径或相对路径打开 */
    fp = fopen(filename, "r");
    if (fp) {
        *fullpath = strdup(filename);
        return fp;
    }
    
    /* 尝试额外目录（如果提供） */
    if (extra_dir && extra_dir[0]) {
        snprintf(buf, sizeof(buf), "%s/%s", extra_dir, filename);
        fp = fopen(buf, "r");
        if (fp) {
            *fullpath = strdup(buf);
            return fp;
        }
    }
    
    /* 在包含路径中搜索 */
    for (Iter i = list_iter(ctx->include_paths); !iter_end(i);) {
        char *path = iter_next(&i);
        snprintf(buf, sizeof(buf), "%s/%s", path, filename);
        fp = fopen(buf, "r");
        if (fp) {
            *fullpath = strdup(buf);
            return fp;
        }
    }
    
    return NULL;
}

/* 处理#include */
static bool handle_include(PPContext *ctx, const char *args)
{
    const char *p = skip_space(args);
    char filename[512];
    char current_dir[512] = "";
    
    /* 获取当前文件所在目录 */
    if (ctx->input && ctx->input->filename) {
        get_dirname(ctx->input->filename, current_dir, sizeof(current_dir));
    }
    
    if (*p == '"') {
        /* "filename" - 先在当前文件所在目录查找，再到包含路径 */
        p++;
        int i = 0;
        while (*p && *p != '"' && i < sizeof(filename) - 1) {
            filename[i++] = *p++;
        }
        filename[i] = '\0';
        
        /* 使用带额外目录的打开函数 */
        char *fullpath = NULL;
        FILE *fp = open_include_file_with_dir(ctx, filename, current_dir, &fullpath);
        if (!fp) {
            error("Cannot open include file: %s", filename);
            return false;
        }
        
        InputFile *f = malloc(sizeof(InputFile));
        f->fp = fp;
        f->filename = fullpath;
        f->line = 0;
        f->buf = malloc(PP_LINE_SIZE);
        f->buf_len = 0;
        f->next = ctx->input;
        ctx->input = f;
        
    } else if (*p == '<') {
        /* <filename> - 在系统目录查找 */
        p++;
        int i = 0;
        while (*p && *p != '>' && i < sizeof(filename) - 1) {
            filename[i++] = *p++;
        }
        filename[i] = '\0';
        
        if (!pp_push_file(ctx, filename)) {
            error("Cannot open include file: <%s>", filename);
            return false;
        }
    } else {
        error("Invalid #include syntax");
        return false;
    }
    
    return true;
}

/* 处理#define */
static bool handle_define(PPContext *ctx, const char *args)
{
    const char *p = skip_space(args);
    int len;
    char *name = pp_get_ident(p, &len);
    if (!name) {
        error("Expected identifier in #define");
        return false;
    }
    p += len;
    
    /* 检查是否为函数式宏 */
    if (*p == '(') {
        /* 函数式宏 */
        List *params = make_list();
        p++;
        while (1) {
            p = skip_space(p);
            if (*p == ')') {
                p++;
                break;
            }
            char *param = pp_get_ident(p, &len);
            if (!param) {
                error("Expected parameter name");
                return false;
            }
            list_push(params, param);
            p += len;
            p = skip_space(p);
            if (*p == ',') {
                p++;
            } else if (*p != ')') {
                error("Expected ',' or ')'");
                return false;
            }
        }
        const char *body = skip_space(p);
        pp_define_func(ctx, name, params, body);
    } else {
        /* 对象式宏 */
        const char *body = skip_space(p);
        pp_define(ctx, name, body);
    }
    
    free(name);
    return true;
}

/* 处理#undef */
static bool handle_undef(PPContext *ctx, const char *args)
{
    const char *p = skip_space(args);
    int len;
    char *name = pp_get_ident(p, &len);
    if (!name) {
        error("Expected identifier in #undef");
        return false;
    }
    pp_undef(ctx, name);
    free(name);
    return true;
}

/* 处理#ifdef */
static bool handle_ifdef(PPContext *ctx, const char *args, bool is_ifndef)
{
    const char *p = skip_space(args);
    int len;
    char *name = pp_get_ident(p, &len);
    if (!name) {
        error("Expected identifier in #ifdef/#ifndef");
        return false;
    }
    bool defined = is_pp_macro(ctx, name);
    bool active = is_ifndef ? !defined : defined;
    cond_push(ctx, active && !should_skip(ctx));
    free(name);
    return true;
}

/* 处理#else */
static bool handle_else(PPContext *ctx, const char *args)
{
    cond_else(ctx);
    return true;
}

/* 处理#endif */
static bool handle_endif(PPContext *ctx, const char *args)
{
    cond_pop(ctx);
    return true;
}

/* 处理预处理指令 */
static bool handle_directive(PPContext *ctx, const char *line)
{
    const char *p = skip_space(line);
    if (*p != '#') return false;
    p++;
    p = skip_space(p);
    
    int len;
    char *directive = pp_get_ident(p, &len);
    if (!directive) return false;
    p += len;
    const char *args = skip_space(p);
    
    if (strcmp(directive, "include") == 0) {
        if (!should_skip(ctx)) {
            handle_include(ctx, args);
        }
    } else if (strcmp(directive, "define") == 0) {
        if (!should_skip(ctx)) {
            handle_define(ctx, args);
        }
    } else if (strcmp(directive, "undef") == 0) {
        if (!should_skip(ctx)) {
            handle_undef(ctx, args);
        }
    } else if (strcmp(directive, "ifdef") == 0) {
        handle_ifdef(ctx, args, false);
    } else if (strcmp(directive, "ifndef") == 0) {
        handle_ifdef(ctx, args, true);
    } else if (strcmp(directive, "else") == 0) {
        handle_else(ctx, args);
    } else if (strcmp(directive, "endif") == 0) {
        handle_endif(ctx, args);
    } else {
        /* 未知的预处理指令，忽略 */
    }
    
    free(directive);
    return true;
}

/* 读取并预处理一行 */
char *pp_read_line(PPContext *ctx)
{
    /* 释放上次返回的行 */
    if (ctx->last_line) {
        free(ctx->last_line);
        ctx->last_line = NULL;
    }
    
    while (ctx->input) {
        char *line = read_line_from_file(ctx->input);
        if (!line) {
            /* 当前文件结束，弹出 */
            pp_pop_file(ctx);
            continue;
        }
        
        /* 处理预处理指令 */
        const char *p = skip_space(line);
        if (*p == '#') {
            handle_directive(ctx, line);
            /* 预处理指令不输出，返回空行 */
            ctx->last_line = strdup("");
            return ctx->last_line;
        }
        
        /* 如果在跳过状态下，返回空行 */
        if (should_skip(ctx)) {
            ctx->last_line = strdup("");
            return ctx->last_line;
        }
        
        /* 展开宏 */
        ctx->last_line = expand_macro_simple(ctx, line);
        return ctx->last_line;
    }
    
    return NULL;  /* 所有文件处理完毕 */
}

/* 从文件进行预处理，输出到stdout */
bool pp_preprocess_file(PPContext *ctx, const char *filename)
{
    if (!pp_push_file(ctx, filename)) {
        fprintf(stderr, "Cannot open file: %s\n", filename);
        return false;
    }
    
    char *line;
    while ((line = pp_read_line(ctx)) != NULL) {
        if (line[0] != '\0') {
            printf("%s\n", line);
        }
    }
    /* 最后一行由 pp_free 统一释放 */
    
    return true;
}

/* 获取当前文件名 */
const char *pp_current_file(PPContext *ctx)
{
    if (ctx->input) return ctx->input->filename;
    return NULL;
}

/* 获取当前行号 */
int pp_current_line(PPContext *ctx)
{
    if (ctx->input) return ctx->input->line;
    return 0;
}

/* 全局预处理器接口 */
static PPContext *g_pp = NULL;

void pp_global_init(void)
{
    g_pp = pp_init();
}

void pp_global_free(void)
{
    if (g_pp) {
        pp_free(g_pp);
        g_pp = NULL;
    }
}

bool pp_global_push_file(const char *filename)
{
    if (!g_pp) pp_global_init();
    return pp_push_file(g_pp, filename);
}

char *pp_global_read_line(void)
{
    if (!g_pp) return NULL;
    return pp_read_line(g_pp);
}

const char *pp_global_current_file(void)
{
    if (!g_pp) return NULL;
    return pp_current_file(g_pp);
}

int pp_global_current_line(void)
{
    if (!g_pp) return 0;
    return pp_current_line(g_pp);
}

/* 高级接口：预处理文件并重定向到stdin */
bool pp_preprocess_to_stdin(const char *filename)
{
    char tmpfile[] = "/tmp/mazucc_pp_XXXXXX";
    int fd = mkstemp(tmpfile);
    if (fd < 0) return false;
    
    FILE *tmp = fdopen(fd, "w");
    if (!tmp) { close(fd); return false; }
    
    pp_global_init();
    if (!pp_global_push_file(filename)) {
        fclose(tmp);
        pp_global_free();
        unlink(tmpfile);
        return false;
    }
    
    char *line;
    while ((line = pp_global_read_line()) != NULL)
        fprintf(tmp, "%s\n", line);
    
    fclose(tmp);
    pp_global_free();
    
    bool ok = freopen(tmpfile, "r", stdin) != NULL;
    unlink(tmpfile);
    return ok;
}

#ifdef MINITEST_IMPLEMENTATION
#include "minitest.h"

TEST(test, pp) {
    char infile[256];
    printf("file path: ");
    if (!fgets(infile, sizeof infile, stdin) || !pp_preprocess_to_stdin(strtok(infile, "\n")))
        puts("preprocess fail"), exit(1);

    set_current_filename(infile);
        
    List *toplevels = read_toplevels();
    for (Iter i = list_iter(toplevels); !iter_end(i);) {
        Ast *v = iter_next(&i);
        printf("%s\n", ast_to_string(v));
    }
    list_free(cstrings);
    list_free(ctypes);
}

#endif /* MINITEST_IMPLEMENTATION */
