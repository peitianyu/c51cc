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
    bool in_block_comment;  /* 是否处于跨行块注释中 */
} PPContext;

static PPContext *g_pp_ctx = NULL;

/* 前向声明 */
static bool is_pp_macro(PPContext *ctx, const char *name);
static Macro *get_pp_macro(PPContext *ctx, const char *name);
void pp_undef(PPContext *ctx, const char *name);
static bool handle_ifdef(PPContext *ctx, const char *args, bool is_ifndef);
static bool handle_if(PPContext *ctx, const char *args);
static bool handle_elif(PPContext *ctx, const char *args);
static bool handle_else(PPContext *ctx, const char *args);
static bool handle_endif(PPContext *ctx, const char *args);
static char *expand_macro_simple(PPContext *ctx, const char *line);
static bool should_skip(PPContext *ctx);

static bool pp_remove_macro_entry(PPContext *ctx, const char *name, Macro **out_macro);

/* helpers (defined later) */
static inline bool is_ident_start(char c);
static inline bool is_ident_char(char c);
static inline char *string_steal(String *s);
static bool list_contains_cstr(List *list, const char *s);

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
    return get_pp_macro(ctx, name) != NULL;
}

/* 获取宏定义 */
static Macro *get_pp_macro(PPContext *ctx, const char *name)
{
    if (!ctx || !ctx->macros || !ctx->macros->list) return NULL;
    Macro *found = NULL;
    for (Iter i = list_iter(ctx->macros->list); !iter_end(i);) {
        DictEntry *e = iter_next(&i);
        if (e && e->key && strcmp(e->key, name) == 0) {
            found = (Macro *)e->val;
        }
    }
    return found;
}

/* 定义宏 */
void pp_define(PPContext *ctx, const char *name, const char *body)
{
    /* 最新定义覆盖旧定义 */
    pp_undef(ctx, name);
    char *name_copy = strdup(name);
    Macro *m = macro_create(name_copy, MACRO_OBJ, body);
    dict_put(ctx->macros, name_copy, m);
}

/* 定义函数式宏 */
void pp_define_func(PPContext *ctx, const char *name, List *params, const char *body)
{
    /* 最新定义覆盖旧定义 */
    pp_undef(ctx, name);
    char *name_copy = strdup(name);
    Macro *m = macro_create(name_copy, MACRO_FUNC, body);
    m->params = params;
    dict_put(ctx->macros, name_copy, m);
}

/* 从宏表中移除最后一次定义（最新的） */
static bool pp_remove_macro_entry(PPContext *ctx, const char *name, Macro **out_macro)
{
    if (out_macro) *out_macro = NULL;
    if (!ctx || !ctx->macros || !ctx->macros->list) return false;

    ListNode *node = ctx->macros->list->tail;
    while (node) {
        DictEntry *entry = (DictEntry *)node->elem;
        if (entry && entry->key && strcmp(entry->key, name) == 0) {
            ListNode *prev = node->prev;
            ListNode *next = node->next;
            if (prev) prev->next = next;
            else ctx->macros->list->head = next;
            if (next) next->prev = prev;
            else ctx->macros->list->tail = prev;

            ctx->macros->list->len--;

            if (out_macro) *out_macro = (Macro *)entry->val;
            /* entry->key 归 Macro->name 所有权同源，只释放一次 */
            free(entry->key);
            free(entry);
            free(node);
            return true;
        }
        node = node->prev;
    }
    return false;
}

/* 取消宏定义 - 删除最新定义，并释放 Macro */
void pp_undef(PPContext *ctx, const char *name)
{
    Macro *m = NULL;
    if (pp_remove_macro_entry(ctx, name, &m) && m) {
        m->name = NULL;
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

/* 检查父级条件块是否正在跳过（不包含栈顶自身） */
static bool should_skip_parent(PPContext *ctx)
{
    if (!ctx || !ctx->cond_stack) return false;
    for (CondState *s = ctx->cond_stack->next; s; s = s->next) {
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

/* ===== #if/#elif 常量表达式求值 ===== */
typedef enum {
    PP_TOK_END,
    PP_TOK_NUM,
    PP_TOK_IDENT,
    PP_TOK_OP,
} PPExprTokType;

typedef struct {
    PPExprTokType type;
    long num;
    char ident[128];
    char op[3];
} PPExprTok;

typedef struct {
    const char *p;
    PPExprTok cur;
    PPContext *ctx;
} PPExprLexer;

static void pp_expr_next(PPExprLexer *lx)
{
    const char *p = lx->p;
    while (*p && isspace((unsigned char)*p)) p++;

    lx->cur.type = PP_TOK_END;
    lx->cur.num = 0;
    lx->cur.ident[0] = '\0';
    lx->cur.op[0] = '\0';

    if (!*p) {
        lx->p = p;
        lx->cur.type = PP_TOK_END;
        return;
    }

    if (isdigit((unsigned char)*p)) {
        char *endp = NULL;
        long v = strtol(p, &endp, 0);
        lx->cur.type = PP_TOK_NUM;
        lx->cur.num = v;
        lx->p = endp;
        return;
    }

    if (is_ident_start(*p)) {
        int i = 0;
        while (*p && is_ident_char(*p) && i < (int)sizeof(lx->cur.ident) - 1) {
            lx->cur.ident[i++] = *p++;
        }
        lx->cur.ident[i] = '\0';
        lx->cur.type = PP_TOK_IDENT;
        lx->p = p;
        return;
    }

    /* 多字符运算符 */
    if ((p[0] == '|' && p[1] == '|') || (p[0] == '&' && p[1] == '&') ||
        (p[0] == '<' && p[1] == '<') || (p[0] == '>' && p[1] == '>') ||
        (p[0] == '<' && p[1] == '=') || (p[0] == '>' && p[1] == '=') ||
        (p[0] == '=' && p[1] == '=') || (p[0] == '!' && p[1] == '=')) {
        lx->cur.type = PP_TOK_OP;
        lx->cur.op[0] = p[0];
        lx->cur.op[1] = p[1];
        lx->cur.op[2] = '\0';
        lx->p = p + 2;
        return;
    }

    /* 单字符运算符/括号 */
    lx->cur.type = PP_TOK_OP;
    lx->cur.op[0] = *p;
    lx->cur.op[1] = '\0';
    lx->p = p + 1;
}

static bool pp_tok_is_op(PPExprLexer *lx, const char *op)
{
    return lx->cur.type == PP_TOK_OP && strcmp(lx->cur.op, op) == 0;
}

static long pp_parse_expr(PPExprLexer *lx);

static long pp_parse_primary(PPExprLexer *lx)
{
    if (lx->cur.type == PP_TOK_NUM) {
        long v = lx->cur.num;
        pp_expr_next(lx);
        return v;
    }

    if (lx->cur.type == PP_TOK_IDENT && strcmp(lx->cur.ident, "defined") == 0) {
        /* defined X / defined(X) */
        pp_expr_next(lx);
        bool paren = false;
        if (pp_tok_is_op(lx, "(")) {
            paren = true;
            pp_expr_next(lx);
        }
        if (lx->cur.type != PP_TOK_IDENT) {
            error("Expected identifier after defined");
        }
        bool v = is_pp_macro(lx->ctx, lx->cur.ident);
        pp_expr_next(lx);
        if (paren) {
            if (!pp_tok_is_op(lx, ")")) error("Expected ')' after defined(...)");
            pp_expr_next(lx);
        }
        return v ? 1 : 0;
    }

    if (lx->cur.type == PP_TOK_IDENT) {
        /* 未定义标识符按 0 处理（宏在预展开阶段会被替换掉） */
        pp_expr_next(lx);
        return 0;
    }

    if (pp_tok_is_op(lx, "(")) {
        pp_expr_next(lx);
        long v = pp_parse_expr(lx);
        if (!pp_tok_is_op(lx, ")")) error("Expected ')' in #if expression");
        pp_expr_next(lx);
        return v;
    }

    error("Unexpected token in #if expression");
    return 0;
}

static long pp_parse_unary(PPExprLexer *lx)
{
    if (pp_tok_is_op(lx, "+")) { pp_expr_next(lx); return +pp_parse_unary(lx); }
    if (pp_tok_is_op(lx, "-")) { pp_expr_next(lx); return -pp_parse_unary(lx); }
    if (pp_tok_is_op(lx, "!")) { pp_expr_next(lx); return !pp_parse_unary(lx); }
    if (pp_tok_is_op(lx, "~")) { pp_expr_next(lx); return ~pp_parse_unary(lx); }
    return pp_parse_primary(lx);
}

static long pp_parse_mul(PPExprLexer *lx)
{
    long v = pp_parse_unary(lx);
    while (pp_tok_is_op(lx, "*") || pp_tok_is_op(lx, "/") || pp_tok_is_op(lx, "%")) {
        char op0 = lx->cur.op[0];
        pp_expr_next(lx);
        long r = pp_parse_unary(lx);
        if (op0 == '*') v = v * r;
        else if (op0 == '/') {
            if (r == 0) error("Division by zero in #if expression");
            v = v / r;
        } else {
            if (r == 0) error("Modulo by zero in #if expression");
            v = v % r;
        }
    }
    return v;
}

static long pp_parse_add(PPExprLexer *lx)
{
    long v = pp_parse_mul(lx);
    while (pp_tok_is_op(lx, "+") || pp_tok_is_op(lx, "-")) {
        char op0 = lx->cur.op[0];
        pp_expr_next(lx);
        long r = pp_parse_mul(lx);
        v = (op0 == '+') ? (v + r) : (v - r);
    }
    return v;
}

static long pp_parse_shift(PPExprLexer *lx)
{
    long v = pp_parse_add(lx);
    while (pp_tok_is_op(lx, "<<") || pp_tok_is_op(lx, ">>")) {
        bool is_shl = (lx->cur.op[0] == '<');
        pp_expr_next(lx);
        long r = pp_parse_add(lx);
        v = is_shl ? (v << r) : (v >> r);
    }
    return v;
}

static long pp_parse_rel(PPExprLexer *lx)
{
    long v = pp_parse_shift(lx);
    while (pp_tok_is_op(lx, "<") || pp_tok_is_op(lx, ">") || pp_tok_is_op(lx, "<=") || pp_tok_is_op(lx, ">=")) {
        char op1 = lx->cur.op[0];
        bool eq = (lx->cur.op[1] == '=');
        pp_expr_next(lx);
        long r = pp_parse_shift(lx);
        if (op1 == '<') v = eq ? (v <= r) : (v < r);
        else v = eq ? (v >= r) : (v > r);
        v = v ? 1 : 0;
    }
    return v;
}

static long pp_parse_eq(PPExprLexer *lx)
{
    long v = pp_parse_rel(lx);
    while (pp_tok_is_op(lx, "==") || pp_tok_is_op(lx, "!=")) {
        bool neq = (lx->cur.op[0] == '!');
        pp_expr_next(lx);
        long r = pp_parse_rel(lx);
        v = neq ? (v != r) : (v == r);
        v = v ? 1 : 0;
    }
    return v;
}

static long pp_parse_bitand(PPExprLexer *lx)
{
    long v = pp_parse_eq(lx);
    while (pp_tok_is_op(lx, "&")) {
        pp_expr_next(lx);
        long r = pp_parse_eq(lx);
        v = v & r;
    }
    return v;
}

static long pp_parse_bitxor(PPExprLexer *lx)
{
    long v = pp_parse_bitand(lx);
    while (pp_tok_is_op(lx, "^")) {
        pp_expr_next(lx);
        long r = pp_parse_bitand(lx);
        v = v ^ r;
    }
    return v;
}

static long pp_parse_bitor(PPExprLexer *lx)
{
    long v = pp_parse_bitxor(lx);
    while (pp_tok_is_op(lx, "|")) {
        pp_expr_next(lx);
        long r = pp_parse_bitxor(lx);
        v = v | r;
    }
    return v;
}

static long pp_parse_logand(PPExprLexer *lx)
{
    long v = pp_parse_bitor(lx);
    while (pp_tok_is_op(lx, "&&")) {
        pp_expr_next(lx);
        long r = pp_parse_bitor(lx);
        v = (v && r) ? 1 : 0;
    }
    return v;
}

static long pp_parse_logor(PPExprLexer *lx)
{
    long v = pp_parse_logand(lx);
    while (pp_tok_is_op(lx, "||")) {
        pp_expr_next(lx);
        long r = pp_parse_logand(lx);
        v = (v || r) ? 1 : 0;
    }
    return v;
}

static long pp_parse_expr(PPExprLexer *lx)
{
    return pp_parse_logor(lx);
}

static char *pp_expand_macros_for_if(PPContext *ctx, const char *args, List *expanding, int depth)
{
    if (!args) return strdup("");
    if (depth > 32) return strdup(args);

    String out = make_string();
    const char *p = args;
    bool expecting_defined_operand = false;

    while (*p) {
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p) break;

        if (is_ident_start(*p)) {
            int len = 0;
            char *ident = pp_get_ident(p, &len);
            if (!ident) break;

            if (strcmp(ident, "defined") == 0) {
                string_appendf(&out, "defined ");
                expecting_defined_operand = true;
                free(ident);
                p += len;
                continue;
            }

            if (expecting_defined_operand) {
                string_appendf(&out, "%s ", ident);
                expecting_defined_operand = false;
                free(ident);
                p += len;
                continue;
            }

            if (list_contains_cstr(expanding, ident)) {
                string_appendf(&out, "%s ", ident);
                free(ident);
                p += len;
                continue;
            }

            Macro *m = get_pp_macro(ctx, ident);
            if (m && m->type == MACRO_OBJ) {
                List *next_expanding = make_list();
                for (Iter it = list_iter(expanding); !iter_end(it);) {
                    char *v = iter_next(&it);
                    list_push(next_expanding, strdup(v));
                }
                list_push(next_expanding, strdup(ident));

                const char *body = m->body ? m->body : "";
                const char *b = skip_space(body);
                if (!*b) {
                    string_appendf(&out, "0 ");
                } else {
                    char *expanded_body = pp_expand_macros_for_if(ctx, body, next_expanding, depth + 1);
                    string_appendf(&out, "( %s ) ", expanded_body);
                    free(expanded_body);
                }

                list_free(next_expanding);
                free(next_expanding);
            } else {
                string_appendf(&out, "%s ", ident);
            }

            free(ident);
            p += len;
            continue;
        }

        /* 操作符/括号 */
        if (p[0] == '(') {
            string_appendf(&out, "( ");
            if (expecting_defined_operand) {
                /* defined( ... ) 仍在等待 ident */
            }
            p++;
            continue;
        }
        if (p[0] == ')') {
            string_appendf(&out, ") ");
            p++;
            continue;
        }

        /* 多字符运算符优先 */
        if ((p[0] == '|' && p[1] == '|') || (p[0] == '&' && p[1] == '&') ||
            (p[0] == '<' && p[1] == '<') || (p[0] == '>' && p[1] == '>') ||
            (p[0] == '<' && p[1] == '=') || (p[0] == '>' && p[1] == '=') ||
            (p[0] == '=' && p[1] == '=') || (p[0] == '!' && p[1] == '=')) {
            string_appendf(&out, "%c%c ", p[0], p[1]);
            p += 2;
            continue;
        }

        if (isdigit((unsigned char)*p)) {
            char *endp = NULL;
            long v = strtol(p, &endp, 0);
            string_appendf(&out, "%ld ", v);
            p = endp;
            continue;
        }

        /* 单字符 */
        string_appendf(&out, "%c ", *p);
        p++;
    }

    return string_steal(&out);
}

static long pp_eval_if_expr(PPContext *ctx, const char *args)
{
    List *expanding = make_list();
    char *expanded = pp_expand_macros_for_if(ctx, args, expanding, 0);
    list_free(expanding);
    free(expanding);

    PPExprLexer lx = {.p = expanded, .ctx = ctx};
    pp_expr_next(&lx);
    long v = pp_parse_expr(&lx);
    if (lx.cur.type != PP_TOK_END) {
        /* 允许尾随空白，但不允许额外 token */
        error("Trailing tokens in #if expression: '%s'", expanded);
    }
    free(expanded);
    return v;
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

/* 从当前文件读取一行（物理行），返回 f->buf（不含换行符） */
static char *read_physical_line(InputFile *f)
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

/* 读取逻辑行：处理反斜杠续行（\\\n），返回 ctx->line */
static char *read_logical_line(PPContext *ctx, InputFile *f)
{
    if (!ctx || !f) return NULL;

    char *line = read_physical_line(f);
    if (!line) return NULL;

    /* 拷贝到 ctx->line，便于拼接 */
    ctx->line[0] = '\0';
    size_t cap = PP_LINE_SIZE;
    size_t used = 0;

    while (1) {
        size_t n = strlen(line);
        if (used + n + 1 > cap) {
            error("PP line too long (>%d)", PP_LINE_SIZE);
            return NULL;
        }
        memcpy(ctx->line + used, line, n);
        used += n;
        ctx->line[used] = '\0';

        /* 反斜杠续行：去掉末尾 \\ 并继续读取下一物理行 */
        if (used > 0 && ctx->line[used - 1] == '\\') {
            ctx->line[--used] = '\0';
            line = read_physical_line(f);
            if (!line) break;
            continue;
        }
        break;
    }

    return ctx->line;
}

static inline bool is_ident_start(char c)
{
    return isalpha((unsigned char)c) || c == '_';
}

static inline bool is_ident_char(char c)
{
    return isalnum((unsigned char)c) || c == '_';
}

static inline char *string_steal(String *s)
{
    char *r = s->body;
    s->body = NULL;
    s->nalloc = s->len = 0;
    return r;
}

static bool list_contains_cstr(List *list, const char *s)
{
    if (!list) return false;
    for (Iter i = list_iter(list); !iter_end(i);) {
        char *v = iter_next(&i);
        if (v && strcmp(v, s) == 0) return true;
    }
    return false;
}

static char *trim_copy_range(const char *start, const char *end)
{
    while (start < end && isspace((unsigned char)*start)) start++;
    while (end > start && isspace((unsigned char)*(end - 1))) end--;
    size_t n = (size_t)(end - start);
    char *r = malloc(n + 1);
    memcpy(r, start, n);
    r[n] = '\0';
    return r;
}

static bool parse_macro_call_args(const char *p, const char **out_after, List **out_args)
{
    /* p 指向 '(' */
    if (*p != '(') return false;
    p++;

    List *args = make_list();
    const char *arg_start = p;
    int depth = 0;
    bool in_str = false, in_chr = false;

    while (*p) {
        char c = *p;

        if (in_str) {
            if (c == '\\' && p[1]) { p += 2; continue; }
            if (c == '"') in_str = false;
            p++;
            continue;
        }
        if (in_chr) {
            if (c == '\\' && p[1]) { p += 2; continue; }
            if (c == '\'') in_chr = false;
            p++;
            continue;
        }

        if (c == '"') { in_str = true; p++; continue; }
        if (c == '\'') { in_chr = true; p++; continue; }

        if (c == '(') { depth++; p++; continue; }
        if (c == ')') {
            if (depth == 0) {
                char *arg = trim_copy_range(arg_start, p);
                /* 允许空参数列表：() => args.len==0 */
                if (!(args->len == 0 && arg[0] == '\0')) {
                    list_push(args, arg);
                } else {
                    free(arg);
                }
                p++;
                if (out_after) *out_after = p;
                if (out_args) *out_args = args;
                return true;
            }
            depth--;
            p++;
            continue;
        }
        if (c == ',' && depth == 0) {
            char *arg = trim_copy_range(arg_start, p);
            list_push(args, arg);
            p++;
            arg_start = p;
            continue;
        }

        p++;
    }

    /* 未闭合 */
    list_free(args);
    free(args);
    return false;
}

static char *expand_macro_text(PPContext *ctx, const char *text, List *expanding, int depth);

static char *substitute_macro_params(PPContext *ctx, Macro *m, List *args, List *expanding, int depth)
{
    if (!m->params) {
        return strdup(m->body);
    }
    String out = make_string();
    const char *p = m->body;

    while (*p) {
        if (*p == '"') {
            string_append(&out, *p++);
            while (*p) {
                char c = *p;
                string_append(&out, c);
                p++;
                if (c == '\\' && *p) {
                    string_append(&out, *p++);
                    continue;
                }
                if (c == '"') break;
            }
            continue;
        }
        if (*p == '\'') {
            string_append(&out, *p++);
            while (*p) {
                char c = *p;
                string_append(&out, c);
                p++;
                if (c == '\\' && *p) {
                    string_append(&out, *p++);
                    continue;
                }
                if (c == '\'') break;
            }
            continue;
        }

        if (is_ident_start(*p)) {
            int len = 0;
            char *ident = pp_get_ident(p, &len);
            if (ident) {
                bool replaced = false;
                int idx = 0;
                for (Iter it = list_iter(m->params); !iter_end(it); idx++) {
                    char *param = iter_next(&it);
                    if (param && strcmp(param, ident) == 0) {
                        char *arg = (char *)list_get(args, idx);
                        if (!arg) arg = "";
                        char *expanded_arg = expand_macro_text(ctx, arg, expanding, depth + 1);
                        string_appendf(&out, "%s", expanded_arg);
                        free(expanded_arg);
                        replaced = true;
                        break;
                    }
                }
                if (!replaced) {
                    string_appendf(&out, "%s", ident);
                }
                free(ident);
                p += len;
                continue;
            }
        }

        string_append(&out, *p);
        p++;
    }

    return string_steal(&out);
}

static char *expand_macro_text(PPContext *ctx, const char *text, List *expanding, int depth)
{
    if (!text) return strdup("");
    if (depth > 64) return strdup(text);

    String out = make_string();
    const char *p = text;

    while (*p) {
        /* 处理跨行块注释状态 */
        if (ctx->in_block_comment) {
            const char *q = strstr(p, "*/");
            if (!q) {
                string_appendf(&out, "%s", p);
                return string_steal(&out);
            }
            /* 输出到 */
            while (p < q + 2) string_append(&out, *p++);
            ctx->in_block_comment = false;
            continue;
        }

        /* 行注释 */
        if (p[0] == '/' && p[1] == '/') {
            string_appendf(&out, "%s", p);
            return string_steal(&out);
        }
        /* 块注释开始 */
        if (p[0] == '/' && p[1] == '*') {
            const char *q = strstr(p + 2, "*/");
            if (!q) {
                ctx->in_block_comment = true;
                string_appendf(&out, "%s", p);
                return string_steal(&out);
            }
            while (p < q + 2) string_append(&out, *p++);
            continue;
        }

        /* 字符串/字符常量：不展开 */
        if (*p == '"') {
            string_append(&out, *p++);
            while (*p) {
                char c = *p;
                string_append(&out, c);
                p++;
                if (c == '\\' && *p) {
                    string_append(&out, *p++);
                    continue;
                }
                if (c == '"') break;
            }
            continue;
        }
        if (*p == '\'') {
            string_append(&out, *p++);
            while (*p) {
                char c = *p;
                string_append(&out, c);
                p++;
                if (c == '\\' && *p) {
                    string_append(&out, *p++);
                    continue;
                }
                if (c == '\'') break;
            }
            continue;
        }

        if (is_ident_start(*p)) {
            int len = 0;
            char *ident = pp_get_ident(p, &len);
            if (ident) {
                Macro *m = get_pp_macro(ctx, ident);
                if (!m || list_contains_cstr(expanding, ident)) {
                    string_appendf(&out, "%s", ident);
                    free(ident);
                    p += len;
                    continue;
                }

                /* 对象式宏 */
                if (m->type == MACRO_OBJ) {
                    List *next_expanding = make_list();
                    /* 复制 expanding */
                    for (Iter it = list_iter(expanding); !iter_end(it);) {
                        char *v = iter_next(&it);
                        list_push(next_expanding, strdup(v));
                    }
                    list_push(next_expanding, strdup(ident));

                    char *expanded_body = expand_macro_text(ctx, m->body, next_expanding, depth + 1);
                    string_appendf(&out, "%s", expanded_body);

                    free(expanded_body);
                    list_free(next_expanding);
                    free(next_expanding);
                    free(ident);
                    p += len;
                    continue;
                }

                /* 函数式宏：识别调用 */
                const char *q = p + len;
                while (*q && isspace((unsigned char)*q)) q++;
                if (*q != '(') {
                    string_appendf(&out, "%s", ident);
                    free(ident);
                    p += len;
                    continue;
                }

                const char *after = NULL;
                List *args = NULL;
                if (!parse_macro_call_args(q, &after, &args)) {
                    /* 解析失败：当作普通标识符输出 */
                    string_appendf(&out, "%s", ident);
                    free(ident);
                    p += len;
                    continue;
                }

                int nparams = m->params ? m->params->len : 0;
                int nargs = args ? args->len : 0;
                if (nparams != nargs) {
                    /* 参数不匹配：保守起见不展开 */
                    /* 输出原始调用文本 */
                    while (p < after) string_append(&out, *p++);
                    free(ident);
                    list_free(args);
                    free(args);
                    continue;
                }

                List *next_expanding = make_list();
                for (Iter it = list_iter(expanding); !iter_end(it);) {
                    char *v = iter_next(&it);
                    list_push(next_expanding, strdup(v));
                }
                list_push(next_expanding, strdup(ident));

                char *substed = substitute_macro_params(ctx, m, args, next_expanding, depth + 1);
                char *expanded = expand_macro_text(ctx, substed, next_expanding, depth + 1);
                string_appendf(&out, "%s", expanded);

                free(expanded);
                free(substed);
                list_free(next_expanding);
                free(next_expanding);
                list_free(args);
                free(args);
                free(ident);

                p = after;
                continue;
            }
        }

        string_append(&out, *p);
        p++;
    }

    return string_steal(&out);
}

/* 展开宏 - 支持对象式/函数式、递归展开、并跳过字符串/注释区域 */
static char *expand_macro_simple(PPContext *ctx, const char *line)
{
    List *expanding = make_list();
    char *r = expand_macro_text(ctx, line, expanding, 0);
    list_free(expanding);
    free(expanding);
    return r;
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

/* 处理#if */
static bool handle_if(PPContext *ctx, const char *args)
{
    long v = pp_eval_if_expr(ctx, args);
    bool active = (v != 0);
    cond_push(ctx, active && !should_skip(ctx));
    return true;
}

/* 处理#elif */
static bool handle_elif(PPContext *ctx, const char *args)
{
    if (!ctx->cond_stack) {
        error("#elif without #if");
        return false;
    }

    CondState *s = ctx->cond_stack;
    if (s->taken) {
        s->active = false;
        return true;
    }

    if (should_skip_parent(ctx)) {
        s->active = false;
        return true;
    }

    long v = pp_eval_if_expr(ctx, args);
    s->active = (v != 0);
    if (s->active) s->taken = true;
    return true;
}

/* 处理#else */
static bool handle_else(PPContext *ctx, const char *args)
{
    if (!ctx->cond_stack) {
        error("#else without #if");
        return false;
    }
    cond_else(ctx);
    /* 外层不激活时，#else 也不能激活 */
    if (should_skip_parent(ctx)) {
        ctx->cond_stack->active = false;
    }
    return true;
}

/* 处理#endif */
static bool handle_endif(PPContext *ctx, const char *args)
{
    if (!ctx->cond_stack) {
        error("#endif without #if");
        return false;
    }
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
    } else if (strcmp(directive, "if") == 0) {
        handle_if(ctx, args);
    } else if (strcmp(directive, "elif") == 0) {
        handle_elif(ctx, args);
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
        char *line = read_logical_line(ctx, ctx->input);
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
    char *last_file = NULL;
    int last_line = 0;
    while ((line = pp_global_read_line()) != NULL) {
        const char *cur_file = pp_global_current_file();
        int cur_line = pp_global_current_line();
        if (cur_file) {
            if (!last_file || strcmp(cur_file, last_file) != 0 || cur_line != last_line + 1) {
                fprintf(tmp, "#line %d \"%s\"\n", cur_line, cur_file);
            }
            if (last_file) free(last_file);
            last_file = strdup(cur_file);
            last_line = cur_line;
        }
        fprintf(tmp, "%s\n", line);
    }
    if (last_file) free(last_file);
    
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
