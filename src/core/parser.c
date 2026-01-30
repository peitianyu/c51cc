#include <ctype.h>
#include <limits.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cc.h"

#define MAX_ARGS 6
#define MAX_OP_PRIO 16
#define MAX_ALIGN 16

List *ctypes = &EMPTY_LIST;
List *strings = &EMPTY_LIST;
List *flonums = &EMPTY_LIST;

static Dict *globalenv = &EMPTY_DICT;
static Dict *localenv = NULL;
static Dict *struct_defs = &EMPTY_DICT;
static Dict *union_defs = &EMPTY_DICT;
static Dict *enum_defs = &EMPTY_DICT;
static Dict *functionenv = &EMPTY_DICT;
static Dict *typedefenv = &EMPTY_DICT;
static List *localvars = NULL;
static List *labels = NULL;
static bool in_cond_expr = false;  // 标记是否在?:的then分支中

static Ctype *ctype_void = &(Ctype){0, CTYPE_VOID, 0, NULL};
static Ctype *ctype_int = &(Ctype){0, CTYPE_INT, 2, NULL};
static Ctype *ctype_long = &(Ctype){0, CTYPE_LONG, 4, NULL};
static Ctype *ctype_bool = &(Ctype){0, CTYPE_BOOL, 1, NULL};
static Ctype *ctype_char = &(Ctype){0, CTYPE_CHAR, 1, NULL};
static Ctype *ctype_float = &(Ctype){0, CTYPE_FLOAT, 4, NULL};
static Ctype *ctype_double = &(Ctype){0, CTYPE_DOUBLE, 8, NULL};

static int labelseq = 0;

static Ast *read_expr(void);
static Ast *read_expr_int(int prec);
static Ctype *make_ptr_type(Ctype *ctype);
static Ctype *make_array_type(Ctype *ctype, int size);
static Ast *read_compound_stmt(void);
static Ast *read_decl_or_stmt(void);
static Ctype *result_type(char op, Ctype *a, Ctype *b);
static Ctype *convert_array(Ctype *ctype);
static Ast *read_stmt(void);
static Ctype *read_decl_int(Token *name);
static int read_decl_ctype_attr(Token tok, int *attr_out);
static bool have_redefine_var(char* var_name);
static bool get_enum_val(char* key, int* val);
static bool is_type_keyword(const Token tok);
static Ctype *read_decl_spec(void);
static Ctype *read_array_dimensions(Ctype *basetype);
static void read_func_ptr_params(void);

static Ast *ast_uop(int type, Ctype *ctype, Ast *operand)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = type;
    r->ctype = ctype;
    r->operand = operand;
    return r;
}

static Ast *ast_binop(int type, Ast *left, Ast *right)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = type;
    r->ctype = result_type(type, left->ctype, right->ctype);
    if (type != '=' && convert_array(left->ctype)->type != CTYPE_PTR &&
        convert_array(right->ctype)->type == CTYPE_PTR) {
        r->left = right;
        r->right = left;
    } else {
        r->left = left;
        r->right = right;
    }
    return r;
}

static Ast *ast_inttype(Ctype *ctype, long val)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_LITERAL;
    r->ctype = ctype;
    r->ival = val;
    return r;
}

static Ast *ast_double(double val)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_LITERAL;
    r->ctype = ctype_double;
    r->fval = val;
    list_push(flonums, r);
    return r;
}

char *make_label(void)
{
    String s = make_string();
    string_appendf(&s, ".L%d", labelseq++);
    return get_cstring(s);
}

static Ast *ast_lvar(Ctype *ctype, char *name)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_LVAR;
    r->ctype = ctype;
    r->varname = name;
    dict_put(localenv, name, r);
    if (localvars)
        list_push(localvars, r);
    return r;
}

static Ast *ast_gvar(Ctype *ctype, char *name, bool filelocal)
{
    // FIXME: 应该考虑多文件的, 暂时不考虑
    if(have_redefine_var(name))
        error("Redefine global var: %s", name);
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_GVAR;
    r->ctype = ctype;
    r->varname = name;
    r->glabel = filelocal ? make_label() : name;
    dict_put(globalenv, name, r);
    return r;
}

static Ast *ast_string(char *str)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_STRING;
    r->ctype = make_array_type(ctype_char, strlen(str) + 1);
    r->sval = str;
    r->slabel = make_label();
    return r;
}

static Ast *ast_funcall(Ctype *ctype, char *fname, List *args)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_FUNCALL;
    r->ctype = ctype;
    r->fname = fname;
    r->args = args;
    return r;
}

static Ast *ast_typedef(Ctype *ctype, char *typename) 
{
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_TYPE_DEF;
    r->ctype = ctype;
    r->typename = typename;
    return r;
}

static Ast *ast_func_def(Ctype *rettype,
                     char *fname,
                     List *params,
                     Ast *body,
                     List *localvars, 
                     List *labels)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_FUNC_DEF;
    r->ctype = rettype;
    r->fname = fname;
    r->params = params;
    r->localvars = localvars;
    r->labels = labels;
    r->body = body;
    return r;
}

static Ast *ast_func_decl(Ctype *rettype, char *fname, List *params)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_FUNC_DECL;
    r->ctype = rettype;
    r->fname = fname;
    r->params = params;
    r->localvars = NULL;
    r->labels = NULL;
    r->body = NULL;
    return r;
}
                    

static bool valid_init_var(Ast *var, Ast *init)
{
    // NOTE: 未初始化, 则不判断
    if(!init) return true;
    if(init->type == AST_CAST) init = init->cast_expr;
    switch(var->ctype->type) {
        case CTYPE_BOOL ... CTYPE_DOUBLE:
            return (init->ctype->type <= CTYPE_DOUBLE);
        case CTYPE_ARRAY:
            // 支持数组初始化列表和字符串初始化字符数组
            if (init->type == AST_ARRAY_INIT) return true;
            if (init->type == AST_STRING && var->ctype->ptr->type == CTYPE_CHAR) return true;
            return false;
        case CTYPE_PTR:
            // 函数指针可以接受：其他指针、数组、函数声明、整数字面量、取地址表达式
            if (init->ctype->type == CTYPE_PTR || init->ctype->type == CTYPE_ARRAY ||
                init->ctype->type == CTYPE_INT || init->type == AST_ADDR)
                return true;
            // 函数名赋值给函数指针（AST_FUNC_DECL/AST_FUNC_DEF的ctype是返回类型）
            if (init->type == AST_FUNC_DECL || init->type == AST_FUNC_DEF)
                return true;
            return false;
        case CTYPE_STRUCT:
            return (init->ctype->type == CTYPE_STRUCT);
        case CTYPE_ENUM:
              return (init->ctype->type == CTYPE_ENUM || init->ctype->type == CTYPE_INT);
        default: return false;
    }
}

static Ast *ast_decl(Ast *var, Ast *init)
{
    if(!valid_init_var(var, init))
        error("Invalid var init: (%s) -> (%s)\n", ctype_to_string(init->ctype), ctype_to_string(var->ctype));

    Ast *r = malloc(sizeof(Ast));
    r->type = AST_DECL;
    r->ctype = NULL;
    r->declvar = var;
    r->declinit = init;
    return r;
}

static Ast *ast_array_init(List *arrayinit)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_ARRAY_INIT;
    r->ctype = NULL;
    r->arrayinit = arrayinit;
    return r;
}

static Ast *ast_struct_init(Ctype *ctype, List *structinit) {
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_STRUCT_INIT;
    r->ctype = ctype;
    r->structinit = structinit;
    return r;
}

static Ast *ast_if(Ast *cond, Ast *then, Ast *els)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_IF;
    r->ctype = NULL;
    r->cond = cond;
    r->then = then;
    r->els = els;
    return r;
}

static Ast *ast_ternary(Ctype *ctype, Ast *cond, Ast *then, Ast *els)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_TERNARY;
    r->ctype = ctype;
    r->cond = cond;
    r->then = then;
    r->els = els;
    return r;
}

static Ast *ast_switch(Ast *ctrl, List *cases, Ast *def_stmt)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_SWITCH;
    r->ctype = NULL;
    r->ctrl = ctrl;
    r->cases = cases;
    r->default_stmt = def_stmt;
    return r;
}

static SwitchCase *make_switch_case(long low, long high, Ast *stmt)
{
    SwitchCase *c = malloc(sizeof(SwitchCase));
    c->low  = low;
    c->high  = high;
    c->stmt = stmt;
    return c;
}

static Ast *ast_for(Ast *init, Ast *cond, Ast *step, Ast *body)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_FOR;
    r->ctype = NULL;
    r->forinit = init;
    r->forcond = cond;
    r->forstep = step;
    r->forbody = body;
    return r;
}

static Ast *ast_while(Ast *cond, Ast *body)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_WHILE;
    r->while_cond = cond;
    r->while_body = body;
    return r;
}

static Ast *ast_dowhile(Ast *cond, Ast *body)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_DO_WHILE;
    r->while_cond = cond;
    r->while_body = body;
    return r;
}

static Ast *ast_goto(char* label)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_GOTO;
    r->label = label;
    return r;
}

static Ast *ast_label(char* label)
{
    for (Iter i = list_iter(labels); !iter_end(i);) {
        char* v = iter_next(&i);
        if(!strcmp(v, label)) error("duplicate label: %s", label);
    }

    Ast *r = malloc(sizeof(Ast));
    r->type = AST_LABEL;
    r->label = strdup(label);
    list_push(labels, r->label);
    return r;
}

Ast *ast_break(void)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_BREAK;
    return r;
}

Ast *ast_continue(void)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_CONTINUE;
    return r;
}

static Ast *ast_return(Ast *retval)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_RETURN;
    r->ctype = NULL;
    r->retval = retval;
    return r;
}

static Ast *ast_compound_stmt(List *stmts)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_COMPOUND_STMT;
    r->ctype = NULL;
    r->stmts = stmts;
    return r;
}

static Ast *ast_struct_ref(Ctype *ctype, Ast *struc, char *name)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_STRUCT_REF;
    r->ctype = ctype;
    r->struc = struc;
    r->field = name;
    return r;
}

static Ast *ast_struct_def(Ctype *ctype) {
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_STRUCT_DEF;
    r->ctype = ctype;
    return r;
};

static Ast *ast_enum_def(Ctype *ctype) {
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_ENUM_DEF;
    r->ctype = ctype;
    return r;
};

static Ast *ast_cast(Ctype *target, Ast *expr)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_CAST;
    r->ctype = target;
    r->cast_expr = expr;
    return r;
}

static Ctype *make_ptr_type(Ctype *ctype)
{
    Ctype *r = malloc(sizeof(Ctype));
    r->type = CTYPE_PTR;
    r->ptr = ctype;
    r->size = 2; 
    r->attr = ctype->attr;
    r->bit_offset = 0;
    r->bit_size = 0;
    list_push(ctypes, r);
    return r;
}

static Ctype *clone_ctype_with_attr(Ctype *ctype, int attr)
{
    Ctype *r = malloc(sizeof(Ctype));
    memcpy(r, ctype, sizeof(Ctype));
    r->attr = attr;
    list_push(ctypes, r);
    return r;
}

static Ctype *make_array_type(Ctype *ctype, int len)
{
    Ctype *r = malloc(sizeof(Ctype));
    r->type = CTYPE_ARRAY;
    r->ptr = ctype;
    r->attr = ctype->attr;
    r->bit_offset = 0;
    r->bit_size = 0;
    r->size = (len < 0) ? -1 : ctype->size * len;
    r->len = len;
    list_push(ctypes, r);
    return r;
}

static Ctype *make_struct_field_type(Ctype *ctype, int offset, int bit_offset, int bit_size)
{
    Ctype *r = malloc(sizeof(Ctype));
    memcpy(r, ctype, sizeof(Ctype));
    r->offset = offset;
    r->bit_offset = bit_offset;
    r->bit_size = bit_size;
    list_push(ctypes, r);
    return r;
}

static Ctype *make_struct_type(Dict *fields, int size, bool is_union)
{
    Ctype *r = malloc(sizeof(Ctype));
    r->type = CTYPE_STRUCT;
    r->fields = fields;
    r->size = size;
    r->bit_offset = 0;
    r->bit_size = 0;
    r->is_union = is_union;
    list_push(ctypes, r);
    return r;
}

static Ctype *make_enum_type(Dict *fields)
{
    Ctype *r = malloc(sizeof(Ctype));
    r->type = CTYPE_ENUM;
    r->fields = fields;
    list_push(ctypes, r);
    return r;
}

bool is_inttype(Ctype *ctype)
{
    return ctype->type == CTYPE_BOOL || ctype->type == CTYPE_CHAR || ctype->type == CTYPE_INT ||
           ctype->type == CTYPE_LONG || ctype->type == CTYPE_ENUM;
}

bool is_flotype(Ctype *ctype)
{
    return ctype->type == CTYPE_FLOAT || ctype->type == CTYPE_DOUBLE;
}

static void ensure_lvalue(Ast *ast)
{
    switch (ast->type) {
    case AST_LVAR:
    case AST_GVAR:
    case AST_DEREF:
    case AST_STRUCT_REF:
        return;
    default:
        error("lvalue expected, but got %s", ast_to_string(ast));
    }
}

static void expect(char punct)
{
    Token tok = read_token();
    if (!is_punct(tok, punct))
        error("'%c' expected, but got %s", punct, token_to_string(tok));
}

static bool is_ident(const Token tok, char *s)
{
    return get_ttype(tok) == TTYPE_IDENT && !strcmp(get_ident(tok), s);
}

static bool is_right_assoc(const Token tok)
{
    return get_punct(tok) == '=';
}

static int eval_intexpr(Ast *ast)
{
    switch (ast->type) {
    case AST_LITERAL:
        if (is_inttype(ast->ctype)) return ast->ival;
        error("Integer expression expected, but got %s", ast_to_string(ast));
    case '+': return eval_intexpr(ast->left) + eval_intexpr(ast->right);
    case '-': return eval_intexpr(ast->left) - eval_intexpr(ast->right);
    case '*': return eval_intexpr(ast->left) * eval_intexpr(ast->right);
    case '/': return eval_intexpr(ast->left) / eval_intexpr(ast->right);
    case '%': return eval_intexpr(ast->left) % eval_intexpr(ast->right);
    case '^': return eval_intexpr(ast->left) % eval_intexpr(ast->right);
    case '|': return eval_intexpr(ast->left) | eval_intexpr(ast->right);
    case '&': return eval_intexpr(ast->left) & eval_intexpr(ast->right);
    case '>': return eval_intexpr(ast->left) > eval_intexpr(ast->right);
    case '<': return eval_intexpr(ast->left) < eval_intexpr(ast->right);
    case '!': return !eval_intexpr(ast->left);
    case '~': return ~eval_intexpr(ast->left);
    case PUNCT_LSHIFT: return eval_intexpr(ast->left) << eval_intexpr(ast->right);
    case PUNCT_RSHIFT: return eval_intexpr(ast->left) >> eval_intexpr(ast->right);
    case PUNCT_LOGAND: return eval_intexpr(ast->left) && eval_intexpr(ast->right);
    case PUNCT_LOGOR:  return eval_intexpr(ast->left) || eval_intexpr(ast->right);
    case PUNCT_EQ:     return eval_intexpr(ast->left) == eval_intexpr(ast->right);
    case PUNCT_GE:     return eval_intexpr(ast->left) >= eval_intexpr(ast->right);
    case PUNCT_LE:     return eval_intexpr(ast->left) <= eval_intexpr(ast->right);
    case PUNCT_NE:     return eval_intexpr(ast->left) != eval_intexpr(ast->right);
    default:
        error("Integer expression expected, but got %s", ast_to_string(ast));
        return 0; /* non-reachable */
    }
}

static float eval_floatexpr(Ast *ast) 
{
    switch (ast->type) {
    case AST_LITERAL:
        if (is_flotype(ast->ctype))
            return ast->fval;
        else if (is_inttype(ast->ctype))
            return ast->ival;
        error("Float expression expected, but got %s", ast_to_string(ast));
    case '+':
        return eval_floatexpr(ast->left) + eval_floatexpr(ast->right);
    case '-':
        return eval_floatexpr(ast->left) - eval_floatexpr(ast->right);
    case '*':
        return eval_floatexpr(ast->left) * eval_floatexpr(ast->right);
    case '/':
        return eval_floatexpr(ast->left) / eval_floatexpr(ast->right);
    default:
        error("Float expression expected, but got %s", ast_to_string(ast));
        return 0; /* non-reachable */
    }
}

static int priority(const Token tok)
{
    switch (get_punct(tok)) {
    case '[':
    case '.':
    case PUNCT_ARROW:
        return 1;
    case PUNCT_INC:
    case PUNCT_DEC:
        return 2;
    case '*':
    case '/':
    case '%':
        return 3;
    case '+':
    case '-':
        return 4;
    case PUNCT_LSHIFT:
    case PUNCT_RSHIFT:
        return 5;
    case '<':
    case '>':
        return 6;
    case '&':
        return 8;
    case '^':
        return 9;
    case '|':
        return 10;
    case PUNCT_EQ:
    case PUNCT_GE:
    case PUNCT_LE:
    case PUNCT_NE:
        return 7;
    case PUNCT_LOGAND:
        return 11;
    case PUNCT_LOGOR:
        return 12;
    case '?':
        return 13;
    case '=':
        return 14;
    default:
        return -1;
    }
}

static bool have_redefine_var(char* var_name) 
{
    if(dict_get(globalenv, var_name)) return true;
    if(dict_get(localenv, var_name)) return true;
    return false;
}

static bool have_redefine_func(char* func_name) 
{
    return dict_get(functionenv, func_name);
}

static Ast *read_func_args(char *fname, Ast *func_ptr)
{
    List *args = make_list();
    while (1) {
        Token tok = read_token();
        if (is_punct(tok, ')'))
            break;
        unget_token(tok);
        list_push(args, read_expr());
        tok = read_token();
        if (is_punct(tok, ')'))
            break;
        if (!is_punct(tok, ','))
            error("Unexpected token: '%s'", token_to_string(tok));
    }
    if (MAX_ARGS < list_len(args))
        error("Too many arguments: %s", fname);

    // 如果提供了函数指针，使用函数指针的类型
    if (func_ptr) {
        return ast_funcall(func_ptr->ctype->ptr, fname, args);
    }
    
    Ast *func = dict_get(functionenv, fname);
    if(!func) error("Undecl function: %s", fname);
    
    return ast_funcall(func->ctype, fname, args);
}

static Ast *read_ident_or_func(char *name)
{
    Token tok = read_token();
    if (is_punct(tok, '(')) {
        // 检查是否是函数指针变量调用
        Ast *v = dict_get(localenv, name);
        if (!v) v = dict_get(globalenv, name);
        if (v && v->ctype && v->ctype->type == CTYPE_PTR) {
            // 可能是函数指针调用，检查返回类型是否有效
            return read_func_args(name, v);
        }
        return read_func_args(name, NULL);
    }
    
    // 只有在不在?:的then分支中，且下一个token是:时，才认为是标签
    if (!in_cond_expr && is_punct(tok, ':'))
        return ast_label(name);

    unget_token(tok);

    Ast *v = dict_get(localenv, name);
    if (!v) {
        v = dict_get(globalenv, name);
        if(!v) {
            // 检查是否是函数名（用于函数指针初始化）
            Ast *func = dict_get(functionenv, name);
            if(func) {
                // 返回函数声明/定义的AST，其ctype是返回类型
                return func;
            }
            error("Undefined varaible: %s", name);
        }
    }
        
    return v;
}

static bool is_long_token(char *p)
{
    for (; *p; p++) {
        if (!isdigit(*p))
            return (*p == 'L' || *p == 'l') && p[1] == '\0';
    }
    return false;
}

static bool is_int_token(char *p)
{
    for (; *p; p++)
        if (!isdigit(*p))
            return false;
    return true;
}

static bool is_float_token(char *p)
{
    for (; *p; p++)
        if (!isdigit(*p))
            break;
    if (*p++ != '.')
        return false;
    for (; *p; p++)
        if (!isdigit(*p))
            return false;
    return true;
}

static Ast *read_prim(void)
{
    Token tok = read_token();
    switch (get_ttype(tok)) {
    case TTYPE_NULL:
        return NULL;
    case TTYPE_IDENT: {
        int enum_val = 0;
        if(get_enum_val(get_ident(tok), &enum_val)) return ast_inttype(ctype_int, enum_val);
        else                                        return read_ident_or_func(get_ident(tok));
    }
    case TTYPE_NUMBER: {
        char *number = get_number(tok);
        if (is_long_token(number))
            return ast_inttype(ctype_long, atol(number));
        if (is_int_token(number)) {
            long val = atol(number);
            if (val & ~(long) UINT_MAX)
                return ast_inttype(ctype_long, val);
            return ast_inttype(ctype_int, val);
        }
        if (is_float_token(number))
            return ast_double(atof(number));
        error("Malformed number: %s", token_to_string(tok));
    }
    case TTYPE_CHAR:
        return ast_inttype(ctype_char, get_char(tok));
    case TTYPE_STRING: {
        Ast *r = ast_string(get_strtok(tok));
        list_push(strings, r);
        return r;
    }
    case TTYPE_PUNCT:
        unget_token(tok);
        return NULL;
    default:
        error("internal error: unknown token type: %d", get_ttype(tok));
        return NULL; /* non-reachable */
    }
}

#define swap(a, b)         \
    {                      \
        typeof(a) tmp = b; \
        b = a;             \
        a = tmp;           \
    }


static Ctype *arith_bin_type[CTYPE_DOUBLE+1][CTYPE_DOUBLE+1];
static void init_arith_table(void)
{
    #define T(a,b,res) arith_bin_type[a][b] = arith_bin_type[b][a] = (res)
    T(CTYPE_BOOL,   CTYPE_BOOL,   ctype_bool);
    T(CTYPE_BOOL,   CTYPE_CHAR,   ctype_char);
    T(CTYPE_BOOL,   CTYPE_INT,    ctype_int);
    T(CTYPE_BOOL,   CTYPE_LONG,   ctype_long);
    T(CTYPE_BOOL,   CTYPE_FLOAT,  ctype_float);
    T(CTYPE_BOOL,   CTYPE_DOUBLE, ctype_double);

    T(CTYPE_CHAR,   CTYPE_CHAR,   ctype_char);
    T(CTYPE_CHAR,   CTYPE_INT,    ctype_int);
    T(CTYPE_CHAR,   CTYPE_LONG,   ctype_long);
    T(CTYPE_CHAR,   CTYPE_FLOAT,  ctype_float);
    T(CTYPE_CHAR,   CTYPE_DOUBLE, ctype_double);

    T(CTYPE_INT,    CTYPE_INT,    ctype_int);
    T(CTYPE_INT,    CTYPE_LONG,   ctype_long);
    T(CTYPE_INT,    CTYPE_FLOAT,  ctype_float);
    T(CTYPE_INT,    CTYPE_DOUBLE, ctype_double);

    T(CTYPE_LONG,   CTYPE_LONG,   ctype_long);
    T(CTYPE_LONG,   CTYPE_FLOAT,  ctype_float);
    T(CTYPE_LONG,   CTYPE_DOUBLE, ctype_double);

    T(CTYPE_FLOAT,  CTYPE_FLOAT,  ctype_float);
    T(CTYPE_FLOAT,  CTYPE_DOUBLE, ctype_double);

    T(CTYPE_DOUBLE, CTYPE_DOUBLE, ctype_double);
    #undef T
}

static Ctype *result_type_int(jmp_buf *jmp, char op, Ctype *a, Ctype *b)
{
    static int arith_table_inited = 0;
    if (!arith_table_inited) {
        init_arith_table();
        arith_table_inited = 1;
    }

    if (a->type == CTYPE_PTR || b->type == CTYPE_PTR) {
        if (op == '=') return a->type == CTYPE_PTR ? a : b;          // 赋值取左值指针
        if (op != '+' && op != '-') goto err;
        return a->type == CTYPE_PTR ? a : b;                         // +/- 结果取指针侧
    }
    if (a->type == CTYPE_ARRAY || b->type == CTYPE_ARRAY) goto err;

    int ai = (a->type==CTYPE_ENUM) ? CTYPE_INT : a->type;
    int bi = (b->type==CTYPE_ENUM) ? CTYPE_INT : b->type;
    if ((unsigned)ai >= CTYPE_DOUBLE+1 || (unsigned)bi >= CTYPE_DOUBLE+1) goto err;

    Ctype *t = arith_bin_type[ai][bi];

    if (!t) goto err;
    return t;

err:
    longjmp(*jmp, 1);
    return ctype_void;
}

static Ast *read_subscript_expr(Ast *ast)
{
    Ast *sub = read_expr();
    expect(']');
    Ast *t = ast_binop('+', ast, sub);
    return ast_uop(AST_DEREF, t->ctype->ptr, t);
}

static Ctype *convert_array(Ctype *ctype)
{
    if (ctype->type != CTYPE_ARRAY)
        return ctype;
    return make_ptr_type(ctype->ptr);
}

static Ctype *result_type(char op, Ctype *a, Ctype *b)
{
    // 特殊处理：函数指针赋值
    if (op == '=') {
        // 允许将函数名赋值给函数指针
        // 或者允许指针之间的赋值
        if (a->type == CTYPE_PTR && b->type == CTYPE_PTR)
            return a;
        // 允许 int 赋值给指针（地址值）
        if (a->type == CTYPE_PTR && b->type <= CTYPE_LONG)
            return a;
    }
    
    jmp_buf jmpbuf;
    if (setjmp(jmpbuf) == 0)
        return result_type_int(&jmpbuf, op, convert_array(a), convert_array(b));
    error("incompatible operands: %c: <%s> and <%s>", op, ctype_to_string(a),
          ctype_to_string(b));
    return NULL; /* non-reachable */
}

static Ast *read_unary_expr(void)
{
    Token tok = read_token();
    if (get_ttype(tok) != TTYPE_PUNCT && get_ttype(tok) != TTYPE_IDENT) {
        unget_token(tok);
        return read_prim();
    }

    if (is_punct(tok, '(') && is_type_keyword(peek_token())) {
        Ctype *target = read_decl_spec();
        expect(')');
        Ast *expr = read_unary_expr();
        return ast_cast(target, expr);
    }

    if (is_ident(tok, "sizeof")) {
        expect('(');
        Ast *e = read_expr();
        expect(')');
        return ast_inttype(ctype_int, e->ctype->size);
    }

    if (is_punct(tok, '(')) {
        Ast *r = read_expr();
        expect(')');
        return r;
    }
    if (is_punct(tok, '&')) {
        Ast *operand = read_unary_expr();
        ensure_lvalue(operand);
        return ast_uop(AST_ADDR, make_ptr_type(operand->ctype), operand);
    }
    if (is_punct(tok, '!')) {
        Ast *operand = read_unary_expr();
        return ast_uop('!', ctype_int, operand);
    }
    if (is_punct(tok, '~')) {
        Ast *operand = read_unary_expr();
        return ast_uop('~', ctype_int, operand);
    }
    if (is_punct(tok, '*')) {
        Ast *operand = read_unary_expr();
        Ctype *ctype = convert_array(operand->ctype);
        if (ctype->type != CTYPE_PTR)
            error("pointer type expected, but got %s", ast_to_string(operand));
        if (ctype->ptr == ctype_void)
            error("pointer to void can not be dereferenced, but got %s",
                  ast_to_string(operand));
        return ast_uop(AST_DEREF, operand->ctype->ptr, operand);
    }
    // 一元正号: +a 等同于 a
    if (is_punct(tok, '+')) {
        Ast *operand = read_unary_expr();
        return operand;
    }
    // 一元负号: -a 等同于 0 - a
    if (is_punct(tok, '-')) {
        Ast *operand = read_unary_expr();
        return ast_binop('-', ast_inttype(ctype_int, 0), operand);
    }
    // 前置自增: ++a
    if (is_punct(tok, PUNCT_INC)) {
        Ast *operand = read_unary_expr();
        ensure_lvalue(operand);
        return ast_uop(PUNCT_INC, operand->ctype, operand);
    }
    // 前置自减: --a
    if (is_punct(tok, PUNCT_DEC)) {
        Ast *operand = read_unary_expr();
        ensure_lvalue(operand);
        return ast_uop(PUNCT_DEC, operand->ctype, operand);
    }
    unget_token(tok);
    return read_prim();
}

static Ast *read_cond_expr(Ast *cond)
{
    // 三元运算符是右结合的
    // then 分支使用优先级14（高于?:的13），这样遇到:时会停止
    // 设置标志，防止read_ident_or_func将identifier:当作标签
    in_cond_expr = true;
    Ast *then = read_expr_int(14);
    in_cond_expr = false;
    expect(':');
    // else 分支使用优先级13（?:的优先级），支持右结合
    Ast *els = read_expr_int(13);
    // 三元运算符的类型是 then 和 else 分支的公共类型
    Ctype *ctype = result_type(':', then->ctype, els->ctype);
    return ast_ternary(ctype, cond, then, els);
}

static Ast *read_struct_field(Ast *struc)
{
    if (struc->ctype->type != CTYPE_STRUCT)
        error("struct expected, but got %s", ast_to_string(struc));
    Token name = read_token();
    if (get_ttype(name) != TTYPE_IDENT)
        error("field name expected, but got %s", token_to_string(name));
    char *ident = get_ident(name);
    Ctype *field = dict_get(struc->ctype->fields, ident);
    return ast_struct_ref(field, struc, ident);
}

static Ast *read_expr_int(int prec)
{
    Ast *ast = read_unary_expr();
    if (!ast)
        return NULL;
    while (1) {
        Token tok = read_token();
        if (get_ttype(tok) != TTYPE_PUNCT) {
            unget_token(tok);
            return ast;
        }
        int prec2 = priority(tok);
        if (prec2 < 0 || prec <= prec2) {
            unget_token(tok);
            return ast;
        }
        if (is_punct(tok, '?')) {
            ast = read_cond_expr(ast);
            continue;
        }
        if (is_punct(tok, '.')) {
            ast = read_struct_field(ast);
            continue;
        }
        if (is_punct(tok, PUNCT_ARROW)) {
            if (ast->ctype->type != CTYPE_PTR)
                error("pointer type expected, but got %s %s",
                      ctype_to_string(ast->ctype), ast_to_string(ast));
            ast = ast_uop(AST_DEREF, ast->ctype->ptr, ast);
            ast = read_struct_field(ast);
            continue;
        }
        if (is_punct(tok, '[')) {
            ast = read_subscript_expr(ast);
            continue;
        }
        // 支持 (*fp)(args) 形式的函数指针调用
        if (is_punct(tok, '(')) {
            // 检查左侧是否是解引用表达式（函数指针调用）
            if (ast->type == AST_DEREF && ast->operand &&
                ast->operand->ctype && ast->operand->ctype->type == CTYPE_PTR) {
                // (*fp)(args) 形式 - 获取函数指针变量名
                Ast *func_ptr = ast->operand;
                if (func_ptr->type == AST_LVAR || func_ptr->type == AST_GVAR) {
                    ast = read_func_args(func_ptr->varname, func_ptr);
                    continue;
                }
            }
            // 普通函数调用已在 read_ident_or_func 处理
            unget_token(tok);
            return ast;
        }
        // FIXME: this is BUG!! ++ should be in read_unary_expr() , I think.
        if (is_punct(tok, PUNCT_INC) || is_punct(tok, PUNCT_DEC)) {
            ensure_lvalue(ast);
            ast = ast_uop(get_punct(tok), ast->ctype, ast);
            continue;
        }
        if (is_punct(tok, '='))
            ensure_lvalue(ast);
        
        Ast *rest = read_expr_int(prec2 + (is_right_assoc(tok) ? 1 : 0));
        if (!rest)
            error("second operand missing");
        if (is_punct(tok, PUNCT_LSHIFT) || is_punct(tok, PUNCT_RSHIFT)) {
            if (!is_inttype(ast->ctype) || !is_inttype(rest->ctype))
                error("invalid operand to shift");
        }
        ast = ast_binop(get_punct(tok), ast, rest);
    }
}

static Ast *read_expr_float(int prec)
{
    return NULL;
} 

static Ast *read_expr()
{
    return read_expr_int(MAX_OP_PRIO);
}

static Ctype *get_ctype(const Token tok)
{
    if (get_ttype(tok) != TTYPE_IDENT) return NULL;

    char *ident = get_ident(tok);
    if (!strcmp(ident, "void"))     return ctype_void;
    if (!strcmp(ident, "int"))      return ctype_int;
    if (!strcmp(ident, "long"))     return ctype_long;
    if (!strcmp(ident, "bool"))     return ctype_bool;
    if (!strcmp(ident, "char"))     return ctype_char;
    if (!strcmp(ident, "float"))    return ctype_float;
    if (!strcmp(ident, "double"))   return ctype_double;
    return NULL;
}

static bool is_type_keyword(const Token tok)
{
    bool is_keyword = get_ctype(tok) || is_ident(tok, "struct") || is_ident(tok, "union") || is_ident(tok, "enum") || 
        is_ident(tok, "const") || is_ident(tok, "volatile") || is_ident(tok, "restrict") ||
        is_ident(tok, "static") || is_ident(tok, "extern") || is_ident(tok, "unsigned")|| 
        is_ident(tok, "register") || is_ident(tok, "typedef") || is_ident(tok, "inline") || 
        is_ident(tok, "noreturn") || is_ident(tok, "data") || is_ident(tok, "idata") || 
        is_ident(tok, "pdata") || is_ident(tok, "xdata") || is_ident(tok, "edata") || 
        is_ident(tok, "code");   

    if(is_keyword) 
        return true;            
    
    if(get_ttype(tok) != TTYPE_IDENT) 
        return false;
    
    return dict_get(typedefenv, get_ident(tok));
}


static int array_n_elts(Ctype *ctype)
{
    if (ctype->type != CTYPE_ARRAY) return -1;
    return ctype->len;          /* -1 表示“未知” */
}

static Ast *read_decl_array_init_recurse(Ctype *ctype)
{
    Token tok = read_token();

    if (ctype->ptr->type == CTYPE_CHAR && get_ttype(tok) == TTYPE_STRING)
        return ast_string(get_strtok(tok));

    if (!is_punct(tok, '{'))
        error("Expected '{' for array initializer of %s, got %s",
              ctype_to_string(ctype), token_to_string(tok));

    List *row_list = make_list();   
    int expect_rows = array_n_elts(ctype);
    int actual_rows = 0;

    while (1) {
        if (is_punct(peek_token(), '}'))  
            break;

        Ast *one_row;
        if (ctype->ptr->type == CTYPE_ARRAY)
            one_row = read_decl_array_init_recurse(ctype->ptr);
        else {
            Token t = read_token();
            unget_token(t);
            one_row = read_expr();
            result_type('=', one_row->ctype, ctype->ptr);
        }
        list_push(row_list, one_row);
        actual_rows++;

        if (is_punct(peek_token(), ',')) {
            read_token();
            continue;
        }
        break;
    }

    expect('}');

    if (expect_rows != -1 && actual_rows != expect_rows)
        error("Array row count mismatch: expect %d, got %d",
              expect_rows, actual_rows);

    return ast_array_init(row_list);
}

static List *init_empty_struct_init(Ctype *ctype) {
    List *initlist = make_list();
    for (Iter it = list_iter(ctype->fields->list); !iter_end(it);) {
        DictEntry *e = iter_next(&it);
        Ctype *type = dict_get(ctype->fields, e->key);
        switch(type->type) {
            case CTYPE_BOOL ... CTYPE_LONG:
                list_push(initlist, ast_inttype(type, 0));
                break;
            case CTYPE_FLOAT ... CTYPE_DOUBLE:
                list_push(initlist, ast_double(0.0));
                break;
            case CTYPE_ARRAY:
                list_push(initlist, ast_array_init(make_list()));
                break;
            case CTYPE_PTR:
                list_push(initlist, make_ptr_type(type));
                break;
            case CTYPE_STRUCT:
                list_push(initlist, ast_struct_init(ctype, make_list()));
                break;
            default:
                error("internal error: unknown field type %d", type->type);
        };
    }
    return initlist;
}

static int struct_field_index(Ctype *ctype, const char *name)
{
    int idx = 0;
    for (Iter it = list_iter(ctype->fields->list); !iter_end(it); idx++) {
        DictEntry *e = iter_next(&it);
        if (!strcmp(e->key, name))
            return idx;
    }
    return -1;
}

static Ast *read_decl_struct_init(Ctype *ctype)
{
    Token tok = read_token();
    if (!is_punct(tok, '{'))
        error("Expected an initializer struct for %s, but got %s",
              ctype_to_string(ctype), token_to_string(tok));
    List *initlist = init_empty_struct_init(ctype);
    Iter it = list_iter(initlist);
    int idx = 0;
    while (1) {
        Token tok = read_token();
        if (is_punct(tok, '}')) break;
        unget_token(tok);

        // 检查是否为指定初始化器 .field = value
        if(is_punct(tok, '.')) {
            read_token(); // 消费 '.'
            tok = read_token();
            if(get_ttype(tok) != TTYPE_IDENT)
                error("Expected identifier for struct: %s, but got: %s", ctype_to_string(ctype), token_to_string(tok));
            idx = struct_field_index(ctype, get_ident(tok));
            expect('=');
            // 获取该字段的类型，用于可能的嵌套初始化
            Iter field_it = list_iter(ctype->fields->list);
            Ctype *field_type = NULL;
            for (int i = 0; i <= idx && !iter_end(field_it); i++) {
                DictEntry *e = iter_next(&field_it);
                if (i == idx) field_type = dict_get(ctype->fields, e->key);
            }
            // 根据字段类型选择合适的初始化读取方式
            Ast *var;
            if (field_type && field_type->type == CTYPE_STRUCT) {
                var = read_decl_struct_init(field_type);
            } else if (field_type && field_type->type == CTYPE_ARRAY) {
                var = read_decl_array_init_recurse(field_type);
            } else {
                var = read_expr();
            }
            list_set(initlist, idx, var);
            tok = read_token();
        } else {
            // 顺序初始化
            if(iter_end(it))
                error("Expected value for struct: %s, out of range", ctype_to_string(ctype));
            // 获取当前字段的类型
            Iter field_it = list_iter(ctype->fields->list);
            Ctype *field_type = NULL;
            int current_idx = 0;
            for (; !iter_end(field_it) && current_idx <= idx; current_idx++) {
                DictEntry *e = iter_next(&field_it);
                if (current_idx == idx) field_type = dict_get(ctype->fields, e->key);
            }
            // 根据字段类型选择合适的初始化读取方式
            Ast *v;
            if (field_type && field_type->type == CTYPE_STRUCT) {
                v = read_decl_struct_init(field_type);
            } else if (field_type && field_type->type == CTYPE_ARRAY) {
                v = read_decl_array_init_recurse(field_type);
            } else {
                Token t = read_token();
                unget_token(t);
                v = read_expr();
            }
            list_set(initlist, idx, v);
            iter_next(&it);
            idx++;
            tok = read_token();
            if(iter_end(it) && !is_punct(tok, '}') && !is_punct(tok, ','))
                error("Expected value for struct: %s, out of range", ctype_to_string(ctype));
        }

        if (!is_punct(tok, ',')) unget_token(tok);
    }

    return ast_struct_init(ctype, initlist);
}

static char *read_struct_union_enum_tag(void)
{
    Token tok = read_token();
    if (get_ttype(tok) == TTYPE_IDENT)
        return get_ident(tok);
    unget_token(tok);
    return NULL;
}

static Dict *read_struct_union_fields(bool is_struct_type)
{
    Dict *r = make_dict(NULL);
    expect('{');
    int bit_offset = 0;
    while (1) {
        if (!is_type_keyword(peek_token()))
            break;
        
        // 读取类型说明符
        Ctype *ctype = read_decl_spec();
        Token name = read_token();
        
        // 检查是否是函数指针语法: type (*name)(params)
        if (is_punct(name, '(')) {
            Token next_tok = read_token();
            if (is_punct(next_tok, '*')) {
                // 函数指针: type (*name)(params)
                name = read_token();
                if (get_ttype(name) != TTYPE_IDENT)
                    error("Identifier expected in function pointer, but got %s", token_to_string(name));
                expect(')');
                expect('(');
                // 读取参数列表
                read_func_ptr_params();
                // 创建函数指针类型
                ctype = make_ptr_type(ctype);
            } else {
                unget_token(next_tok);
                error("Identifier expected, but got %s", token_to_string(name));
            }
        } else if (get_ttype(name) != TTYPE_IDENT) {
            error("Identifier expected, but got %s", token_to_string(name));
        }
        
        // 读取数组维度
        ctype = read_array_dimensions(ctype);
        
        int bit_size = 0;
        Token tok = peek_token();
        if(is_struct_type && is_punct(tok, ':')) {
            read_token();
            Ast* bit_ast = read_expr();
            if(!is_inttype(bit_ast->ctype))
                error("Bit field need int type, but got %s", ctype_to_string(bit_ast->ctype));
            bit_size = eval_intexpr(bit_ast);
        }

        dict_put(r, get_ident(name), make_struct_field_type(ctype, 0, bit_offset, bit_size));
        bit_offset += bit_size;
        expect(';');
    }
    expect('}');
    return r;
}

static Ctype *read_union_def(void)
{
    char *tag = read_struct_union_enum_tag();
    Ctype *ctype = dict_get(union_defs, tag);
    if (ctype)
        return ctype;
    Dict *fields = read_struct_union_fields(false);
    int maxsize = 0;
    for (Iter i = list_iter(dict_values(fields)); !iter_end(i);) {
        Ctype *fieldtype = iter_next(&i);
        maxsize = (maxsize < fieldtype->size) ? fieldtype->size : maxsize;
    }
    Ctype *r = make_struct_type(fields, maxsize, true);
    if (tag)
        dict_put(union_defs, tag, r);
    return r;
}

static Ctype *read_struct_def(void)
{
    char *tag = read_struct_union_enum_tag();
    Ctype *ctype = dict_get(struct_defs, tag);
    if (ctype)
        return ctype;
    Dict *fields = read_struct_union_fields(true);
    int offset = 0;
    Iter i = list_iter(dict_values(fields));
    Ctype *fieldtype;
    for (; !iter_end(i);) {
        fieldtype = iter_next(&i);
        int size = (fieldtype->size < MAX_ALIGN) ? fieldtype->size : MAX_ALIGN;
        if (offset % size != 0)
            offset += size - offset % size;
        fieldtype->offset = offset;
        offset += fieldtype->size;
    }
    if(fieldtype->bit_size) {
        offset = (fieldtype->bit_offset+fieldtype->bit_size)/8;
        if((fieldtype->bit_offset+fieldtype->bit_size)%8) offset++;
    }

    Ctype *r = make_struct_type(fields, offset, false);
    if (tag)
        dict_put(struct_defs, tag, r);
    return r;
}

static bool get_enum_val(char* key, int* val) {
    for (Iter i = list_iter(enum_defs->list); !iter_end(i);) {
        DictEntry *e = iter_next(&i);
        Ctype *type = e->val;
        int *v = dict_get(type->fields, key);
        if (v) {
            *val = *v;  
            return true;
        }
    }
    return false;
}

static Dict *read_enum_fields(void) 
{
    Dict *r = make_dict(NULL);
    expect('{');
    int cnt = 0;
    while (1) {
        Token name = read_token();
        if(is_punct(name, '}')) {
            unget_token(name);
            break;
        }

        if(get_ttype(name) != TTYPE_IDENT) 
            error("Enum need identify, but got %s", token_to_string(name));
        
        Token tok = read_token(); 
        if(is_punct(tok, '=')) {
            tok = read_token();
            char *number = get_number(tok);
            if (is_int_token(number))   cnt = atoi(number);
            else                        error("Enum need int type: %s", token_to_string(tok));
        }else {
            unget_token(tok);
        }

        int *enum_val = malloc(sizeof(int));
        *enum_val = cnt;
        dict_put(r, get_ident(name), enum_val);
        
        cnt++;
        tok = peek_token(); 
        if(is_punct(tok, '}')) break;

        expect(',');
    }
    expect('}');
    return r;
}

static Ctype *read_enum_def(void)
{
    char *tag = read_struct_union_enum_tag();
    Ctype *ctype = dict_get(enum_defs, tag);
    if (ctype) 
        return ctype;

    Dict *fields = read_enum_fields();
    Ctype *r = make_enum_type(fields);
    if (tag)
        dict_put(enum_defs, tag, r);
    return r;
}

static int read_decl_ctype_attr(Token tok, int *attr_out) {
    if(get_ttype(tok) != TTYPE_IDENT) return 0;

    union { CtypeAttr c_attr; int i_attr; }attr = {0};
    
    if(is_ident(tok, "const"))          { attr.c_attr.ctype_const = 1; }
    else if(is_ident(tok, "volatile"))  { attr.c_attr.ctype_volatile = 1; }
    else if (is_ident(tok, "restrict")) { attr.c_attr.ctype_restrict = 1; }
    else if (is_ident(tok, "static"))   { attr.c_attr.ctype_static = 1; }
    else if (is_ident(tok, "extern"))   { attr.c_attr.ctype_extern = 1; }
    else if (is_ident(tok, "unsigned")) { attr.c_attr.ctype_unsigned = 1; }
    else if (is_ident(tok, "register")) { attr.c_attr.ctype_register = 1; }
    else if (is_ident(tok, "typedef"))  { attr.c_attr.ctype_typedef = 1; }
    else if (is_ident(tok, "inline"))   { attr.c_attr.ctype_inline = 1; }
    else if (is_ident(tok, "noreturn")) { attr.c_attr.ctype_noreturn = 1; }

    /* mcs51单片机专用 */
    else if (is_ident(tok, "data"))     { attr.c_attr.ctype_data = 1; }
    else if (is_ident(tok, "idata"))    { attr.c_attr.ctype_data = 2; }
    else if (is_ident(tok, "pdata"))    { attr.c_attr.ctype_data = 3; }
    else if (is_ident(tok, "xdata"))    { attr.c_attr.ctype_data = 4; }
    else if (is_ident(tok, "edata"))    { attr.c_attr.ctype_data = 5; }
    else if (is_ident(tok, "code"))     { attr.c_attr.ctype_data = 6; }
    *attr_out |= attr.i_attr;
    return attr.i_attr;
}

static Ctype *read_decl_spec(void)
{
    Token tok = read_token();
    int attr = 0;
    while(read_decl_ctype_attr(tok, &attr)) tok = read_token();
       
    Ctype *ctype =
        is_ident(tok, "struct") ? read_struct_def() : 
        is_ident(tok, "union") ? read_union_def() : 
        is_ident(tok, "enum") ? read_enum_def() : get_ctype(tok);

    if (!ctype && get_ttype(tok) == TTYPE_IDENT && !get_attr(attr).ctype_typedef) 
        ctype = dict_get(typedefenv, get_ident(tok));

    if (!ctype) 
        error("Type expected, but got %s", token_to_string(tok));
        
    while (1) {
        tok = read_token();
        if (!is_punct(tok, '*')) {
            while(read_decl_ctype_attr(tok, &attr)) tok = read_token();
            unget_token(tok);
            return clone_ctype_with_attr(ctype, attr);
        }
        ctype = make_ptr_type(ctype);
    }
}

static Ast *read_decl_init_val(Ast *var, bool consume_semicolon)
{
    if (var->ctype->type == CTYPE_ARRAY) {
        Ast *init = read_decl_array_init_recurse(var->ctype);
        int len = (init->type == AST_STRING) ? strlen(init->sval) + 1
                                             : list_len(init->arrayinit);
        if (var->ctype->len == -1) {
            var->ctype->len = len;
            var->ctype->size = len * var->ctype->ptr->size;
        } else if (var->ctype->len != len) {
            error("Invalid array initializer: expected %d items but got %d",
                  var->ctype->len, len);
        }
        if (consume_semicolon) expect(';');
        return ast_decl(var, init);
    } else if(var->ctype->type == CTYPE_STRUCT) {
        Ast *init = read_decl_struct_init(var->ctype);
        if (consume_semicolon) expect(';');
        return ast_decl(var, init);
    } else if(var->ctype->type == CTYPE_PTR) {
        Ast *init = read_expr();
        if (consume_semicolon) expect(';');
        if(init->type == AST_ADDR) return ast_decl(var, init);
        
        // 允许数组名直接赋值给指针（数组退化为指向首元素的指针）
        if(init->ctype->type == CTYPE_ARRAY) {
            // 将数组类型转换为指针类型
            init->ctype = make_ptr_type(init->ctype->ptr);
            return ast_decl(var, init);
        }
        
        // 允许函数名赋值给函数指针
        if(init->type == AST_FUNC_DECL || init->type == AST_FUNC_DEF) {
            // 函数名作为指针，使用函数标签作为地址
            return ast_decl(var, init);
        }

        // FIXME: 注意这里直接填地址有危险, 不建议这么做, 程序可能会飞, 后期将这部分限制住????
        ast_inttype(ctype_int, eval_intexpr(init));
        return ast_decl(var, init);
    }

    Ast *init = read_expr();
    if (consume_semicolon) expect(';');

    if (var->type == AST_GVAR) {
        init = (is_inttype(var->ctype)) ? ast_inttype(ctype_int, eval_intexpr(init))
                                        : ast_double(eval_floatexpr(init));
    }

    if (init->type == AST_LITERAL && is_inttype(init->ctype) && is_inttype(var->ctype))
        init->ctype = var->ctype;

    return ast_decl(var, init);
}

// 读取函数指针参数列表并跳过
static void read_func_ptr_params(void)
{
    // 读取参数列表，只处理到匹配的 ')'
    int depth = 1;
    while (depth > 0) {
        Token t = read_token();
        if (is_punct(t, '('))
            depth++;
        else if (is_punct(t, ')'))
            depth--;
        else if (get_ttype(t) == TTYPE_NULL)
            error("Unexpected end of input in function pointer declaration");
    }
}

static Ctype *read_array_dimensions_int(Ctype *basetype)
{
    Token tok = read_token();
    if (!is_punct(tok, '[')) {
        unget_token(tok);
        return NULL;
    }
    int dim = -1;
    if (!is_punct(peek_token(), ']')) {
        Ast *size = read_expr();
        dim = eval_intexpr(size);
    }
    expect(']');
    Ctype *sub = read_array_dimensions_int(basetype);
    if (sub) {
        if (sub->len == -1 && dim == -1)
            error("Array size is not specified");
        return make_array_type(sub, dim);
    }
    return make_array_type(basetype, dim);
}

static Ctype *read_array_dimensions(Ctype *basetype)
{
    Ctype *ctype = read_array_dimensions_int(basetype);
    return ctype ? ctype : basetype;
}

static Ast *read_decl_init(Ast *var)
{
    Token tok = read_token();
    if (is_punct(tok, '='))
        return read_decl_init_val(var, true);
    if (var->ctype->len == -1)
        error("Missing array initializer");
    unget_token(tok);
    expect(';');
    return ast_decl(var, NULL);
}


static Ctype *read_decl_int(Token *name)
{
    Ctype *ctype = read_decl_spec();
    *name = read_token();
    
    // 检查是否是函数指针语法: type (*name)(params)
    if (is_punct(*name, '(')) {
        Token next_tok = read_token();
        if (is_punct(next_tok, '*')) {
            // 函数指针: type (*name)(params)
            *name = read_token();
            if (get_ttype((*name)) != TTYPE_IDENT)
                error("Identifier expected in function pointer, but got %s", token_to_string((*name)));
            expect(')');
            expect('(');
            // 读取参数列表
            read_func_ptr_params();
            // 创建函数指针类型：作为指向函数的指针
            // 这里我们使用普通指针类型，运行时通过名称调用
            return make_ptr_type(ctype);
        } else {
            // 不是函数指针，回退token
            unget_token(next_tok);
            // 继续正常处理，但此时*name是'('
            error("Identifier expected, but got %s", token_to_string(*name));
        }
    }
    
    if (get_ttype((*name)) != TTYPE_IDENT)
        error("Identifier expected, but got %s", token_to_string(*name));
    return read_array_dimensions(ctype);
}

// 读取单个变量的初始化（不处理分号，由上层统一处理）
static Ast *read_decl_init_single(Ast *var)
{
    Token tok = read_token();
    if (is_punct(tok, '='))
        return read_decl_init_val(var, false);
    if (var->ctype->len == -1)
        error("Missing array initializer");
    unget_token(tok);
    return ast_decl(var, NULL);
}

// 读取逗号分隔的多个变量声明
static Ast *read_decl_multi(Ctype *ctype, Token first_name)
{
    List *decls = make_list();
    Token varname = first_name;
    
    while (1) {
        if (ctype->type == CTYPE_VOID)
            error("Storage size of '%s' is not known", token_to_string(varname));
        if (have_redefine_var(get_ident(varname)))
            error("Fuction redefine local val: %s", token_to_string(varname));
        
        Ctype *var_ctype = read_array_dimensions(ctype);
        Ast *var = ast_lvar(var_ctype, get_ident(varname));
        Ast *decl = read_decl_init_single(var);
        list_push(decls, decl);
        
        Token tok = read_token();
        if (!is_punct(tok, ',')) {
            unget_token(tok);
            break;
        }
        
        // 读取下一个变量名
        varname = read_token();
        if (get_ttype(varname) != TTYPE_IDENT)
            error("Identifier expected, but got %s", token_to_string(varname));
    }
    
    expect(';');
    
    if (list_len(decls) == 1)
        return list_get(decls, 0);
    
    // 返回复合声明语句
    return ast_compound_stmt(decls);
}

static Ast *read_decl(void)
{
    Ctype *ctype = read_decl_spec();
    Token varname = read_token();
    
    // 检查是否是函数指针语法: type (*name)(params)
    if (is_punct(varname, '(')) {
        Token next_tok = read_token();
        if (is_punct(next_tok, '*')) {
            // 函数指针: type (*name)(params)
            varname = read_token();
            if (get_ttype(varname) != TTYPE_IDENT)
                error("Identifier expected in function pointer, but got %s", token_to_string(varname));
            expect(')');
            expect('(');
            // 读取参数列表
            read_func_ptr_params();
            // 创建函数指针类型
            ctype = make_ptr_type(ctype);
            return read_decl_multi(ctype, varname);
        } else {
            unget_token(next_tok);
            error("Identifier expected, but got %s", token_to_string(varname));
        }
    }
    
    if (get_ttype(varname) != TTYPE_IDENT)
        error("Identifier expected, but got %s", token_to_string(varname));
    return read_decl_multi(ctype, varname);
}

static Ast *read_if_stmt(void)
{
    expect('(');
    Ast *cond = read_expr();
    expect(')');
    Ast *then = read_stmt();

    Token tok = read_token();
    if (get_ttype(tok) != TTYPE_IDENT || strcmp(get_ident(tok), "else")) {
        unget_token(tok);
        return ast_if(cond, then, NULL);
    }

    tok = read_token();
    if (get_ttype(tok) == TTYPE_IDENT && strcmp(get_ident(tok), "if") == 0) {
        Ast *els = read_if_stmt();
        return ast_if(cond, then, els);
    } else {
        unget_token(tok);
        Ast *els = read_stmt();
        return ast_if(cond, then, els);
    }
}

static Ast *read_switch_stmt(void)
{
    expect('(');
    Ast *ctrl = read_expr();
    expect(')');

    /* 用来查重 case 值 */
    Dict *seen = &EMPTY_DICT;
    List *cases = make_list();
    Ast  *def_stmt = NULL;

    expect('{');
    while (1) {
        Token tok = peek_token();
        if (is_punct(tok, '}')) { read_token(); break; }

        if (is_ident(tok, "case")) {
            read_token();
            long cv = eval_intexpr(read_expr());
            long low = cv, high = cv;

            tok = peek_token();
            if(is_punct(tok, PUNCT_ELLIPSIS)) {
                read_token();
                high = eval_intexpr(read_expr());
                if (high < low) error("case range end (%ld) < start (%ld)", high, low);
            }

            
            for (long v = low; v <= high; ++v) {
                String buf = make_string();
                string_appendf(&buf, "%ld", v);
                char *key = get_cstring(buf);
                if (dict_get(seen, key))
                    error("duplicate case value %ld in range", key);
                
                dict_put(seen, key, (void *)1);
            }
                
            expect(':');
            list_push(cases, make_switch_case(low, high, read_stmt()));
            continue;
        }

        if (is_ident(tok, "default")) {
            read_token();
            if (def_stmt) error("multiple default labels");
            expect(':'); 
            def_stmt = read_stmt();
            continue;
        }

        read_stmt();  
    }

    seen = NULL;
    return ast_switch(ctrl, cases, def_stmt);
}


static Ast *read_opt_decl_or_stmt(void)
{
    Token tok = read_token();
    if (is_punct(tok, ';'))
        return NULL;
    unget_token(tok);
    return read_decl_or_stmt();
}

static Ast *read_opt_expr(void)
{
    Token tok = read_token();
    if (is_punct(tok, ';'))
        return NULL;
    unget_token(tok);
    Ast *r = read_expr();
    expect(';');
    return r;
}

static Ast *read_for_stmt(void)
{
    expect('(');
    localenv = make_dict(localenv);
    Ast *init = read_opt_decl_or_stmt();
    Ast *cond = read_opt_expr();
    Ast *step = is_punct(peek_token(), ')') ? NULL : read_expr();
    expect(')');
    Ast *body = read_stmt();
    localenv = dict_parent(localenv);
    return ast_for(init, cond, step, body);
}

static Ast *read_while_stmt(void)
{
    expect('(');
    Ast *cond = read_expr();          
    expect(')');                      
    Ast *body = read_stmt();          
    return ast_while(cond, body);     
}

static Ast *read_dowhile_stmt(void)
{
    Ast *body = read_stmt(); 
    Token tok = read_token();
    if(!is_ident(tok, "while"))
        error("Do while need while, but got %s", token_to_string(tok));
    expect('(');
    Ast *cond = read_expr();   
    expect(')');
    expect(';');             
    return ast_dowhile(cond, body);
}

static Ast *read_goto_stmt(void) 
{
    Token tok = read_token();
    if(get_ttype(tok) != TTYPE_IDENT)
        error("Goto need a identify, but got %s", token_to_string(tok));

    // FIXME: 应该需要检查一下是否存在标签
    expect(';'); 
    return ast_goto(get_ident(tok));
}

static Ast *read_break_stmt(void)
{
    expect(';');
    return ast_break();
}

static Ast *read_continue_stmt(void)
{
    expect(';');
    return ast_continue();
}

static Ast *read_return_stmt(void)
{
    Ast *retval = read_expr();
    expect(';');
    return ast_return(retval);
}

static bool is_first = true;
static Ast *read_stmt(void)
{
    Token tok = peek_token();  
    if(!is_first) {
        if (is_ident(tok, "continue"))  { read_token(); return read_continue_stmt(); } 
        if (is_ident(tok, "break"))     { read_token(); return read_break_stmt(); }
    }
    is_first = false;

    if (is_ident(tok, "if"))     { read_token(); return read_if_stmt(); }
    if (is_ident(tok, "switch")) { read_token(); return read_switch_stmt(); }
    if (is_ident(tok, "for"))    { read_token(); return read_for_stmt(); }
    if (is_ident(tok, "while"))  { read_token(); return read_while_stmt(); }
    if (is_ident(tok, "do"))     { read_token(); return read_dowhile_stmt(); }
    if (is_ident(tok, "return")) { read_token(); return read_return_stmt(); }
    if (is_ident(tok, "goto"))   { read_token(); return read_goto_stmt(); }
    if (is_punct(tok, '{'))      { read_token(); return read_compound_stmt(); }

    Ast *r = read_expr();
    if(r->type != AST_LABEL) expect(';');
    return r;
}

static Ast *read_decl_or_stmt(void)
{
    Token tok = peek_token();
    if (get_ttype(tok) == TTYPE_NULL)
        return NULL;
    
    return is_type_keyword(tok) ? read_decl() : read_stmt();
}

static Ast *read_compound_stmt(void)
{
    localenv = make_dict(localenv);
    List *list = make_list();
    while (1) {
        Token tok = read_token();
        if (is_punct(tok, '}'))
            break;
        unget_token(tok);

        Ast *stmt = read_decl_or_stmt();

        if (stmt)
            list_push(list, stmt);
        if (!stmt)
            break;
    }
    localenv = dict_parent(localenv);
    return ast_compound_stmt(list);
}

static List *read_params(void)
{
    List *params = make_list();
    Token tok = read_token();
    if (is_punct(tok, ')'))
        return params;
    unget_token(tok);
    while (1) {
        Ctype *ctype = read_decl_spec();
        tok = read_token();
        
        // 检查是否是函数指针语法: type (*name)(params)
        if (is_punct(tok, '(')) {
            // 可能是函数指针，检查下一个token是否是 *
            Token next_tok = read_token();
            if (is_punct(next_tok, '*')) {
                // 读取函数指针名称
                Token name_tok = read_token();
                if (get_ttype(name_tok) != TTYPE_IDENT)
                    error("Identifier expected in function pointer, but got %s", token_to_string(name_tok));
                char *fn_name = get_ident(name_tok);
                expect(')');
                expect('(');
                // 读取函数指针的参数列表（忽略具体参数，只处理到右括号）
                int depth = 1;
                while (depth > 0) {
                    Token t = read_token();
                    if (is_punct(t, '('))
                        depth++;
                    else if (is_punct(t, ')'))
                        depth--;
                    else if (get_ttype(t) == TTYPE_NULL)
                        error("Unexpected end of input in function pointer declaration");
                }
                // 创建函数指针类型（作为普通指针处理）
                Ctype *fn_ptr_type = make_ptr_type(ctype);
                if(have_redefine_var(fn_name))
                    error("Function have redefined param: %s", fn_name);
                list_push(params, ast_lvar(fn_ptr_type, fn_name));
                
                tok = read_token();
                if (is_punct(tok, ')'))
                    return params;
                if (!is_punct(tok, ','))
                    error("Comma expected, but got %s", token_to_string(tok));
                continue;
            } else {
                // 不是函数指针，回退token
                unget_token(next_tok);
                unget_token(tok);
                tok = read_token();
            }
        }
        
        if (get_ttype(tok) != TTYPE_IDENT) {
            if(ctype->type == CTYPE_VOID && is_punct(tok, ')') && params->len == 0) {
                return params;
            } else  {
                error("Identifier expected, but got %s", token_to_string(tok));
            }
        }
            
        ctype = read_array_dimensions(ctype);
        if (ctype->type == CTYPE_ARRAY)
            ctype = make_ptr_type(ctype->ptr);
        if(have_redefine_var(get_ident(tok)))
            error("Function have redefined param: %s", token_to_string(tok));
        list_push(params, ast_lvar(ctype, get_ident(tok)));
        tok = read_token();
        if (is_punct(tok, ')'))
            return params;
        if (!is_punct(tok, ','))
            error("Comma expected, but got %s", token_to_string(tok));
    }
}

static Ast *ast_interrupt_def(Ctype *rettype, int int_id, int bank_id,
                               Ast *body, List *localvars, List *labels)
{
    Ast *r = malloc(sizeof(Ast));
    r->type = AST_INTERRUPT_DEF;
    r->ctype = rettype;
    r->interrupt_id = int_id;   // 使用专用字段
    r->bank_id = bank_id;
    r->body = body;
    r->localvars = localvars;
    r->labels = labels;
    return r;
}

static Ast *read_func_def(Ctype *rettype, char *fname)
{
    // 检测是否是 interrupt_func 特殊函数
    if (strcmp(fname, "interrupt_func") == 0) {
        expect('(');
        // 解析中断号 (常量表达式)
        Ast *id_ast = read_expr();
        int int_id = eval_intexpr(id_ast);
        expect(',');
        // 解析寄存器组号 (常量表达式)
        Ast *bank_ast = read_expr();
        int bank_id = eval_intexpr(bank_ast);
        expect(')');
        
        // 验证范围
        if (int_id < 0 || int_id > 7)
            error("Interrupt id must be 0-7, got %d", int_id);
        if (bank_id < 0 || bank_id > 3)
            error("Bank id must be 0-3, got %d", bank_id);
        
        // 读取函数体
        Token tok = read_token();
        if (!is_punct(tok, '{'))
            error("Expected '{' for interrupt function body");
        
        is_first = true;
        localenv = make_dict(globalenv);
        localenv = make_dict(localenv);
        localvars = make_list();
        labels = make_list();
        Ast *body = read_compound_stmt();
        
        Ast *r = ast_interrupt_def(rettype, int_id, bank_id, body, localvars, labels);
        
        localenv = dict_parent(dict_parent(localenv));
        localvars = NULL;
        labels = NULL;
        return r;
    }
    
    if(have_redefine_func(fname))
        error("Redeclaration function: %s", fname);
    
    expect('(');
    localenv = make_dict(globalenv);
    List *params = read_params();

    Token tok = read_token();
    if(is_punct(tok, '{')) {
        is_first = true;
        // 先创建函数声明并添加到符号表，支持递归调用
        Ast *func_decl = ast_func_decl(rettype, fname, params);
        dict_put(functionenv, fname, func_decl);
        
        localenv = make_dict(localenv);
        localvars = make_list();
        labels = make_list();
        Ast *body = read_compound_stmt();
        Ast *r = ast_func_def(rettype, fname, params, body, localvars, labels);
        localenv = dict_parent(localenv);
        localvars = NULL;
        labels = NULL;

        // 更新符号表中的函数定义
        dict_put(functionenv, fname, r);
        return r;
    }else if (is_punct(tok, ';')) {
        Ast *r = ast_func_decl(rettype, fname, params);
        dict_put(functionenv, fname, r);
        return r;
    }

    return NULL;
}

static Ast *read_decl_or_func_def(void)
{
    Token tok = peek_token();
    if (get_ttype(tok) == TTYPE_NULL)
        return NULL;
    Ctype *ctype = read_decl_spec();
    Token tok1 = read_token();
    char *ident;
    
    // 检查是否是typedef函数指针: typedef type (*name)(params);
    if (is_punct(tok1, '(')) {
        Token next_tok = read_token();
        if (is_punct(next_tok, '*')) {
            // typedef函数指针: typedef type (*name)(params);
            Token name_tok = read_token();
            if (get_ttype(name_tok) != TTYPE_IDENT)
                error("Identifier expected in typedef function pointer, but got %s", token_to_string(name_tok));
            ident = get_ident(name_tok);
            expect(')');
            expect('(');
            read_func_ptr_params();
            // 创建函数指针类型
            ctype = make_ptr_type(ctype);
            // 继续处理typedef
            expect(';');
            dict_put(typedefenv, ident, ctype);
            return ast_typedef(ctype, ident);
        } else {
            unget_token(next_tok);
            unget_token(tok1);
            tok1 = read_token();
        }
    }
    
    if (get_ttype(tok1) != TTYPE_IDENT) {
        if(is_punct(tok1, ';')) {
            if(ctype->type == CTYPE_STRUCT) return ast_struct_def(ctype);
            else if(ctype->type == CTYPE_ENUM) return ast_enum_def(ctype);
        }
        error("Identifier expected, but got %s", token_to_string(tok1));
    }
    ident = get_ident(tok1);
    tok = peek_token();
    if (is_punct(tok, '('))
        return read_func_def(ctype, ident);
    if (ctype->type == CTYPE_VOID)
        error("Storage size of '%s' is not known", token_to_string(tok1));
    ctype = read_array_dimensions(ctype);
    if (is_punct(tok, '=') || ctype->type == CTYPE_ARRAY) {
        Ast *var = ast_gvar(ctype, ident, false);
        return read_decl_init(var);
    }
    if (is_punct(tok, ';')) {
        if(get_attr(ctype->attr).ctype_typedef) {
            dict_put(typedefenv, ident, ctype);
            read_token();
            return ast_typedef(ctype, ident);
        }

        read_token();
        Ast *var = ast_gvar(ctype, ident, false);
        return ast_decl(var, NULL);
    }
    error("Don't know how to handle %s", token_to_string(tok));
    return NULL; /* non-reachable */
}

List *read_toplevels(void)
{
    List *r = make_list();
    while (1) {
        Ast *ast = read_decl_or_func_def();
        if (!ast)
            return r;
        list_push(r, ast);
    }
    list_free(globalenv->list);
    return r;
}

CtypeAttr get_attr(int in_attr) 
{
    union { CtypeAttr c_attr; int i_attr; }attr = {0};
    attr.i_attr = in_attr;
    return attr.c_attr;
}