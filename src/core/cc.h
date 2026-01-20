#ifndef CC_H
#define CC_H

#include <stdbool.h>
#include <stdint.h>
#include <assert.h>
#include "dict.h"
#include "list.h"
#include "util.h"

enum TokenType {
    TTYPE_NULL,
    TTYPE_IDENT,
    TTYPE_PUNCT,
    TTYPE_NUMBER,
    TTYPE_CHAR,
    TTYPE_STRING,
};

typedef struct {
    int type;
    uintptr_t priv;
} Token;

typedef struct {
    const char *file;
    int line, col, len;
} TokenInfo;

enum {
    AST_LITERAL = 256,
    AST_STRING,
    AST_LVAR,
    AST_GVAR,
    AST_FUNCALL,
    AST_FUNC_DECL,
    AST_FUNC_DEF,
    AST_DECL,
    AST_ARRAY_INIT,
    AST_ADDR,
    AST_DEREF,
    AST_IF,
    AST_TERNARY,
    AST_FOR,
    AST_WHILE,
    AST_DO_WHILE,
    AST_LABEL,
    AST_GOTO,
    AST_BREAK,
    AST_CONTINUE,
    AST_RETURN,
    AST_SWITCH,
    AST_COMPOUND_STMT,
    AST_STRUCT_REF,
    AST_STRUCT_DEF,
    AST_STRUCT_INIT,
    AST_ENUM_DEF,
    AST_TYPE_DEF, 
    AST_CAST,
    PUNCT_EQ,
    PUNCT_GE,        // >=
    PUNCT_LE,        // <=
    PUNCT_NE,        // !=
    PUNCT_ELLIPSIS,
    PUNCT_INC,
    PUNCT_DEC,
    PUNCT_LOGAND,
    PUNCT_LOGOR,
    PUNCT_ARROW,
    PUNCT_LSHIFT,
    PUNCT_RSHIFT,
};

enum {
    CTYPE_VOID,
    CTYPE_BOOL,
    CTYPE_CHAR,
    CTYPE_INT,
    CTYPE_LONG,
    CTYPE_FLOAT,
    CTYPE_DOUBLE,
    CTYPE_ARRAY,
    CTYPE_PTR,
    CTYPE_STRUCT,
    CTYPE_ENUM
};

typedef struct __CtypeAttr {
    int ctype_const         : 1;
    int ctype_volatile      : 1;
    int ctype_restrict      : 1;
    int ctype_static        : 1;
    int ctype_extern        : 1;
    int ctype_unsigned      : 1;
    int ctype_register      : 1; /* NOTE: c51中使用这个关键词申明sfr, sfr16, sbit */ 
    int ctype_data          : 3; /* NONE, DATA, IDATA, PDATA, XDATA, EDATA, CODE */
    int ctype_typedef       : 1; 

    /* 函数限定 */
    int ctype_inline        : 1;
    int ctype_noreturn      : 1;
} CtypeAttr;

typedef struct __Ctype {
    int attr;
    int type;
    int size;
    struct __Ctype *ptr; /* pointer or array */
    int len;             /* array length */
    /* struct */
    Dict *fields;
    int offset;

    int bit_offset;     /* 位域支持 */
    int bit_size;
} Ctype;

typedef struct __Ast {
    int type;
    Ctype *ctype;
    union {
        /* char, int, or long */
        long ival;

        /* float or double */
        struct {
            union {
                double fval;
                int lval[2];
            };
            char *flabel;
        };

        /* string literal */
        struct {
            char *sval;
            char *slabel;
        };

        /* Local/global variable */
        struct {
            char *varname;
            struct {
                int loff;
                char *glabel;
            };
        };

        /* Binary operator */
        struct {
            struct __Ast *left;
            struct __Ast *right;
        };

        /* Unary operator */
        struct {
            struct __Ast *operand;
        };

        /* Function call or function declaration */
        struct {
            char *fname;
            struct {
                List *args;
                struct {
                    List *params;
                    List *localvars;
                    List *labels;
                    struct __Ast *body;
                };
            };
        };

        /* Declaration */
        struct {
            struct __Ast *declvar;
            struct __Ast *declinit;
        };

        /* Array initializer */
        List *arrayinit;

        /* Struct initializer */
        List *structinit; 

        /* Typedef name */
        char* typename;

        /* if statement or ternary operator */
        struct {
            struct __Ast *cond;
            struct __Ast *then;
            struct __Ast *els;
        };

        /* for statement */
        struct {
            struct __Ast *forinit;
            struct __Ast *forcond;
            struct __Ast *forstep;
            struct __Ast *forbody;
        };

        /* while/do-while statement */
        struct {
            struct __Ast *while_cond;
            struct __Ast *while_body;
        };

        /* switch-case statement */
        struct {
            struct __Ast *ctrl;         
            List *cases;       /* List<SwitchCase*> */
            struct __Ast *default_stmt; 
        };

        /* goto/label */
        char* label;

        /* return statement */
        struct __Ast *retval;

        /* Compound statement */
        List *stmts;

        /* Struct reference */
        struct {
            struct __Ast *struc;
            char *field; /* specific to ast_to_string only */
        };

        /* cast */
        struct {
            struct __Ast *cast_expr;   
        };
    };
} Ast;

typedef struct { long low, high;; Ast *stmt; } SwitchCase;

/* verbose.c */
extern char *token_to_string(const Token tok);
extern char *ast_to_string(Ast *ast);
extern char *ctype_to_string(Ctype *ctype);

/* lexer.c */
extern bool is_punct(const Token tok, int c);
extern void unget_token(const Token tok);
extern Token peek_token(void);
extern Token read_token(void);
extern TokenInfo get_current_token_info(void);
extern void set_current_filename(const char *filename);

#define get_priv(tok, type)                                       \
    ({                                                            \
        assert(__builtin_types_compatible_p(typeof(tok), Token)); \
        ((type) tok.priv);                                        \
    })

#define get_ttype(tok)                                            \
    ({                                                            \
        assert(__builtin_types_compatible_p(typeof(tok), Token)); \
        (tok.type);                                               \
    })

#define get_token(tok, ttype, priv_type) \
    ({                                   \
        assert(get_ttype(tok) == ttype); \
        get_priv(tok, priv_type);        \
    })

#define get_char(tok) get_token(tok, TTYPE_CHAR, char)
#define get_strtok(tok) get_token(tok, TTYPE_STRING, char *)
#define get_ident(tok) get_token(tok, TTYPE_IDENT, char *)
#define get_number(tok) get_token(tok, TTYPE_NUMBER, char *)
#define get_punct(tok) get_token(tok, TTYPE_PUNCT, int)

/* parser.c */
extern List *strings;
extern List *flonums;
extern List *ctypes;
extern char *make_label(void);
extern List *read_toplevels(void);
extern bool is_inttype(Ctype *ctype);
extern bool is_flotype(Ctype *ctype);

/* debug */
#define error(...) errorf(__FILE__, __LINE__, __VA_ARGS__)
static inline void errorf(char *file, int line, char *fmt, ...)
{
    #if C51CC_DEBUG
    fprintf(stderr, "%s:%d: ", file, line);
    #else 
    TokenInfo info = get_current_token_info();
    fprintf(stderr, "%s:%d: ", info.file, info.line);
    #endif 
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
    exit(1);
}

static inline CtypeAttr get_attr(int in_attr) 
{
    union { CtypeAttr c_attr; int i_attr; }attr = {0};
    attr.i_attr = in_attr;
    return attr.c_attr;
}


#endif /* CC_H */
