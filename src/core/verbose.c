#include "cc.h"

/* 把 Ctype::attr 转成 "const volatile static …" 这种字符串 */
static const char *ctype_attr_string(int attr)
{
    /* 64 字节足够放下所有关键字 + 空格 + '\0' */
    static char buf[64];
    char *p = buf;
    *p = '\0';

    /* 注意顺序：一般按 C 语法习惯把 "const/volatile" 放最前 */
    if (attr & (1 << 0)) { strcpy(p, "const ");     p += 6; }
    if (attr & (1 << 1)) { strcpy(p, "volatile "); p += 9; }
    if (attr & (1 << 2)) { strcpy(p, "restrict "); p += 9; }
    if (attr & (1 << 3)) { strcpy(p, "static ");    p += 7; }
    if (attr & (1 << 4)) { strcpy(p, "extern ");    p += 7; }
    if (attr & (1 << 5)) { strcpy(p, "unsigned "); p += 9; }
    if (attr & (1 << 6)) { strcpy(p, "register "); p += 9; }
    /* 函数限定符 */
    if (attr & (1 << 8)) { strcpy(p, "inline ");    p += 7; }
    if (attr & (1 << 9)) { strcpy(p, "noreturn "); p += 10; }

    /* 51 地址空间关键字 */
    int data = (attr >> 7) & 7;          /* 提取 3-bit data 字段 */
    switch (data) {
    case 1:  strcpy(p, "data ");    p += 5; break;
    case 2:  strcpy(p, "idata ");   p += 6; break;
    case 3:  strcpy(p, "pdata ");   p += 6; break;
    case 4:  strcpy(p, "xdata ");   p += 6; break;
    case 5:  strcpy(p, "edata ");   p += 6; break;
    case 6:  strcpy(p, "code ");    p += 5; break;
    default: break;
    }
    
    /* 末尾如果是空格，退一格覆盖掉 */
    if (p > buf && *(p-1) == ' ') *(p-1) = '\0';
    return buf;
}

char *ctype_to_string(Ctype *ctype) {
    if (!ctype) return "(nil)";
    String s = make_string();
    const char *a = ctype_attr_string(ctype->attr);
    if (*a) string_appendf(&s, "%s ", a);

    switch (ctype->type) {
    case CTYPE_VOID:  string_appendf(&s, "void"); break;
    case CTYPE_INT:   string_appendf(&s, "int"); break;
    case CTYPE_LONG:  string_appendf(&s, "long"); break;
    case CTYPE_CHAR:  string_appendf(&s, "char"); break;
    case CTYPE_FLOAT: string_appendf(&s, "float"); break;
    case CTYPE_DOUBLE:string_appendf(&s, "double"); break;
    case CTYPE_PTR:   string_appendf(&s, "*%s", ctype_to_string(ctype->ptr)); return get_cstring(s);
    case CTYPE_ARRAY: string_appendf(&s, "[%d]%s", ctype->len, ctype_to_string(ctype->ptr)); return get_cstring(s);
    case CTYPE_STRUCT:
        string_appendf(&s, ctype->offset==ctype->size?"(union":"(struct");
        for (Iter i=list_iter(ctype->fields->list); !iter_end(i);) {
            DictEntry *e=iter_next(&i);
            string_appendf(&s, " (%s %s)", ctype_to_string(e->val), e->key);
        }
        string_appendf(&s, ")");
        return get_cstring(s);
    default: error("Unknown ctype: %d", ctype);
    }
    return get_cstring(s);
}

static void uop_to_string(String *buf, char *op, Ast *ast)
{
    string_appendf(buf, "(%s %s)", op, ast_to_string(ast->operand));
}

static void binop_to_string(String *buf, char *op, Ast *ast)
{
    string_appendf(buf, "(%s %s %s)", op, ast_to_string(ast->left),
                   ast_to_string(ast->right));
}

static void ast_to_string_int(String *buf, Ast *ast)
{
    if (!ast) {
        string_appendf(buf, "(nil)");
        return;
    }
    switch (ast->type) {
    case AST_LITERAL:
        switch (ast->ctype->type) {
        case CTYPE_CHAR:
            if (ast->ival == '\n')
                string_appendf(buf, "'\n'");
            else if (ast->ival == '\\')
                string_appendf(buf, "'\\\\'");
            else
                string_appendf(buf, "'%c'", ast->ival);
            break;
        case CTYPE_INT:
            string_appendf(buf, "%d", ast->ival);
            break;
        case CTYPE_LONG:
            string_appendf(buf, "%ldL", ast->ival);
            break;
        case CTYPE_FLOAT:
        case CTYPE_DOUBLE:
            string_appendf(buf, "%f", ast->fval);
            break;
        default:
            error("internal error");
        }
        break;
    case AST_STRING:
        string_appendf(buf, "\"%s\"", quote_cstring(ast->sval));
        break;
    case AST_LVAR:
    case AST_GVAR:
        string_appendf(buf, "%s", ast->varname);
        break;
    case AST_FUNCALL: {
        string_appendf(buf, "(%s)%s(", ctype_to_string(ast->ctype), ast->fname);
        for (Iter i = list_iter(ast->args); !iter_end(i);) {
            string_appendf(buf, "%s", ast_to_string(iter_next(&i)));
            if (!iter_end(i))
                string_appendf(buf, ",");
        }
        string_appendf(buf, ")");
        break;
    }
    case AST_FUNC: {
        string_appendf(buf, "(%s)%s(", ctype_to_string(ast->ctype), ast->fname);
        for (Iter i = list_iter(ast->params); !iter_end(i);) {
            Ast *param = iter_next(&i);
            string_appendf(buf, "%s %s", ctype_to_string(param->ctype),
                           ast_to_string(param));
            if (!iter_end(i))
                string_appendf(buf, ",");
        }
        string_appendf(buf, ")");
        ast_to_string_int(buf, ast->body);
        break;
    }
    case AST_DECL:
        string_appendf(buf, "(decl %s %s", ctype_to_string(ast->declvar->ctype),
                       ast->declvar->varname);
        if (ast->declinit)
            string_appendf(buf, " %s)", ast_to_string(ast->declinit));
        else
            string_appendf(buf, ")");
        break;
    case AST_ARRAY_INIT:
        string_appendf(buf, "{");
        for (Iter i = list_iter(ast->arrayinit); !iter_end(i);) {
            ast_to_string_int(buf, iter_next(&i));
            if (!iter_end(i))
                string_appendf(buf, ",");
        }
        string_appendf(buf, "}");
        break;
    case AST_STRUCT_INIT:
        string_appendf(buf, "{");
        for (Iter i = list_iter(ast->arrayinit); !iter_end(i);) {
            ast_to_string_int(buf, iter_next(&i));
            if (!iter_end(i))
                string_appendf(buf, ",");
        }
        string_appendf(buf, "}");
        break;
    case AST_IF:
        string_appendf(buf, "(if %s %s", ast_to_string(ast->cond),
                       ast_to_string(ast->then));
        if (ast->els)
            string_appendf(buf, " %s", ast_to_string(ast->els));
        string_appendf(buf, ")");
        break;
    case AST_TERNARY:
        string_appendf(buf, "(? %s %s %s)", ast_to_string(ast->cond),
                       ast_to_string(ast->then), ast_to_string(ast->els));
        break;
    case AST_FOR:
        string_appendf(buf, "(for %s %s %s ", ast_to_string(ast->forinit),
                       ast_to_string(ast->forcond),
                       ast_to_string(ast->forstep));
        string_appendf(buf, "%s)", ast_to_string(ast->forbody));
        break;
    case AST_RETURN:
        string_appendf(buf, "(return %s)", ast_to_string(ast->retval));
        break;
    case AST_COMPOUND_STMT: {
        string_appendf(buf, "{");
        for (Iter i = list_iter(ast->stmts); !iter_end(i);) {
            ast_to_string_int(buf, iter_next(&i));
            string_appendf(buf, ";");
        }
        string_appendf(buf, "}");
        break;
    }
    case AST_STRUCT_REF:
        ast_to_string_int(buf, ast->struc);
        string_appendf(buf, ".");
        string_appendf(buf, ast->field);
        break;
    case AST_STRUCT_DEF:
        string_appendf(buf, "(def %s)", ctype_to_string(ast->ctype));
        break;
    case AST_ADDR:
        uop_to_string(buf, "addr", ast);
        break;
    case AST_DEREF:
        uop_to_string(buf, "deref", ast);
        break;
    case PUNCT_INC:
        uop_to_string(buf, "++", ast);
        break;
    case PUNCT_DEC:
        uop_to_string(buf, "--", ast);
        break;
    case PUNCT_LOGAND:
        binop_to_string(buf, "and", ast);
        break;
    case PUNCT_LOGOR:
        binop_to_string(buf, "or", ast);
        break;
    case '!':
        uop_to_string(buf, "!", ast);
        break;
    case '&':
        binop_to_string(buf, "&", ast);
        break;
    case '|':
        binop_to_string(buf, "|", ast);
        break;
    default: {
        char *left = ast_to_string(ast->left);
        char *right = ast_to_string(ast->right);
        if (ast->type == PUNCT_EQ)
            string_appendf(buf, "(== ");
        else
            string_appendf(buf, "(%c ", ast->type);
        string_appendf(buf, "%s %s)", left, right);
    }
    }
}

char *ast_to_string(Ast *ast)
{
    String s = make_string();
    ast_to_string_int(&s, ast);
    return get_cstring(s);
}

char *token_to_string(const Token tok)
{
    enum TokenType ttype = get_ttype(tok);
    if (ttype == TTYPE_NULL)
        return "(null)";
    String s = make_string();
    switch (ttype) {
    case TTYPE_NULL:
        error("internal error: unknown token type: %d", get_ttype(tok));
    case TTYPE_IDENT:
        return get_ident(tok);
    case TTYPE_PUNCT:
        if (is_punct(tok, PUNCT_EQ))
            string_appendf(&s, "==");
        else
            string_appendf(&s, "%c", get_punct(tok));
        return get_cstring(s);
    case TTYPE_CHAR:
        string_append(&s, get_char(tok));
        return get_cstring(s);
    case TTYPE_NUMBER:
        return get_number(tok);
    case TTYPE_STRING:
        string_appendf(&s, "\"%s\"", get_strtok(tok));
        return get_cstring(s);
    }
    error("internal error: unknown token type: %d", get_ttype(tok));
    return NULL; /* non-reachable */
}


#ifdef MINITEST_IMPLEMENTATION

#include "minitest.h"

TEST(test, verbose) {
    char infile[256];
    printf("file path: ");
    if (!fgets(infile, sizeof infile, stdin) || !freopen(strtok(infile, "\n"), "r", stdin))
        puts("open fail"), exit(1);
        
    List *toplevels = read_toplevels();
    for (Iter i = list_iter(toplevels); !iter_end(i);) {
        Ast *v = iter_next(&i);
        printf("%s", ast_to_string(v));
    }
    list_free(cstrings);
    list_free(ctypes);
}

#endif /* MINITEST_IMPLEMENTATION */