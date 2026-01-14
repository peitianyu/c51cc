#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cc.h"

#define make_null(x) make_token(TTYPE_NULL, (uintptr_t) 0)
#define make_strtok(x) make_token(TTYPE_STRING, (uintptr_t) get_cstring(x))
#define make_ident(x) make_token(TTYPE_IDENT, (uintptr_t) get_cstring(x))
#define make_punct(x) make_token(TTYPE_PUNCT, (uintptr_t)(x))
#define make_number(x) make_token(TTYPE_NUMBER, (uintptr_t)(x))
#define make_char(x) make_token(TTYPE_CHAR, (uintptr_t)(x))

static bool ungotten = false;
static Token ungotten_buf = {0};

// 位置跟踪变量
static int curr_line = 1;
static int curr_col = 1;
static const char *curr_filename = "<stdin>";
static TokenInfo curr_token_info = {0};

// 用于跟踪上一行的长度，以便正确回退
static int last_line_length = 0;
static int prev_col = 1;

static Token make_token(enum TokenType type, uintptr_t data)
{
    return (Token){
        .type = type,
        .priv = data,
    };
}

static void update_pos(int c) {
    if (c == '\n') {
        curr_line++;
        last_line_length = curr_col;
        curr_col = 1;
    } else {
        curr_col++;
    }
}

static int getc_with_pos(void) {
    int c = getc(stdin);
    if (c != EOF) {
        update_pos(c);
    }
    return c;
}

static int ungetc_with_pos(int c) {
    if (c == '\n') {
        curr_line--;
        curr_col = last_line_length;
    } else if (c != EOF) {
        curr_col--;
    }
    return ungetc(c, stdin);
}

static int getc_nonspace(void)
{
    int c;
    while ((c = getc_with_pos()) != EOF) {
        if (c == '\n' || c == '\r' || c == ' ' || c == '\t')
            continue;
        return c;
    }
    return EOF;
}


static Token read_number(char first)
{
    String s = make_string();
    long ival = 0, fval = 0;
    int  base = 10, dot = 0, fscale = 0;

    /* 0x... / 0b... 前缀 */
    if (first == '0') {
        int x = getc_with_pos();
        if (x == 'x' || x == 'X')        base = 16;
        else if (x == 'b' || x == 'B')   base = 2;
        else ungetc_with_pos(x);
    }

    /* 主循环：读整数/小数/十六进制位 */
    for (int c = first;; c = getc_with_pos()) {
        if (base == 16 && isxdigit(c))
            ival = ival * 16 + (isdigit(c) ? c - '0' : (c & 0xDF) - 'A' + 10);
        else if ((base == 2 && (c == '0' || c == '1')) ||
                 (base == 10 && isdigit(c))) {
            if (!dot) ival = ival * base + (c - '0');
            else      fval = fval * 10 + (c - '0'), ++fscale;
        }
        else if (base == 10 && c == '.' && !dot) { dot = 1; }
        else { ungetc_with_pos(c); break; }
    }

    /* 后缀 f/F/l/L 仅影响输出格式 */
    int suf = getc_with_pos();
    if (suf != 'f' && suf != 'F' && suf != 'l' && suf != 'L')
        ungetc_with_pos(suf);

    if (dot || suf == 'f' || suf == 'F')
        string_appendf(&s, "%ld.%0*ld", ival, fscale, fval);
    else
        string_appendf(&s, "%ld", ival);

    return make_number(get_cstring(s));
}

static Token read_char(void)
{
    char c = getc_with_pos();
    if (c == EOF)
        goto err;
    if (c == '\\') {
        c = getc_with_pos();
        if (c == EOF)
            goto err;
    }
    char c2 = getc_with_pos();
    if (c2 == EOF)
        goto err;
    if (c2 != '\'')
        error("Malformed char literal");
    return make_char(c);
err:
    error("Unterminated char");
    return make_null(); /* non-reachable */
}

static Token read_string(void)
{
    String s = make_string();
    while (1) {
        int c = getc_with_pos();
        if (c == EOF)
            error("Unterminated string");
        if (c == '"')
            break;
        if (c == '\\') {
            c = getc_with_pos();
            switch (c) {
            case EOF:
                error("Unterminated \\");
            case '\"':
                break;
            case 'n':
                c = '\n';
                break;
            default:
                error("Unknown quote: %c", c);
            }
        }
        string_append(&s, c);
    }
    return make_strtok(s);
}

static Token read_ident(char c)
{
    String s = make_string();
    string_append(&s, c);
    while (1) {
        int c2 = getc_with_pos();
        if (isalnum(c2) || c2 == '_') {
            string_append(&s, c2);
        } else {
            ungetc_with_pos(c2);
            return make_ident(s);
        }
    }
}

static void skip_line_comment(void)
{
    while (1) {
        int c = getc_with_pos();
        if (c == '\n' || c == EOF)
            return;
    }
}

static void skip_block_comment(void)
{
    enum { in_comment, asterisk_read } state = in_comment;
    while (1) {
        int c = getc_with_pos();
        if (c == EOF) {
            error("Unterminated block comment");
            return;
        }
        
        if (state == in_comment) {
            if (c == '*')
                state = asterisk_read;
        } else if (state == asterisk_read) {
            if (c == '/') {
                return;
            } else if (c == '*') {
                continue;
            } else {
                state = in_comment;
            }
        }
    }
}

static Token read_rep(int expect, int t1, int t2)
{
    int c = getc_with_pos();
    if (c == expect)
        return make_punct(t2);
    ungetc_with_pos(c);
    return make_punct(t1);
}

static void update_token_info(int start_line, int start_col, Token *tok) {
    int token_len = curr_col - start_col;
    if (token_len < 0) {
        token_len = 1;
    } else if (token_len == 0) {
        token_len = 1;
    }
    
    curr_token_info = (TokenInfo){
        .file = curr_filename,
        .line = start_line,
        .col = start_col,
        .len = token_len
    };
}

static Token read_token_int(void)
{
    int c = getc_nonspace();
    int start_line = curr_line;
    int start_col = curr_col-1;

    Token tok;
    switch (c) {
    case '0' ... '9':
        tok = read_number(c);
        update_token_info(start_line, start_col, &tok);
        return tok;
    case 'a' ... 'z':
    case 'A' ... 'Z':
    case '_':
        tok = read_ident(c);
        update_token_info(start_line, start_col, &tok);
        return tok;
    case '/': {
        c = getc_with_pos();
        if (c == '/') {
            skip_line_comment();
            return read_token_int();
        }
        if (c == '*') {
            skip_block_comment();
            return read_token_int();
        }
        ungetc_with_pos(c);
        tok = make_punct('/');
        update_token_info(start_line, start_col, &tok);
        return tok;
    }
    case '*':
    case '(':
    case ')':
    case ',':
    case ';':
    case '.':
    case '[':
    case ']':
    case '{':
    case '}':
    case '!':
    case '?':
    case ':':
    case '%':
        tok = make_punct(c);
        update_token_info(start_line, start_col, &tok);
        return tok;
    case '-':
        c = getc_with_pos();
        if (c == '-') {
            tok = make_punct(PUNCT_DEC);
            update_token_info(start_line, start_col, &tok);
            return tok;
        }
        if (c == '>') {
            tok = make_punct(PUNCT_ARROW);
            update_token_info(start_line, start_col, &tok);
            return tok;
        }
        ungetc_with_pos(c);
        tok = make_punct('-');
        update_token_info(start_line, start_col, &tok);
        return tok;
    case '=':
        tok = read_rep('=', '=', PUNCT_EQ);
        update_token_info(start_line, start_col, &tok);
        return tok;
    case '+':
        tok = read_rep('+', '+', PUNCT_INC);
        update_token_info(start_line, start_col, &tok);
        return tok;
    case '&':
        tok = read_rep('&', '&', PUNCT_LOGAND);
        update_token_info(start_line, start_col, &tok);
        return tok;
    case '|':
        tok = read_rep('|', '|', PUNCT_LOGOR);
        update_token_info(start_line, start_col, &tok);
        return tok;
    case '<':
        tok = read_rep('<', '<', PUNCT_LSHIFT);
        update_token_info(start_line, start_col, &tok);
        return tok;
    case '>':
        tok = read_rep('>', '>', PUNCT_RSHIFT);
        update_token_info(start_line, start_col, &tok);
        return tok;
    case '"':
        tok = read_string();
        update_token_info(start_line, start_col, &tok);
        return tok;
    case '\'':
        tok = read_char();
        update_token_info(start_line, start_col, &tok);
        return tok;
    case EOF:
        tok = make_null();
        update_token_info(start_line, start_col, &tok);
        return tok;
    default:
        error("Unexpected character: '%c'", c);
        tok = make_null(); /* non-reachable */
        update_token_info(start_line, start_col, &tok);
        return tok;
    }
}

bool is_punct(const Token tok, int c)
{
    return (get_ttype(tok) == TTYPE_PUNCT) && (get_punct(tok) == c);
}

void unget_token(const Token tok)
{
    if (get_ttype(tok) == TTYPE_NULL)
        return;
    if (ungotten)
        error("Push back buffer is already full");
    ungotten = true;
    ungotten_buf = make_token(tok.type, tok.priv);
}

Token peek_token(void)
{
    Token tok = read_token();
    unget_token(tok);
    return tok;
}

Token read_token(void)
{
    if (ungotten) {
        ungotten = false;
        return make_token(ungotten_buf.type, ungotten_buf.priv);
    }
    return read_token_int();
}

TokenInfo get_current_token_info(void) {
    return curr_token_info;
}

void set_current_filename(const char *filename) {
    curr_filename = filename;
    curr_line = 1;
    curr_col = 1;
    last_line_length = 0;
}

#ifdef MINITEST_IMPLEMENTATION

#include "minitest.h"

TEST(test, lexer) {
    char infile[256];
    printf("file path: ");
    if (!fgets(infile, sizeof infile, stdin) || !freopen(strtok(infile, "\n"), "r", stdin))
        puts("open fail"), exit(1);
    
    set_current_filename(infile);
    
    while(true) {
        Token tok = read_token();
        TokenInfo info = get_current_token_info();
        printf("[%s:%d:%d:%d] ", info.file, info.line, info.col, info.len);
        
        switch(tok.type) {
            case TTYPE_NULL:                                                    return;
            case TTYPE_IDENT:   printf("TTYPE_IDENT: %s\n", get_ident(tok));    break;
            case TTYPE_PUNCT: {
                int punct = get_punct(tok);
                if(punct < 256) printf("TTYPE_PUNCT: %c\n", punct);
                else            printf("TTYPE_PUNCT: %d\n", punct);
                break;}
            case TTYPE_NUMBER:  printf("TTYPE_NUMBER: %s\n", get_number(tok));  break;
            case TTYPE_CHAR:    printf("TTYPE_CHAR: %c\n", get_char(tok));      break;
            case TTYPE_STRING:  printf("TTYPE_STRING: %s\n", get_strtok(tok));  break;
            default:                                                            break;
        }
    }
}

#endif /* MINITEST_IMPLEMENTATION */