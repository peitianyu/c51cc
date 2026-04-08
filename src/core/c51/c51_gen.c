#include "c51_gen.h"
#include "c51_isel.h"
#include "c51_gen_global_var.h"
#include "c51_optimize.h"
#include "c51_encode.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ????????*/
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
    /* spill section: IDATA for small RAM, use MOV not MOVX.
     * spill 6 regs, MOVX costs 2 MOV cycles.
     * DATA range 128 bytes (0x00-0x7F).
     * Use XDATA for large: spill_use_xdata_for_large */
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
    
    // ???: ctx->obj ??????????
    
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

/* ????????? */
static void process_global_var(C51GenContext *ctx, GlobalVar *g)
{
    if (!g || !g->name || !ctx) return;

    if (handle_const_global_var(ctx, g)) return;
    if (handle_mmio_global_var(ctx, g)) return;
    if (handle_extern_global_var(ctx, g)) return;
    handle_normal_global_var(ctx, g);
}

/* ?????? */
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

/* ???????????*/
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

    if (getenv("C51CC_REGDEBUG"))
        fprintf(stderr, "[c51_gen] C51CC_NO_OPT=%s\n", getenv("C51CC_NO_OPT") ? getenv("C51CC_NO_OPT") : "NULL");
    if (!getenv("C51CC_NO_OPT")) c51_optimize(ctx, ctx->obj);
    c51_encode(ctx, ctx->obj);

    ObjFile* obj = ctx->obj;
    ctx->obj = NULL;  // ????????
    c51_ctx_free(ctx);
    
    return obj;
}

static char *dup_dirname(const char *path)
{
    const char *slash;
    const char *bslash;
    const char *sep;
    size_t len;
    char *dir;

    if (!path) return NULL;
    slash  = strrchr(path, '/');
    bslash = strrchr(path, '\\');
    /* ?????????????????Windows ??Unix ?????*/
    sep = (bslash && (!slash || bslash > slash)) ? bslash : slash;
    if (!sep) return strdup(".");

    len = (size_t)(sep - path);
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
    char *parent;
    char *fallback;

    dir = dup_dirname(source_path);
    if (!dir) return NULL;

    /* 1. Same directory as source file */
    path = join_path2(dir, "STARTUP.A51");
    if (path && file_exists(path)) { free(dir); return path; }
    free(path);

    /* 2. Parent directory of source file (common shared startup) */
    parent = dup_dirname(dir);
    free(dir);
    if (parent) {
        path = join_path2(parent, "STARTUP.A51");
        free(parent);
        if (path && file_exists(path)) return path;
        free(path);
    }

    /* 3. Current working directory */
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

/* -----------------------------------------------------------------------
 * Built-in C51 runtime library
 *
 * These functions replicate the Keil ?C? runtime routines so that the
 * generated hex is self-contained and does not require Keil libraries.
 *
 * ?C?SCDIV  ??signed 8-bit divide/modulo
 *   In:  A = dividend, B = divisor
 *   Out: A = quotient,  B = remainder  (C-style truncation-toward-zero)
 *
 * ?C?SIDIV  ??signed 16-bit divide/modulo
 *   In:  R6:R7 = dividend, R4:R5 = divisor
 *   Out: R6:R7 = quotient, R4:R5 = remainder
 *
 * ?C?UIDIV  ??unsigned 16-bit divide/modulo
 *   In:  R6:R7 = dividend, R4:R5 = divisor
 *   Out: R6:R7 = quotient, R4:R5 = remainder
 *
 * ?C?IMUL   ??16-bit multiply (signed and unsigned share the same low 16 bits)
 *   In:  R6:R7 = multiplicand, R4:R5 = multiplier
 *   Out: R6:R7 = product (low 16 bits)
 * ----------------------------------------------------------------------- */

/* Assembly source for each runtime function.
 * Uses only standard 8051 mnemonics that c51cc's encoder already handles. */

static const char *k_scdiv_v2 =
    /* ?C?SCDIV ??Signed 8-bit division (C99 truncate-toward-zero)
     * Entry:  A = dividend,  B = divisor
     * Exit:   A = quotient,  B = remainder
     * Uses: R0 (sign_quot), R1 (sign_num), R2 (temp)
     */
    "?C?SCDIV:\n"
    /* abs(dividend) ??A; sign ??R1 */
    "MOV R1, #0\n"
    "JNB ACC.7, Lsd_a\n"
    "CPL A\n"
    "INC A\n"
    "MOV R1, #1\n"
    "Lsd_a:\n"
    "MOV R2, A\n"            /* R2 = |dividend| */
    /* abs(divisor) via A; sign XOR ??R0 */
    "MOV R0, R1\n"           /* R0 = sign_num */
    "MOV A, B\n"
    "JNB ACC.7, Lsd_b\n"
    "CPL A\n"
    "INC A\n"
    "MOV B, A\n"             /* B = |divisor| */
    "MOV A, R0\n"
    "XRL A, #1\n"
    "MOV R0, A\n"            /* R0 ^= 1 */
    "Lsd_b:\n"
    "MOV A, R2\n"            /* A = |dividend| */
    "DIV AB\n"               /* A = |quotient|, B = |remainder| */
    /* negate quotient if R0 != 0 */
    "JZ Lsd_qz\n"
    "MOV R2, A\n"
    "MOV A, R0\n"
    "JZ Lsd_qpos\n"
    "MOV A, R2\n"
    "CPL A\n"
    "INC A\n"
    "MOV R2, A\n"
    "Lsd_qpos:\n"
    "MOV A, R2\n"
    "Lsd_qz:\n"
    /* negate remainder if R1 != 0 and remainder != 0 */
    "MOV R2, A\n"            /* save quotient */
    "MOV A, B\n"
    "JZ Lsd_rz\n"
    "MOV A, R1\n"
    "JZ Lsd_rpos\n"
    "MOV A, B\n"
    "CPL A\n"
    "INC A\n"
    "MOV B, A\n"
    "Lsd_rpos:\n"
    "Lsd_rz:\n"
    "MOV A, R2\n"
    "RET\n";

/* ?C?UIDIV ??Unsigned 16-bit division
 * Entry:  R6:R7 = dividend (R6=hi, R7=lo), R4:R5 = divisor (R4=hi, R5=lo)
 * Exit:   R6:R7 = quotient,  R4:R5 = remainder
 * Uses: R0, R1, R2, R3 as scratch (loop count = 16 iterations of shift-subtract)
 *
 * Algorithm: non-restoring long division (16-bit shift-and-subtract)
 *   rem = 0; quot = dividend
 *   for i=0..15:
 *     rem = (rem<<1) | (quot>>15)  -- shift msb of quot into rem
 *     quot <<= 1
 *     if rem >= divisor: rem -= divisor; quot |= 1
 *   quotient = quot; remainder = rem
 *
 * Register map:
 *   R6:R7  = quot (starts as dividend, becomes quotient)
 *   R2:R3  = rem  (starts 0)
 *   R4:R5  = divisor (preserved for comparison)
 *   R0     = loop count
 *   A, B   = scratch
 */
static const char *k_uidiv =
    "?C?UIDIV:\n"
    "MOV R2, #0\n"
    "MOV R3, #0\n"
    "MOV R0, #16\n"
    "CLR C\n"                 /* ensure carry=0 before first RLC */
    "Luid_loop:\n"
    /* shift rem:quot left by 1; carry-in for rem is MSB of quot_hi (R6.7) */
    "MOV A, R7\n"
    "RLC A\n"                 /* shift quot_lo left, MSB into C */
    "MOV R7, A\n"
    "MOV A, R6\n"
    "RLC A\n"                 /* shift quot_hi left, MSB into C, old C from quot_lo.MSB in */
    "MOV R6, A\n"
    "MOV A, R3\n"
    "RLC A\n"                 /* shift rem_lo left, carry-in = old quot_hi.MSB */
    "MOV R3, A\n"
    "MOV A, R2\n"
    "RLC A\n"
    "MOV R2, A\n"             /* rem_hi */
    /* compare rem (R2:R3) >= divisor (R4:R5) */
    "MOV A, R2\n"
    "CLR C\n"
    "SUBB A, R4\n"
    "JC Luid_lt\n"
    "JNZ Luid_ge\n"           /* R2 > R4: definitely >=; R2==R4: check low */
    "MOV A, R3\n"
    "CLR C\n"
    "SUBB A, R5\n"
    "JC Luid_lt\n"            /* R3 < R5: rem < div */
    "Luid_ge:\n"
    /* rem >= divisor: rem -= divisor; set LSB of quot */
    "MOV A, R3\n"
    "CLR C\n"
    "SUBB A, R5\n"
    "MOV R3, A\n"
    "MOV A, R2\n"
    "SUBB A, R4\n"
    "MOV R2, A\n"
    /* set LSB of quotient (R7) */
    "MOV A, R7\n"
    "ORL A, #1\n"
    "MOV R7, A\n"
    "Luid_lt:\n"
    "CLR C\n"                 /* clear carry before next RLC shift (SUBB may leave C=1) */
    "DJNZ R0, Luid_loop\n"
    /* R6:R7 = quotient; move remainder R2:R3 ??R4:R5 */
    "MOV R4, R2\n"
    "MOV R5, R3\n"
    "RET\n";

/* ?C?SIDIV ??Signed 16-bit division
 * Entry:  R6:R7 = dividend, R4:R5 = divisor
 * Exit:   R6:R7 = quotient, R4:R5 = remainder  (C99 trunc)
 * Uses: R0 (sign_quot), R1 (sign_num), A
 */
static const char *k_sidiv =
    "?C?SIDIV:\n"
    /* abs(dividend R6:R7); sign ??R1 */
    "MOV R1, #0\n"
    "MOV A, R6\n"
    "JNB ACC.7, Lsid_a\n"
    /* negate R6:R7 */
    "MOV A, R7\n"
    "CPL A\n"
    "ADD A, #1\n"
    "MOV R7, A\n"
    "MOV A, R6\n"
    "CPL A\n"
    "ADDC A, #0\n"
    "MOV R6, A\n"
    "MOV R1, #1\n"
    "Lsid_a:\n"
    /* abs(divisor R4:R5); sign XOR ??R0 */
    "MOV R0, R1\n"
    "MOV A, R4\n"
    "JNB ACC.7, Lsid_b\n"
    "MOV A, R5\n"
    "CPL A\n"
    "ADD A, #1\n"
    "MOV R5, A\n"
    "MOV A, R4\n"
    "CPL A\n"
    "ADDC A, #0\n"
    "MOV R4, A\n"
    "MOV A, R0\n"
    "XRL A, #1\n"
    "MOV R0, A\n"
    "Lsid_b:\n"
    /* save R0 (sign_quot flag) across UIDIV call, since UIDIV clobbers R0 */
    "MOV A, R0\n"
    "PUSH ACC\n"
    /* call unsigned division */
    "LCALL ?C?UIDIV\n"
    /* restore sign_quot flag */
    "POP ACC\n"
    "MOV R0, A\n"
    /* R6:R7 = |quotient|, R4:R5 = |remainder| */
    /* negate quotient if R0 != 0 */
    "MOV A, R0\n"
    "JZ Lsid_qp\n"
    "MOV A, R7\n"
    "CPL A\n"
    "ADD A, #1\n"
    "MOV R7, A\n"
    "MOV A, R6\n"
    "CPL A\n"
    "ADDC A, #0\n"
    "MOV R6, A\n"
    "Lsid_qp:\n"
    /* negate remainder if R1 != 0 (same sign as dividend) */
    "MOV A, R1\n"
    "JZ Lsid_rp\n"
    /* check if remainder is zero */
    "MOV A, R4\n"
    "ORL A, R5\n"
    "JZ Lsid_rp\n"
    "MOV A, R5\n"
    "CPL A\n"
    "ADD A, #1\n"
    "MOV R5, A\n"
    "MOV A, R4\n"
    "CPL A\n"
    "ADDC A, #0\n"
    "MOV R4, A\n"
    "Lsid_rp:\n"
    "RET\n";

/* ?C?IMUL ??16-bit multiply (low 16 bits; same for signed & unsigned)
 * Entry:  R6:R7 = a (a_hi=R6, a_lo=R7), R4:R5 = b (b_hi=R4, b_lo=R5)
 * Exit:   R6:R7 = product low 16 bits
 * Uses: A, B, R0, R1
 *
 * product = a_lo*b_lo + (a_hi*b_lo + a_lo*b_hi)<<8  (only lo 16 bits needed)
 */
static const char *k_imul =
    "?C?IMUL:\n"
    /* a_lo*b_lo -> R0 (lo byte), carry (hi byte) */
    "MOV A, R7\n"
    "MOV B, R5\n"
    "MUL AB\n"               /* A=lo, B=hi of a_lo*b_lo */
    "MOV R0, A\n"            /* save lo */
    "MOV R1, B\n"            /* save hi (= partial carry into byte 1) */
    /* a_hi*b_lo -> contribute to byte 1 only */
    "MOV A, R6\n"
    "MOV B, R5\n"
    "MUL AB\n"               /* A = a_hi*b_lo (lo byte; hi byte overflows 16-bit, discard) */
    "ADD A, R1\n"            /* add partial hi */
    "MOV R1, A\n"            /* R1 = byte1 so far */
    /* a_lo*b_hi -> contribute to byte 1 only */
    "MOV A, R7\n"
    "MOV B, R4\n"
    "MUL AB\n"
    "ADD A, R1\n"
    /* Result: A = byte1, R0 = byte0 */
    "MOV R6, A\n"            /* R6 = hi byte */
    "MOV R7, R0\n"           /* R7 = lo byte */
    "RET\n";

/* ?C?ULDIV ??Unsigned 32-bit division / modulo
 * Entry:  R4:R5:R6:R7 = dividend (R4=MSB, R7=LSB)
 *         R0:R1:R2:R3 = divisor  (R0=MSB, R3=LSB)
 * Exit:   R4:R5:R6:R7 = quotient
 *         R0:R1:R2:R3 = remainder
 *
 * Algorithm: 32-bit shift-and-subtract long division (32 iterations)
 * Scratch:   IDATA bytes at 0x20-0x27 used as 8-byte rem+quot buffer,
 *            but here we just use A and B as temporaries in-loop.
 *
 * Register layout during the loop:
 *   R4:R5:R6:R7 = quot (starts as dividend, becomes quotient)
 *   20H:21H:22H:23H = rem (4 bytes in direct-access RAM; starts 0)
 *   R0:R1:R2:R3 = divisor (preserved)
 *   24H = loop counter (32)
 *
 * Because 8051 has only 8 registers (R0-R7) and we need 4 for divisor +
 * 4 for quot/dividend, remainder lives in direct-access internal RAM.
 */
/* ?C?ULDIV ??Unsigned 32-bit division / modulo
 * Entry:  R4:R5:R6:R7 = dividend (R4=MSB, R7=LSB)
 *         R0:R1:R2:R3 = divisor  (R0=MSB, R3=LSB)
 * Exit:   R4:R5:R6:R7 = quotient
 *         R0:R1:R2:R3 = remainder
 * Uses idata 20H..24H as scratch:
 *   20H..23H = remainder (20H=MSB, 23H=LSB)
 *   24H      = loop counter (32 iterations)
 * All operations use A as temp; only standard A-src ALU forms used.
 */
static const char *k_uldiv =
    "?C?ULDIV:\n"
    /* remainder = 0 */
    "MOV 20H, #0\n"
    "MOV 21H, #0\n"
    "MOV 22H, #0\n"
    "MOV 23H, #0\n"
    "MOV 24H, #32\n"
    "Luld_loop:\n"
    /* Shift [rem | quot/dividend] left by 1 bit.
     * Order: CLR C, then RLC from LSB of quot (R7) up through MSB of rem (20H).
     * After 32 iterations quot (R4..R7) contains the quotient bits. */
    "CLR C\n"
    "MOV A, R7\n"   "RLC A\n"   "MOV R7, A\n"
    "MOV A, R6\n"   "RLC A\n"   "MOV R6, A\n"
    "MOV A, R5\n"   "RLC A\n"   "MOV R5, A\n"
    "MOV A, R4\n"   "RLC A\n"   "MOV R4, A\n"
    "MOV A, 23H\n"  "RLC A\n"   "MOV 23H, A\n"
    "MOV A, 22H\n"  "RLC A\n"   "MOV 22H, A\n"
    "MOV A, 21H\n"  "RLC A\n"   "MOV 21H, A\n"
    "MOV A, 20H\n"  "RLC A\n"   "MOV 20H, A\n"
    /* Compare rem (20H:21H:22H:23H) with divisor (R0:R1:R2:R3).
     * We do rem - divisor using SUBB; if borrow (C=1) rem < divisor. */
    "MOV A, 23H\n"
    "CLR C\n"
    "SUBB A, R3\n"
    "MOV A, 22H\n"
    "SUBB A, R2\n"
    "MOV A, 21H\n"
    "SUBB A, R1\n"
    "MOV A, 20H\n"
    "SUBB A, R0\n"
    /* C=1 means rem < divisor, skip subtraction */
    "JC Luld_lt\n"
    /* rem >= divisor: rem -= divisor, set bit0 of R7 */
    "MOV A, 23H\n"
    "CLR C\n"
    "SUBB A, R3\n"
    "MOV 23H, A\n"
    "MOV A, 22H\n"
    "SUBB A, R2\n"
    "MOV 22H, A\n"
    "MOV A, 21H\n"
    "SUBB A, R1\n"
    "MOV 21H, A\n"
    "MOV A, 20H\n"
    "SUBB A, R0\n"
    "MOV 20H, A\n"
    /* Set quotient bit (R7 bit 0) ??the last RLC already shifted in a 0 there */
    "MOV A, R7\n"
    "ORL A, #1\n"
    "MOV R7, A\n"
    "Luld_lt:\n"
    "DJNZ 24H, Luld_loop\n"
    /* Quotient in R4:R5:R6:R7; copy remainder from 20H..23H to R0:R1:R2:R3 */
    "MOV A, 20H\n"  "MOV R0, A\n"
    "MOV A, 21H\n"  "MOV R1, A\n"
    "MOV A, 22H\n"  "MOV R2, A\n"
    "MOV A, 23H\n"  "MOV R3, A\n"
    "RET\n";

/* ?C?SLDIV ??Signed 32-bit division / modulo (C99: truncate toward zero)
 * Entry/Exit convention same as ?C?ULDIV.
 * Uses 25H = sign_of_quotient, 26H = sign_of_dividend (= sign_of_remainder).
 */
static const char *k_sldiv =
    "?C?SLDIV:\n"
    "MOV 25H, #0\n"
    "MOV 26H, #0\n"
    /* Check sign of dividend (R4 MSB) */
    "MOV A, R4\n"
    "JNB ACC.7, Lsld_divpos\n"
    /* Negate dividend: R4:R5:R6:R7 = -R4:R5:R6:R7 (two's complement) */
    "MOV A, R7\n"  "CPL A\n"  "ADD A, #1\n"  "MOV R7, A\n"
    "MOV A, R6\n"  "CPL A\n"  "ADDC A, #0\n" "MOV R6, A\n"
    "MOV A, R5\n"  "CPL A\n"  "ADDC A, #0\n" "MOV R5, A\n"
    "MOV A, R4\n"  "CPL A\n"  "ADDC A, #0\n" "MOV R4, A\n"
    "MOV 25H, #1\n"
    "MOV 26H, #1\n"
    "Lsld_divpos:\n"
    /* Check sign of divisor (R0 MSB) */
    "MOV A, R0\n"
    "JNB ACC.7, Lsld_dvsor_pos\n"
    /* Negate divisor: R0:R1:R2:R3 = -R0:R1:R2:R3 */
    "MOV A, R3\n"  "CPL A\n"  "ADD A, #1\n"  "MOV R3, A\n"
    "MOV A, R2\n"  "CPL A\n"  "ADDC A, #0\n" "MOV R2, A\n"
    "MOV A, R1\n"  "CPL A\n"  "ADDC A, #0\n" "MOV R1, A\n"
    "MOV A, R0\n"  "CPL A\n"  "ADDC A, #0\n" "MOV R0, A\n"
    /* Flip quotient sign */
    "MOV A, 25H\n"
    "XRL A, #1\n"
    "MOV 25H, A\n"
    "Lsld_dvsor_pos:\n"
    /* Perform unsigned division */
    "LCALL ?C?ULDIV\n"
    /* Result: quot in R4:R5:R6:R7, rem in R0:R1:R2:R3 */
    /* Negate quotient if 25H != 0 */
    "MOV A, 25H\n"
    "JZ Lsld_qpos\n"
    "MOV A, R7\n"  "CPL A\n"  "ADD A, #1\n"  "MOV R7, A\n"
    "MOV A, R6\n"  "CPL A\n"  "ADDC A, #0\n" "MOV R6, A\n"
    "MOV A, R5\n"  "CPL A\n"  "ADDC A, #0\n" "MOV R5, A\n"
    "MOV A, R4\n"  "CPL A\n"  "ADDC A, #0\n" "MOV R4, A\n"
    "Lsld_qpos:\n"
    /* Negate remainder if 26H != 0 and remainder != 0 */
    "MOV A, 26H\n"
    "JZ Lsld_rpos\n"
    /* Check if remainder is zero */
    "MOV A, R0\n"  "ORL A, R1\n"  "ORL A, R2\n"  "ORL A, R3\n"
    "JZ Lsld_rpos\n"
    "MOV A, R3\n"  "CPL A\n"  "ADD A, #1\n"  "MOV R3, A\n"
    "MOV A, R2\n"  "CPL A\n"  "ADDC A, #0\n" "MOV R2, A\n"
    "MOV A, R1\n"  "CPL A\n"  "ADDC A, #0\n" "MOV R1, A\n"
    "MOV A, R0\n"  "CPL A\n"  "ADDC A, #0\n" "MOV R0, A\n"
    "Lsld_rpos:\n"
    "RET\n";

/* Check whether any relocation in obj references the given symbol name */
static int obj_needs_symbol(const ObjFile *obj, const char *sym)
{
    if (!obj || !sym) return 0;
    for (Iter it = list_iter(obj->relocs); !iter_end(it);) {
        Reloc *rel = iter_next(&it);
        if (rel && rel->symbol && strcmp(rel->symbol, sym) == 0) return 1;
    }
    return 0;
}

/* Build a runtime ObjFile containing the assembly for the given function */
static ObjFile *build_runtime_obj(const char *sym_name, const char *asm_src)
{
    ObjFile *obj;
    Section *sec;
    int sec_idx;

    if (!sym_name || !asm_src) return NULL;

    obj = obj_new();
    sec_idx = obj_add_section(obj, sym_name, SEC_CODE, 0, 1);
    sec = obj_get_section(obj, sec_idx);
    if (!sec) { obj_free(obj); return NULL; }

    c51_emit_asm_text(sec, asm_src);
    /* Add a global symbol for the entry point (offset 0 in this section) */
    obj_add_symbol(obj, sym_name, SYM_FUNC, sec_idx, 0, 0, SYM_FLAG_GLOBAL);
    /* Encode the assembly into bytes */
    c51_encode(NULL, obj);
    return obj;
}

/* Inject any needed runtime objects into the link list.
 * Returns 1 if any were added. */
static int inject_runtime_libs(const ObjFile *main_obj, List *objs)
{
    int added = 0;

    /* Table of (symbol_name, asm_source) pairs */
    struct { const char *sym; const char *src; } table[] = {
        { "?C?SCDIV", k_scdiv_v2 },
        { "?C?UIDIV", k_uidiv    },
        { "?C?SIDIV", k_sidiv    },
        { "?C?IMUL",  k_imul     },
        { "?C?ULDIV", k_uldiv    },
        { "?C?SLDIV", k_sldiv    },
    };
    int n = (int)(sizeof(table) / sizeof(table[0]));

    for (int i = 0; i < n; i++) {
        if (!obj_needs_symbol(main_obj, table[i].sym)) continue;
        ObjFile *rt = build_runtime_obj(table[i].sym, table[i].src);
        if (rt) { list_push(objs, rt); added++; }
    }
    return added;
}

ObjFile *c51_link_startup(const char *source_path, ObjFile *main_obj)
{
    char *startup_path;
    ObjFile *startup_obj = NULL;
    ObjFile *linked;
    List objs = EMPTY_LIST;

    if (!main_obj) return main_obj;

    /* Always inject needed runtime functions first */
    inject_runtime_libs(main_obj, &objs);

    /* ?C?SIDIV calls ?C?UIDIV internally ??if SIDIV was added, ensure UIDIV is present too */
    {
        int has_sidiv = 0, has_uidiv = 0;
        for (Iter it = list_iter(&objs); !iter_end(it);) {
            ObjFile *o = iter_next(&it);
            if (!o) continue;
            for (Iter sit = list_iter(o->symbols); !iter_end(sit);) {
                Symbol *s = iter_next(&sit);
                if (s && s->name) {
                    if (strcmp(s->name, "?C?SIDIV") == 0) has_sidiv = 1;
                    if (strcmp(s->name, "?C?UIDIV") == 0) has_uidiv = 1;
                }
            }
        }
        if (has_sidiv && !has_uidiv) {
            ObjFile *rt = build_runtime_obj("?C?UIDIV", k_uidiv);
            if (rt) list_push(&objs, rt);
        }
    }

    /* ?C?SLDIV calls ?C?ULDIV internally ??if SLDIV was added, ensure ULDIV is present too */
    {
        int has_sldiv = 0, has_uldiv = 0;
        for (Iter it = list_iter(&objs); !iter_end(it);) {
            ObjFile *o = iter_next(&it);
            if (!o) continue;
            for (Iter sit = list_iter(o->symbols); !iter_end(sit);) {
                Symbol *s = iter_next(&sit);
                if (s && s->name) {
                    if (strcmp(s->name, "?C?SLDIV") == 0) has_sldiv = 1;
                    if (strcmp(s->name, "?C?ULDIV") == 0) has_uldiv = 1;
                }
            }
        }
        if (has_sldiv && !has_uldiv) {
            ObjFile *rt = build_runtime_obj("?C?ULDIV", k_uldiv);
            if (rt) list_push(&objs, rt);
        }
    }

    /* Optional startup file */
    if (source_path) {
        startup_path = find_startup_path(source_path);
        if (startup_path) {
            startup_obj = compile_startup_file(startup_path);
            free(startup_path);
        }
    }

    /* startup must come first so its code lands at address 0x0000,
     * then main, then runtime libs. */
    {
        List ordered = EMPTY_LIST;
        if (startup_obj) list_push(&ordered, startup_obj);
        list_push(&ordered, main_obj);
        /* append runtime libs that were collected in objs */
        for (Iter it = list_iter(&objs); !iter_end(it);) {
            ObjFile *o = iter_next(&it);
            if (o) list_push(&ordered, o);
        }
        while (!list_empty(&objs)) list_shift(&objs);
        objs = ordered;
    }

    if (objs.len <= 1) {
        /* Only main_obj ??nothing to link */
        while (!list_empty(&objs)) list_shift(&objs);
        return main_obj;
    }

    linked = obj_link(&objs);

    /* Free runtime and startup objects (main_obj is owned by caller) */
    {
        List to_free = EMPTY_LIST;
        for (Iter it = list_iter(&objs); !iter_end(it);) {
            ObjFile *o = iter_next(&it);
            if (o && o != main_obj) list_push(&to_free, o);
        }
        for (Iter it = list_iter(&to_free); !iter_end(it);) {
            obj_free(iter_next(&it));
        }
        while (!list_empty(&to_free)) list_shift(&to_free);
    }
    while (!list_empty(&objs)) list_shift(&objs);

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

    // //ssa_optimize(b->unit, OPT_O1);
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


