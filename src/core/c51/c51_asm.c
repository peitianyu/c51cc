#include "c51_obj.h"
#include <ctype.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void *asm_alloc(size_t size)
{
    void *p = calloc(1, size);
    if (!p) {
        fprintf(stderr, "c51_asm: out of memory\n");
        exit(1);
    }
    return p;
}

static char *asm_strdup(const char *s)
{
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char *d = asm_alloc(len);
    memcpy(d, s, len);
    return d;
}

static void set_error(char **err, int *err_line, int line, const char *fmt, ...)
{
    if (!err || *err) return;
    char buf[512];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    *err = asm_strdup(buf);
    if (err_line) *err_line = line;
}

static char *trim(char *s)
{
    while (*s && isspace((unsigned char)*s)) s++;
    if (!*s) return s;
    char *end = s + strlen(s);
    while (end > s && isspace((unsigned char)*(end - 1)))
        *(--end) = '\0';
    return s;
}

static char *strip_comment(char *s)
{
    for (char *p = s; *p; ++p) {
        if (*p == ';' || *p == '#') {
            *p = '\0';
            break;
        }
        if (*p == '/' && *(p + 1) == '/') {
            *p = '\0';
            break;
        }
    }
    return s;
}

static bool is_ident(const char *s)
{
    if (!s || !*s) return false;
    if (!(isalpha((unsigned char)*s) || *s == '_'))
        return false;
    for (const char *p = s + 1; *p; ++p) {
        if (!(isalnum((unsigned char)*p) || *p == '_'))
            return false;
    }
    return true;
}

static bool parse_int(const char *s, int *out)
{
    if (!s || !*s) return false;
    char *end = NULL;
    long v = strtol(s, &end, 0);
    if (!end || *end != '\0')
        return false;
    *out = (int)v;
    return true;
}

static const char *section_kind_str(SectionKind kind)
{
    switch (kind) {
    case SEC_CODE:  return "CODE";
    case SEC_DATA:  return "DATA";
    case SEC_IDATA: return "IDATA";
    case SEC_XDATA: return "XDATA";
    case SEC_BIT:   return "BIT";
    case SEC_BDATA: return "BDATA";
    case SEC_PDATA: return "PDATA";
    default:        return "CODE";
    }
}

static const char *default_section_name(SectionKind kind)
{
    switch (kind) {
    case SEC_CODE:  return ".text";
    case SEC_DATA:  return ".data";
    case SEC_IDATA: return ".idata";
    case SEC_XDATA: return ".xdata";
    case SEC_BIT:   return ".bit";
    case SEC_BDATA: return ".bdata";
    case SEC_PDATA: return ".pdata";
    default:        return ".text";
    }
}

static SectionKind parse_section_kind(const char *s, bool *ok)
{
    if (ok) *ok = true;
    if (!s) { if (ok) *ok = false; return SEC_CODE; }
    if (!strcmp(s, "CODE")) return SEC_CODE;
    if (!strcmp(s, "DATA")) return SEC_DATA;
    if (!strcmp(s, "IDATA")) return SEC_IDATA;
    if (!strcmp(s, "XDATA")) return SEC_XDATA;
    if (!strcmp(s, "BIT")) return SEC_BIT;
    if (!strcmp(s, "BDATA")) return SEC_BDATA;
    if (!strcmp(s, "PDATA")) return SEC_PDATA;
    if (ok) *ok = false;
    return SEC_CODE;
}

static SectionKind parse_section_kind_relaxed(const char *s, bool *ok)
{
    if (!s) { if (ok) *ok = false; return SEC_CODE; }
    char buf[32];
    size_t n = strlen(s);
    if (n >= sizeof(buf)) n = sizeof(buf) - 1;
    for (size_t i = 0; i < n; ++i)
        buf[i] = (char)toupper((unsigned char)s[i]);
    buf[n] = '\0';
    return parse_section_kind(buf, ok);
}

static int ensure_section_by_kind(ObjFile *obj, SectionKind kind)
{
    int idx = 0;
    for (Iter it = list_iter(obj->sections); !iter_end(it); ++idx) {
        Section *sec = iter_next(&it);
        if (sec && sec->kind == kind)
            return idx;
    }
    const char *name = default_section_name(kind);
    return objfile_add_section(obj, name, kind, 0, 1);
}

static Symbol *find_symbol(ObjFile *obj, const char *name)
{
    for (Iter it = list_iter(obj->symbols); !iter_end(it);) {
        Symbol *sym = iter_next(&it);
        if (sym && sym->name && !strcmp(sym->name, name))
            return sym;
    }
    return NULL;
}

static void define_symbol(ObjFile *obj, const char *name, int section, int value)
{
    Symbol *sym = find_symbol(obj, name);
    if (!sym) {
        objfile_add_symbol(obj, name, SYM_LABEL, section, value, 0, SYM_FLAG_LOCAL);
        return;
    }
    sym->section = section;
    sym->value = value;
    sym->flags &= ~SYM_FLAG_EXTERN;
}

static void add_global_symbol(ObjFile *obj, const char *name)
{
    Symbol *sym = find_symbol(obj, name);
    if (!sym) {
        objfile_add_symbol(obj, name, SYM_LABEL, -1, 0, 0, SYM_FLAG_GLOBAL);
        return;
    }
    sym->flags |= SYM_FLAG_GLOBAL;
}

static void add_extern_symbol(ObjFile *obj, const char *name)
{
    Symbol *sym = find_symbol(obj, name);
    if (!sym) {
        objfile_add_symbol(obj, name, SYM_LABEL, -1, 0, 0, SYM_FLAG_EXTERN);
        return;
    }
    sym->flags |= SYM_FLAG_EXTERN;
    sym->section = -1;
}

static void parse_symbol_list(ObjFile *obj, char *args, void (*handler)(ObjFile *, const char *))
{
    char *p = args;
    while (p && *p) {
        char *comma = strchr(p, ',');
        if (comma) *comma = '\0';
        char *name = trim(p);
        if (*name)
            handler(obj, name);
        if (!comma) break;
        p = comma + 1;
    }
}

static int section_index_from_ptr(ObjFile *obj, Section *sec)
{
    int idx = 0;
    for (Iter it = list_iter(obj->sections); !iter_end(it); ++idx) {
        if (iter_next(&it) == sec)
            return idx;
    }
    return -1;
}

static AsmInstr *asm_instr_new(const char *op)
{
    AsmInstr *ins = asm_alloc(sizeof(AsmInstr));
    ins->op = asm_strdup(op);
    ins->args = make_list();
    ins->ssa = NULL;
    return ins;
}

static void asm_instr_add_arg(AsmInstr *ins, const char *arg)
{
    if (!ins || !arg) return;
    list_push(ins->args, asm_strdup(arg));
}

static void parse_data_list(char **err, int *err_line, ObjFile *obj, Section *sec, const char *args, int unit, int line)
{
    char *tmp = asm_strdup(args ? args : "");
    char *p = tmp;
    while (p && *p) {
        char *comma = strchr(p, ',');
        if (comma) *comma = '\0';
        char *tok = trim(p);
        if (*tok) {
            int val = 0;
            if (parse_int(tok, &val)) {
                if (unit == 1) {
                    unsigned char b = (unsigned char)(val & 0xFF);
                    section_append_bytes(sec, &b, 1);
                } else {
                    unsigned char b[2];
                    b[0] = (unsigned char)(val & 0xFF);
                    b[1] = (unsigned char)((val >> 8) & 0xFF);
                    section_append_bytes(sec, b, 2);
                }
            } else if (is_ident(tok)) {
                int offset = sec->bytes_len;
                int sec_index = section_index_from_ptr(obj, sec);
                if (unit == 1) {
                    unsigned char b = 0;
                    section_append_bytes(sec, &b, 1);
                    objfile_add_reloc(obj, sec_index, offset, RELOC_ABS8, tok, 0);
                } else {
                    unsigned char b[2] = {0, 0};
                    section_append_bytes(sec, b, 2);
                    objfile_add_reloc(obj, sec_index, offset, RELOC_ABS16, tok, 0);
                }
            } else {
                set_error(err, err_line, line, "invalid data token: %s", tok);
                break;
            }
        }
        if (!comma) break;
        p = comma + 1;
    }
    free(tmp);
}

ObjFile *c51_asm_from_text(const char *text, char **error, int *error_line)
{
    if (error) *error = NULL;
    if (error_line) *error_line = 0;

    ObjFile *obj = objfile_new();
    int cur_sec = -1;
    if (!text) return obj;

    char *buf = asm_strdup(text);
    int line_no = 0;
    for (char *line = buf; line; ) {
        char *next = strchr(line, '\n');
        if (next) *next = '\0';
        line_no++;

        char *work = strip_comment(line);
        work = trim(work);
        if (*work == '\0') {
            if (next) { line = next + 1; continue; }
            break;
        }

        size_t len = strlen(work);
        if (len > 0 && work[len - 1] == ':') {
            work[len - 1] = '\0';
            char *label = trim(work);
            if (cur_sec < 0)
                set_error(error, error_line, line_no, "label without section");
            else {
                Section *sec = objfile_get_section(obj, cur_sec);
                AsmInstr *ins = asm_instr_new(".label");
                asm_instr_add_arg(ins, label);
                list_push(sec->asminstrs, ins);
            }
            if (next) { line = next + 1; continue; }
            break;
        }

        if (work[0] == '.') {
            char *sp = work;
            while (*sp && !isspace((unsigned char)*sp)) sp++;
            if (*sp) *sp++ = '\0';
            char *dir = work;
            char *args = trim(sp);

            if (!strcmp(dir, ".section")) {
                char *name = NULL;
                char *kind_str = NULL;
                char *align_str = NULL;
                if (*args) {
                    name = args;
                    char *p = args;
                    while (*p && !isspace((unsigned char)*p)) p++;
                    if (*p) { *p++ = '\0'; }
                    kind_str = trim(p);
                    if (*kind_str) {
                        char *q = kind_str;
                        while (*q && !isspace((unsigned char)*q)) q++;
                        if (*q) { *q++ = '\0'; }
                        align_str = trim(q);
                    } else {
                        kind_str = NULL;
                    }
                }
                if (!name || !*name) {
                    set_error(error, error_line, line_no, "section name required");
                } else {
                    bool ok = true;
                    SectionKind kind = SEC_CODE;
                    if (kind_str && *kind_str)
                        kind = parse_section_kind(kind_str, &ok);
                    if (!ok) {
                        set_error(error, error_line, line_no, "unknown section kind: %s", kind_str);
                    } else {
                        int align = 1;
                        if (align_str && *align_str) {
                            if (!parse_int(align_str, &align))
                                set_error(error, error_line, line_no, "invalid align: %s", align_str);
                        }
                        if (!error || !*error)
                            cur_sec = objfile_add_section(obj, name, kind, 0, align);
                    }
                }
            } else if (!strcmp(dir, ".space")) {
                if (!*args) {
                    set_error(error, error_line, line_no, "space kind required");
                } else {
                    bool ok = true;
                    SectionKind kind = parse_section_kind_relaxed(args, &ok);
                    if (!ok) {
                        set_error(error, error_line, line_no, "unknown space kind: %s", args);
                    } else {
                        cur_sec = ensure_section_by_kind(obj, kind);
                    }
                }
            } else if (!strcmp(dir, ".global")) {
                if (!*args) {
                    set_error(error, error_line, line_no, "global needs symbols");
                } else {
                    parse_symbol_list(obj, args, add_global_symbol);
                }
            } else if (!strcmp(dir, ".extern")) {
                if (!*args) {
                    set_error(error, error_line, line_no, "extern needs symbols");
                } else {
                    parse_symbol_list(obj, args, add_extern_symbol);
                }
            } else if (!strcmp(dir, ".label")) {
                if (cur_sec < 0) {
                    set_error(error, error_line, line_no, "label without section");
                } else if (!*args) {
                    set_error(error, error_line, line_no, "label name required");
                } else {
                    Section *sec = objfile_get_section(obj, cur_sec);
                    define_symbol(obj, args, cur_sec, sec->bytes_len);
                }
            } else if (!strcmp(dir, ".db")) {
                if (cur_sec < 0) {
                    set_error(error, error_line, line_no, "db without section");
                } else {
                    Section *sec = objfile_get_section(obj, cur_sec);
                    parse_data_list(error, error_line, obj, sec, args, 1, line_no);
                }
            } else if (!strcmp(dir, ".dw")) {
                if (cur_sec < 0) {
                    set_error(error, error_line, line_no, "dw without section");
                } else {
                    Section *sec = objfile_get_section(obj, cur_sec);
                    parse_data_list(error, error_line, obj, sec, args, 2, line_no);
                }
            } else if (!strcmp(dir, ".ds")) {
                if (cur_sec < 0) {
                    set_error(error, error_line, line_no, "ds without section");
                } else if (!*args) {
                    set_error(error, error_line, line_no, "ds size required");
                } else {
                    int size = 0;
                    if (!parse_int(args, &size)) {
                        set_error(error, error_line, line_no, "invalid ds size: %s", args);
                    } else {
                        Section *sec = objfile_get_section(obj, cur_sec);
                        section_append_zeros(sec, size);
                    }
                }
            } else if (!strcmp(dir, ".org")) {
                if (cur_sec < 0) {
                    set_error(error, error_line, line_no, "org without section");
                } else if (!*args) {
                    set_error(error, error_line, line_no, "org value required");
                } else {
                    int addr = 0;
                    if (!parse_int(args, &addr)) {
                        set_error(error, error_line, line_no, "invalid org value: %s", args);
                    } else {
                        Section *sec = objfile_get_section(obj, cur_sec);
                        if (addr < sec->bytes_len) {
                            set_error(error, error_line, line_no, "org moves backward");
                        } else {
                            section_append_zeros(sec, addr - sec->bytes_len);
                        }
                    }
                }
            } else if (!strcmp(dir, ".interrupt")) {
                if (!*args) {
                    set_error(error, error_line, line_no, "interrupt id required");
                } else {
                    int irq = 0;
                    if (!parse_int(args, &irq))
                        set_error(error, error_line, line_no, "invalid interrupt id: %s", args);
                    else if (irq < 0 || irq > 7)
                        set_error(error, error_line, line_no, "interrupt id out of range: %d", irq);
                }
            } else if (!strcmp(dir, ".using")) {
                if (!*args) {
                    set_error(error, error_line, line_no, "using bank id required");
                } else {
                    int bank = 0;
                    if (!parse_int(args, &bank))
                        set_error(error, error_line, line_no, "invalid bank id: %s", args);
                    else if (bank < 0 || bank > 3)
                        set_error(error, error_line, line_no, "bank id out of range: %d", bank);
                }
            } else if (!strcmp(dir, ".reentrant")) {
                if (*args)
                    set_error(error, error_line, line_no, "reentrant takes no args");
            } else if (!strcmp(dir, ".end")) {
                break;
            } else {
                set_error(error, error_line, line_no, "unknown directive: %s", dir);
            }
        } else {
            if (cur_sec < 0) {
                set_error(error, error_line, line_no, "instruction without section");
            } else {
                char *p = work;
                while (*p && !isspace((unsigned char)*p)) p++;
                if (*p) *p++ = '\0';
                char *op = work;
                char *args = trim(p);
                if (!*op) {
                    set_error(error, error_line, line_no, "invalid instruction");
                } else {
                    Section *sec = objfile_get_section(obj, cur_sec);
                    AsmInstr *ins = asm_instr_new(op);
                    if (*args) {
                        char *tmp = asm_strdup(args);
                        char *q = tmp;
                        while (q && *q) {
                            char *comma = strchr(q, ',');
                            if (comma) *comma = '\0';
                            char *a = trim(q);
                            if (*a) asm_instr_add_arg(ins, a);
                            if (!comma) break;
                            q = comma + 1;
                        }
                        free(tmp);
                    }
                    list_push(sec->asminstrs, ins);
                }
            }
        }

        if (error && *error)
            break;
        if (next) { line = next + 1; continue; }
        break;
    }

    free(buf);
    if (error && *error) {
        objfile_free(obj);
        return NULL;
    }
    return obj;
}

static void write_symbol_visibility(FILE *fp, const ObjFile *obj)
{
    if (!fp || !obj) return;
    for (Iter it = list_iter(obj->symbols); !iter_end(it);) {
        Symbol *sym = iter_next(&it);
        if (!sym || !sym->name) continue;
        // SFR: section == -2, 输出 .equ 定义
        if (sym->section == -2) {
            if (sym->flags & SYM_FLAG_BIT) {
                fprintf(fp, ".equ %s, 0x%02X\n", sym->name, sym->value & 0xFF);
            } else {
                fprintf(fp, ".equ %s, 0x%02X\n", sym->name, sym->value & 0xFF);
            }
        } else {
            if (sym->flags & SYM_FLAG_GLOBAL)
                fprintf(fp, ".global %s\n", sym->name);
            if (sym->flags & SYM_FLAG_EXTERN)
                fprintf(fp, ".extern %s\n", sym->name);
        }
    }
}

static void write_labels_at(FILE *fp, const ObjFile *obj, int sec_index, int offset)
{
    for (Iter it = list_iter(obj->symbols); !iter_end(it);) {
        Symbol *sym = iter_next(&it);
        if (!sym || !sym->name) continue;
        if (sym->section == sec_index && sym->value == offset)
            fprintf(fp, ".label %s\n", sym->name);
    }
}

static bool is_func_symbol(const ObjFile *obj, const char *name)
{
    if (!obj || !name) return false;
    for (Iter it = list_iter(obj->symbols); !iter_end(it);) {
        Symbol *sym = iter_next(&it);
        if (sym && sym->name && sym->kind == SYM_FUNC && !strcmp(sym->name, name))
            return true;
    }
    return false;
}

int c51_write_asm(FILE *fp, const ObjFile *obj)
{
    if (!fp || !obj) return -1;
    write_symbol_visibility(fp, obj);
    for (Iter it = list_iter(obj->sections); !iter_end(it);) {
        Section *sec = iter_next(&it);
        if (!sec) continue;
        fprintf(fp, ".section %s %s %d\n", sec->name, section_kind_str(sec->kind), sec->align ? sec->align : 1);
        int sec_index = section_index_from_ptr((ObjFile *)obj, sec);
        bool has_asminstrs = (sec->asminstrs && sec->asminstrs->len > 0);
        bool printed_any = false;
        if (has_asminstrs) {
            for (Iter ait = list_iter(sec->asminstrs); !iter_end(ait);) {
                AsmInstr *ins = iter_next(&ait);
                if (!ins || !ins->op) continue;
                if (!strcmp(ins->op, ".label")) {
                    char *name = ins->args && ins->args->len > 0 ? list_get(ins->args, 0) : NULL;
                    if (name) {
                        if (printed_any && is_func_symbol(obj, name))
                            fprintf(fp, "\n");
                        fprintf(fp, ".label %s\n", name);
                        printed_any = true;
                    }
                    continue;
                }
                fprintf(fp, "    %s", ins->op);
                if (ins->args && ins->args->len > 0) {
                    fprintf(fp, " ");
                    int first = 1;
                    for (Iter ait2 = list_iter(ins->args); !iter_end(ait2);) {
                        char *arg = iter_next(&ait2);
                        fprintf(fp, "%s%s", first ? "" : ", ", arg ? arg : "");
                        first = 0;
                    }
                }
                if (ins->ssa && ins->ssa[0] != '\0') {
                    fprintf(fp, " ; %s", ins->ssa);
                }
                fprintf(fp, "\n");
                printed_any = true;
            }
        }
        if (!has_asminstrs && sec->bytes && sec->bytes_len > 0) {
            int i = 0;
            while (i < sec->bytes_len) {
                write_labels_at(fp, obj, sec_index, i);
                fprintf(fp, ".db ");
                int chunk = sec->bytes_len - i;
                if (chunk > 16) chunk = 16;
                for (int j = 0; j < chunk; ++j) {
                    fprintf(fp, "0x%02X%s", sec->bytes[i + j], (j + 1 == chunk) ? "" : ",");
                }
                fprintf(fp, "\n");
                i += chunk;
            }
        }
    }
    return 0;
}
