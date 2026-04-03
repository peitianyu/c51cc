#include "c51_gen.h"
#include <string.h>
#include <stdlib.h>

/* 检查 name 是否在任意 CODE 段的指令参数中出现 */
static bool symbol_is_referenced(const ObjFile *obj, const char *name)
{
    if (!obj || !name) return false;
    for (Iter sit = list_iter(obj->sections); !iter_end(sit);) {
        Section *sec = iter_next(&sit);
        if (!sec || sec->kind != SEC_CODE || !sec->asminstrs) continue;
        for (Iter ait = list_iter(sec->asminstrs); !iter_end(ait);) {
            AsmInstr *ins = iter_next(&ait);
            if (!ins || !ins->args) continue;
            for (Iter argit = list_iter(ins->args); !iter_end(argit);) {
                const char *arg = iter_next(&argit);
                if (arg && strstr(arg, name)) return true;
            }
        }
    }
    return false;
}

static bool is_unused_local_spill_symbol(const ObjFile *obj, const Symbol *sym)
{
    if (!obj || !sym || !sym->name) return false;
    if (!(sym->flags & SYM_FLAG_LOCAL)) return false;
    if (strncmp(sym->name, "__spill_", 8) != 0) return false;
    return !symbol_is_referenced(obj, sym->name);
}

static const char* section_kind_name(SectionKind kind)
{
    switch (kind) {
        case SEC_CODE:   return "CODE";
        case SEC_DATA:   return "DATA";
        case SEC_IDATA:  return "IDATA";
        case SEC_XDATA:  return "XDATA";
        case SEC_BIT:    return "BIT";
        case SEC_BDATA:  return "BDATA";
        case SEC_PDATA:  return "PDATA";
        default:         return "UNKNOWN";
    }
}

static const char* symbol_kind_name(SymbolKind kind)
{
    switch (kind) {
        case SYM_FUNC:   return "FUNC";
        case SYM_DATA:   return "DATA";
        case SYM_LABEL:  return "LABEL";
        default:         return "UNKNOWN";
    }
}

static void print_asminstr(FILE *fp, AsmInstr *ins)
{
    if (!ins) return;
    
    if (ins->op && ins->op[strlen(ins->op)-1] == ':') {
        fprintf(fp, "%s\n", ins->op);
        return;
    }
    
    if (ins->op && ins->op[0] == ';') {
        if (ins->ssa) {
            fprintf(fp, "        %s\n", ins->ssa);
        } else {
            fprintf(fp, "        %s\n", ins->op);
        }
        return;
    }

    char instrbuf[256];
    instrbuf[0] = '\0';
    size_t pos = 0;

    if (ins->op) {
        pos += snprintf(instrbuf + pos, sizeof(instrbuf) - pos, "%s", ins->op);
    }

    if (ins->args && ins->args->len > 0) {
        if (pos + 1 < sizeof(instrbuf)) pos += snprintf(instrbuf + pos, sizeof(instrbuf) - pos, " ");
        for (Iter it = list_iter(ins->args); !iter_end(it);) {
            char *arg = iter_next(&it);
            if (pos < sizeof(instrbuf)) pos += snprintf(instrbuf + pos, sizeof(instrbuf) - pos, "%s", arg);
            if (!iter_end(it) && pos < sizeof(instrbuf)) pos += snprintf(instrbuf + pos, sizeof(instrbuf) - pos, ", ");
        }
    }

    /* indent then instruction field (fixed width) */
    fprintf(fp, "        %-24s", instrbuf);

    if (ins->ssa) {
        const char *s = ins->ssa;
        while (*s == ' ' || *s == '\t') s++;

        /* 跳过可能的注释前缀 ';' */
        if (*s == ';') s++;
        while (*s == ' ' || *s == '\t') s++;

        /* 如果 ssa 字符串以指令文本开头，跳过重复部分 */
        size_t instr_len = strlen(instrbuf);
        if (instr_len > 0 && strncmp(s, instrbuf, instr_len) == 0) {
            s += instr_len;
            while (*s == ' ' || *s == '\t' || *s == ',' ) s++;
        }

        /* Only print SSA comment if there is non-whitespace content left */
        const char *t = s;
        while (*t == ' ' || *t == '\t') t++;
        if (*t != '\0') {
            fprintf(fp, "; %s", s);
        }
    }

    fprintf(fp, "\n");
}

static void print_data_section(FILE *fp, Section *sec)
{
    if (!sec || sec->bytes_len == 0) return;
    
    fprintf(fp, "; Data bytes (%d bytes):\n", sec->bytes_len);
    
    for (int i = 0; i < sec->bytes_len; i += 16) {
        fprintf(fp, "        DB      ");
        for (int j = 0; j < 16 && (i + j) < sec->bytes_len; j++) {
            if (j > 0) fprintf(fp, ", ");
            fprintf(fp, "0%02XH", sec->bytes[i + j]);
        }
        fprintf(fp, "\n");
    }
}

static int cmp_sym_symbols(const void *a, const void *b);

static void print_section_with_symbols(FILE *fp, Section *sec, const ObjFile *obj, int sec_idx)
{
    if (!sec) return;

    int count = 0;
    for (Iter it = list_iter(obj->symbols); !iter_end(it);) {
        Symbol *sym = iter_next(&it);
        if (sym && sym->section == sec_idx && !is_unused_local_spill_symbol(obj, sym)) count++;
    }
    if (count == 0) {
        print_data_section(fp, sec);
        return;
    }

    Symbol **arr = malloc(sizeof(Symbol*) * count);
    int i = 0;
    for (Iter it = list_iter(obj->symbols); !iter_end(it);) {
        Symbol *sym = iter_next(&it);
        if (sym && sym->section == sec_idx && !is_unused_local_spill_symbol(obj, sym)) arr[i++] = sym;
    }

    qsort(arr, count, sizeof(Symbol*), cmp_sym_symbols);

    for (int k = 0; k < count; k++) {
        Symbol *s = arr[k];
        int off = s->value;
        int sz = s->size;
        if (!s->name) continue;
        /* Only print a standalone symbol label if it has a non-zero size.
         * Labels for functions and other symbols without a size are emitted
         * by the assembly instruction list; printing them twice creates
         * redundant empty labels in the listing. */
        if (sz <= 0) continue;

        fprintf(fp, "%s:\n", s->name);
        for (int ioff = off; ioff < off + sz; ioff += 16) {
            fprintf(fp, "        DB      ");
            for (int j = 0; j < 16 && (ioff + j) < off + sz; j++) {
                if (j > 0) fprintf(fp, ", ");
                fprintf(fp, "0%02XH", sec->bytes[ioff + j]);
            }
            fprintf(fp, "\n");
        }
    }

    free(arr);
}

static int cmp_sym_symbols(const void *a, const void *b)
{
    Symbol *sa = *(Symbol**)a; Symbol *sb = *(Symbol**)b;
    return sa->value - sb->value;
}

int c51_write_asm(FILE *fp, const ObjFile *obj)
{
    if (!fp || !obj) return -1;
    
    fprintf(fp, "; Generated by C51CC\n");
    fprintf(fp, ";======================================\n\n");
    
    fprintf(fp, "; Symbol Table:\n");
    fprintf(fp, ";--------------------------------------\n");
    if (obj->symbols && obj->symbols->len > 0) {
        for (Iter it = list_iter(obj->symbols); !iter_end(it);) {
            Symbol *sym = iter_next(&it);
            if (!sym) continue;
            if (is_unused_local_spill_symbol(obj, sym)) continue;

            if (sym->section < 0) {
                if (sym->flags & SYM_FLAG_BIT) {
                    int base = sym->value & ~0x7;
                    int bit = sym->value & 0x7;
                    fprintf(fp, "; SBIT %s = 0x%02X.%d\n", sym->name, base, bit);
                    continue;
                } else if (sym->size == 1) {
                    fprintf(fp, "; SFR %s = 0x%02X\n", sym->name, sym->value);
                    continue;
                } else if (sym->size == 2) {
                    fprintf(fp, "; SFR16 %s = 0x%04X\n", sym->name, sym->value);
                    continue;
                }
            }

            const char *kind_text = symbol_kind_name(sym->kind);
            if (sym->kind == SYM_DATA && sym->section >= 0) {
                Section *s = obj_get_section(obj, sym->section);
                if (s) kind_text = section_kind_name(s->kind);
            }

            fprintf(fp, "; %s: %s", sym->name, kind_text);
            if (sym->section >= 0) {
                fprintf(fp, " [sec=%d, off=%d, size=%d]", 
                        sym->section, sym->value, sym->size);
            } else {
                fprintf(fp, " [absolute=%d, size=%d]", sym->value, sym->size);
            }
            
            if (sym->flags & SYM_FLAG_GLOBAL) fprintf(fp, " GLOBAL");
            if (sym->flags & SYM_FLAG_EXTERN) fprintf(fp, " EXTERN");
            if (sym->flags & SYM_FLAG_LOCAL)  fprintf(fp, " LOCAL");
            fprintf(fp, "\n");
        }
    }
    fprintf(fp, "\n");

    /* 一次遍历所有 section：先输出非代码段，再输出代码段 */
    int sec_idx = 0;
    for (Iter it = list_iter(obj->sections); !iter_end(it); sec_idx++) {
        Section *sec = iter_next(&it);
        if (!sec || sec->kind == SEC_CODE) continue;
        print_section_with_symbols(fp, sec, obj, sec_idx);
    }

    sec_idx = 0;
    for (Iter it = list_iter(obj->sections); !iter_end(it); sec_idx++) {
        Section *sec = iter_next(&it);
        if (!sec || sec->kind != SEC_CODE) continue;

        if (sec->bytes_len > 0)
            print_section_with_symbols(fp, sec, obj, sec_idx);

        if (sec->asminstrs) {
            for (Iter ait = list_iter(sec->asminstrs); !iter_end(ait);) {
                AsmInstr *ins = iter_next(&ait);
                print_asminstr(fp, ins);
            }
        }
    }
    
    if (obj->relocs && obj->relocs->len > 0) {
        fprintf(fp, ";======================================\n");
        fprintf(fp, "; Relocations:\n");
        fprintf(fp, ";--------------------------------------\n");
        for (Iter it = list_iter(obj->relocs); !iter_end(it);) {
            Reloc *rel = iter_next(&it);
            if (!rel) continue;
            
            const char* kind_str = "?";
            switch (rel->kind) {
                case RELOC_ABS8:  kind_str = "ABS8"; break;
                case RELOC_ABS16: kind_str = "ABS16"; break;
                case RELOC_REL8:  kind_str = "REL8"; break;
                case RELOC_REL16: kind_str = "REL16"; break;
            }
            
            fprintf(fp, "; sec=%d, off=%d, kind=%s, sym=%s, addend=%d\n",
                    rel->section, rel->offset, kind_str, rel->symbol, rel->addend);
        }
    }
    
    fprintf(fp, "\n; End of file\n");
    return 0;
}

int c51_write_hex(FILE *fp, const ObjFile *obj)
{
    int code_base = 0;
    int sec_idx = 0;

    if (!fp || !obj) return -1;

    for (Iter it = list_iter(obj->sections); !iter_end(it); sec_idx++) {
        Section *sec = iter_next(&it);
        if (!sec || sec->kind != SEC_CODE || sec->bytes_len <= 0) continue;

        if (sec->align > 1) {
            code_base = ((code_base + sec->align - 1) / sec->align) * sec->align;
        }

        for (int offset = 0; offset < sec->bytes_len; offset += 16) {
            unsigned address = (unsigned)(code_base + offset);
            unsigned chunk = (unsigned)((sec->bytes_len - offset) > 16 ? 16 : (sec->bytes_len - offset));
            unsigned sum;

            /* 8051 addresses fit in 16 bits — no Extended Linear Address
               (type 04) record is needed.  Many simple loaders / emulators
               only accept type 00 (data) and type 01 (EOF) records and
               reject type 04, so we intentionally omit it. */

            sum = chunk + ((address >> 8) & 0xFF) + (address & 0xFF);
            fprintf(fp, ":%02X%04X00", chunk, address & 0xFFFF);
            for (unsigned i = 0; i < chunk; i++) {
                unsigned char byte = sec->bytes[offset + (int)i];
                sum += byte;
                fprintf(fp, "%02X", byte);
            }
            fprintf(fp, "%02X\n", (unsigned char)((-((int)sum)) & 0xFF));
        }

        code_base += sec->bytes_len;
    }

    fprintf(fp, ":00000001FF\n");
    return 0;
}
