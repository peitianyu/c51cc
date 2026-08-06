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

/* 数据段注入: 每段一个 MOVC 复制循环 (最多 255 字节/段) */
typedef struct { int dest; int src; int len; const unsigned char *bytes; } HexDataSeg;

/* 段内最小符号偏移 = 数据起点 (跳过 reserve 空洞/寄存器区) */
static int data_seg_start(const ObjFile *obj, int sec_idx)
{
    int min_off = -1;
    for (Iter it = list_iter(obj->symbols); !iter_end(it);) {
        Symbol *sym = iter_next(&it);
        if (sym && sym->section == sec_idx && sym->size > 0) {
            if (min_off < 0 || sym->value < min_off) min_off = sym->value;
        }
    }
    return min_off;
}

static void hex_emit_line(FILE *fp, unsigned address, const unsigned char *bytes, int len)
{
    while (len > 0) {
        int chunk = len > 16 ? 16 : len;
        int sum = chunk + ((address >> 8) & 0xFF) + (address & 0xFF);
        fprintf(fp, ":%02X%04X00", chunk, address & 0xFFFF);
        for (int i = 0; i < chunk; i++) {
            sum += bytes[i];
            fprintf(fp, "%02X", bytes[i]);
        }
        fprintf(fp, "%02X\n", (unsigned char)((-sum) & 0xFF));
        address += chunk;
        bytes += chunk;
        len -= chunk;
    }
}

int c51_write_hex(FILE *fp, const ObjFile *obj)
{
    if (!fp || !obj) return -1;

    /* ── 第一遍: CODE 总长, 启动段 LJMP 目标 ── */
    int code_total = 0;
    int main_addr = -1;
    int startup_ljmp_sec = -1, startup_ljmp_off = -1;
    int sec_idx = 0;
    for (Iter it = list_iter(obj->sections); !iter_end(it); sec_idx++) {
        Section *sec = iter_next(&it);
        if (!sec || sec->kind != SEC_CODE || sec->bytes_len <= 0) continue;
        if (sec->align > 1)
            code_total = ((code_total + sec->align - 1) / sec->align) * sec->align;
        if (main_addr < 0 && sec->bytes_len >= 6) {
            /* 启动段: MOV SP,#07H (75 81 07) + LJMP (02 hh ll) 在段内搜索 */
            const unsigned char *b = sec->bytes;
            int n = sec->bytes_len;
            for (int i = 0; i + 5 < n; i++) {
                if (b[i] == 0x75 && b[i+1] == 0x81 && b[i+2] == 0x07 && b[i+3] == 0x02) {
                    main_addr = (b[i+4] << 8) | b[i+5]; /* LJMP 高字节在前 */
                    startup_ljmp_sec = sec_idx;
                    startup_ljmp_off = i + 4;
                    break;
                }
            }
        }
        code_total += sec->bytes_len;
    }

    /* ── 收集需初始化的数据段 (SEC_DATA / SEC_IDATA, 直接寻址/IRAM) ── */
    HexDataSeg segs[64];
    int nseg = 0;
    sec_idx = 0;
    for (Iter it = list_iter(obj->sections); !iter_end(it); sec_idx++) {
        Section *sec = iter_next(&it);
        if (!sec) continue;
        if (sec->kind != SEC_DATA && sec->kind != SEC_IDATA) continue;
        if (sec->bytes_len <= 0) continue;
        int start = data_seg_start(obj, sec_idx);
        if (start < 0) start = 0;
        int len = sec->bytes_len - start;
        if (len <= 0 || len > 255) continue; /* 单段 >255B 暂不支持, 跳过 */
        if (nseg >= 64) break;
        segs[nseg].dest = start;
        segs[nseg].bytes = sec->bytes + start;
        segs[nseg].len = len;
        nseg++;
    }

    int copy_len = nseg ? (nseg * 14 + 3) : 0;
    int copy_start = code_total;
    int data_base = copy_start + copy_len;
    int d_off = 0;
    for (int i = 0; i < nseg; i++) {
        segs[i].src = data_base + d_off;
        d_off += segs[i].len;
    }

    /* ── 第二遍: 输出 CODE 段 (启动段 LJMP 改指复制代码) ── */
    int code_base = 0;
    sec_idx = 0;
    for (Iter it = list_iter(obj->sections); !iter_end(it); sec_idx++) {
        Section *sec = iter_next(&it);
        if (!sec || sec->kind != SEC_CODE || sec->bytes_len <= 0) continue;
        if (sec->align > 1)
            code_base = ((code_base + sec->align - 1) / sec->align) * sec->align;

        if (sec_idx == startup_ljmp_sec && nseg > 0) {
            /* 复制段字节, 修改 LJMP 目标 → 复制代码首地址 */
            unsigned char *tmp = malloc(sec->bytes_len);
            if (!tmp) return -1;
            memcpy(tmp, sec->bytes, sec->bytes_len);
            tmp[startup_ljmp_off]     = (copy_start >> 8) & 0xFF;
            tmp[startup_ljmp_off + 1] = copy_start & 0xFF;
            hex_emit_line(fp, (unsigned)code_base, tmp, sec->bytes_len);
            free(tmp);
        } else {
            hex_emit_line(fp, (unsigned)code_base, sec->bytes, sec->bytes_len);
        }
        code_base += sec->bytes_len;
    }

    /* ── 复制代码 + 数据 ── */
    for (int i = 0; i < nseg; i++) {
        unsigned char c[14];
        c[0] = 0x78; c[1] = segs[i].dest & 0xFF;              /* MOV R0,#dest   */
        c[2] = 0x90; c[3] = (segs[i].src >> 8) & 0xFF;
        c[4] = segs[i].src & 0xFF;                            /* MOV DPTR,#src  */
        c[5] = 0x79; c[6] = segs[i].len & 0xFF;               /* MOV R1,#len    */
        c[7] = 0xE4; c[8] = 0x93; c[9] = 0xF6;                /* CLR A; MOVC A,@A+DPTR; MOV @R0,A */
        c[10] = 0x08; c[11] = 0xA3;                           /* INC R0; INC DPTR */
        c[12] = 0xD9; c[13] = (unsigned char)(-7);            /* DJNZ R1, loop  */
        hex_emit_line(fp, (unsigned)(copy_start + i * 14), c, 14);
    }
    if (nseg > 0) {
        unsigned char tail[3] = { 0x02, (main_addr >> 8) & 0xFF, main_addr & 0xFF };
        hex_emit_line(fp, (unsigned)(copy_start + nseg * 14), tail, 3);
    }
    for (int i = 0; i < nseg; i++)
        hex_emit_line(fp, (unsigned)segs[i].src, segs[i].bytes, segs[i].len);

    fprintf(fp, ":00000001FF\n");
    return 0;
}
