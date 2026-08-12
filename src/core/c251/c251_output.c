#include "c251_gen.h"
#include "c251_encode.h"
#include <string.h>
#include <stdlib.h>

static const char* section_kind_name(SectionKind kind) {
    switch (kind) {
        case SEC_CODE:  return "CODE";
        case SEC_DATA:  return "DATA";
        case SEC_IDATA: return "IDATA";
        case SEC_XDATA: return "XDATA";
        case SEC_BIT:   return "BIT";
        case SEC_BDATA: return "BDATA";
        case SEC_PDATA: return "PDATA";
        case SEC_EDATA: return "EDATA";
        default:        return "UNKNOWN";
    }
}

static void print_asminstr(FILE *fp, AsmInstr *ins) {
    if (!ins) return;
    if (ins->op && ins->op[strlen(ins->op) - 1] == ':') {
        fprintf(fp, "%s\n", ins->op);
        return;
    }
    if (!ins->op) return;
    fprintf(fp, "    %s", ins->op);
    if (ins->args) {
        for (Iter it = list_iter(ins->args); !iter_end(it);) {
            const char *a = iter_next(&it);
            fprintf(fp, " %s", a ? a : "");
        }
    }
    fprintf(fp, "\n");
}

int c251_write_asm(FILE *fp, const ObjFile *obj) {
    if (!fp || !obj) return -1;
    for (Iter sit = list_iter(obj->sections); !iter_end(sit);) {
        Section *sec = iter_next(&sit);
        if (!sec) continue;
        if (sec->kind == SEC_CODE) {
            fprintf(fp, "; %s section\n", section_kind_name(sec->kind));
            if (sec->asminstrs) {
                for (Iter ait = list_iter(sec->asminstrs); !iter_end(ait);) {
                    print_asminstr(fp, iter_next(&ait));
                }
            }
        } else {
            fprintf(fp, "; %s data (%d bytes)\n", section_kind_name(sec->kind), sec->bytes_len);
        }
    }
    return 0;
}

/* ---- Intel HEX 写出 ---- */
static void hex_emit_line(FILE *fp, unsigned address, const unsigned char *bytes, int len) {
    if (len <= 0) return;
    unsigned char sum = (unsigned char)(len + (address >> 8) + (address & 0xFF));
    fprintf(fp, ":%02X%04X00", len, address);
    for (int i = 0; i < len; i++) { fprintf(fp, "%02X", bytes[i]); sum += bytes[i]; }
    fprintf(fp, "%02X\n", (unsigned char)(0x100 - sum));
}

int c251_write_hex(FILE *fp, const ObjFile *obj) {
    if (!fp || !obj) return -1;
    /* 多文件合并后重编码: obj_link 合并的是各 obj 已编码的 bytes, 跨文件函数引用
     * (libc strlen/calloc) 在单文件 encode 时未定义 → LCALL 填 0。这里对合并后
     * obj 重新 encode, 函数符号已全部定义, fixup 正确填充 (0025/0041-libc)。 */
    c251_encode(NULL, (ObjFile*)obj);
    unsigned addr = 0;
    /* 1) CODE section 裸地址输出（无 type-04 记录 → sim251 默认路由到代码区） */
    for (Iter sit = list_iter(obj->sections); !iter_end(sit);) {
        Section *sec = iter_next(&sit);
        if (!sec || sec->kind != SEC_CODE || sec->bytes_len <= 0) continue;
        int off = 0;
        while (off < sec->bytes_len) {
            int n = sec->bytes_len - off; if (n > 16) n = 16;
            hex_emit_line(fp, addr + off, sec->bytes + off, n);
            off += n;
        }
        addr += sec->bytes_len;
    }
    /* 2) EDATA section：先 type-04 0x0000（路由 IRAM），再 0x00xxxx 数据记录 */
    for (Iter sit = list_iter(obj->sections); !iter_end(sit);) {
        Section *sec = iter_next(&sit);
        if (!sec || sec->kind != SEC_EDATA || sec->bytes_len <= 0) continue;
        fprintf(fp, ":020000040000FA\n");  /* type-04, base=0x0000 → 后续数据路由 IRAM; cksum = 0x100-(02+00+00+04+00+00)=0xFA */
        /* 变量从 C251_EDATA_BASE 起布局（EDATA 首 0x80 为寄存器预留区，reset 默认零，不输出） */
        int off = C251_EDATA_BASE;
        while (off < sec->bytes_len) {
            int n = sec->bytes_len - off; if (n > 16) n = 16;
            hex_emit_line(fp, off, sec->bytes + off, n);
            off += n;
        }
    }
    fprintf(fp, ":00000001FF\n"); /* EOF 记录（必须显式输出） */
    return 0;
}
