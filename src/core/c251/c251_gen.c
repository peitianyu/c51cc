#include "c251_gen.h"
#include "c251_isel.h"
#include "c251_encode.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

C251GenContext* c251_ctx_new(void) {
    C251GenContext* ctx = calloc(1, sizeof(C251GenContext));
    if (!ctx) return NULL;
    ctx->obj = obj_new();
    ctx->value_to_reg = make_dict(NULL);
    ctx->value_type = make_dict(NULL);
    ctx->value_to_const = make_dict(NULL);
    ctx->value_to_addr = make_dict(NULL);
    ctx->value_to_spill = make_dict(NULL);
    ctx->sym_size = make_dict(NULL);
    ctx->sfr_addr = make_dict(NULL);
    ctx->next_spill_id = 0;
    ctx->temp_values = make_list();
    return ctx;
}

void c251_ctx_free(C251GenContext* ctx) {
    if (!ctx) return;
    if (ctx->value_to_reg)  { dict_free(ctx->value_to_reg, free); }
    if (ctx->value_type)    { dict_free(ctx->value_type, NULL); }
    if (ctx->value_to_const){ dict_free(ctx->value_to_const, free); }
    if (ctx->value_to_addr) { dict_free(ctx->value_to_addr, free); }
    if (ctx->value_to_spill){ dict_free(ctx->value_to_spill, free); }
    if (ctx->sym_size)      { dict_free(ctx->sym_size, free); }
    if (ctx->temp_values)   { list_free(ctx->temp_values); }
    free(ctx);
}

char* c251_key(int n) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%02XH", n);
    return strdup(buf);
}

char* c251_value_spill(C251GenContext* ctx, ValueName val) {
    if (!ctx || !ctx->value_to_spill) return NULL;
    char *k = c251_key(val);
    char *sp = (char*)dict_get(ctx->value_to_spill, k);
    free(k);
    return sp;
}

char* c251_alloc_spill(C251GenContext* ctx, ValueName val) {
    if (!ctx) return NULL;
    char *key = c251_key(val);
    char *exist = (char*)dict_get(ctx->value_to_spill, key);
    if (exist) { free(key); return exist; }
    /* EDATA 段追加 2 字节槽 + 符号（与全局变量同段；无全局变量时首次预留 0x80） */
    int sec_idx = obj_find_or_add_section(ctx->obj, "?ED?", SEC_EDATA, 1);
    Section *sec = obj_get_section(ctx->obj, sec_idx);
    if (sec->bytes_len == 0) {
        section_append_zeros(sec, C251_EDATA_BASE);
    }
    int offset = sec->bytes_len;
    section_append_zeros(sec, 2);
    char sym[64];
    snprintf(sym, sizeof(sym), "__spill_%d", ctx->next_spill_id);
    ctx->next_spill_id++;
    obj_add_symbol(ctx->obj, sym, SYM_DATA, sec_idx, offset, 2, SYM_FLAG_LOCAL);
    char *symdup = strdup(sym);
    dict_put(ctx->value_to_spill, key, symdup);
    return symdup;
}

/* blob (小端, SSA 约定) → EDATA 大端内存：按类型元素边界递归反转。
 * 数组: 每元素独立反转 (元素顺序不变)；结构体: 每字段独立反转；标量: 字节序反转。
 * char 元素 size=1 反转无效果 → 字符串安全。consumed 记录已消费的 blob 字节。 */
static void emit_blob_be(Section *sec, int offset, Ctype *type,
                         const unsigned char *blob, int blob_len, int *consumed)
{
    if (!type || !blob || !consumed || *consumed >= blob_len) return;
    switch (type->type) {
    case CTYPE_ARRAY: {
        Ctype *elem = type->ptr;
        int esz = (elem && elem->size > 0) ? elem->size : 1;
        int n = type->size / esz;
        for (int i = 0; i < n && *consumed < blob_len; i++)
            emit_blob_be(sec, offset + i * esz, elem, blob, blob_len, consumed);
        break;
    }
    case CTYPE_STRUCT: {
        if (!type->fields) break;
        int prev_off = -1;
        for (Iter it = list_iter(type->fields->list); !iter_end(it);) {
            DictEntry *e = iter_next(&it);
            if (!e) continue;
            Ctype *field = dict_get(type->fields, e->key);
            if (!field) continue;
            /* 匿名 union 非首成员 (同 offset): 跳过, 不推进 consumed (0051-inits) */
            if (field->offset == prev_off) { prev_off = field->offset; continue; }
            prev_off = field->offset;
            emit_blob_be(sec, offset + field->offset, field, blob, blob_len, consumed);
            if (type->is_union) break;
        }
        break;
    }
    default: {
        int sz = (type->size > 0) ? type->size : 1;
        int avail = blob_len - *consumed;
        if (avail > sz) avail = sz;
        if (avail > 0) {
            for (int i = 0; i < avail; i++)
                sec->bytes[offset + i] = blob[*consumed + avail - 1 - i];
            *consumed += avail;
        }
        break;
    }
    }
}

/* 查全局符号在 EDATA 段的绝对偏移（value 含 C251_EDATA_BASE 基址；未找到返回 -1）
 * SYM_FUNC (函数) 也返回其代码偏移 (函数指针初始化, 0091-fptr) */
static int c251_find_sym_offset(C251GenContext *ctx, const char *name) {
    if (!ctx || !name) return -1;
    for (Iter it = list_iter(ctx->obj->symbols); !iter_end(it);) {
        Symbol *s = iter_next(&it);
        if (s && s->name && strcmp(s->name, name) == 0 &&
            (s->kind == SYM_DATA || s->kind == SYM_FUNC))
            return s->value;
    }
    return -1;
}

/* 填大端 2 字节地址到目标符号 (EDATA 绝对偏移) */
static void c251_fill_ptr_addr(C251GenContext *ctx, Section *sec, int pos, const char *sym) {
    int off = c251_find_sym_offset(ctx, sym);
    if (off < 0) { /* 目标未定义：填 0 占位 */
        sec->bytes[pos] = 0; sec->bytes[pos + 1] = 0;
        return;
    }
    sec->bytes[pos]     = (unsigned char)((off >> 8) & 0xFF);
    sec->bytes[pos + 1] = (unsigned char)(off & 0xFF);
}

/* M1: 整数全局变量 → SEC_EDATA + 符号 + 初始化字节 */
static void process_global_var(C251GenContext *ctx, GlobalVar *g) {
    if (!g || !g->name) return;
    if (g->is_extern) return;
    int size = g->type ? g->type->size : 1;
    if (size < 1) size = 1;
    /* M3: sfr/sbit — 特殊功能寄存器 (固定直接地址 0x80-0xFF), 不进 EDATA.
     * ctype_register 标记 + bit_offset 存 SFR 地址; isel 用 sfr_addr 生成 MOV dir8.
     * sfr_addr 值编码: 低 8 位 = SFR 地址, bit16+ = sbit 位号 (-1 表示 sfr 整字节). */
    {
        union { CtypeAttr a; int i; } att = {0};
        att.i = g->type ? g->type->attr : 0;
        if (att.a.ctype_register && g->type && g->type->bit_offset >= 0) {
            int *addrp = malloc(sizeof(int));
            int bit = (g->type->bit_size >= 0) ? g->type->bit_size : -1;
            *addrp = (g->type->bit_offset & 0xFF) | ((bit & 0xFFFF) << 16);
            dict_put(ctx->sfr_addr, strdup(g->name), addrp);
            return;  /* 不分配 EDATA, 不注册 obj 符号 */
        }
    }
    int sec_idx = obj_find_or_add_section(ctx->obj, "?ED?", SEC_EDATA, 1);
    Section *sec = obj_get_section(ctx->obj, sec_idx);
    /* 首次创建时预留 C251_EDATA_BASE 字节：避开 IRAM 0x00-0x7F（寄存器文件 R0-R7/位区/数据区），
     * 变量从 0x80 起布局，与 hex 输出 (type-04 0x0000 + off) 一致 */
    if (sec->bytes_len == 0) {
        section_append_zeros(sec, C251_EDATA_BASE);
    }
    int offset = sec->bytes_len;
    obj_add_symbol(ctx->obj, g->name, SYM_DATA, sec_idx, offset, size, SYM_FLAG_GLOBAL);
    /* 记录符号字节数（供 isel STORE 宽度判定：char 1B / int 2B） */
    {
        int *szp = malloc(sizeof(int)); *szp = size;
        dict_put(ctx->sym_size, strdup(g->name), szp);
    }
    section_append_zeros(sec, size);
    /* 初始化字节：blob（小端，SSA 约定）→ 大端内存布局（251 字访问大端，addr 处=高字节）。
     * blob 按类型元素边界递归反转（数组每元素独立反转，结构体每字段独立反转，
     * 字符串 char 元素 size=1 反转无效果）；标量 init_value 同样转大端。 */
    if (g->has_init) {
        if (g->init_instr && g->init_instr->imm.blob.bytes && g->init_instr->imm.blob.len > 0) {
            int consumed = 0;
            emit_blob_be(sec, offset, g->type,
                         g->init_instr->imm.blob.bytes,
                         g->init_instr->imm.blob.len, &consumed);
            /* 指针地址重定位：blob 内偏移（小端坐标）→ 目标符号 EDATA 绝对地址（大端） */
            if (g->init_instr->imm.blob.relocs) {
                for (Iter rit = list_iter(g->init_instr->imm.blob.relocs); !iter_end(rit);) {
                    InitReloc *r = iter_next(&rit);
                    if (r && r->symbol && r->offset + 1 < size && r->offset >= 0) {
                        /* 注意 blob 内 offset 是小端坐标；反转后字节位置不变（同偏移） */
                        c251_fill_ptr_addr(ctx, sec, offset + r->offset, r->symbol);
                    }
                }
            }
        } else if (g->init_instr && g->init_instr->labels &&
                   list_len(g->init_instr->labels) > 0 && g->type &&
                   g->type->type == CTYPE_PTR) {
            /* 顶层指针 = &全局符号：labels[0] = 目标符号，填大端 EDATA 地址 */
            const char *sym = (const char*)list_get(g->init_instr->labels, 0);
            c251_fill_ptr_addr(ctx, sec, offset, sym);
        } else {
            long iv = g->init_value;
            for (int i = 0; i < size && i < 4; i++) {
                sec->bytes[offset + i] = (unsigned char)((iv >> (8 * (size - 1 - i))) & 0xFF);
            }
        }
    }
}

static void process_function(C251GenContext *ctx, Func *f) {
    if (f) isel_function(ctx, f);
}

ObjFile *c251_gen(SSAUnit *unit) {
    if (!unit) return NULL;
    C251GenContext *ctx = c251_ctx_new();
    if (!ctx) return NULL;
    ctx->unit = unit;

    for (Iter git = list_iter(unit->globals); !iter_end(git);) {
        GlobalVar *g = iter_next(&git);
        if (g) process_global_var(ctx, g);
    }
    for (Iter fit = list_iter(unit->funcs); !iter_end(fit);) {
        Func *f = iter_next(&fit);
        if (f) process_function(ctx, f);
    }

    /* 入口 stub：存在 main 时在第一个 CODE section 头部插入 LJMP main
     * （sim251 reset 后 PC=0 从代码区开头执行；多函数时第一个函数未必是 main）
     * LJMP 目标经 AbsFixup 两遍填充（函数符号 value 由 c251_encode 标签处理设置） */
    {
        for (Iter sit = list_iter(ctx->obj->sections); !iter_end(sit);) {
            Section *sec = iter_next(&sit);
            if (!sec || sec->kind != SEC_CODE) continue;
            bool has_main = false;
            for (Iter sit2 = list_iter(ctx->obj->symbols); !iter_end(sit2);) {
                Symbol *s = iter_next(&sit2);
                if (s && s->name && strcmp(s->name, "main") == 0) { has_main = true; break; }
            }
            if (has_main) {
                AsmInstr *ai = calloc(1, sizeof(AsmInstr));
                ai->op = strdup("LJMP");
                ai->args = make_list();
                list_push(ai->args, strdup("main"));
                /* 头部插入：stub 在第一个函数之前（地址 0x0000） */
                List *nl = make_list();
                list_push(nl, ai);

                /* M3: 中断向量表 — interrupt N → 地址 0x0003+N*8 放 LJMP ISR_N。
                 * stub 占 0x0000-0x0002, 向量在 0x0003 起 (N=0 的向量紧接 stub)。
                 * 无中断时省掉 0x40 填充 (00-09 系列 72B vs Keil 30B 的主因):
                 * LJMP main 后直接接函数代码。 */
                {
                    int vec_pos = 3;  /* 第一个向量地址 */
                    bool any_vec = false;
                    for (int i = 0; i < (int)list_len(unit->funcs); i++) {
                        Func *ff = (Func*)list_get(unit->funcs, i);
                        if (!ff || !ff->is_interrupt) continue;
                        int vaddr = 3 + ff->interrupt_id * 8;  /* 0x0003 + N*8 */
                        if (vaddr < 0x0040) {
                            any_vec = true;
                            /* NOP 填充到向量地址 */
                            while (vec_pos < vaddr && vec_pos < 0x0040) {
                                AsmInstr *nop = calloc(1, sizeof(AsmInstr));
                                nop->op = strdup("NOP");
                                list_push(nl, nop);
                                vec_pos++;
                            }
                            /* 向量 LJMP ISR_N (占 3 字节) */
                            AsmInstr *vj = calloc(1, sizeof(AsmInstr));
                            vj->op = strdup("LJMP");
                            vj->args = make_list();
                            char isrname[32]; snprintf(isrname, sizeof(isrname), "ISR_%d", ff->interrupt_id);
                            list_push(vj->args, strdup(isrname));
                            list_push(nl, vj);
                            vec_pos += 3;
                        }
                    }
                    /* 有向量时填充到 0x0040 保持对齐; 无向量时直接接函数代码 */
                    if (any_vec) {
                        while (vec_pos < 0x0040) {
                            AsmInstr *nop = calloc(1, sizeof(AsmInstr));
                            nop->op = strdup("NOP");
                            list_push(nl, nop);
                            vec_pos++;
                        }
                    }
                }
                if (sec->asminstrs) {
                    for (Iter ait = list_iter(sec->asminstrs); !iter_end(ait);) {
                        list_push(nl, iter_next(&ait));
                    }
                    sec->asminstrs = nl;
                } else {
                    sec->asminstrs = nl;
                }
                /* stub 占 3 字节 (LJMP 02 hi lo)，函数符号 value 由 encode 标签处理设置 */
            }
            break;
        }
    }

    c251_encode(ctx, ctx->obj);

    /* 全局 init 指针重定位（延迟到函数符号注册后）:
     * process_global_var 早于函数 isel, &func 的 reloc 当时解析不到函数符号 → 填 0。
     * 这里在全部函数处理后重填 (0091-fptr: struct s = { &zero }) */
    for (Iter git2 = list_iter(unit->globals); !iter_end(git2);) {
        GlobalVar *g = iter_next(&git2);
        if (!g || !g->has_init || !g->init_instr) continue;
        int sec_idx = obj_find_or_add_section(ctx->obj, "?ED?", SEC_EDATA, 0);
        if (sec_idx < 0) continue;
        Section *sec = obj_get_section(ctx->obj, sec_idx);
        Symbol *sg = NULL;
        for (Iter sit = list_iter(ctx->obj->symbols); !iter_end(sit);) {
            Symbol *s = iter_next(&sit);
            if (s && s->name && strcmp(s->name, g->name) == 0 && s->kind == SYM_DATA) {
                sg = s; break;
            }
        }
        if (!sg) continue;
        if (g->init_instr->imm.blob.relocs) {
            for (Iter rit = list_iter(g->init_instr->imm.blob.relocs); !iter_end(rit);) {
                InitReloc *r = iter_next(&rit);
                if (r && r->symbol && r->offset >= 0) {
                    c251_fill_ptr_addr(ctx, sec, sg->value + r->offset, r->symbol);
                }
            }
        }
    }

    ObjFile* obj = ctx->obj;
    ctx->obj = NULL;
    c251_ctx_free(ctx);
    return obj;
}

ObjFile *c251_link_startup(const char *source_path, ObjFile *main_obj) {
    /* M1: 不注入启动代码；main 作为第一个 CODE section 从 0x0000 起，sim251 reset 后 PC=0 直接执行 */
    (void)source_path;
    return main_obj;
}
