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

/* M1: 整数全局变量 → SEC_EDATA + 符号 + 初始化字节 */
static void process_global_var(C251GenContext *ctx, GlobalVar *g) {
    if (!g || !g->name) return;
    if (g->is_extern) return;
    int size = g->type ? g->type->size : 1;
    if (size < 1) size = 1;
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
     * init_instr blob 优先，否则标量 init_value 同样转大端。 */
    if (g->has_init) {
        if (g->init_instr && g->init_instr->imm.blob.bytes && g->init_instr->imm.blob.len > 0) {
            int bn = g->init_instr->imm.blob.len;
            if (bn > size) bn = size;
            for (int i = 0; i < bn; i++) {
                sec->bytes[offset + i] = g->init_instr->imm.blob.bytes[bn - 1 - i];
            }
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
                if (sec->asminstrs) {
                    List *nl = make_list();
                    list_push(nl, ai);
                    for (Iter ait = list_iter(sec->asminstrs); !iter_end(ait);) {
                        list_push(nl, iter_next(&ait));
                    }
                    sec->asminstrs = nl;
                } else {
                    sec->asminstrs = make_list();
                    list_push(sec->asminstrs, ai);
                }
                /* stub 占 3 字节 (LJMP 02 hi lo)，函数符号 value 由 encode 标签处理设置 */
            }
            break;
        }
    }

    c251_encode(ctx, ctx->obj);

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
