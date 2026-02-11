#ifndef C51_GEN_FUNCTION_H
#define C51_GEN_FUNCTION_H

#include "c51_gen_internal.h"

static inline void emit_asm(C51GenContext *ctx, Section *sec, const char *op, 
                            const char *arg1, const char *arg2, const char *ssa)
{
    AsmInstr *ins = calloc(1, sizeof(AsmInstr));
    ins->op = strdup(op);
    ins->args = make_list();
    if (arg1) list_push(ins->args, strdup(arg1));
    if (arg2) list_push(ins->args, strdup(arg2));
    if (ssa) ins->ssa = strdup(ssa);
    list_push(sec->asminstrs, ins);
}

static inline char* new_label(C51GenContext *ctx, const char *prefix)
{
    char buf[32];
    snprintf(buf, sizeof(buf), "%s_%d", prefix, ctx->label_counter++);
    return strdup(buf);
}

static inline void handle_function_init(C51GenContext *ctx, Func *f) 
{
    int sec_idx = obj_add_section(ctx->obj, "?PR?", SEC_CODE, 0, 1);
    Section *sec = obj_get_section(ctx->obj, sec_idx);
    
    int flags = SYM_FLAG_GLOBAL;
    obj_add_symbol(ctx->obj, f->name, SYM_FUNC, sec_idx, sec->size, 0, flags);
    
    ctx->current_func = f;
    
    ctx->value_to_reg = make_dict(NULL);
    ctx->value_to_addr = make_dict(NULL);
    ctx->value_type = make_dict(NULL);
}

void c51_instr(C51GenContext* ctx, Section* sec, Instr* ins);

static inline void handle_function_emit(C51GenContext* ctx, Func *f) 
{
    Section *sec = NULL;
    for (Iter it = list_iter(ctx->obj->sections); !iter_end(it);) {
        Section *s = iter_next(&it);
        if (s && s->kind == SEC_CODE) {
            sec = s;
        }
    }
    if (!sec) return;
    
    char label[256];
    snprintf(label, sizeof(label), "_%s:", f->name);
    emit_asm(ctx, sec, label, NULL, NULL, NULL);
    
    int block_count = f->blocks ? f->blocks->len : 0;
    for (Iter bit = list_iter(f->blocks); !iter_end(bit);) {
        Block *block = iter_next(&bit);
        ctx->current_block = block;

        if (block_count > 1) {
            char block_label[32];
            snprintf(block_label, sizeof(block_label), "L%d:", block->id);
            emit_asm(ctx, sec, block_label, NULL, NULL, NULL);
        }

        for (Iter iit = list_iter(block->instrs); !iter_end(iit);) {
            Instr *ins = iter_next(&iit);
            c51_instr(ctx, sec, ins);
        }
    }
}

static inline void handle_function_regalloc(C51GenContext *ctx, Func *f) 
{
    Section *sec = NULL;
    for (Iter it = list_iter(ctx->obj->sections); !iter_end(it);) {
        Section *s = iter_next(&it);
        if (s && s->kind == SEC_CODE) {
            sec = s;
        }
    }
    if (!sec) return;
    
    c51_regalloc(ctx, sec);
}

static inline void handle_function_optimize(C51GenContext *ctx, Func *f) 
{
    Section *sec = NULL;
    for (Iter it = list_iter(ctx->obj->sections); !iter_end(it);) {
        Section *s = iter_next(&it);
        if (s && s->kind == SEC_CODE) {
            sec = s;
        }
    }
    if (!sec) return;
    
    c51_optimize(ctx, sec);
}

static inline void handle_function_encode(C51GenContext *ctx, Func *f) 
{
    Section *sec = NULL;
    for (Iter it = list_iter(ctx->obj->sections); !iter_end(it);) {
        Section *s = iter_next(&it);
        if (s && s->kind == SEC_CODE) {
            sec = s;
        }
    }
    if (!sec) return;
    
    c51_encode(ctx, sec);
}

static inline void handle_function_cleanup(C51GenContext *ctx, Func *f) 
{
    if (ctx->value_to_reg) {
        dict_clear(ctx->value_to_reg);
        ctx->value_to_reg = NULL;
    }
    if (ctx->value_to_addr) {
        dict_clear(ctx->value_to_addr);
        ctx->value_to_addr = NULL;
    }
    if (ctx->value_type) {
        dict_clear(ctx->value_type);
        ctx->value_type = NULL;
    }
    
    ctx->current_func = NULL;
    ctx->current_block = NULL;
}

#endif
