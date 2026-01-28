#include "ssa.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

typedef struct {
    char      *var;
    ValueName  phi;
} IncompletePhi;

typedef struct CFContext {
    Block *break_target;
    Block *continue_target;
    struct CFContext *parent;
} CFContext;

static void* ssa_alloc(size_t size) {
    void *p = malloc(size);
    if (!p) {
        fprintf(stderr, "SSA: out of memory\n");
        exit(1);
    }
    memset(p, 0, size);
    return p;
}

static char* ssa_strdup(const char *s) {
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char *d = ssa_alloc(len);
    memcpy(d, s, len);
    return d;
}

static ValueName ssa_new_value(SSABuild *b) {
    return ++b->next_value;  // 从1开始，0表示undef
}

static Instr* ssa_make_instr(SSABuild *b, IrOp op) {
    Instr *i = ssa_alloc(sizeof(Instr));
    i->op = op;
    i->args = make_list();
    i->labels = make_list();
    return i;
}

static void ssa_add_arg(Instr *i, ValueName val) {
    ValueName *p = ssa_alloc(sizeof(ValueName));
    *p = val;
    list_push(i->args, p);
}

static void ssa_add_label(Instr *i, const char *label) {
    list_push(i->labels, ssa_strdup(label));
}

static void ssa_emit(SSABuild *b, Instr *i) {
    if (!b->cur_block) return;
    list_push(b->cur_block->instrs, i);
    if (i->op == IROP_PHI) {
        list_push(b->cur_block->phis, i);
    }
}

static Block* ssa_build_block(SSABuild *b) {
    Block *blk = ssa_alloc(sizeof(Block));
    blk->id = b->next_block++;
    blk->preds = make_list();
    blk->instrs = make_list();
    blk->phis = make_list();
    blk->var_map = make_dict(NULL);
    blk->incomplete = make_list();
    
    if (b->cur_func) {
        list_push(b->cur_func->blocks, blk);
    }
    return blk;
}

void ssa_build_position(SSABuild *b, Block *blk) {
    b->cur_block = blk;
}

static void ssa_add_pred(Block *blk, Block *pred) {
    if (!blk || !pred) return;
    for (Iter it = list_iter(blk->preds); !iter_end(it);) {
        Block *p = iter_next(&it);
        if (p == pred) return;
    }
    list_push(blk->preds, pred);
}

void ssa_build_write(SSABuild *b, const char *var, ValueName val) {
    if (!b->cur_block) return;
    ValueName *p = ssa_alloc(sizeof(ValueName));
    *p = val;
    dict_put(b->cur_block->var_map, ssa_strdup(var), p);
}

static ValueName ssa_read_recursive(SSABuild *b, const char *var, Block *blk);

static ValueName ssa_build_read(SSABuild *b, const char *var) {
    if (!b->cur_block) return 0;
    
    // 1. 当前块有定义？
    ValueName *p = dict_get(b->cur_block->var_map, (char*)var);
    if (p) return *p;
    
    // 2. 递归查找
    return ssa_read_recursive(b, var, b->cur_block);
}

static ValueName ssa_add_phi_operands(SSABuild *b, const char *var, Instr *phi, Block *blk);
static ValueName ssa_try_remove_trivial_phi(SSABuild *b, Instr *phi);

static ValueName ssa_read_recursive(SSABuild *b, const char *var, Block *blk) {
    ValueName val;
    
    if (!blk->sealed) {
        // 未密封：创建不完整Phi
        Instr *phi = ssa_make_instr(b, IROP_PHI);
        phi->dest = ssa_new_value(b);
        ssa_emit(b, phi);
        
        IncompletePhi *inc = ssa_alloc(sizeof(IncompletePhi));
        inc->var = ssa_strdup(var);
        inc->phi = phi->dest;
        list_push(blk->incomplete, inc);
        
        ssa_build_write(b, var, phi->dest);
        val = phi->dest;
    } 
    else if (blk->preds->len == 1) {
        // 单前驱：直接读取
        Block *pred = list_get(blk->preds, 0);
        ValueName *p = dict_get(pred->var_map, (char*)var);
        val = p ? *p : 0;
    } 
    else {
        // 多前驱：创建Phi
        Instr *phi = ssa_make_instr(b, IROP_PHI);
        phi->dest = ssa_new_value(b);
        ssa_emit(b, phi);
        ssa_build_write(b, var, phi->dest);
        
        val = ssa_add_phi_operands(b, var, phi, blk);
    }
    
    ssa_build_write(b, var, val);
    return val;
}

static ValueName ssa_add_phi_operands(SSABuild *b, const char *var, Instr *phi, Block *blk) {
    for (Iter it = list_iter(blk->preds); !iter_end(it);) {
        Block *pred = iter_next(&it);
        
        Block *saved = b->cur_block;
        b->cur_block = pred;
        ValueName val = ssa_build_read(b, var);
        b->cur_block = saved;
        
        ssa_add_arg(phi, val);
        
        char label[32];
        snprintf(label, sizeof(label), "block%u", pred->id);
        ssa_add_label(phi, label);
    }
    
    return ssa_try_remove_trivial_phi(b, phi);
}

static void replace_uses(SSABuild *b, ValueName old_val, ValueName new_val) {
    for (Iter it = list_iter(b->cur_func->blocks); !iter_end(it);) {
        Block *blk = iter_next(&it);
        for (Iter jt = list_iter(blk->instrs); !iter_end(jt);) {
            Instr *inst = iter_next(&jt);
            for (int i = 0; i < inst->args->len; i++) {
                ValueName *arg = list_get(inst->args, i);
                if (*arg == old_val) {
                    *arg = new_val;
                }
            }
        }
    }
}

static ValueName ssa_try_remove_trivial_phi(SSABuild *b, Instr *phi) {
    ValueName same = 0;
    bool has_same = false;
    
    for (int i = 0; i < phi->args->len; i++) {
        ValueName *p = list_get(phi->args, i);
        ValueName val = *p;
        
        if (val == phi->dest) continue;
        
        if (!has_same) {
            same = val;
            has_same = true;
        } else if (same != val) {
            return phi->dest;
        }
    }
    
    if (has_same) {
        replace_uses(b, phi->dest, same);
        phi->op = IROP_NOP;
        return same;
    }
    return 0;
}

static void ssa_build_seal(SSABuild *b, Block *blk) {
    if (!blk || blk->sealed) return;
    blk->sealed = true;
    
    for (Iter it = list_iter(blk->incomplete); !iter_end(it);) {
        IncompletePhi *inc = iter_next(&it);
        
        for (Iter jt = list_iter(blk->phis); !iter_end(jt);) {
            Instr *phi = iter_next(&jt);
            if (phi->dest == inc->phi && phi->args->len == 0) {
                ValueName result = ssa_add_phi_operands(b, inc->var, phi, blk);
                if (result != phi->dest) {
                    ssa_build_write(b, inc->var, result);
                }
                break;
            }
        }
    }
}

static void ssa_build_push_cf(SSABuild *b, Block *brk, Block *cont) {
    CFContext *ctx = ssa_alloc(sizeof(CFContext));
    ctx->break_target = brk;
    ctx->continue_target = cont;
    ctx->parent = b->cf_ctx;
    b->cf_ctx = ctx;
}

static void ssa_build_pop_cf(SSABuild *b) {
    if (b->cf_ctx) {
        CFContext *p = b->cf_ctx;
        b->cf_ctx = p->parent;
        free(p);
    }
}

static Block* ssa_build_get_break(SSABuild *b) {
    return b->cf_ctx ? b->cf_ctx->break_target : NULL;
}

static Block* ssa_build_get_continue(SSABuild *b) {
    return b->cf_ctx ? b->cf_ctx->continue_target : NULL;
}

SSABuild* ssa_build_create(void) {
    SSABuild *b = ssa_alloc(sizeof(SSABuild));
    b->unit = ssa_alloc(sizeof(SSAUnit));
    b->unit->funcs = make_list();
    b->unit->globals = make_list();
    return b;
}

// 添加全局变量到SSA Unit
void ssa_add_global(SSABuild *b, const char *name, Ctype *type, long init_value, bool has_init) {
    if (!b || !b->unit) return;
    GlobalVar *gvar = ssa_alloc(sizeof(GlobalVar));
    gvar->name = ssa_strdup(name);
    gvar->type = type;
    gvar->init_value = init_value;
    gvar->has_init = has_init;
    list_push(b->unit->globals, gvar);
}

static void ssa_build_reset(SSABuild *b) {
    if (!b) return;
    b->cur_func = NULL;
    b->cur_block = NULL;
    b->cf_ctx = NULL;
    b->next_value = 0;
    b->next_block = 0;
}

void ssa_build_destroy(SSABuild *b) {
    if (!b) return;
    // 简化：不递归释放所有节点，由OS回收或后续添加arena释放
    free(b->unit);
    free(b);
}

static Func* ssa_build_function(SSABuild *b, const char *name, Ctype *ret) {
    Func *f = ssa_alloc(sizeof(Func));
    f->name = name;
    f->ret_type = ret;
    f->params = make_list();
    f->blocks = make_list();
    
    list_push(b->unit->funcs, f);
    b->cur_func = f;
    
    f->entry = ssa_build_block(b);
    b->cur_block = f->entry;
    
    return f;
}

static void ssa_build_param(SSABuild *b, const char *name, Ctype *type) {
    if (!b->cur_func || !b->cur_block) return;
    
    list_push(b->cur_func->params, ssa_strdup(name));
    
    ValueName val = ssa_new_value(b);
    ssa_build_write(b, name, val);
    
    Instr *p = ssa_make_instr(b, IROP_PARAM);
    p->dest = val;
    p->type = type;
    ssa_add_label(p, name);
    ssa_emit(b, p);
}

static ValueName ssa_build_const(SSABuild *b, int64_t val) {
    Instr *i = ssa_make_instr(b, IROP_CONST);
    i->dest = ssa_new_value(b);
    i->imm.ival = val;
    ssa_emit(b, i);
    return i->dest;
}

static ValueName ssa_build_binop(SSABuild *b, IrOp op, ValueName lhs, ValueName rhs) {
    Instr *i = ssa_make_instr(b, op);
    i->dest = ssa_new_value(b);
    ssa_add_arg(i, lhs);
    ssa_add_arg(i, rhs);
    ssa_emit(b, i);
    return i->dest;
}

static ValueName ssa_build_unop(SSABuild *b, IrOp op, ValueName val) {
    Instr *i = ssa_make_instr(b, op);
    i->dest = ssa_new_value(b);
    ssa_add_arg(i, val);
    ssa_emit(b, i);
    return i->dest;
}

static void ssa_build_jmp(SSABuild *b, Block *target) {
    Instr *i = ssa_make_instr(b, IROP_JMP);
    char label[32];
    snprintf(label, sizeof(label), "block%u", target->id);
    ssa_add_label(i, label);
    ssa_emit(b, i);
    ssa_add_pred(target, b->cur_block);
}

static void ssa_build_br(SSABuild *b, ValueName cond, Block *t, Block *f) {
    Instr *i = ssa_make_instr(b, IROP_BR);
    ssa_add_arg(i, cond);
    
    char tl[32], fl[32];
    snprintf(tl, sizeof(tl), "block%u", t->id);
    snprintf(fl, sizeof(fl), "block%u", f->id);
    ssa_add_label(i, tl);
    ssa_add_label(i, fl);
    ssa_emit(b, i);
    
    ssa_add_pred(t, b->cur_block);
    ssa_add_pred(f, b->cur_block);
}

static void ssa_build_ret(SSABuild *b, ValueName val) {
    Instr *i = ssa_make_instr(b, IROP_RET);
    if (val != 0) {
        ssa_add_arg(i, val);
    }
    ssa_emit(b, i);
    b->cur_block = NULL;
}

static ValueName ssa_build_cast(SSABuild *b, IrOp op, ValueName val, Ctype *to_type) {
    Instr *i = ssa_make_instr(b, op);
    i->dest = ssa_new_value(b);
    i->type = to_type;
    ssa_add_arg(i, val);
    ssa_emit(b, i);
    return i->dest;
}

static ValueName ssa_build_trunc(SSABuild *b, ValueName val, Ctype *to_type) {
    return ssa_build_cast(b, IROP_TRUNC, val, to_type);
}

static ValueName ssa_build_zext(SSABuild *b, ValueName val, Ctype *to_type) {
    return ssa_build_cast(b, IROP_ZEXT, val, to_type);
}

static ValueName ssa_build_sext(SSABuild *b, ValueName val, Ctype *to_type) {
    return ssa_build_cast(b, IROP_SEXT, val, to_type);
}

static ValueName ssa_build_bitcast(SSABuild *b, ValueName val, Ctype *to_type) {
    return ssa_build_cast(b, IROP_BITCAST, val, to_type);
}

static ValueName ssa_build_inttoptr(SSABuild *b, ValueName val, Ctype *ptr_type) {
    return ssa_build_cast(b, IROP_INTTOPTR, val, ptr_type);
}

static ValueName ssa_build_ptrtoint(SSABuild *b, ValueName val, Ctype *int_type) {
    return ssa_build_cast(b, IROP_PTRTOINT, val, int_type);
}

static ValueName ssa_build_offset(SSABuild *b, ValueName ptr, ValueName idx, int elem_size) {
    // 优化：如果idx是常量0，直接返回ptr
    // 实际实现先用乘法再相加，或依赖后端优化
    Instr *i = ssa_make_instr(b, IROP_OFFSET);
    i->dest = ssa_new_value(b);
    i->imm.ival = elem_size;
    ssa_add_arg(i, ptr);
    ssa_add_arg(i, idx);
    ssa_emit(b, i);
    return i->dest;
}

static ValueName ssa_build_load(SSABuild *b, ValueName ptr, Ctype *type) {
    Instr *i = ssa_make_instr(b, IROP_LOAD);
    i->dest = ssa_new_value(b);
    i->type = type;
    ssa_add_arg(i, ptr);
    ssa_emit(b, i);
    return i->dest;
}

static void ssa_build_store(SSABuild *b, ValueName ptr, ValueName val) {
    Instr *i = ssa_make_instr(b, IROP_STORE);
    ssa_add_arg(i, ptr);
    ssa_add_arg(i, val);
    ssa_emit(b, i);
}

static ValueName ssa_build_addr(SSABuild *b, const char *var) {
    Instr *i = ssa_make_instr(b, IROP_ADDR);
    i->dest = ssa_new_value(b);
    ssa_add_label(i, var);
    ssa_emit(b, i);
    return i->dest;
}

static ValueName ssa_build_select(SSABuild *b, ValueName cond, ValueName v_true, ValueName v_false) {
    Instr *i = ssa_make_instr(b, IROP_SELECT);
    i->dest = ssa_new_value(b);
    ssa_add_arg(i, cond);
    ssa_add_arg(i, v_true);
    ssa_add_arg(i, v_false);
    ssa_emit(b, i);
    return i->dest;
}

static inline uint64_t bitmask(int bits) {
    return bits >= 64 ? ~0ULL : ((1ULL << bits) - 1);
}

extern List *ctypes;
static Ctype *ctype_int = &(Ctype){0, CTYPE_INT, 2, NULL};
static Ctype *ctype_long = &(Ctype){0, CTYPE_LONG, 4, NULL};
static Ctype *ctype_char = &(Ctype){0, CTYPE_CHAR, 1, NULL};

static ValueName gen_bitfield_read(SSABuild *b, ValueName base_ptr,
                                   int byte_offset, int bit_offset, 
                                   int bit_size, bool is_signed, Ctype *result_type) {
    ValueName addr = ssa_build_offset(b, base_ptr, 
        ssa_build_const(b, byte_offset), 1);
    
    int container_bits = 8;
    if (bit_offset + bit_size > 16) container_bits = 32;
    else if (bit_offset + bit_size > 8) container_bits = 16;
    
    Ctype *container_type = (container_bits == 32) ? ctype_long : 
                           (container_bits == 16) ? ctype_int : ctype_char;
    
    ValueName word = ssa_build_load(b, addr, container_type);
    
    // 3. 右移丢弃低位: word >> bit_offset
    ValueName shifted = ssa_build_binop(b, IROP_SHR, word,
        ssa_build_const(b, bit_offset));
    
    // 4. 掩码提取有效位: & ((1 << bit_size) - 1)
    ValueName masked = ssa_build_binop(b, IROP_AND, shifted,
        ssa_build_const(b, bitmask(bit_size)));
    
    // 5. 有符号位域：符号扩展
    if (is_signed && bit_size < container_bits) {
        // 测试符号位: (masked >> (bit_size-1)) & 1
        ValueName sign_bit = ssa_build_binop(b, IROP_AND,
            ssa_build_binop(b, IROP_SHR, masked, ssa_build_const(b, bit_size - 1)),
            ssa_build_const(b, 1));
        
        // 构建符号扩展值: 如果符号位为1，将高位全设为1
        // 即: masked | (~((1 << bit_size) - 1)) 当符号位为1时
        ValueName sign_mask = ssa_build_const(b, ~bitmask(bit_size));
        
        // 需要条件选择/或算术右移实现
        // 简化：使用 SEXT 指令（如果后端支持）或生成条件逻辑
        // 这里使用算术右移模拟：先左移到最高位，再算术右移回来
        int shift_left = container_bits - bit_size;
        ValueName high = ssa_build_binop(b, IROP_SHL, masked, 
            ssa_build_const(b, shift_left));
        ValueName sign_extended = ssa_build_binop(b, IROP_SHR, high,
            ssa_build_const(b, shift_left));
        
        return sign_extended;
    }
    
    return masked;
}

/* 写入位域: 读-改-写序列 */
static void gen_bitfield_write(SSABuild *b, ValueName base_ptr,
                               int byte_offset, int bit_offset, int bit_size,
                               ValueName new_val, Ctype *container_type) {
    // 1. 计算地址
    ValueName addr = ssa_build_offset(b, base_ptr,
        ssa_build_const(b, byte_offset), 1);
    
    // 2. 加载旧值
    ValueName old_word = ssa_build_load(b, addr, container_type);
    
    // 3. 清除旧位: old & ~(mask << offset)
    uint64_t m = bitmask(bit_size);
    ValueName clear_mask = ssa_build_const(b, ~(m << bit_offset));
    ValueName cleared = ssa_build_binop(b, IROP_AND, old_word, clear_mask);
    
    // 4. 准备新值: (new_val & mask) << offset
    ValueName val_masked = ssa_build_binop(b, IROP_AND, new_val,
        ssa_build_const(b, m));
    ValueName val_shifted = ssa_build_binop(b, IROP_SHL, val_masked,
        ssa_build_const(b, bit_offset));
    
    // 5. 合并写入
    ValueName new_word = ssa_build_binop(b, IROP_OR, cleared, val_shifted);
    ssa_build_store(b, addr, new_word);
}

static ValueName gen_expr(SSABuild *b, Ast *ast);
static void gen_stmt(SSABuild *b, Ast *ast);

static IrOp ast_to_irop(int ast_op) {
    switch (ast_op) {
    case '+': return IROP_ADD;
    case '-': return IROP_SUB;
    case '*': return IROP_MUL;
    case '/': return IROP_DIV;
    case '%': return IROP_MOD;
    case '&': return IROP_AND;
    case '|': return IROP_OR;
    case '^': return IROP_XOR;
    case '~': return IROP_NOT;
    case PUNCT_LSHIFT: return IROP_SHL;
    case PUNCT_RSHIFT: return IROP_SHR;
    case PUNCT_NE: return IROP_NE;
    case PUNCT_EQ: return IROP_EQ;
    case PUNCT_LE: return IROP_LE;
    case PUNCT_GE: return IROP_GE;
    case '<': return IROP_LT;
    case '>': return IROP_GT;
    default: return IROP_NOP;
    }
}

/* 类型转换辅助：根据源类型和目标类型选择正确的IROP */
static ValueName gen_type_cast(SSABuild *b, ValueName val, Ctype *from, Ctype *to) {
    if (!from || !to) return val;
    if (from->type == to->type) return val;
    
    int from_sz = from->size;
    int to_sz = to->size;
    
    // 指针与整数互转
    if (to->type == CTYPE_PTR && is_inttype(from)) {
        return ssa_build_inttoptr(b, val, to);
    }
    if (from->type == CTYPE_PTR && is_inttype(to)) {
        return ssa_build_ptrtoint(b, val, to);
    }
    
    // 浮点<->整数位重解释（union punning风格）
    if ((is_inttype(to) && is_flotype(from)) || 
        (is_flotype(to) && is_inttype(from))) {
        return ssa_build_bitcast(b, val, to);
    }
    
    // 整数截断/扩展
    if (is_inttype(from) && is_inttype(to)) {
        if (to_sz < from_sz) {
            return ssa_build_trunc(b, val, to);
        } else if (to_sz > from_sz) {
            // 根据源类型符号性选择
            CtypeAttr from_attr = get_attr(from->attr);
            if (from_attr.ctype_unsigned) {
                return ssa_build_zext(b, val, to);
            } else {
                return ssa_build_sext(b, val, to);
            }
        }
    }
    
    return val;
}

static ValueName gen_expr(SSABuild *b, Ast *ast) {
    if (!ast) return 0;
    
    switch (ast->type) {
    case AST_LITERAL:
        return ssa_build_const(b, ast->ival);
        
    case AST_LVAR: {
        return ssa_build_read(b, ast->varname);
    }
        
    case AST_ADDR: {
        // &var
        if (ast->operand && ast->operand->type == AST_LVAR) {
            return ssa_build_addr(b, ast->operand->varname);
        }
        // &array[i] 等复杂情况
        ValueName ptr = gen_expr(b, ast->operand);
        return ptr; // 已经是地址
    }
    
    case AST_DEREF: {
        // *ptr
        ValueName ptr = gen_expr(b, ast->operand);
        return ssa_build_load(b, ptr, ast->ctype);
    }
        
    case AST_FUNCALL: {
        List *args = make_list();
        if (ast->args) {
            for (Iter it = list_iter(ast->args); !iter_end(it);) {
                Ast *arg = iter_next(&it);
                ValueName val = gen_expr(b, arg);
                ValueName *p = ssa_alloc(sizeof(ValueName));
                *p = val;
                list_push(args, p);
            }
        }
        // 注意：args内存未释放，简化处理
        Instr *i = ssa_make_instr(b, IROP_CALL);
        i->dest = ssa_new_value(b);
        i->type = ast->ctype;
        ssa_add_label(i, ast->fname);
        for (Iter it = list_iter(args); !iter_end(it);) {
            ValueName *p = iter_next(&it);
            ssa_add_arg(i, *p);
        }
        ssa_emit(b, i);
        return i->dest;
    }
    
    case '+': case '-': case '*': case '/': case '%':
    case '&': case '|': case '^': 
    case PUNCT_LSHIFT: case PUNCT_RSHIFT:
    case PUNCT_EQ: case PUNCT_NE:
    case '<': case '>': case PUNCT_LE: case PUNCT_GE: {
        ValueName lhs = gen_expr(b, ast->left);
        ValueName rhs = gen_expr(b, ast->right);
        // 类型转换（算术转换）
        // 简化：假设左右类型相同，实际应查找common type
        ValueName res = ssa_build_binop(b, ast_to_irop(ast->type), lhs, rhs);
        return res;
    }
    
    case '~': case '!': {
        ValueName val = gen_expr(b, ast->operand);
        IrOp op = (ast->type == '~') ? IROP_NOT : IROP_LNOT;
        return ssa_build_unop(b, op, val);
    }
    
    case '=': {
        if (ast->left && ast->left->type == AST_LVAR) {
            ValueName val = gen_expr(b, ast->right);
            // 可能需要类型转换
            val = gen_type_cast(b, val, ast->right->ctype, ast->left->ctype);
            ssa_build_write(b, ast->left->varname, val);
            return val;
        } else if (ast->left && ast->left->type == AST_DEREF) {
            // *ptr = val
            ValueName ptr = gen_expr(b, ast->left->operand);
            ValueName val = gen_expr(b, ast->right);
            ssa_build_store(b, ptr, val);
            return val;
        }
        return gen_expr(b, ast->right);
    }
    
    case AST_TERNARY: {
        ValueName cond = gen_expr(b, ast->cond);
        Block *then_b = ssa_build_block(b);
        Block *else_b = ssa_build_block(b);
        Block *merge_b = ssa_build_block(b);
        
        // 条件为0时跳else，否则跳then（C语义）
        ValueName zero = ssa_build_const(b, 0);
        ValueName cmp = ssa_build_binop(b, IROP_NE, cond, zero);
        ssa_build_br(b, cmp, then_b, else_b);
        
        // Then分支
        ssa_build_position(b, then_b);
        ValueName t = gen_expr(b, ast->then);
        ssa_build_jmp(b, merge_b);
        ssa_build_seal(b, then_b);
        
        // Else分支
        ssa_build_position(b, else_b);
        ValueName e = gen_expr(b, ast->els);
        ssa_build_jmp(b, merge_b);
        ssa_build_seal(b, else_b);
        
        // Merge块：使用PHI或SELECT
        ssa_build_position(b, merge_b);
        // 使用SELECT简化：在value层面合并
        ssa_build_seal(b, merge_b);
        return ssa_build_select(b, cond, t, e);
    }
    
    case AST_CAST: {
        ValueName val = gen_expr(b, ast->cast_expr);
        return gen_type_cast(b, val, ast->cast_expr->ctype, ast->ctype);
    }
    
    case AST_STRUCT_REF: {
        // ptr->field 或 s.field（后者先取地址）
        ValueName base;
        Ctype *struct_type;
        
        if (ast->struc->type == AST_LVAR) {
            // s.field -> (&s)->field
            base = ssa_build_addr(b, ast->struc->varname);
            struct_type = ast->struc->ctype;
        } else {
            base = gen_expr(b, ast->struc);
            struct_type = ast->struc->ctype;
        }
        
        // 查找字段
        Ctype *field = dict_get(struct_type->fields, ast->field);
        if (!field) return 0;
        
        // 位域处理
        if (field->bit_size > 0) {
            return gen_bitfield_read(b, base, field->offset, 
                field->bit_offset, field->bit_size,
                !get_attr(field->attr).ctype_unsigned, field);
        }
        
        // 普通字段：计算偏移地址后加载
        ValueName field_addr = ssa_build_offset(b, base,
            ssa_build_const(b, field->offset), 1);
        return ssa_build_load(b, field_addr, field);
    }
    
    default:
        return 0;
    }
}

static void gen_stmt(SSABuild *b, Ast *ast) {
    if (!ast || !b->cur_block) return;
    
    switch (ast->type) {
    case AST_DECL: {
        Ast *var = ast->declvar;
        if (var && var->type == AST_LVAR) {
            if (ast->declinit) {
                ValueName val = gen_expr(b, ast->declinit);
                val = gen_type_cast(b, val, ast->declinit->ctype, var->ctype);
                ssa_build_write(b, var->varname, val);
            } else {
                ssa_build_write(b, var->varname, 0);
            }
        }
        break;
    }
    
    case AST_COMPOUND_STMT: {
        if (ast->stmts) {
            for (Iter it = list_iter(ast->stmts); !iter_end(it);) {
                gen_stmt(b, iter_next(&it));
            }
        }
        break;
    }
    
    case AST_IF: {
        ValueName cond = gen_expr(b, ast->cond);
        Block *then_b = ssa_build_block(b);
        Block *else_b = ssa_build_block(b);
        Block *merge_b = ssa_build_block(b);
        
        ValueName zero = ssa_build_const(b, 0);
        ValueName cmp = ssa_build_binop(b, IROP_NE, cond, zero);
        ssa_build_br(b, cmp, then_b, else_b);
        
        ssa_build_position(b, then_b);
        gen_stmt(b, ast->then);
        ssa_build_jmp(b, merge_b);
        ssa_build_seal(b, then_b);
        
        ssa_build_position(b, else_b);
        if (ast->els) gen_stmt(b, ast->els);
        ssa_build_jmp(b, merge_b);
        ssa_build_seal(b, else_b);
        
        ssa_build_position(b, merge_b);
        ssa_build_seal(b, merge_b);
        break;
    }
    
    case AST_WHILE: {
        Block *header = ssa_build_block(b);
        Block *body = ssa_build_block(b);
        Block *exit = ssa_build_block(b);
        
        ssa_build_jmp(b, header);
        ssa_build_position(b, header);
        
        ValueName cond = gen_expr(b, ast->while_cond);
        ValueName zero = ssa_build_const(b, 0);
        ValueName cmp = ssa_build_binop(b, IROP_NE, cond, zero);
        ssa_build_br(b, cmp, body, exit);
        
        ssa_build_position(b, body);
        ssa_build_push_cf(b, exit, header);
        gen_stmt(b, ast->while_body);
        ssa_build_pop_cf(b);
        
        ssa_build_jmp(b, header);
        ssa_build_seal(b, body);
        
        ssa_build_position(b, exit);
        ssa_build_seal(b, header);
        ssa_build_seal(b, exit);
        break;
    }
    
    case AST_FOR: {
        if (ast->forinit) gen_stmt(b, ast->forinit);
        
        Block *header = ssa_build_block(b);
        Block *body = ssa_build_block(b);
        Block *step = ssa_build_block(b);
        Block *exit = ssa_build_block(b);
        
        ssa_build_jmp(b, header);
        ssa_build_position(b, header);
        
        ValueName cond = ast->forcond ? gen_expr(b, ast->forcond) : ssa_build_const(b, 1);
        ValueName zero = ssa_build_const(b, 0);
        ValueName cmp = ssa_build_binop(b, IROP_NE, cond, zero);
        ssa_build_br(b, cmp, body, exit);
        
        ssa_build_position(b, body);
        ssa_build_push_cf(b, exit, step);
        gen_stmt(b, ast->forbody);
        ssa_build_pop_cf(b);
        ssa_build_jmp(b, step);
        
        ssa_build_position(b, step);
        if (ast->forstep) gen_expr(b, ast->forstep);
        ssa_build_jmp(b, header);
        
        ssa_build_seal(b, body);
        ssa_build_seal(b, step);
        
        ssa_build_position(b, exit);
        ssa_build_seal(b, header);
        ssa_build_seal(b, exit);
        break;
    }
    
    case AST_BREAK: {
        Block *t = ssa_build_get_break(b);
        if (t) {
            ssa_build_jmp(b, t);
            b->cur_block = NULL;
        }
        break;
    }
    
    case AST_CONTINUE: {
        Block *t = ssa_build_get_continue(b);
        if (t) {
            ssa_build_jmp(b, t);
            b->cur_block = NULL;
        }
        break;
    }
    
    case AST_RETURN: {
        ValueName val = ast->retval ? gen_expr(b, ast->retval) : 0;
        ssa_build_ret(b, val);
        break;
    }
    
    default:
        gen_expr(b, ast);
        break;
    }
}

static void gen_func(SSABuild *b, Ast *ast) {
    if (!ast || ast->type != AST_FUNC_DEF) return;
    
    Ctype *ret = (ast->ctype && ast->ctype->type == CTYPE_PTR)
                 ? ast->ctype->ptr : NULL;
    
    ssa_build_function(b, ast->fname, ret);
    
    if (ast->params) {
        for (Iter it = list_iter(ast->params); !iter_end(it);) {
            Ast *p = iter_next(&it);
            if (p->type == AST_DECL && p->declvar) {
                ssa_build_param(b, p->declvar->varname, p->declvar->ctype);
            } else if (p->type == AST_LVAR) {
                ssa_build_param(b, p->varname, p->ctype);
            }
        }
    }
    
    if (ast->body) {
        gen_stmt(b, ast->body);
    }
    
    if (b->cur_block) {
        ssa_build_ret(b, 0);
    }
}

static void gen_interrupt_func(SSABuild *b, Ast *ast) {
    if (!ast || ast->type != AST_INTERRUPT_DEF) return;
    
    // 生成中断函数名：ISR_0, ISR_1, ...
    char isr_name[32];
    snprintf(isr_name, sizeof(isr_name), "ISR_%d", ast->interrupt_id);
    
    Ctype *ret = (ast->ctype && ast->ctype->type == CTYPE_PTR)
                 ? ast->ctype->ptr : NULL;
    
    // 创建函数并标记为中断
    Func *f = ssa_build_function(b, ssa_strdup(isr_name), ret);
    f->is_interrupt = true;
    f->interrupt_id = ast->interrupt_id;
    f->bank_id = ast->bank_id;
    
    // 中断函数无参数
    
    if (ast->body) {
        gen_stmt(b, ast->body);
    }
    
    if (b->cur_block) {
        ssa_build_ret(b, 0);
    }
}

void ssa_convert_ast(SSABuild *b, Ast *ast) {
    if (!ast) return;
    switch (ast->type) {
    case AST_FUNC_DEF: gen_func(b, ast); break;
    case AST_INTERRUPT_DEF: gen_interrupt_func(b, ast); break;
    case AST_DECL: {
        // 处理全局变量声明
        Ast *var = ast->declvar;
        if (var && var->type == AST_GVAR) {
            long init_val = 0;
            bool has_init = false;
            if (ast->declinit && ast->declinit->type == AST_LITERAL &&
                is_inttype(ast->declinit->ctype)) {
                init_val = ast->declinit->ival;
                has_init = true;
            }
            ssa_add_global(b, var->varname, var->ctype, init_val, has_init);
        }
        break;
    }
    default: break;
    }
}

static const char* get_type_str(Ctype *type) {
    if (!type) return "int";
    switch (type->type) {
    case CTYPE_VOID: return "void";
    case CTYPE_BOOL: return "bool";
    case CTYPE_CHAR: return "char";
    case CTYPE_INT: return "int";
    case CTYPE_LONG: return "long";
    case CTYPE_FLOAT: return "float";
    case CTYPE_DOUBLE: return "double";
    case CTYPE_PTR: return "ptr";
    default: return "int";
    }
}

static void print_instr(FILE *fp, Instr *i) {
    if (i->op == IROP_NOP) return;
    
    if (i->dest > 0) {
        fprintf(fp, "    v%d: %s = ", i->dest, get_type_str(i->type));
    } else {
        fprintf(fp, "    ");
    }
    
    switch (i->op) {
    case IROP_PARAM:
        fprintf(fp, "param %s", (char*)list_get(i->labels, 0));
        break;
    case IROP_CONST:
        fprintf(fp, "const %ld", i->imm.ival);
        i->type = ctype_int;  // 常量默认int类型
        break;
    case IROP_ADD: case IROP_SUB: case IROP_MUL: case IROP_DIV: case IROP_MOD: {
        const char *op_str = (i->op == IROP_ADD) ? "add" :
                            (i->op == IROP_SUB) ? "sub" :
                            (i->op == IROP_MUL) ? "mul" :
                            (i->op == IROP_DIV) ? "div" : "mod";
        ValueName *a1 = list_get(i->args, 0);
        ValueName *a2 = list_get(i->args, 1);
        fprintf(fp, "%s v%d, v%d", op_str, *a1, *a2);
        break;
    }
    case IROP_NEG: {
        ValueName *a = list_get(i->args, 0);
        fprintf(fp, "neg v%d", *a);
        break;
    }
    case IROP_AND: case IROP_OR: case IROP_XOR: {
        const char *op_str = (i->op == IROP_AND) ? "and" :
                            (i->op == IROP_OR) ? "or" : "xor";
        ValueName *a1 = list_get(i->args, 0);
        ValueName *a2 = list_get(i->args, 1);
        fprintf(fp, "%s v%d, v%d", op_str, *a1, *a2);
        break;
    }
    case IROP_NOT: case IROP_LNOT: {
        const char *op_str = (i->op == IROP_NOT) ? "not" : "lnot";
        ValueName *a = list_get(i->args, 0);
        fprintf(fp, "%s v%d", op_str, *a);
        break;
    }
    case IROP_SHL: case IROP_SHR: {
        const char *op_str = (i->op == IROP_SHL) ? "shl" : "shr";
        ValueName *a1 = list_get(i->args, 0);
        ValueName *a2 = list_get(i->args, 1);
        fprintf(fp, "%s v%d, v%d", op_str, *a1, *a2);
        break;
    }
    case IROP_EQ: case IROP_LT: case IROP_GT: case IROP_LE: case IROP_GE: case IROP_NE: {
        const char *op_str = (i->op == IROP_EQ) ? "eq" :
                            (i->op == IROP_LT) ? "lt" :
                            (i->op == IROP_GT) ? "gt" :
                            (i->op == IROP_LE) ? "le" :
                            (i->op == IROP_GE) ? "ge" : "ne";
        ValueName *a1 = list_get(i->args, 0);
        ValueName *a2 = list_get(i->args, 1);
        fprintf(fp, "%s v%d, v%d", op_str, *a1, *a2);
        break;
    }
    case IROP_TRUNC: case IROP_ZEXT: case IROP_SEXT: 
    case IROP_BITCAST: case IROP_INTTOPTR: case IROP_PTRTOINT: {
        const char *op_str = (i->op == IROP_TRUNC) ? "trunc" :
                            (i->op == IROP_ZEXT) ? "zext" :
                            (i->op == IROP_SEXT) ? "sext" :
                            (i->op == IROP_BITCAST) ? "bitcast" :
                            (i->op == IROP_INTTOPTR) ? "inttoptr" : "ptrtoint";
        ValueName *a = list_get(i->args, 0);
        fprintf(fp, "%s v%d", op_str, *a);
        break;
    }
    case IROP_OFFSET: {
        ValueName *a1 = list_get(i->args, 0);
        ValueName *a2 = list_get(i->args, 1);
        fprintf(fp, "offset v%d, v%d, #%ld", *a1, *a2, i->imm.ival);
        break;
    }
    case IROP_SELECT: {
        ValueName *c = list_get(i->args, 0);
        ValueName *t = list_get(i->args, 1);
        ValueName *f = list_get(i->args, 2);
        fprintf(fp, "select v%d, v%d, v%d", *c, *t, *f);
        break;
    }
    case IROP_LOAD: {
        ValueName *p = list_get(i->args, 0);
        fprintf(fp, "load v%d", *p);
        break;
    }
    case IROP_STORE: {
        ValueName *p = list_get(i->args, 0);
        ValueName *v = list_get(i->args, 1);
        fprintf(fp, "store v%d, v%d", *p, *v);
        break;
    }
    case IROP_ADDR:
        fprintf(fp, "addr @%s", (char*)list_get(i->labels, 0));
        break;
    case IROP_PHI: {
        fprintf(fp, "phi ");
        for (int k = 0; k < i->args->len; k++) {
            if (k > 0) fprintf(fp, ", ");
            ValueName *v = list_get(i->args, k);
            char *lbl = list_get(i->labels, k);
            // label格式是"blockN"，输出为"%N"以保持一致性
            int block_id = 0;
            sscanf(lbl, "block%d", &block_id);
            fprintf(fp, "[v%d, b%d]", *v, block_id);
        }
        break;
    }
    case IROP_JMP: {
        char *lbl = (char*)list_get(i->labels, 0);
        int block_id = 0;
        sscanf(lbl, "block%d", &block_id);
        fprintf(fp, "jmp b%d", block_id);
        break;
    }
    case IROP_BR: {
        ValueName *c = list_get(i->args, 0);
        char *lbl_true = (char*)list_get(i->labels, 0);
        char *lbl_false = (char*)list_get(i->labels, 1);
        int block_id_true = 0, block_id_false = 0;
        sscanf(lbl_true, "block%d", &block_id_true);
        sscanf(lbl_false, "block%d", &block_id_false);
        fprintf(fp, "br v%d, b%d, b%d", *c,
                block_id_true, block_id_false);
        break;
    }
    case IROP_CALL: {
        fprintf(fp, "call @%s(", (char*)list_get(i->labels, 0));
        for (int k = 0; k < i->args->len; k++) {
            if (k > 0) fprintf(fp, ", ");
            ValueName *v = list_get(i->args, k);
            fprintf(fp, "v%d", *v);
        }
        fprintf(fp, ")");
        break;
    }
    case IROP_RET: {
        fprintf(fp, "ret");
        if (i->args->len > 0) {
            ValueName *v = list_get(i->args, 0);
            fprintf(fp, " v%d", *v);
        }
        break;
    }
    default:
        fprintf(fp, "op%d", i->op);
    }
    fprintf(fp, "\n");
}

static void ssa_print_func(FILE *fp, Func *f) {
    // Bril风格函数签名: @name(param: type, ...): ret_type
    fprintf(fp, "@%s(", f->name);
    for (int i = 0; i < f->params->len; i++) {
        if (i > 0) fprintf(fp, ", ");
        fprintf(fp, "%s: int", (char*)list_get(f->params, i));
    }
    fprintf(fp, "): %s {\n", get_type_str(f->ret_type));
    
    for (int j = 0; j < f->blocks->len; j++) {
        Block *blk = list_get(f->blocks, j);
        // Bril风格块标签: .bN:
        fprintf(fp, "\n  .b%d:\n", blk->id);
        
        // 先打印PHI
        for (int i = 0; i < blk->phis->len; i++) {
            print_instr(fp, list_get(blk->phis, i));
        }
        
        // 再打印普通指令
        for (int i = 0; i < blk->instrs->len; i++) {
            Instr *inst = list_get(blk->instrs, i);
            if (inst->op != IROP_PHI) // PHI已在上面打印
                print_instr(fp, inst);
        }
    }
    fprintf(fp, "}\n");
}

void ssa_print(FILE *fp, SSAUnit *unit) {
    for (Iter it = list_iter(unit->funcs); !iter_end(it);) {
        Func *f = iter_next(&it);
        ssa_print_func(fp, f);
        fprintf(fp, "\n");
    }
}

#ifdef MINITEST_IMPLEMENTATION
#include "minitest.h"

TEST(test, ssa) {
    char infile[256];
    printf("file path: ");
    if (!fgets(infile, sizeof infile, stdin) || !freopen(strtok(infile, "\n"), "r", stdin))
        puts("open fail"), exit(1);

    set_current_filename(infile);
    
    SSABuild *b = ssa_build_create();
    List *toplevels = read_toplevels();
    
    for (Iter i = list_iter(toplevels); !iter_end(i);) {
        Ast *v = iter_next(&i);
        printf("ast: %s\n", ast_to_string(v));
        ssa_convert_ast(b, v);
    }
    
    printf("\n=== SSA Output ===\n");
    ssa_print(stdout, b->unit);
    
    ssa_build_destroy(b);
    list_free(cstrings);
    list_free(ctypes);
}
#endif