/* ssa_pass.c - SSA 优化 Pass */

#include "ssa.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

static SSAUnit *g_unit = NULL;

/* Pass 统计 */
typedef struct PassStats {
    int instructions_removed;
    int instructions_added;
    int values_folded;
    int blocks_merged;
    int phis_removed;
} PassStats;

static void* pass_alloc(size_t size) {
    void *p = malloc(size);
    if (!p) {
        fprintf(stderr, "SSA Pass: out of memory\n");
        exit(1);
    }
    memset(p, 0, size);
    return p;
}

/* 分析工具 */

static bool is_volatile_mem(const Instr *i) {
    if (!i || !i->mem_type) return false;
    CtypeAttr attr = get_attr(i->mem_type->attr);
    return attr.ctype_volatile || attr.ctype_register;
}

static bool is_pure_instr(Instr *i) {
    switch (i->op) {
    case IROP_CONST:
    case IROP_ADD: case IROP_SUB: case IROP_MUL:
    case IROP_AND: case IROP_OR: case IROP_XOR:
    case IROP_SHL: case IROP_SHR:
    case IROP_NOT: case IROP_NEG: case IROP_LNOT:
    case IROP_EQ: case IROP_LT: case IROP_GT:
    case IROP_LE: case IROP_GE: case IROP_NE:
    case IROP_TRUNC: case IROP_ZEXT: case IROP_SEXT:
    case IROP_BITCAST: case IROP_INTTOPTR: case IROP_PTRTOINT:
    case IROP_SELECT: case IROP_PHI: case IROP_OFFSET:
    case IROP_ADDR:
        return true;
    case IROP_LOAD:
        return !is_volatile_mem(i);
    case IROP_STORE: case IROP_CALL:
    case IROP_RET: case IROP_JMP: case IROP_BR:
    case IROP_PARAM: case IROP_NOP:
    default:
        return false;
    }
}

static bool is_value_used(Func *f, ValueName val) {
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *blk = iter_next(&it);
        for (Iter jt = list_iter(blk->instrs); !iter_end(jt);) {
            Instr *inst = iter_next(&jt);
            if (!inst->args) continue;
            for (int i = 0; i < inst->args->len; i++) {
                ValueName *arg = list_get(inst->args, i);
                if (*arg == val) return true;
            }
        }
        for (Iter jt = list_iter(blk->phis); !iter_end(jt);) {
            Instr *phi = iter_next(&jt);
            if (!phi->args) continue;
            for (int i = 0; i < phi->args->len; i++) {
                ValueName *arg = list_get(phi->args, i);
                if (*arg == val) return true;
            }
        }
    }
    return false;
}

static ValueName get_arg(Instr *i, int idx) {
    if (idx >= i->args->len) return 0;
    ValueName *p = list_get(i->args, idx);
    return *p;
}

/* Pass 1: 常量折叠 */

static bool fold_binary_op(IrOp op, int64_t a, int64_t b, bool is_unsigned, int64_t *result) {
    uint64_t ua = (uint64_t)a;
    uint64_t ub = (uint64_t)b;
    switch (op) {
    case IROP_ADD: *result = is_unsigned ? (int64_t)(ua + ub) : (a + b); return true;
    case IROP_SUB: *result = is_unsigned ? (int64_t)(ua - ub) : (a - b); return true;
    case IROP_MUL: *result = is_unsigned ? (int64_t)(ua * ub) : (a * b); return true;
    case IROP_DIV:
        if (b == 0) return false;
        *result = is_unsigned ? (int64_t)(ua / ub) : (a / b);
        return true;
    case IROP_MOD:
        if (b == 0) return false;
        *result = is_unsigned ? (int64_t)(ua % ub) : (a % b);
        return true;
    case IROP_AND: *result = (int64_t)(ua & ub); return true;
    case IROP_OR:  *result = (int64_t)(ua | ub); return true;
    case IROP_XOR: *result = (int64_t)(ua ^ ub); return true;
    case IROP_SHL: *result = (int64_t)(ua << ub); return true;
    case IROP_SHR:
        *result = is_unsigned ? (int64_t)(ua >> ub) : (a >> b);
        return true;
    case IROP_EQ:  *result = (a == b) ? 1 : 0; return true;
    case IROP_NE:  *result = (a != b) ? 1 : 0; return true;
    case IROP_LT:  *result = is_unsigned ? (ua < ub) : (a < b); return true;
    case IROP_GT:  *result = is_unsigned ? (ua > ub) : (a > b); return true;
    case IROP_LE:  *result = is_unsigned ? (ua <= ub) : (a <= b); return true;
    case IROP_GE:  *result = is_unsigned ? (ua >= ub) : (a >= b); return true;
    default: return false;
    }
}

/* Pass 2: 代数简化 */

typedef struct SimplifyResult {
    bool simplified;
    ValueName replacement;
    bool to_const_zero;
} SimplifyResult;

static Instr *find_def_instr(Func *f, ValueName val) {
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *blk = iter_next(&it);
        for (Iter jt = list_iter(blk->instrs); !iter_end(jt);) {
            Instr *inst = iter_next(&jt);
            if (inst->dest == val) return inst;
        }
        for (Iter jt = list_iter(blk->phis); !iter_end(jt);) {
            Instr *phi = iter_next(&jt);
            if (phi->dest == val) return phi;
        }
    }
    return NULL;
}

static GlobalVar *find_global(SSAUnit *unit, const char *name) {
    if (!unit || !name) return NULL;
    for (Iter it = list_iter(unit->globals); !iter_end(it);) {
        GlobalVar *g = iter_next(&it);
        if (g->name && strcmp(g->name, name) == 0) return g;
    }
    return NULL;
}

static bool get_const_value(Func *f, ValueName val, int64_t *out) {
    Instr *def = find_def_instr(f, val);
    if (!def || def->op != IROP_CONST) return false;
    if (out) *out = def->imm.ival;
    return true;
}

static bool is_unsigned_type(Ctype *type) {
    return type && get_attr(type->attr).ctype_unsigned;
}

static bool is_const_global(GlobalVar *g) {
    if (!g || !g->type) return false;
    CtypeAttr attr = get_attr(g->type->attr);
    if (!attr.ctype_const) return false;
    if (attr.ctype_volatile || attr.ctype_register) return false;
    return g->has_init;
}

static SimplifyResult try_simplify(Instr *i) {
    SimplifyResult res = {false, 0, false};
    if (i->args->len < 1) return res;
    
    ValueName a = get_arg(i, 0);
    ValueName b = (i->args->len >= 2) ? get_arg(i, 1) : 0;
    
    switch (i->op) {
    case IROP_SUB: case IROP_XOR:
        if (a == b) { res.simplified = true; res.to_const_zero = true; }
        break;
    case IROP_AND: case IROP_OR:
        if (a == b) { res.simplified = true; res.replacement = a; }
        break;
    default:
        break;
    }
    return res;
}

/* Pass: 常量折叠 */
static bool pass_const_fold(Func *f, PassStats *stats) {
    bool changed = false;
    int folded = 0;

    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *blk = iter_next(&it);
        for (Iter jt = list_iter(blk->instrs); !iter_end(jt);) {
            Instr *inst = iter_next(&jt);
            if (inst->op == IROP_NOP || inst->op == IROP_CONST) continue;

            int64_t a = 0;
            int64_t b = 0;
            bool has_a = false;
            bool has_b = false;

            if (inst->args->len >= 1) {
                ValueName v = get_arg(inst, 0);
                has_a = get_const_value(f, v, &a);
            }
            if (inst->args->len >= 2) {
                ValueName v = get_arg(inst, 1);
                has_b = get_const_value(f, v, &b);
            }

            int64_t res = 0;
            bool is_unsigned = is_unsigned_type(inst->type);
            bool can_fold = false;

            switch (inst->op) {
            case IROP_ADD: case IROP_SUB: case IROP_MUL: case IROP_DIV:
            case IROP_MOD: case IROP_AND: case IROP_OR: case IROP_XOR:
            case IROP_SHL: case IROP_SHR:
            case IROP_EQ: case IROP_NE: case IROP_LT: case IROP_GT:
            case IROP_LE: case IROP_GE:
                if (has_a && has_b)
                    can_fold = fold_binary_op(inst->op, a, b, is_unsigned, &res);
                break;
            case IROP_NEG:
                if (has_a) {
                    res = is_unsigned ? (int64_t)(0ULL - (uint64_t)a) : -a;
                    can_fold = true;
                }
                break;
            case IROP_NOT:
                if (has_a) { res = ~a; can_fold = true; }
                break;
            case IROP_LNOT:
                if (has_a) { res = (!a) ? 1 : 0; can_fold = true; }
                break;
            case IROP_TRUNC:
            if (has_a) {
                // 根据目标类型大小进行截断
                int size = inst->type ? inst->type->size : 1;
                uint64_t mask = (size == 1) ? 0xFF :
                            (size == 2) ? 0xFFFF :
                            (size == 4) ? 0xFFFFFFFF : 0xFFFFFFFFFFFFFFFF;
                res = a & mask;
                can_fold = true;
            }
            break;
            case IROP_STORE:
                // store (addr @g), const 优化标记：labels[0] = "@g", imm.ival = const_val, 清除 args
                if (inst->args->len >= 2) {
                    ValueName ptr_val = get_arg(inst, 0);
                    ValueName val = get_arg(inst, 1);
                    Instr *ptr_def = find_def_instr(f, ptr_val);
                    Instr *val_def = find_def_instr(f, val);
                    if (ptr_def && ptr_def->op == IROP_ADDR &&
                        val_def && val_def->op == IROP_CONST) {
                        const char *name = (const char*)list_get(ptr_def->labels, 0);
                        if (name) {
                            // 标记为已优化（labels[0] 存全局变量名，imm 存常量值）
                            inst->imm.ival = val_def->imm.ival;
                            list_clear(inst->args);
                            list_clear(inst->labels);
                            char *label_copy = pass_alloc(strlen(name) + 2);
                            label_copy[0] = '@';
                            strcpy(label_copy + 1, name);
                            list_push(inst->labels, label_copy);
                            folded++;
                            changed = true;
                        }
                    }
                }
                continue;
            case IROP_RET:
                // ret const 优化标记：imm.ival = const_val, 清除 args
                if (inst->args->len >= 1) {
                    ValueName val = get_arg(inst, 0);
                    Instr *val_def = find_def_instr(f, val);
                    if (val_def && val_def->op == IROP_CONST) {
                        inst->imm.ival = val_def->imm.ival;
                        list_clear(inst->args);
                        folded++;
                        changed = true;
                    }
                }
                continue;
            default:
                break;
            }

            if (can_fold) {
                inst->op = IROP_CONST;
                inst->imm.ival = res;
                list_clear(inst->args);
                list_clear(inst->labels);
                folded++;
                changed = true;
            }
        }
    }

    if (stats) stats->values_folded += folded;
    return changed;
}

/* Pass: 只读全局常量折叠 (load @g -> const) */
static bool pass_const_global_load(Func *f, PassStats *stats) {
    if (!g_unit) return false;
    bool changed = false;
    int folded = 0;

    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *blk = iter_next(&it);
        for (Iter jt = list_iter(blk->instrs); !iter_end(jt);) {
            Instr *inst = iter_next(&jt);
            if (inst->op != IROP_LOAD) continue;
            if (is_volatile_mem(inst)) continue;

            ValueName ptr = get_arg(inst, 0);
            Instr *def = find_def_instr(f, ptr);
            if (!def || def->op != IROP_ADDR) continue;
            const char *name = (const char*)list_get(def->labels, 0);
            if (!name) continue;

            GlobalVar *g = find_global(g_unit, name);
            if (!is_const_global(g)) continue;

            inst->op = IROP_CONST;
            inst->imm.ival = g->init_value;
            inst->type = g->type;
            inst->mem_type = NULL;
            list_clear(inst->args);
            list_clear(inst->labels);
            folded++;
            changed = true;
        }
    }

    if (stats) stats->values_folded += folded;
    return changed;
}

/* Pass 3: 死代码消除 */

static bool pass_simple_dce(Func *f, PassStats *stats) {
    bool changed = false;
    int removed = 0;
    
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *blk = iter_next(&it);
        List *new_instrs = make_list();
        
        for (Iter jt = list_iter(blk->instrs); !iter_end(jt);) {
            Instr *inst = iter_next(&jt);
            
            if (inst->op == IROP_PHI) {
                list_push(new_instrs, inst);
                continue;
            }
            
            bool is_dead = false;
            if (inst->op == IROP_NOP) {
                is_dead = true;
            } else if (is_pure_instr(inst) && inst->dest > 0) {
                if (inst->op != IROP_PARAM && !is_value_used(f, inst->dest)) {
                    is_dead = true;
                }
            }
            
            if (is_dead) {
                inst->op = IROP_NOP;
                removed++;
                changed = true;
            } else {
                list_push(new_instrs, inst);
            }
        }
        blk->instrs = new_instrs;
    }
    
    if (stats) stats->instructions_removed += removed;
    return changed;
}

/* Pass 4: PHI 简化 */

static bool try_simplify_phi(Instr *phi, ValueName *replacement) {
    if (phi->op != IROP_PHI) return false;
    if (phi->args->len == 0) { *replacement = 0; return true; }
    
    ValueName first = 0;
    for (int i = 0; i < phi->args->len; i++) {
        ValueName *arg = list_get(phi->args, i);
        if (*arg != phi->dest) { first = *arg; break; }
    }
    
    if (first == 0) { *replacement = 0; return true; }
    
    for (int i = 0; i < phi->args->len; i++) {
        ValueName *arg = list_get(phi->args, i);
        if (*arg != phi->dest && *arg != first) return false;
    }
    
    *replacement = first;
    return true;
}

static bool pass_simplify_phis(Func *f, PassStats *stats) {
    bool changed = false;
    int removed = 0;
    
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *blk = iter_next(&it);
        List *new_phis = make_list();
        
        for (Iter jt = list_iter(blk->phis); !iter_end(jt);) {
            Instr *phi = iter_next(&jt);
            ValueName replacement;
            
            if (try_simplify_phi(phi, &replacement)) {
                phi->op = IROP_NOP;
                removed++;
                changed = true;
            } else {
                list_push(new_phis, phi);
            }
        }
        blk->phis = new_phis;
    }
    
    if (stats) stats->phis_removed += removed;
    return changed;
}

/* Pass 5: 代数简化 Pass */

static bool pass_algebraic_simplify(Func *f, PassStats *stats) {
    bool changed = false;
    int simplified = 0;
    
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *blk = iter_next(&it);
        for (Iter jt = list_iter(blk->instrs); !iter_end(jt);) {
            Instr *inst = iter_next(&jt);
            SimplifyResult res = try_simplify(inst);
            if (res.simplified) simplified++;
        }
    }
    
    if (stats) stats->values_folded += simplified;
    return changed;
}

/* Pass 6: 比较链简化 (ne (eq x, 0), 0) -> x */
static bool pass_simplify_compare_chain(Func *f, PassStats *stats) {
    bool changed = false;
    int simplified = 0;
    
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *blk = iter_next(&it);
        for (Iter jt = list_iter(blk->instrs); !iter_end(jt);) {
            Instr *inst = iter_next(&jt);
            
            // 模式：ne (eq x, 0), 0 -> x
            if (inst->op == IROP_NE && inst->args->len == 2) {
                ValueName a = get_arg(inst, 0);
                ValueName b = get_arg(inst, 1);
                
                // 检查 b 是否是 const 0
                Instr *b_def = find_def_instr(f, b);
                if (b_def && b_def->op == IROP_CONST && b_def->imm.ival == 0) {
                    // 检查 a 是否是 eq x, 0
                    Instr *a_def = find_def_instr(f, a);
                    if (a_def && a_def->op == IROP_EQ && a_def->args->len == 2) {
                        ValueName eq_a = get_arg(a_def, 0);
                        ValueName eq_b = get_arg(a_def, 1);
                        
                        // 检查 eq 的第二个操作数是否是 const 0
                        Instr *eq_b_def = find_def_instr(f, eq_b);
                        if (eq_b_def && eq_b_def->op == IROP_CONST && eq_b_def->imm.ival == 0) {
                            // 替换：ne (eq x, 0), 0 -> x
                            list_clear(inst->args);
                            ValueName *new_arg = pass_alloc(sizeof(ValueName));
                            *new_arg = eq_a;
                            list_push(inst->args, new_arg);
                            inst->op = IROP_TRUNC;  // 使用 trunc 作为布尔转换
                            simplified++;
                            changed = true;
                        }
                    }
                }
            }
        }
    }
    
    if (stats) stats->values_folded += simplified;
    return changed;
}

/* 优化 API */
void ssa_optimize_func(Func *f, int level) {
    if (!f || level == OPT_O0) return;
    
    PassStats stats = {0};
    bool changed = true;
    int max_iterations = 10;
    int iteration = 0;
    
    while (changed && iteration < max_iterations) {
        changed = false;
        iteration++;
        changed |= pass_const_fold(f, &stats);
        changed |= pass_const_global_load(f, &stats);
        changed |= pass_simplify_compare_chain(f, &stats);
        changed |= pass_simplify_phis(f, &stats);
        changed |= pass_simple_dce(f, &stats);
        changed |= pass_algebraic_simplify(f, &stats);
    }
}

void ssa_optimize(SSAUnit *unit, int level) {
    if (!unit) return;
    g_unit = unit;
    for (Iter it = list_iter(unit->funcs); !iter_end(it);) {
        Func *f = iter_next(&it);
        ssa_optimize_func(f, level);
    }
    g_unit = NULL;
}

/* 测试 */

#ifdef MINITEST_IMPLEMENTATION
#include "minitest.h"

extern List *ctypes;
extern List *strings;
extern List *read_toplevels(void);
extern void set_current_filename(const char *filename);
extern char *ast_to_string(Ast *ast);

TEST(test, ssa_opt) {
    char infile[256];
    printf("file path for SSA optimization test: ");
    if (!fgets(infile, sizeof infile, stdin) || !freopen(strtok(infile, "\n"), "r", stdin))
        puts("open fail"), exit(1);

    set_current_filename(infile);
    
    SSABuild *b = ssa_build_create();
    List *toplevels = read_toplevels();
    
    printf("\n=== Parsing AST ===\n");
    for (Iter i = list_iter(toplevels); !iter_end(i);) {
        Ast *v = iter_next(&i);
        printf("ast: %s\n", ast_to_string(v));
        ssa_convert_ast(b, v);
    }
    
    printf("\n=== Original SSA Output ===\n");
    ssa_print(stdout, b->unit);
    
    printf("\n=== Running Optimizations (O1) ===\n");
    ssa_optimize(b->unit, OPT_O1);
    
    printf("\n=== Optimized SSA Output ===\n");
    ssa_print(stdout, b->unit);
    
    ssa_build_destroy(b);
    list_free(strings);
    list_free(ctypes);
}
#endif
