/* ssa_pass.c - SSA 优化 Pass */

#include "ssa.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

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
        return true;
    case IROP_LOAD: case IROP_STORE: case IROP_CALL:
    case IROP_RET: case IROP_JMP: case IROP_BR:
    case IROP_PARAM: case IROP_ADDR: case IROP_NOP:
    default:
        return false;
    }
}

static bool is_value_used(Func *f, ValueName val) {
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *blk = iter_next(&it);
        for (Iter jt = list_iter(blk->instrs); !iter_end(jt);) {
            Instr *inst = iter_next(&jt);
            for (int i = 0; i < inst->args->len; i++) {
                ValueName *arg = list_get(inst->args, i);
                if (*arg == val) return true;
            }
        }
        for (Iter jt = list_iter(blk->phis); !iter_end(jt);) {
            Instr *phi = iter_next(&jt);
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

static bool fold_binary_op(IrOp op, int64_t a, int64_t b, int64_t *result) {
    switch (op) {
    case IROP_ADD: *result = a + b; return true;
    case IROP_SUB: *result = a - b; return true;
    case IROP_MUL: *result = a * b; return true;
    case IROP_DIV: if (b == 0) return false; *result = a / b; return true;
    case IROP_MOD: if (b == 0) return false; *result = a % b; return true;
    case IROP_AND: *result = a & b; return true;
    case IROP_OR:  *result = a | b; return true;
    case IROP_XOR: *result = a ^ b; return true;
    case IROP_SHL: *result = a << b; return true;
    case IROP_SHR: *result = a >> b; return true;
    case IROP_EQ:  *result = (a == b) ? 1 : 0; return true;
    case IROP_NE:  *result = (a != b) ? 1 : 0; return true;
    case IROP_LT:  *result = (a < b)  ? 1 : 0; return true;
    case IROP_GT:  *result = (a > b)  ? 1 : 0; return true;
    case IROP_LE:  *result = (a <= b) ? 1 : 0; return true;
    case IROP_GE:  *result = (a >= b) ? 1 : 0; return true;
    default: return false;
    }
}

/* Pass 2: 代数简化 */

typedef struct SimplifyResult {
    bool simplified;
    ValueName replacement;
    bool to_const_zero;
} SimplifyResult;

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
        changed |= pass_simplify_phis(f, &stats);
        changed |= pass_simple_dce(f, &stats);
        changed |= pass_algebraic_simplify(f, &stats);
    }
}

void ssa_optimize(SSAUnit *unit, int level) {
    if (!unit) return;
    for (Iter it = list_iter(unit->funcs); !iter_end(it);) {
        Func *f = iter_next(&it);
        ssa_optimize_func(f, level);
    }
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
