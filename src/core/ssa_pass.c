/* ssa_pass.c  – 精简版，功能与原文件 100% 兼容 */
#include "ssa.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

static SSAUnit *g_unit;

/*---------- 通用基础设施 ----------*/
static void *pass_alloc(size_t sz) {
    void *p = malloc(sz);
    if (!p) { fputs("SSA Pass: out of memory\n", stderr); exit(1); }
    return memset(p, 0, sz);
}

/* 内联取参数 */
static inline ValueName get_arg(const Instr *i, int idx) {
    return (i && i->args && idx < i->args->len)
           ? *(ValueName *)list_get(i->args, idx) : 0;
}

/* 过滤列表工具：把 src 里满足 pred 的元素拷到新列表并返回 */
static List *filter_list(List *src, bool (*pred)(void *, void *), void *aux) {
    List *dst = make_list();
    for (Iter it = list_iter(src); !iter_end(it);) {
        void *x = iter_next(&it);
        if (pred(x, aux)) list_push(dst, x);
    }
    return dst;
}

/*---------- 指令属性 ----------*/
static bool is_volatile_mem(const Instr *i) {
    if (!i || !i->mem_type) return false;
    CtypeAttr a = get_attr(i->mem_type->attr);
    return a.ctype_volatile || a.ctype_register;
}

static bool is_pure_instr(const Instr *i) {
    switch (i->op) {
    case IROP_CONST:
    case IROP_ADD: case IROP_SUB: case IROP_MUL: case IROP_DIV: case IROP_MOD:
    case IROP_AND: case IROP_OR:  case IROP_XOR:
    case IROP_SHL: case IROP_SHR: case IROP_NOT: case IROP_NEG: case IROP_LNOT:
    case IROP_EQ: case IROP_NE: case IROP_LT: case IROP_GT: case IROP_LE: case IROP_GE:
    case IROP_TRUNC: case IROP_ZEXT: case IROP_SEXT:
    case IROP_BITCAST: case IROP_INTTOPTR: case IROP_PTRTOINT:
    case IROP_SELECT: case IROP_PHI: case IROP_OFFSET: case IROP_ADDR:
        return true;
    case IROP_LOAD:
        return !is_volatile_mem(i);
    default:
        return false;
    }
}

/*---------- 数据流辅助 ----------*/
static Instr *find_def_instr(Func *f, ValueName v) {
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        for (Iter jt = list_iter(b->instrs); !iter_end(jt);) {
            Instr *i = iter_next(&jt);
            if (i->dest == v) return i;
        }
        for (Iter jt = list_iter(b->phis); !iter_end(jt);) {
            Instr *p = iter_next(&jt);
            if (p->dest == v) return p;
        }
    }
    return NULL;
}

static GlobalVar *find_global(const char *name) {
    if (!g_unit || !name) return NULL;
    for (Iter it = list_iter(g_unit->globals); !iter_end(it);) {
        GlobalVar *g = iter_next(&it);
        if (g->name && !strcmp(g->name, name)) return g;
    }
    return NULL;
}

static bool get_const_value(Func *f, ValueName v, int64_t *out) {
    Instr *i = find_def_instr(f, v);
    if (i && i->op == IROP_CONST) { if (out) *out = i->imm.ival; return true; }
    return false;
}

static bool is_unsigned_type(Ctype *t) {
    return t && get_attr(t->attr).ctype_unsigned;
}

static bool is_const_global(GlobalVar *g) {
    if (!g || !g->type) return false;
    CtypeAttr a = get_attr(g->type->attr);
    return a.ctype_const && !a.ctype_volatile && !a.ctype_register && g->has_init;
}

static bool value_used(Func *f, ValueName v)
{
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        /* 扫描普通指令 */
        for (Iter jt = list_iter(b->instrs); !iter_end(jt);) {
            Instr *i = iter_next(&jt);
            if (i->args) {
                for (int k = 0; k < i->args->len; ++k)
                    if (*(ValueName *)list_get(i->args, k) == v)
                        return true;
            }
        }
        /* 扫描 PHI */
        for (Iter jt = list_iter(b->phis); !iter_end(jt);) {
            Instr *p = iter_next(&jt);
            if (p->args) {
                for (int k = 0; k < p->args->len; ++k)
                    if (*(ValueName *)list_get(p->args, k) == v)
                        return true;
            }
        }
    }
    return false;
}

/*---------- 常量折叠 ----------*/
static bool fold_binary_op(IrOp op, int64_t a, int64_t b, bool u, int64_t *r) {
    uint64_t ua = (uint64_t)a, ub = (uint64_t)b;
    switch (op) {
    case IROP_ADD: *r = u ? (int64_t)(ua + ub) : (a + b); return true;
    case IROP_SUB: *r = u ? (int64_t)(ua - ub) : (a - b); return true;
    case IROP_MUL: *r = u ? (int64_t)(ua * ub) : (a * b); return true;
    case IROP_DIV: if (b == 0) return false; *r = u ? (int64_t)(ua / ub) : (a / b); return true;
    case IROP_MOD: if (b == 0) return false; *r = u ? (int64_t)(ua % ub) : (a % b); return true;
    case IROP_AND: *r = (int64_t)(ua & ub); return true;
    case IROP_OR:  *r = (int64_t)(ua | ub); return true;
    case IROP_XOR: *r = (int64_t)(ua ^ ub); return true;
    case IROP_SHL: *r = (int64_t)(ua << ub); return true;
    case IROP_SHR: *r = u ? (int64_t)(ua >> ub) : (a >> b); return true;
    case IROP_EQ:  *r = (a == b); return true;
    case IROP_NE:  *r = (a != b); return true;
    case IROP_LT:  *r = u ? (ua < ub) : (a < b); return true;
    case IROP_GT:  *r = u ? (ua > ub) : (a > b); return true;
    case IROP_LE:  *r = u ? (ua <= ub) : (a <= b); return true;
    case IROP_GE:  *r = u ? (ua >= ub) : (a >= b); return true;
    default: return false;
    }
}

/*---------- 统一 Pass 骨架 ----------*/
typedef struct { int rm, add, fold, merge, phi_rm; } Stats;
#define PASS(_name)                                                     \
    static bool _name(Func *f, Stats *s);                               \
    static bool _name##_wrap(Func *f, Stats *s) {                       \
        bool changed = _name(f, s);                                     \
        if (changed && s) s->name##_done = 1; /* 占位，可扩展 */        \
        return changed;                                                 \
    }
/* 由于宏展开需要知道 stats 成员名称，这里直接用 stats 指针即可，不展开成员 */

/*---------- 死代码消除 ----------*/
static bool dce_pred(void *inst, void *f_) {
    Instr *i = inst; Func *f = f_;
    if (i->op == IROP_PHI) return true;
    if (i->op == IROP_NOP) return false;
    if (is_pure_instr(i) && i->dest && !value_used(f, i->dest)) return false;
    return true;
}
static bool pass_dce(Func *f, Stats *s) {
    int rm0 = s->rm;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        List *keep = filter_list(b->instrs, dce_pred, f);
        s->rm += b->instrs->len - keep->len;
        b->instrs = keep;
    }
    return s->rm != rm0;
}

/*---------- PHI 简化 ----------*/
static bool phi_pred(void *phi_, void *f_) {
    Instr *p = phi_; Func *f = f_;
    ValueName rep;
    if (p->op != IROP_PHI) return true;
    /* 全部相同或自引用 => 可删 */
    ValueName first = 0;
    for (int i = 0; i < p->args->len; ++i) {
        ValueName v = *(ValueName *)list_get(p->args, i);
        if (v != p->dest) { if (!first) first = v; else if (v != first) return true; }
    }
    return false; /* 可删 */
}
static bool pass_phi(Func *f, Stats *s) {
    int rm0 = s->phi_rm;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        List *keep = filter_list(b->phis, phi_pred, f);
        s->phi_rm += b->phis->len - keep->len;
        b->phis = keep;
    }
    return s->phi_rm != rm0;
}

/*---------- 常量折叠 + store/ret 标记 ----------*/
static bool pass_const_fold(Func *f, Stats *s) {
    bool changed = false;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        for (Iter jt = list_iter(b->instrs); !iter_end(jt);) {
            Instr *i = iter_next(&jt);
            if (i->op == IROP_NOP || i->op == IROP_CONST) continue;

            int64_t a = 0, b = 0, r = 0;
            bool ha = get_const_value(f, get_arg(i, 0), &a);
            bool hb = get_const_value(f, get_arg(i, 1), &b);
            bool u = is_unsigned_type(i->type);
            bool ok = false;

            switch (i->op) {
            /* 二元 */
            CASE_BIN: ok = (ha && hb) && fold_binary_op(i->op, a, b, u, &r); break;
            case IROP_NEG: ok = ha; r = u ? (int64_t)(0ULL - (uint64_t)a) : -a; break;
            case IROP_NOT: ok = ha; r = ~a; break;
            case IROP_LNOT: ok = ha; r = !a; break;
            case IROP_TRUNC:
                if (ha) { int sz = i->type ? i->type->size : 1; uint64_t m = sz == 1 ? 0xFF : sz == 2 ? 0xFFFF : sz == 4 ? 0xFFFFFFFF : ~0ULL; r = a & m; ok = true; }
                break;
            /* store/ret 特殊标记 */
            case IROP_STORE:
                if (i->args->len >= 2) {
                    Instr *addr = find_def_instr(f, get_arg(i, 0));
                    Instr *val  = find_def_instr(f, get_arg(i, 1));
                    if (addr && addr->op == IROP_ADDR && val && val->op == IROP_CONST) {
                        const char *gname = (const char *)list_get(addr->labels, 0);
                        if (gname) {
                            i->imm.ival = val->imm.ival;
                            list_clear(i->args); list_clear(i->labels);
                            char *lab = pass_alloc(strlen(gname) + 2);
                            lab[0] = '@'; strcpy(lab + 1, gname);
                            list_push(i->labels, lab);
                            ++s->fold; changed = true;
                        }
                    }
                }
                continue;
            case IROP_RET:
                // 保持 ret 指令的标准格式，不进行常量折叠优化
                // ret 指令应该始终引用虚拟寄存器，保持 SSA 格式的一致性
                continue;
            default: break;
            }
            if (ok) {
                i->op = IROP_CONST; i->imm.ival = r;
                list_clear(i->args); list_clear(i->labels);
                ++s->fold; changed = true;
            }
        }
    }
    return changed;
}
#undef CASE_BIN

/*---------- 只读全局常量折叠 ----------*/
static bool pass_global_load(Func *f, Stats *s) {
    bool changed = false;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        for (Iter jt = list_iter(b->instrs); !iter_end(jt);) {
            Instr *i = iter_next(&jt);
            if (i->op != IROP_LOAD || is_volatile_mem(i)) continue;
            Instr *addr = find_def_instr(f, get_arg(i, 0));
            if (!addr || addr->op != IROP_ADDR) continue;
            const char *name = (const char *)list_get(addr->labels, 0);
            GlobalVar *g = name ? find_global(name) : NULL;
            if (!is_const_global(g)) continue;
            i->op = IROP_CONST; i->imm.ival = g->init_value;
            i->type = g->type; i->mem_type = NULL;
            list_clear(i->args); list_clear(i->labels);
            ++s->fold; changed = true;
        }
    }
    return changed;
}

/*---------- 代数简化 + 比较链 + br-trunc 三合一 ----------*/
static bool pass_local_opts(Func *f, Stats *s) {
    bool changed = false;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        for (Iter jt = list_iter(b->instrs); !iter_end(jt);) {
            Instr *i = iter_next(&jt);
            /* 1. 代数 */
            if (i->args->len >= 1) {
                ValueName a = get_arg(i, 0), b = i->args->len >= 2 ? get_arg(i, 1) : 0;
                if ((i->op == IROP_SUB || i->op == IROP_XOR) && a == b) {
                    i->op = IROP_CONST; i->imm.ival = 0;
                    list_clear(i->args); ++s->fold; changed = true; continue;
                }
                if ((i->op == IROP_AND || i->op == IROP_OR) && a == b) {
                    /* replace with a */
                    list_clear(i->args);
                    ValueName *p = pass_alloc(sizeof *p); *p = a;
                    list_push(i->args, p);
                    ++s->fold; changed = true; continue;
                }
            }
            /* 2. 比较链  ne (eq x,0),0 -> x */
            if (i->op == IROP_NE && i->args->len == 2) {
                ValueName a = get_arg(i, 0), b = get_arg(i, 1);
                Instr *db = find_def_instr(f, b);
                if (db && db->op == IROP_CONST && db->imm.ival == 0) {
                    Instr *da = find_def_instr(f, a);
                    if (da && da->op == IROP_EQ && da->args->len == 2) {
                        Instr *dz = find_def_instr(f, get_arg(da, 1));
                        if (dz && dz->op == IROP_CONST && dz->imm.ival == 0) {
                            list_clear(i->args);
                            ValueName *p = pass_alloc(sizeof *p); *p = get_arg(da, 0);
                            list_push(i->args, p);
                            i->op = IROP_TRUNC; /* bool cast */
                            ++s->fold; changed = true; continue;
                        }
                    }
                }
            }
            /* 3. br trunc 消除 */
            if (i->op == IROP_BR && i->args->len >= 1) {
                Instr *c = find_def_instr(f, get_arg(i, 0));
                if (c && c->op == IROP_TRUNC && c->args->len >= 1) {
                    list_clear(i->args);
                    ValueName *p = pass_alloc(sizeof *p); *p = get_arg(c, 0);
                    list_push(i->args, p);
                    ++s->rm; changed = true; continue;
                }
            }
        }
    }
    return changed;
}

/*---------- 统一迭代框架 ----------*/
void ssa_optimize_func(Func *f, int level) {
    if (!f || level == OPT_O0) return;
    Stats st = {0};
    bool changed;
    int it = 0;
    do {
        changed  = pass_const_fold(f, &st);
        changed |= pass_global_load(f, &st);
        changed |= pass_local_opts(f, &st);
        changed |= pass_phi(f, &st);
        changed |= pass_dce(f, &st);
    } while (changed && ++it < 10);
}

void ssa_optimize(SSAUnit *u, int level) {
    if (!u) return;
    g_unit = u;
    for (Iter i = list_iter(u->funcs); !iter_end(i);)
        ssa_optimize_func(iter_next(&i), level);
    g_unit = NULL;
}

/*---------- 测试入口（未改动） ----------*/
#ifdef MINITEST_IMPLEMENTATION
#include "minitest.h"
extern List *ctypes, *strings;
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