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

static bool block_ptr_eq(void *a, void *b) { return a == b; }

static int max_value_in_func(Func *f) {
    int maxv = 0;
    if (!f || !f->blocks) return 0;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b) continue;
        if (b->phis) {
            for (Iter jt = list_iter(b->phis); !iter_end(jt);) {
                Instr *i = iter_next(&jt);
                if (!i) continue;
                if (i->dest > maxv) maxv = i->dest;
                if (i->args) {
                    for (int k = 0; k < i->args->len; ++k) {
                        int v = *(ValueName *)list_get(i->args, k);
                        if (v > maxv) maxv = v;
                    }
                }
            }
        }
        if (b->instrs) {
            for (Iter jt = list_iter(b->instrs); !iter_end(jt);) {
                Instr *i = iter_next(&jt);
                if (!i) continue;
                if (i->dest > maxv) maxv = i->dest;
                if (i->args) {
                    for (int k = 0; k < i->args->len; ++k) {
                        int v = *(ValueName *)list_get(i->args, k);
                        if (v > maxv) maxv = v;
                    }
                }
            }
        }
    }
    return maxv;
}

static void replace_value(Func *f, ValueName from, ValueName to) {
    if (!f || from == to) return;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b) continue;
        if (b->phis) {
            for (Iter jt = list_iter(b->phis); !iter_end(jt);) {
                Instr *i = iter_next(&jt);
                if (!i || !i->args) continue;
                for (int k = 0; k < i->args->len; ++k) {
                    ValueName *v = list_get(i->args, k);
                    if (v && *v == from) *v = to;
                }
            }
        }
        if (b->instrs) {
            for (Iter jt = list_iter(b->instrs); !iter_end(jt);) {
                Instr *i = iter_next(&jt);
                if (!i || !i->args) continue;
                for (int k = 0; k < i->args->len; ++k) {
                    ValueName *v = list_get(i->args, k);
                    if (v && *v == from) *v = to;
                }
            }
        }
    }
}

static void replace_value_skip_phi(Func *f, ValueName from, ValueName to, Instr *skip_phi) {
    if (!f || from == to) return;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b) continue;
        if (b->phis) {
            for (Iter jt = list_iter(b->phis); !iter_end(jt);) {
                Instr *i = iter_next(&jt);
                if (!i || i == skip_phi || !i->args) continue;
                for (int k = 0; k < i->args->len; ++k) {
                    ValueName *v = list_get(i->args, k);
                    if (v && *v == from) *v = to;
                }
            }
        }
        if (b->instrs) {
            for (Iter jt = list_iter(b->instrs); !iter_end(jt);) {
                Instr *i = iter_next(&jt);
                if (!i || !i->args) continue;
                for (int k = 0; k < i->args->len; ++k) {
                    ValueName *v = list_get(i->args, k);
                    if (v && *v == from) *v = to;
                }
            }
        }
    }
}

static bool block_has_ret(Block *b) {
    if (!b || !b->instrs) return false;
    for (Iter it = list_iter(b->instrs); !iter_end(it);) {
        Instr *i = iter_next(&it);
        if (i && i->op == IROP_RET) return true;
    }
    return false;
}

static void replace_phi_pred_label(Block *blk, int old_id, int new_id) {
    if (!blk || !blk->phis) return;
    char old_lbl[32];
    char new_lbl[32];
    snprintf(old_lbl, sizeof(old_lbl), "block%d", old_id);
    snprintf(new_lbl, sizeof(new_lbl), "block%d", new_id);

    for (Iter it = list_iter(blk->phis); !iter_end(it);) {
        Instr *phi = iter_next(&it);
        if (!phi || !phi->labels) continue;
        for (int k = 0; k < phi->labels->len; ++k) {
            char *lbl = (char *)list_get(phi->labels, k);
            if (!lbl) continue;
            if (strcmp(lbl, old_lbl) == 0) {
                char *rep = pass_alloc(strlen(new_lbl) + 1);
                strcpy(rep, new_lbl);
                list_set(phi->labels, k, rep);
            }
        }
    }
}

static void list_remove_last(List *list, void **out) {
    if (out) *out = NULL;
    if (!list || !list->tail) return;
    ListNode *tail = list->tail;
    if (out) *out = tail->elem;
    list->tail = tail->prev;
    if (list->tail) list->tail->next = NULL;
    else list->head = NULL;
    free(tail);
    list->len--;
}

static void list_clear_shallow(List *list) {
    if (!list) return;
    ListNode *node = list->head;
    while (node) {
        ListNode *next = node->next;
        free(node);
        node = next;
    }
    list->len = 0;
    list->head = list->tail = NULL;
}

static List *preds_remove(List *preds, Block *rem) {
    List *dst = make_list();
    if (!preds) return dst;
    for (Iter it = list_iter(preds); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (b != rem) list_push(dst, b);
    }
    return dst;
}

static void replace_term_target(Block *pred, int old_id, int new_id) {
    if (!pred || !pred->instrs || pred->instrs->len == 0) return;
    Instr *term = (Instr *)list_get(pred->instrs, pred->instrs->len - 1);
    if (!term || !term->labels) return;
    for (int k = 0; k < term->labels->len; ++k) {
        char *lbl = (char *)list_get(term->labels, k);
        if (!lbl) continue;
        int tid = -1;
        if (sscanf(lbl, "block%d", &tid) == 1 && tid == old_id) {
            char *rep = pass_alloc(32);
            snprintf(rep, 32, "block%d", new_id);
            list_set(term->labels, k, rep);
        }
    }
}

/*---------- 指令属性 ----------*/
static bool is_volatile_mem(const Instr *i) {
    if (!i || !i->mem_type) return false;
    CtypeAttr a = get_attr(i->mem_type->attr);
    return a.ctype_volatile || a.ctype_register;
}

// store->load 转发：屏蔽 volatile 与 register（SFR/SBIT）
static bool is_volatile_for_forwarding(const Instr *i) {
    if (!i || !i->mem_type) return false;
    CtypeAttr a = get_attr(i->mem_type->attr);
    return a.ctype_volatile || a.ctype_register;
}

static bool is_pure_instr(const Instr *i) {
    switch (i->op) {
    case IROP_PARAM:
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

static Block *find_block_by_id(Func *f, int id) {
    if (!f || !f->blocks) return NULL;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (b && (int)b->id == id) return b;
    }
    return NULL;
}

/*---------- 重新构建前驱列表 ----------*/
static void rebuild_preds(Func *f) {
    if (!f || !f->blocks) return;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b) continue;
        if (!b->preds) b->preds = make_list();
        else list_clear_shallow(b->preds);
    }

    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b || !b->instrs || b->instrs->len == 0) continue;
        Instr *term = (Instr *)list_get(b->instrs, b->instrs->len - 1);
        if (!term || !term->labels) continue;

        if (term->op == IROP_JMP && term->labels->len >= 1) {
            int tid = -1;
            sscanf((char *)list_get(term->labels, 0), "block%d", &tid);
            Block *t = find_block_by_id(f, tid);
            if (t) list_unique_push(t->preds, b, block_ptr_eq);
        } else if (term->op == IROP_BR && term->labels->len >= 2) {
            int t1 = -1, t2 = -1;
            sscanf((char *)list_get(term->labels, 0), "block%d", &t1);
            sscanf((char *)list_get(term->labels, 1), "block%d", &t2);
            Block *b1 = find_block_by_id(f, t1);
            Block *b2 = find_block_by_id(f, t2);
            if (b1) list_unique_push(b1->preds, b, block_ptr_eq);
            if (b2) list_unique_push(b2->preds, b, block_ptr_eq);
        }
    }
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
            if (i && i->op == IROP_STORE && i->labels && i->labels->len > 0) {
                char *label = (char *)list_get(i->labels, 0);
                if (label && label[0] == '@') {
                    continue; /* const store 的参数不计为使用 */
                }
            }
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

static int count_uses(Func *f, ValueName v)
{
    int cnt = 0;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        /* 普通指令 */
        for (Iter jt = list_iter(b->instrs); !iter_end(jt);) {
            Instr *i = iter_next(&jt);
            if (i && i->op == IROP_STORE && i->labels && i->labels->len > 0) {
                char *label = (char *)list_get(i->labels, 0);
                if (label && label[0] == '@') {
                    continue; /* const store 的参数不计为使用 */
                }
            }
            if (i->args) {
                for (int k = 0; k < i->args->len; ++k)
                    if (*(ValueName *)list_get(i->args, k) == v)
                        cnt++;
            }
        }
        /* PHI */
        for (Iter jt = list_iter(b->phis); !iter_end(jt);) {
            Instr *p = iter_next(&jt);
            if (p->args) {
                for (int k = 0; k < p->args->len; ++k)
                    if (*(ValueName *)list_get(p->args, k) == v)
                        cnt++;
            }
        }
    }
    return cnt;
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
#define CASE_BIN \
    case IROP_ADD: case IROP_SUB: case IROP_MUL: case IROP_DIV: case IROP_MOD: \
    case IROP_AND: case IROP_OR:  case IROP_XOR: \
    case IROP_SHL: case IROP_SHR: \
    case IROP_EQ:  case IROP_NE:  case IROP_LT: case IROP_GT: case IROP_LE: case IROP_GE
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
                            /* 注意：不要清空 args。否则会破坏后续 pass_store_load_forwarding 对 store 的识别。 */
                            list_clear(i->labels);
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
                ++s->fold; changed = true;
            }
        }
    }
    return changed;
}
#undef CASE_BIN

/*---------- 复制传播 ----------*/
static bool is_copy_instr(const Instr *i) {
    if (!i) return false;
    /* trunc, zext, sext 作为复制操作 */
    if (i->op == IROP_TRUNC || i->op == IROP_ZEXT || i->op == IROP_SEXT) {
        return i->args && i->args->len == 1;
    }
    return false;
}

static bool pass_copy_prop(Func *f, Stats *s) {
    bool changed = false;
    /* 第一遍：收集所有复制指令 y = copy(x) */
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        for (Iter jt = list_iter(b->instrs); !iter_end(jt);) {
            Instr *i = iter_next(&jt);
            if (is_copy_instr(i)) {
                ValueName src = get_arg(i, 0);
                /* 避免循环依赖：检查源是否也是复制 */
                Instr *src_def = find_def_instr(f, src);
                while (src_def && is_copy_instr(src_def)) {
                    src = get_arg(src_def, 0);
                    src_def = find_def_instr(f, src);
                }
                /* 将当前指令的目的地映射到最终的源 */
                if (src != i->dest) {
                    /* 替换所有使用 i->dest 的地方为 src */
                    for (Iter kt = list_iter(f->blocks); !iter_end(kt);) {
                        Block *bb = iter_next(&kt);
                        /* 替换普通指令 */
                        for (Iter lt = list_iter(bb->instrs); !iter_end(lt);) {
                            Instr *use = iter_next(&lt);
                            if (use->args) {
                                for (int idx = 0; idx < use->args->len; ++idx) {
                                    ValueName *arg = list_get(use->args, idx);
                                    if (*arg == i->dest) {
                                        *arg = src;
                                        changed = true;
                                    }
                                }
                            }
                        }
                        /* 替换 PHI 节点 */
                        for (Iter lt = list_iter(bb->phis); !iter_end(lt);) {
                            Instr *phi = iter_next(&lt);
                            if (phi->args) {
                                for (int idx = 0; idx < phi->args->len; ++idx) {
                                    ValueName *arg = list_get(phi->args, idx);
                                    if (*arg == i->dest) {
                                        *arg = src;
                                        changed = true;
                                    }
                                }
                            }
                        }
                    }
                    if (changed) {
                        /* 将此指令转为 NOP，后续DCE会删除 */
                        i->op = IROP_NOP;
                        ++s->fold;
                    }
                }
            }
        }
    }
    return changed;
}

/*---------- 公共常量合并 (Common Subexpression Elimination for const) ----------*/
static bool pass_const_merge(Func *f, Stats *s) {
    bool changed = false;
    /* 使用简单数组记录常量：最多支持64个不同的常量值 */
    #define MAX_CONSTS 64
    int64_t const_vals[MAX_CONSTS];
    ValueName const_names[MAX_CONSTS];
    int const_count = 0;
    
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        for (Iter jt = list_iter(b->instrs); !iter_end(jt);) {
            Instr *i = iter_next(&jt);
            if (i->op != IROP_CONST) continue;
            
            int64_t val = i->imm.ival;
            /* 查找是否已有相同值的常量 */
            int found_idx = -1;
            for (int k = 0; k < const_count; k++) {
                if (const_vals[k] == val) {
                    found_idx = k;
                    break;
                }
            }
            
            if (found_idx >= 0) {
                /* 已经有相同的常量，替换所有使用当前指令dest的地方 */
                ValueName existing = const_names[found_idx];
                for (Iter kt = list_iter(f->blocks); !iter_end(kt);) {
                    Block *bb = iter_next(&kt);
                    /* 替换普通指令 */
                    for (Iter lt = list_iter(bb->instrs); !iter_end(lt);) {
                        Instr *use = iter_next(&lt);
                        if (use->args) {
                            for (int idx = 0; idx < use->args->len; ++idx) {
                                ValueName *arg = list_get(use->args, idx);
                                if (*arg == i->dest) {
                                    *arg = existing;
                                    changed = true;
                                }
                            }
                        }
                    }
                    /* 替换 PHI 节点 */
                    for (Iter lt = list_iter(bb->phis); !iter_end(lt);) {
                        Instr *phi = iter_next(&lt);
                        if (phi->args) {
                            for (int idx = 0; idx < phi->args->len; ++idx) {
                                ValueName *arg = list_get(phi->args, idx);
                                if (*arg == i->dest) {
                                    *arg = existing;
                                    changed = true;
                                }
                            }
                        }
                    }
                }
                /* 将此指令转为 NOP，后续DCE会删除 */
                i->op = IROP_NOP;
                ++s->fold;
            } else if (const_count < MAX_CONSTS) {
                /* 记录这个常量 */
                const_vals[const_count] = val;
                const_names[const_count] = i->dest;
                const_count++;
            }
        }
    }
    return changed;
}

/*---------- 地址公共子表达式合并 (Common Subexpression Elimination for addr) ----------*/
static bool pass_addr_merge(Func *f, Stats *s) {
    bool changed = false;
    #define MAX_ADDRS 64
    typedef struct { const char *label; Ctype *mem_type; ValueName val; } AddrEntry;
    AddrEntry addrs[MAX_ADDRS];
    int addr_count = 0;

    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        for (Iter jt = list_iter(b->instrs); !iter_end(jt);) {
            Instr *i = iter_next(&jt);
            if (!i || i->op != IROP_ADDR || !i->labels || i->labels->len == 0) continue;
            const char *label = (const char *)list_get(i->labels, 0);
            if (!label) continue;

            int found_idx = -1;
            for (int k = 0; k < addr_count; k++) {
                if (addrs[k].label && !strcmp(addrs[k].label, label) &&
                    addrs[k].mem_type == i->mem_type) {
                    found_idx = k;
                    break;
                }
            }

            if (found_idx >= 0) {
                ValueName existing = addrs[found_idx].val;
                for (Iter kt = list_iter(f->blocks); !iter_end(kt);) {
                    Block *bb = iter_next(&kt);
                    for (Iter lt = list_iter(bb->instrs); !iter_end(lt);) {
                        Instr *use = iter_next(&lt);
                        if (use->args) {
                            for (int idx = 0; idx < use->args->len; ++idx) {
                                ValueName *arg = list_get(use->args, idx);
                                if (*arg == i->dest) {
                                    *arg = existing;
                                    changed = true;
                                }
                            }
                        }
                    }
                    for (Iter lt = list_iter(bb->phis); !iter_end(lt);) {
                        Instr *phi = iter_next(&lt);
                        if (phi->args) {
                            for (int idx = 0; idx < phi->args->len; ++idx) {
                                ValueName *arg = list_get(phi->args, idx);
                                if (*arg == i->dest) {
                                    *arg = existing;
                                    changed = true;
                                }
                            }
                        }
                    }
                }
                i->op = IROP_NOP;
                ++s->fold;
            } else if (addr_count < MAX_ADDRS) {
                addrs[addr_count].label = label;
                addrs[addr_count].mem_type = i->mem_type;
                addrs[addr_count].val = i->dest;
                addr_count++;
            }
        }
    }
    return changed;
}

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
            if (!i || !i->args) continue;
            /* 1. 代数：x - x = 0, x ^ x = 0 */
            if (i->args->len >= 2) {
                ValueName a = get_arg(i, 0), bv = get_arg(i, 1);
                if ((i->op == IROP_SUB || i->op == IROP_XOR) && a == bv) {
                    i->op = IROP_CONST; i->imm.ival = 0;
                    list_clear(i->args);
                    ++s->fold; changed = true; continue;
                }
                /* 1.1 比较自反：eq x,x = 1; ne x,x = 0 */
                if ((i->op == IROP_EQ || i->op == IROP_NE) && a == bv) {
                    bool is_eq = (i->op == IROP_EQ);
                    i->op = IROP_CONST; i->imm.ival = is_eq ? 1 : 0;
                    list_clear(i->args);
                    ++s->fold; changed = true; continue;
                }
            }
            /* 2. 代数：x & x = x, x | x = x */
            if (i->args->len >= 2) {
                ValueName a = get_arg(i, 0), bv = get_arg(i, 1);
                if ((i->op == IROP_AND || i->op == IROP_OR) && a == bv) {
                    /* replace with a */
                    i->op = IROP_TRUNC; /* 使用TRUNC作为identity/copy操作 */
                    list_clear(i->args);
                    ValueName *p = pass_alloc(sizeof *p); *p = a;
                    list_push(i->args, p);
                    ++s->fold; changed = true; continue;
                }
                /* 2.1 常量比较：eq/ne const,const -> const */
                if (i->op == IROP_EQ || i->op == IROP_NE) {
                    int64_t ca = 0, cb = 0;
                    if (get_const_value(f, a, &ca) && get_const_value(f, bv, &cb)) {
                        bool is_eq = (i->op == IROP_EQ);
                        i->op = IROP_CONST;
                        i->imm.ival = is_eq ? (ca == cb) : (ca != cb);
                        list_clear(i->args);
                        ++s->fold; changed = true; continue;
                    }
                }
            }
            /* 3. 代数简化扩展：x+0=x, x*1=x, x*0=0等 */
            if (i->args->len >= 1) {
                ValueName a = get_arg(i, 0);
                int64_t b_val = 0;
                bool has_b = false;
                if (i->args->len >= 2) {
                    has_b = get_const_value(f, get_arg(i, 1), &b_val);
                }
                
                /* x + 0 = x, x - 0 = x */
                if ((i->op == IROP_ADD || i->op == IROP_SUB) && has_b && b_val == 0) {
                    i->op = IROP_TRUNC; /* copy */
                    list_clear(i->args);
                    ValueName *p = pass_alloc(sizeof *p); *p = a;
                    list_push(i->args, p);
                    ++s->fold; changed = true; continue;
                }
                /* x * 1 = x, x / 1 = x */
                if ((i->op == IROP_MUL || i->op == IROP_DIV) && has_b && b_val == 1) {
                    i->op = IROP_TRUNC; /* copy */
                    list_clear(i->args);
                    ValueName *p = pass_alloc(sizeof *p); *p = a;
                    list_push(i->args, p);
                    ++s->fold; changed = true; continue;
                }
                /* x * 0 = 0, 0 * x = 0 */
                if (i->op == IROP_MUL && has_b && b_val == 0) {
                    i->op = IROP_CONST; i->imm.ival = 0;
                    list_clear(i->args);
                    ++s->fold; changed = true; continue;
                }
                /* x << 0 = x, x >> 0 = x */
                if ((i->op == IROP_SHL || i->op == IROP_SHR) && has_b && b_val == 0) {
                    i->op = IROP_TRUNC; /* copy */
                    list_clear(i->args);
                    ValueName *p = pass_alloc(sizeof *p); *p = a;
                    list_push(i->args, p);
                    ++s->fold; changed = true; continue;
                }
                /* x & 0 = 0, 0 & x = 0 */
                if (i->op == IROP_AND && has_b && b_val == 0) {
                    i->op = IROP_CONST; i->imm.ival = 0;
                    list_clear(i->args);
                    ++s->fold; changed = true; continue;
                }
                /* x & -1 = x (全部置位), x | 0 = x, x ^ 0 = x */
                if ((i->op == IROP_AND && has_b && b_val == -1) ||
                    (i->op == IROP_OR && has_b && b_val == 0) ||
                    (i->op == IROP_XOR && has_b && b_val == 0)) {
                    i->op = IROP_TRUNC; /* copy */
                    list_clear(i->args);
                    ValueName *p = pass_alloc(sizeof *p); *p = a;
                    list_push(i->args, p);
                    ++s->fold; changed = true; continue;
                }
            }
            /* 4. 比较链优化：ne (gt x, y), 0 -> gt x, y
                     ne (lt x, y), 0 -> lt x, y
                     ne (eq x, y), 0 -> ne x, y */
            if ((i->op == IROP_NE || i->op == IROP_EQ) && i->args->len == 2) {
                ValueName a = get_arg(i, 0), b = get_arg(i, 1);
                Instr *db = find_def_instr(f, b);
                /* 检查 b 是否为 const 0 */
                if (db && db->op == IROP_CONST && db->imm.ival == 0) {
                    Instr *da = find_def_instr(f, a);
                    if (da && (da->op == IROP_GT || da->op == IROP_LT ||
                               da->op == IROP_GE || da->op == IROP_LE ||
                               da->op == IROP_EQ || da->op == IROP_NE)) {
                        /* 比较操作已经是0/1结果，ne v, 0 或 eq v, 1 可以简化 */
                        if (i->op == IROP_NE) {
                            /* ne (cmp x y), 0 -> trunc (cmp x y) */
                            i->op = IROP_TRUNC;
                            list_clear(i->args);
                            ValueName *p = pass_alloc(sizeof *p); *p = a;
                            list_push(i->args, p);
                            ++s->fold; changed = true; continue;
                        }
                    }
                }
            }
            /* 5. 复制传播：trunc x -> 如果x只有一个用户，可以替换 */
            /* 已经在其他优化中处理 */
            /* 6. br trunc 消除 */
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

/*---------- 存储到加载转发 ----------*/
static bool pass_store_load_forwarding(Func *f, Stats *s) {
    bool changed = false;
    
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        
        // 使用简单映射记录当前块内每个地址的最新存储值
        // 地址 -> 存储的值
        typedef struct { const char *name; ValueName val; } StoreMap;
        StoreMap stores[64];
        int store_count = 0;
        
        for (Iter jt = list_iter(b->instrs); !iter_end(jt);) {
            Instr *i = iter_next(&jt);
            
            if (i->op == IROP_STORE) {
                if (is_volatile_for_forwarding(i)) {
                    store_count = 0;
                    continue;
                }
                // 记录这次存储
                Instr *addr = find_def_instr(f, get_arg(i, 0));
                if (addr && addr->op == IROP_ADDR) {
                    const char *name = list_get(addr->labels, 0);
                    // 更新映射
                    bool found = false;
                    for (int k = 0; k < store_count; k++) {
                        if (stores[k].name && !strcmp(stores[k].name, name)) {
                            stores[k].val = get_arg(i, 1);
                            found = true;
                            break;
                        }
                    }
                    if (!found && store_count < 64) {
                        stores[store_count].name = name;
                        stores[store_count].val = get_arg(i, 1);
                        store_count++;
                    }
                }
            }
            else if (i->op == IROP_LOAD) {
                if (is_volatile_for_forwarding(i)) {
                    store_count = 0;
                    continue;
                }
                // 检查是否有可用的存储转发
                Instr *addr = find_def_instr(f, get_arg(i, 0));
                if (addr && addr->op == IROP_ADDR) {
                    const char *name = list_get(addr->labels, 0);
                    for (int k = 0; k < store_count; k++) {
                        if (stores[k].name && !strcmp(stores[k].name, name)) {
                            // 找到匹配的store，进行转发
                            i->op = IROP_TRUNC; // 使用trunc作为复制
                            list_clear(i->args);
                            ValueName *p = pass_alloc(sizeof *p);
                            *p = stores[k].val;
                            list_push(i->args, p);
                            changed = true;
                            s->fold++;
                            break;
                        }
                    }
                }
            }
            // 如果遇到函数调用或volatile操作，清空映射
            else if (i->op == IROP_CALL) {
                store_count = 0;
            }
        }
    }
    return changed;
}

/*---------- store 标记后清理 ----------*/
static bool pass_store_cleanup(Func *f, Stats *s) {
    bool changed = false;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        for (Iter jt = list_iter(b->instrs); !iter_end(jt);) {
            Instr *i = iter_next(&jt);
            if (!i || i->op != IROP_STORE) continue;
            if (!i->labels || i->labels->len == 0) continue;
            char *label = (char *)list_get(i->labels, 0);
            if (label && label[0] == '@' && i->args && i->args->len > 0) {
                list_clear(i->args);
                changed = true;
                s->rm++;
            }
        }
    }
    return changed;
}

/*---------- ret 常量内联 ----------*/
static bool pass_ret_const_inline(Func *f, Stats *s) {
    bool changed = false;
    if (!f || !f->ret_type || f->ret_type->type == CTYPE_VOID) return false;

    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        for (Iter jt = list_iter(b->instrs); !iter_end(jt);) {
            Instr *i = iter_next(&jt);
            if (!i || i->op != IROP_RET) continue;
            if (!i->args || i->args->len < 1) continue;
            ValueName v = get_arg(i, 0);
            Instr *def = find_def_instr(f, v);
            if (!def || def->op != IROP_CONST) continue;

            i->imm.ival = def->imm.ival;
            list_clear(i->args);
            i->args = NULL;
            if (!i->labels) i->labels = make_list();
            list_clear(i->labels);
            char *tag = pass_alloc(4);
            strcpy(tag, "imm");
            list_push(i->labels, tag);
            /* 如果该常量仅用于本次ret，标记为NOP以便清理 */
            if (count_uses(f, def->dest) == 0) {
                def->op = IROP_NOP;
            }
            changed = true;
            s->fold++;
        }
    }
    return changed;
}

/*---------- 仅用于const store的常量清理 ----------*/
static bool pass_const_store_prune(Func *f, Stats *s) {
    bool changed = false;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        for (Iter jt = list_iter(b->instrs); !iter_end(jt);) {
            Instr *def = iter_next(&jt);
            if (!def || def->op != IROP_CONST || def->dest == 0) continue;

            bool used = false;
            bool ok = true;

            for (Iter it2 = list_iter(f->blocks); !iter_end(it2);) {
                Block *bb = iter_next(&it2);
                for (Iter jt2 = list_iter(bb->instrs); !iter_end(jt2);) {
                    Instr *use = iter_next(&jt2);
                    if (!use || !use->args) continue;
                    for (int k = 0; k < use->args->len; ++k) {
                        if (*(ValueName *)list_get(use->args, k) != def->dest) continue;
                        used = true;
                        if (use->op != IROP_STORE) { ok = false; }
                        else if (!use->labels || use->labels->len == 0) { ok = false; }
                        else {
                            char *label = (char *)list_get(use->labels, 0);
                            if (!label || label[0] != '@') ok = false;
                        }
                    }
                }
            }

            if (!used || !ok) continue;

            for (Iter it2 = list_iter(f->blocks); !iter_end(it2);) {
                Block *bb = iter_next(&it2);
                for (Iter jt2 = list_iter(bb->instrs); !iter_end(jt2);) {
                    Instr *use = iter_next(&jt2);
                    if (!use || !use->args) continue;
                    bool hit = false;
                    for (int k = 0; k < use->args->len; ++k) {
                        if (*(ValueName *)list_get(use->args, k) == def->dest) {
                            hit = true;
                            break;
                        }
                    }
                    if (hit && use->op == IROP_STORE) {
                        list_clear(use->args);
                    }
                }
            }

            def->op = IROP_NOP;
            s->rm++;
            changed = true;
        }
    }
    return changed;
}

/*---------- 二元运算立即数内联 ----------*/
static bool pass_binop_const_inline(Func *f, Stats *s) {
    bool changed = false;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        for (Iter jt = list_iter(b->instrs); !iter_end(jt);) {
            Instr *i = iter_next(&jt);
            bool is_cmp = false;
            if (!i || !i->args || i->args->len < 2) continue;
            switch (i->op) {
            case IROP_ADD: case IROP_SUB: case IROP_MUL: case IROP_DIV: case IROP_MOD:
            case IROP_AND: case IROP_OR:  case IROP_XOR:
            case IROP_SHL: case IROP_SHR:
                break;
            case IROP_EQ: case IROP_NE: case IROP_LT: case IROP_GT: case IROP_LE: case IROP_GE:
                is_cmp = true;
                break;
            default:
                continue;
            }
            bool keep_args = is_cmp || (i->type && i->type->size >= 2);

            ValueName lhs = get_arg(i, 0);
            ValueName rhs = get_arg(i, 1);

            Instr *def = find_def_instr(f, rhs);
            if ((!def || def->op != IROP_CONST) &&
                (i->op == IROP_ADD || i->op == IROP_MUL || i->op == IROP_AND ||
                 i->op == IROP_OR || i->op == IROP_XOR || i->op == IROP_EQ ||
                 i->op == IROP_NE)) {
                Instr *def2 = find_def_instr(f, lhs);
                if (def2 && def2->op == IROP_CONST) {
                    rhs = lhs;
                    lhs = get_arg(i, 1);
                    def = def2;
                }
            }
            if (!def || def->op != IROP_CONST) continue;

            i->imm.ival = def->imm.ival;
            if (!i->labels) i->labels = make_list();
            list_clear(i->labels);
            char *tag = pass_alloc(4);
            strcpy(tag, "imm");
            list_push(i->labels, tag);

            if (!keep_args) {
                list_clear(i->args);
                ValueName *p = pass_alloc(sizeof *p); *p = lhs;
                list_push(i->args, p);
            }

            changed = true;
            s->fold++;
        }
    }
    return changed;
}

/*---------- 基本块合并 ----------*/
static bool pass_block_merge(Func *f, Stats *s) {
    bool changed = false;
    if (!f || !f->blocks) return false;

    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b || !b->instrs || b->instrs->len == 0) continue;
        Instr *term = (Instr *)list_get(b->instrs, b->instrs->len - 1);
        if (!term || term->op != IROP_JMP || !term->labels || term->labels->len < 1) continue;

        int tid = -1;
        sscanf((char *)list_get(term->labels, 0), "block%d", &tid);
        if (tid < 0) continue;
        Block *t = find_block_by_id(f, tid);
        if (!t || t == b) continue;
        if (t->phis && t->phis->len > 0) continue;
        if (!t->instrs || t->instrs->len == 0) continue;
        if (t->preds && t->preds->len != 1) continue;

        /* 移除b的终结jmp */
        list_remove_last(b->instrs, NULL);

        /* 追加目标块指令 */
        for (Iter jt = list_iter(t->instrs); !iter_end(jt);) {
            Instr *inst = iter_next(&jt);
            list_push(b->instrs, inst);
        }

        /* 更新目标块后继的preds */
        if (t->instrs && t->instrs->len > 0) {
            Instr *tterm = (Instr *)list_get(t->instrs, t->instrs->len - 1);
            if (tterm && tterm->labels) {
                if (tterm->op == IROP_JMP && tterm->labels->len >= 1) {
                    int sid = -1;
                    sscanf((char *)list_get(tterm->labels, 0), "block%d", &sid);
                    Block *sblk = find_block_by_id(f, sid);
                    if (sblk) {
                        sblk->preds = preds_remove(sblk->preds, t);
                        list_unique_push(sblk->preds, b, block_ptr_eq);
                        replace_phi_pred_label(sblk, t->id, b->id);
                    }
                } else if (tterm->op == IROP_BR && tterm->labels->len >= 2) {
                    int s1 = -1, s2 = -1;
                    sscanf((char *)list_get(tterm->labels, 0), "block%d", &s1);
                    sscanf((char *)list_get(tterm->labels, 1), "block%d", &s2);
                    Block *sblk1 = find_block_by_id(f, s1);
                    Block *sblk2 = find_block_by_id(f, s2);
                    if (sblk1) {
                        sblk1->preds = preds_remove(sblk1->preds, t);
                        list_unique_push(sblk1->preds, b, block_ptr_eq);
                        replace_phi_pred_label(sblk1, t->id, b->id);
                    }
                    if (sblk2) {
                        sblk2->preds = preds_remove(sblk2->preds, t);
                        list_unique_push(sblk2->preds, b, block_ptr_eq);
                        replace_phi_pred_label(sblk2, t->id, b->id);
                    }
                }
            }
        }

        /* 清空目标块 */
        list_clear_shallow(t->instrs);
        t->instrs = make_list();
        list_clear_shallow(t->phis);
        t->phis = make_list();
        t->preds = make_list();

        s->merge++;
        changed = true;
    }
    return changed;
}

/*---------- 常量分支消除 + 死块删除 ----------*/
static bool pass_const_branch(Func *f, Stats *s) {
    bool changed = false;
    
    // 第一遍：识别常量分支并简化
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        Instr *terminator = list_empty(b->instrs) ? NULL 
            : list_get(b->instrs, b->instrs->len - 1);
        if (!terminator || terminator->op != IROP_BR) continue;
        ValueName cond = get_arg(terminator, 0);
        int64_t val;
        if (!get_const_value(f, cond, &val)) continue;
        
        // 确定目标块和死块
        const char *live_label = val ? list_get(terminator->labels, 0) 
                                      : list_get(terminator->labels, 1);
        const char *dead_label = val ? list_get(terminator->labels, 1) 
                                      : list_get(terminator->labels, 0);

        char *live_label_copy = NULL;
        if (live_label) {
            live_label_copy = pass_alloc(strlen(live_label) + 1);
            strcpy(live_label_copy, live_label);
        }
        
        // 将br替换为无条件jmp
        terminator->op = IROP_JMP;
        list_clear(terminator->args);
        list_clear(terminator->labels);
        if (live_label_copy) list_push(terminator->labels, live_label_copy);
        s->fold++;
        changed = true;
    }
    
    // 第二遍：从入口块做可达性分析，清空不可达块（避免SSA输出残留死分支）
    if (f && f->blocks && f->blocks->len > 0) {
        int max_id = 0;
        for (Iter it = list_iter(f->blocks); !iter_end(it);) {
            Block *b = iter_next(&it);
            if (b && (int)b->id > max_id) max_id = (int)b->id;
        }

        bool *seen = (bool *)calloc((size_t)max_id + 1, sizeof(bool));
        Block **work = (Block **)malloc(((size_t)max_id + 1) * sizeof(Block *));
        int wlen = 0;

        Block *entry = f->entry ? f->entry : (Block *)list_get(f->blocks, 0);
        if (entry && (int)entry->id <= max_id) {
            seen[entry->id] = true;
            work[wlen++] = entry;
        }

        while (wlen > 0) {
            Block *b = work[--wlen];
            if (!b || !b->instrs || b->instrs->len == 0) continue;
            Instr *term = (Instr *)list_get(b->instrs, b->instrs->len - 1);
            if (!term || !term->labels) continue;

            if (term->op == IROP_JMP && term->labels->len >= 1) {
                int tid = -1;
                sscanf((char *)list_get(term->labels, 0), "block%d", &tid);
                if (tid >= 0 && tid <= max_id && !seen[tid]) {
                    Block *t = find_block_by_id(f, tid);
                    if (t) { seen[tid] = true; work[wlen++] = t; }
                }
            } else if (term->op == IROP_BR && term->labels->len >= 2) {
                int t1 = -1, t2 = -1;
                sscanf((char *)list_get(term->labels, 0), "block%d", &t1);
                sscanf((char *)list_get(term->labels, 1), "block%d", &t2);
                if (t1 >= 0 && t1 <= max_id && !seen[t1]) {
                    Block *t = find_block_by_id(f, t1);
                    if (t) { seen[t1] = true; work[wlen++] = t; }
                }
                if (t2 >= 0 && t2 <= max_id && !seen[t2]) {
                    Block *t = find_block_by_id(f, t2);
                    if (t) { seen[t2] = true; work[wlen++] = t; }
                }
            }
        }

        bool has_reachable_ret = false;
        for (Iter it = list_iter(f->blocks); !iter_end(it);) {
            Block *b = iter_next(&it);
            if (!b) continue;
            if ((int)b->id <= max_id && seen[b->id]) {
                if (block_has_ret(b)) { has_reachable_ret = true; break; }
            }
        }

        /* 额外标记：如果可达块的PHI引用了某前驱块，也视为可达 */
        for (Iter it = list_iter(f->blocks); !iter_end(it);) {
            Block *b = iter_next(&it);
            if (!b || (int)b->id > max_id || !seen[b->id]) continue;
            if (!b->phis) continue;
            for (Iter jt = list_iter(b->phis); !iter_end(jt);) {
                Instr *phi = iter_next(&jt);
                if (!phi || !phi->labels) continue;
                for (int k = 0; k < phi->labels->len; ++k) {
                    char *lbl = (char *)list_get(phi->labels, k);
                    if (!lbl) continue;
                    int pid = -1;
                    if (sscanf(lbl, "block%d", &pid) == 1 && pid >= 0 && pid <= max_id) {
                        seen[pid] = true;
                    }
                }
            }
        }

        for (Iter it = list_iter(f->blocks); !iter_end(it);) {
            Block *b = iter_next(&it);
            if (!b) continue;
            if (entry && b == entry) continue;
            if ((int)b->id <= max_id && !seen[b->id]) {
                if (!has_reachable_ret && block_has_ret(b)) {
                    continue; /* 保留一个ret块，避免优化后无ret */
                }
                b->preds = make_list();
                b->phis = make_list();
                b->instrs = make_list();
                changed = true;
                s->rm++;
            }
        }

        free(work);
        free(seen);
    }
    
    return changed;
}

/*---------- jmp 跳转链折叠 ----------*/
static bool pass_jump_threading(Func *f, Stats *s) {
    bool changed = false;
    if (!f || !f->blocks) return false;

    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b || !b->instrs || b->instrs->len == 0) continue;
        Instr *term = (Instr *)list_get(b->instrs, b->instrs->len - 1);
        if (!term || term->op != IROP_JMP || !term->labels || term->labels->len < 1) continue;

        int tid = -1;
        sscanf((char *)list_get(term->labels, 0), "block%d", &tid);
        if (tid < 0) continue;
        Block *t = find_block_by_id(f, tid);
        if (!t || t == b) continue;
        if (t->phis && t->phis->len > 0) continue;
        if (!t->instrs || t->instrs->len != 1) continue;

        Instr *tterm = (Instr *)list_get(t->instrs, t->instrs->len - 1);
        if (!tterm || tterm->op != IROP_JMP || !tterm->labels || tterm->labels->len < 1) continue;

        int sid = -1;
        sscanf((char *)list_get(tterm->labels, 0), "block%d", &sid);
        if (sid < 0 || sid == (int)b->id) continue;

        char *new_label = NULL;
        const char *raw = (const char *)list_get(tterm->labels, 0);
        if (raw) {
            new_label = pass_alloc(strlen(raw) + 1);
            strcpy(new_label, raw);
        }
        if (!new_label) continue;

        list_clear(term->labels);
        list_push(term->labels, new_label);

        /* 更新 preds */
        if (t->preds) t->preds = preds_remove(t->preds, b);
        Block *sblk = find_block_by_id(f, sid);
        if (sblk) {
            list_unique_push(sblk->preds, b, block_ptr_eq);
            replace_phi_pred_label(sblk, t->id, b->id);
        }

        changed = true;
        s->fold++;
    }
    return changed;
}

/*---------- 入口块空跳转消除 ----------*/
static bool pass_entry_jmp_elim(Func *f, Stats *s) {
    if (!f || !f->entry || !f->blocks) return false;
    Block *b = f->entry;
    if (!b || (b->phis && b->phis->len > 0)) return false;
    if (!b->instrs || b->instrs->len != 1) return false;
    Instr *term = (Instr *)list_get(b->instrs, 0);
    if (!term || term->op != IROP_JMP || !term->labels || term->labels->len < 1) return false;

    int tid = -1;
    sscanf((char *)list_get(term->labels, 0), "block%d", &tid);
    if (tid < 0) return false;
    Block *t = find_block_by_id(f, tid);
    if (!t || t == b) return false;
    if (t->phis && t->phis->len > 0) return false;
    if (t->preds && t->preds->len != 1) return false;

    /* 将入口设置为目标块，清理目标块前驱 */
    f->entry = t;
    if (t->preds) t->preds = preds_remove(t->preds, b);

    /* 清空旧入口块 */
    list_clear_shallow(b->instrs);
    b->instrs = make_list();
    b->preds = make_list();

    s->rm++;
    return true;
}

/*---------- 入口块参数下沉 ----------*/
static bool pass_entry_param_sink(Func *f, Stats *s) {
    if (!f || !f->entry || !f->blocks) return false;
    Block *b = f->entry;
    if (!b || (b->phis && b->phis->len > 0)) return false;
    if (!b->instrs || b->instrs->len < 2) return false;

    Instr *term = (Instr *)list_get(b->instrs, b->instrs->len - 1);
    if (!term || term->op != IROP_JMP || !term->labels || term->labels->len < 1) return false;

    int tid = -1;
    sscanf((char *)list_get(term->labels, 0), "block%d", &tid);
    if (tid < 0) return false;
    Block *t = find_block_by_id(f, tid);
    if (!t || t == b) return false;
    /* 入口块除终结跳转外必须全是param */
    for (int i = 0; i < b->instrs->len - 1; ++i) {
        Instr *inst = (Instr *)list_get(b->instrs, i);
        if (!inst || inst->op != IROP_PARAM) return false;
    }

    int next_val = max_value_in_func(f) + 1;

    /* 重定向所有前驱：将指向t的边改为指向b */
    if (t->preds) {
        for (Iter it = list_iter(t->preds); !iter_end(it);) {
            Block *pred = iter_next(&it);
            if (!pred || pred == b || !pred->instrs || pred->instrs->len == 0) continue;
            Instr *pterm = (Instr *)list_get(pred->instrs, pred->instrs->len - 1);
            if (!pterm || !pterm->labels) continue;
            if (pterm->op == IROP_JMP && pterm->labels->len >= 1) {
                int pid = -1;
                sscanf((char *)list_get(pterm->labels, 0), "block%d", &pid);
                if (pid == (int)t->id) {
                    char *rep = pass_alloc(32);
                    snprintf(rep, 32, "block%d", b->id);
                    list_set(pterm->labels, 0, rep);
                    list_unique_push(b->preds, pred, block_ptr_eq);
                }
            } else if (pterm->op == IROP_BR && pterm->labels->len >= 2) {
                for (int k = 0; k < pterm->labels->len; ++k) {
                    int pid = -1;
                    sscanf((char *)list_get(pterm->labels, k), "block%d", &pid);
                    if (pid == (int)t->id) {
                        char *rep = pass_alloc(32);
                        snprintf(rep, 32, "block%d", b->id);
                        list_set(pterm->labels, k, rep);
                        list_unique_push(b->preds, pred, block_ptr_eq);
                    }
                }
            }
        }
    }

    /* 为入口参数引入PHI（多前驱时） */
    if (b->preds && b->preds->len > 1) {
        for (int i = 0; i < b->instrs->len - 1; ++i) {
            Instr *param = (Instr *)list_get(b->instrs, i);
            if (!param || param->op != IROP_PARAM) continue;

            Instr *phi = pass_alloc(sizeof(Instr));
            memset(phi, 0, sizeof(*phi));
            phi->op = IROP_PHI;
            phi->dest = next_val++;
            phi->type = param->type;
            phi->args = make_list();
            phi->labels = make_list();

            for (Iter it = list_iter(b->preds); !iter_end(it);) {
                Block *pred = iter_next(&it);
                char *lbl = pass_alloc(32);
                snprintf(lbl, 32, "block%d", pred->id);
                list_push(phi->labels, lbl);

                ValueName *v = pass_alloc(sizeof(ValueName));
                *v = param->dest;
                list_push(phi->args, v);
            }

            list_push(b->phis, phi);
            replace_value_skip_phi(f, param->dest, phi->dest, phi);
        }
    }

    /* 移除b的终结jmp */
    list_remove_last(b->instrs, NULL);

    /* 合并PHI */
    if (t->phis && t->phis->len > 0) {
        if (!b->phis) b->phis = make_list();
        for (Iter it = list_iter(t->phis); !iter_end(it);) {
            Instr *phi = iter_next(&it);
            list_push(b->phis, phi);
        }
    }

    /* 追加目标块指令到入口块 */
    if (t->instrs) {
        for (Iter it = list_iter(t->instrs); !iter_end(it);) {
            Instr *inst = iter_next(&it);
            list_push(b->instrs, inst);
        }
    }

    /* 更新目标块后继的preds */
    if (t->instrs && t->instrs->len > 0) {
        Instr *tterm = (Instr *)list_get(t->instrs, t->instrs->len - 1);
        if (tterm && tterm->labels) {
            if (tterm->op == IROP_JMP && tterm->labels->len >= 1) {
                int sid = -1;
                sscanf((char *)list_get(tterm->labels, 0), "block%d", &sid);
                Block *sblk = find_block_by_id(f, sid);
                if (sblk) {
                    sblk->preds = preds_remove(sblk->preds, t);
                    list_unique_push(sblk->preds, b, block_ptr_eq);
                    replace_phi_pred_label(sblk, t->id, b->id);
                }
            } else if (tterm->op == IROP_BR && tterm->labels->len >= 2) {
                int s1 = -1, s2 = -1;
                sscanf((char *)list_get(tterm->labels, 0), "block%d", &s1);
                sscanf((char *)list_get(tterm->labels, 1), "block%d", &s2);
                Block *sblk1 = find_block_by_id(f, s1);
                Block *sblk2 = find_block_by_id(f, s2);
                if (sblk1) {
                    sblk1->preds = preds_remove(sblk1->preds, t);
                    list_unique_push(sblk1->preds, b, block_ptr_eq);
                    replace_phi_pred_label(sblk1, t->id, b->id);
                }
                if (sblk2) {
                    sblk2->preds = preds_remove(sblk2->preds, t);
                    list_unique_push(sblk2->preds, b, block_ptr_eq);
                    replace_phi_pred_label(sblk2, t->id, b->id);
                }
            }
        }
    }

    /* 清空目标块 */
    list_clear_shallow(t->instrs);
    t->instrs = make_list();
    list_clear_shallow(t->phis);
    t->phis = make_list();
    t->preds = make_list();

    s->merge++;
    return true;
}

/*---------- 空块消除（空块视为fallthrough到下一个块） ----------*/
static bool pass_empty_block_elim(Func *f, Stats *s) {
    bool changed = false;
    if (!f || !f->blocks) return false;

    for (int i = 0; i < f->blocks->len; ++i) {
        Block *b = list_get(f->blocks, i);
        if (!b || b == f->entry) continue;
        bool has_phi = b->phis && b->phis->len > 0;
        bool has_instrs = b->instrs && b->instrs->len > 0;
        if (has_phi || has_instrs) continue;

        if (!b->preds || b->preds->len != 1) continue;
        Block *pred = (Block *)list_get(b->preds, 0);
        if (!pred || pred == b) continue;

        Block *succ = NULL;
        for (int j = i + 1; j < f->blocks->len; ++j) {
            Block *n = list_get(f->blocks, j);
            if (n) { succ = n; break; }
        }
        if (!succ || succ == b) continue;

        replace_term_target(pred, b->id, succ->id);

        if (succ->preds) succ->preds = preds_remove(succ->preds, b);
        list_unique_push(succ->preds, pred, block_ptr_eq);
        replace_phi_pred_label(succ, b->id, pred->id);

        b->preds = make_list();
        b->phis = make_list();
        b->instrs = make_list();

        s->rm++;
        changed = true;
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
        changed = false;
        changed |= pass_const_fold(f, &st);
        changed |= pass_store_load_forwarding(f, &st);
        changed |= pass_global_load(f, &st);
        changed |= pass_copy_prop(f, &st);
        changed |= pass_const_merge(f, &st);
        changed |= pass_addr_merge(f, &st);
        changed |= pass_local_opts(f, &st);
        changed |= pass_const_branch(f, &st);
        changed |= pass_jump_threading(f, &st);
        changed |= pass_entry_jmp_elim(f, &st);
        changed |= pass_entry_param_sink(f, &st);
        rebuild_preds(f);
        if (pass_empty_block_elim(f, &st)) {
            changed = true;
            rebuild_preds(f);
        }
        changed |= pass_phi(f, &st);
        changed |= pass_store_cleanup(f, &st);
        changed |= pass_binop_const_inline(f, &st);
        changed |= pass_ret_const_inline(f, &st);
        changed |= pass_const_store_prune(f, &st);
        changed |= pass_block_merge(f, &st);
        changed |= pass_dce(f, &st);
    } while (changed && ++it < 20);
}

void ssa_optimize(SSAUnit *u, int level) {
    if (!u) return;
    g_unit = u;
    for (Iter i = list_iter(u->funcs); !iter_end(i);)
        ssa_optimize_func(iter_next(&i), level);
    g_unit = NULL;
}

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
    // printf("\n=== Original SSA Output ===\n");
    // ssa_print(stdout, b->unit);
    // printf("\n=== Running Optimizations (O1) ===\n");
    ssa_optimize(b->unit, OPT_O1);
    printf("\n=== Optimized SSA Output ===\n");
    ssa_print(stdout, b->unit);
    ssa_build_destroy(b);
    list_free(strings);
    list_free(ctypes);
}
#endif