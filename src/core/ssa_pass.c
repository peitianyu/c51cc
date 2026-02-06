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

static inline ValueName get_arg(const Instr *i, int idx) {
    return (i && i->args && idx < i->args->len)
           ? *(ValueName *)list_get(i->args, idx) : 0;
}

static bool block_ptr_eq(void *a, void *b) { return a == b; }

static int max_value_in_func(Func *f) {
    int maxv = 0;
    if (!f || !f->blocks) return 0;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b) continue;
        List *lists[2] = {b->phis, b->instrs};
        for (int li = 0; li < 2; li++) {
            if (!lists[li]) continue;
            for (Iter jt = list_iter(lists[li]); !iter_end(jt);) {
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

static Func *find_func_in_unit(const char *name) {
    if (!g_unit || !name) return NULL;
    for (Iter it = list_iter(g_unit->funcs); !iter_end(it);) {
        Func *f = iter_next(&it);
        if (f && f->name && strcmp(f->name, name) == 0) return f;
    }
    return NULL;
}

typedef struct { ValueName from, to; } ValueMapEntry;

typedef struct { const char *name; ValueName val; } ParamMapEntry;

static bool vmap_put(ValueMapEntry *map, int *count, int cap, ValueName from, ValueName to) {
    if (*count >= cap) return false;
    map[*count].from = from;
    map[*count].to = to;
    (*count)++;
    return true;
}

static ValueName vmap_get(ValueMapEntry *map, int count, ValueName from, bool *found) {
    for (int i = 0; i < count; ++i) {
        if (map[i].from == from) {
            if (found) *found = true;
            return map[i].to;
        }
    }
    if (found) *found = false;
    return 0;
}

static ValueName pmap_get(ParamMapEntry *map, int count, const char *name, bool *found) {
    for (int i = 0; i < count; ++i) {
        if (map[i].name && name && strcmp(map[i].name, name) == 0) {
            if (found) *found = true;
            return map[i].val;
        }
    }
    if (found) *found = false;
    return 0;
}

static bool inline_allowed_op(IrOp op) {
    switch (op) {
    case IROP_CONST:
    case IROP_ADD: case IROP_SUB: case IROP_MUL: case IROP_DIV: case IROP_MOD: case IROP_NEG:
    case IROP_AND: case IROP_OR: case IROP_XOR: case IROP_NOT:
    case IROP_SHL: case IROP_SHR:
    case IROP_EQ: case IROP_LT: case IROP_GT: case IROP_LE: case IROP_GE: case IROP_NE:
    case IROP_LNOT:
    case IROP_TRUNC: case IROP_ZEXT: case IROP_SEXT: case IROP_BITCAST:
    case IROP_INTTOPTR: case IROP_PTRTOINT:
    case IROP_OFFSET:
        return true;
    default:
        return false;
    }
}

/* 替换值：在phi参数和指令参数中替换 */
static void replace_value(Func *f, ValueName from, ValueName to) {
    if (!f || from == to) return;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b) continue;
        List *lists[2] = {b->phis, b->instrs};
        for (int li = 0; li < 2; li++) {
            if (!lists[li]) continue;
            for (Iter jt = list_iter(lists[li]); !iter_end(jt);) {
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
    char old_lbl[32], new_lbl[32];
    snprintf(old_lbl, sizeof(old_lbl), "block%d", old_id);
    snprintf(new_lbl, sizeof(new_lbl), "block%d", new_id);

    for (Iter it = list_iter(blk->phis); !iter_end(it);) {
        Instr *phi = iter_next(&it);
        if (!phi || !phi->labels) continue;
        for (int k = 0; k < phi->labels->len; ++k) {
            char *lbl = (char *)list_get(phi->labels, k);
            if (lbl && strcmp(lbl, old_lbl) == 0) {
                char *rep = pass_alloc(strlen(new_lbl) + 1);
                strcpy(rep, new_lbl);
                list_set(phi->labels, k, rep);
            }
        }
    }
}

static void replace_label_all(Func *f, int old_id, int new_id) {
    if (!f || !f->blocks) return;
    char old_lbl[32], new_lbl[32];
    snprintf(old_lbl, sizeof(old_lbl), "block%d", old_id);
    snprintf(new_lbl, sizeof(new_lbl), "block%d", new_id);

    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b) continue;
        List *lists[2] = {b->phis, b->instrs};
        for (int li = 0; li < 2; li++) {
            if (!lists[li]) continue;
            for (Iter jt = list_iter(lists[li]); !iter_end(jt);) {
                Instr *i = iter_next(&jt);
                if (!i || !i->labels) continue;
                for (int k = 0; k < i->labels->len; ++k) {
                    char *lbl = (char *)list_get(i->labels, k);
                    if (lbl && strcmp(lbl, old_lbl) == 0) {
                        char *rep = pass_alloc(strlen(new_lbl) + 1);
                        strcpy(rep, new_lbl);
                        list_set(i->labels, k, rep);
                    }
                }
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

static bool block_only_jmp_in_func(Func *f, Block *b, Instr **term_out) {
    (void)f;
    if (term_out) *term_out = NULL;
    if (!b || !b->instrs) return false;
    Instr *term = NULL;
    for (Iter it = list_iter(b->instrs); !iter_end(it);) {
        Instr *i = iter_next(&it);
        if (!i || i->op == IROP_NOP) continue;
        if (i->op == IROP_PARAM) continue;
        if (term) return false;
        term = i;
    }
    if (!term || term->op != IROP_JMP || !term->labels || term->labels->len < 1) return false;
    if (term_out) *term_out = term;
    return true;
}

static bool block_has_other_preds(Func *f, Block *t, Block *only) {
    if (!f || !t) return false;
    int tid = (int)t->id;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b || b == only) continue;
        if (!b->instrs || b->instrs->len == 0) continue;
        Instr *term = (Instr *)list_get(b->instrs, b->instrs->len - 1);
        if (!term || !term->labels) continue;
        for (int k = 0; k < term->labels->len; k++) {
            int id = -1;
            sscanf((char *)list_get(term->labels, k), "block%d", &id);
            if (id == tid) return true;
        }
    }
    return false;
}

static bool block_only_ret(Block *b, Instr **ret_out) {
    if (ret_out) *ret_out = NULL;
    if (!b || !b->instrs) return false;
    Instr *term = NULL;
    for (Iter it = list_iter(b->instrs); !iter_end(it);) {
        Instr *i = iter_next(&it);
        if (!i || i->op == IROP_NOP) continue;
        if (term) return false;
        term = i;
    }
    if (!term || term->op != IROP_RET) return false;
    if (ret_out) *ret_out = term;
    return true;
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

static bool addr_used_only_by_loads(Func *f, ValueName addr) {
    if (!f || addr <= 0) return false;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b) continue;
        for (Iter jt = list_iter(b->phis); !iter_end(jt);) {
            Instr *p = iter_next(&jt);
            if (!p || !p->args) continue;
            for (int k = 0; k < p->args->len; ++k)
                if (*(ValueName *)list_get(p->args, k) == addr) return false;
        }
        for (Iter jt = list_iter(b->instrs); !iter_end(jt);) {
            Instr *i = iter_next(&jt);
            if (!i || !i->args) continue;
            for (int k = 0; k < i->args->len; ++k) {
                if (*(ValueName *)list_get(i->args, k) != addr) continue;
                if (i->op != IROP_LOAD) return false;
            }
        }
    }
    return true;
}

/*---------- 数据流辅助 ----------*/
static Instr *find_def_instr(Func *f, ValueName v) {
    if (!f || v <= 0) return NULL;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b) continue;
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

static int max_block_id(Func *f) {
    int max_id = -1;
    if (!f || !f->blocks) return max_id;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (b && (int)b->id > max_id) max_id = (int)b->id;
    }
    return max_id;
}

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
        for (int k = 0; k < term->labels->len; k++) {
            int tid = -1;
            sscanf((char *)list_get(term->labels, k), "block%d", &tid);
            Block *t = find_block_by_id(f, tid);
            if (t) list_unique_push(t->preds, b, block_ptr_eq);
        }
    }
}

/* 检查是否有任意指令或 PHI 的标签引用到块 b（例如 "blockN"） */
static bool block_referenced_by_any_label(Func *f, Block *b) {
    if (!f || !f->blocks || !b) return false;
    int bid = (int)b->id;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *tb = iter_next(&it);
        if (!tb) continue;
        List *lists[2] = {tb->phis, tb->instrs};
        for (int li = 0; li < 2; ++li) {
            List *lst = lists[li];
            if (!lst) continue;
            for (Iter jt = list_iter(lst); !iter_end(jt);) {
                Instr *inst = iter_next(&jt);
                if (!inst || !inst->labels) continue;
                for (int k = 0; k < inst->labels->len; ++k) {
                    char *lbl = (char *)list_get(inst->labels, k);
                    int id = -1;
                    if (lbl && sscanf(lbl, "block%d", &id) == 1 && id == bid) return true;
                }
            }
        }
    }
    return false;
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

static bool get_shift_imm(Func *f, Instr *i, ValueName *lhs_out, int64_t *sh_out) {
    if (!i || (i->op != IROP_SHL && i->op != IROP_SHR) || !lhs_out || !sh_out) return false;
    if (!i->args || i->args->len < 1) return false;
    *lhs_out = get_arg(i, 0);
    if (i->args->len >= 2) {
        int64_t s = 0;
        if (get_const_value(f, get_arg(i, 1), &s)) { *sh_out = s; return true; }
    }
    if (i->labels && i->labels->len > 0) {
        char *tag = (char *)list_get(i->labels, 0);
        if (tag && strcmp(tag, "imm") == 0) { *sh_out = i->imm.ival; return true; }
    }
    return false;
}

static bool resolve_base_offset(Func *f, ValueName addr, ValueName *base, int64_t *off) {
    int64_t total = 0;
    ValueName cur = addr;
    for (int depth = 0; depth < 8; ++depth) {
        Instr *def = find_def_instr(f, cur);
        if (!def) return false;
        if (def->op == IROP_OFFSET) {
            ValueName b = get_arg(def, 0);
            int64_t o = 0;
            if (def->args && def->args->len >= 2) {
                ValueName ov = get_arg(def, 1);
                if (!get_const_value(f, ov, &o)) return false;
            } else if (def->labels && def->labels->len >= 2) {
                char *tag = (char *)list_get(def->labels, 0);
                char *imm = (char *)list_get(def->labels, 1);
                if (!tag || strcmp(tag, "imm") != 0 || !imm) return false;
                o = strtoll(imm, NULL, 10);
            } else {
                return false;
            }
            int64_t scale = def->imm.ival ? def->imm.ival : 1;
            total += o * scale;
            cur = b;
            continue;
        }
        if (def->op == IROP_ADD) {
            ValueName a0 = get_arg(def, 0), a1 = get_arg(def, 1);
            int64_t c = 0;
            if (get_const_value(f, a0, &c)) { total += c; cur = a1; continue; }
            if (get_const_value(f, a1, &c)) { total += c; cur = a0; continue; }
            return false;
        }
        if (def->op == IROP_ADDR) {
            if (base) *base = cur;
            if (off) *off = total;
            return true;
        }
        return false;
    }
    return false;
}

static bool is_local_addr_base(Func *f, ValueName base) {
    if (!f || !f->stack_offsets) return false;
    Instr *def = find_def_instr(f, base);
    if (!def || def->op != IROP_ADDR || !def->labels || def->labels->len == 0) return false;
    const char *name = (const char *)list_get(def->labels, 0);
    return name && dict_get(f->stack_offsets, (char *)name) != NULL;
}

static bool is_unsigned_type(Ctype *t) {
    return t && get_attr(t->attr).ctype_unsigned;
}

static bool is_const_global(GlobalVar *g) {
    if (!g || !g->type) return false;
    CtypeAttr a = get_attr(g->type->attr);
    return a.ctype_const && !a.ctype_volatile && !a.ctype_register && g->has_init;
}

static bool value_used(Func *f, ValueName v) {
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b) continue;
        List *lists[2] = {b->phis, b->instrs};
        for (int li = 0; li < 2; li++) {
            if (!lists[li]) continue;
            for (Iter jt = list_iter(lists[li]); !iter_end(jt);) {
                Instr *i = iter_next(&jt);
                if (!i) continue;
                if (i->op == IROP_STORE && i->labels && i->labels->len > 0) {
                    char *label = (char *)list_get(i->labels, 0);
                    if (label && label[0] == '@') continue;
                }
                if (i->args) {
                    for (int k = 0; k < i->args->len; ++k)
                        if (*(ValueName *)list_get(i->args, k) == v) return true;
                }
            }
        }
    }
    return false;
}

static int count_uses(Func *f, ValueName v) {
    int cnt = 0;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b) continue;
        List *lists[2] = {b->phis, b->instrs};
        for (int li = 0; li < 2; li++) {
            if (!lists[li]) continue;
            for (Iter jt = list_iter(lists[li]); !iter_end(jt);) {
                Instr *i = iter_next(&jt);
                if (!i) continue;
                if (i->op == IROP_STORE && i->labels && i->labels->len > 0) {
                    char *label = (char *)list_get(i->labels, 0);
                    if (label && label[0] == '@') continue;
                }
                if (i->args) {
                    for (int k = 0; k < i->args->len; ++k)
                        if (*(ValueName *)list_get(i->args, k) == v) cnt++;
                }
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

/*---------- 统计结构 ----------*/
typedef struct { int rm, add, fold, merge, phi_rm; } Stats;

/* 过滤列表工具 */
static List *filter_list(List *src, bool (*pred)(void *, void *), void *aux) {
    List *dst = make_list();
    for (Iter it = list_iter(src); !iter_end(it);) {
        void *x = iter_next(&it);
        if (pred(x, aux)) list_push(dst, x);
    }
    return dst;
}

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
        if (!b) continue;
        int before = b->instrs ? b->instrs->len : 0;
        List *keep = filter_list(b->instrs, dce_pred, f);
        int after = keep ? keep->len : 0;
        int removed = before - after;
        if (removed > 0) {
            /* print removed instructions */
            for (int i = 0; i < before; ++i) {
                Instr *inst = (Instr *)list_get(b->instrs, i);
                bool keep_flag = false;
                for (int j = 0; j < after; ++j) {
                    Instr *k = (Instr *)list_get(keep, j);
                    if (k == inst) { keep_flag = true; break; }
                }
                if (!keep_flag && inst) ssa_print_instr(stdout, inst, NULL);
            }
        }
        s->rm += before - after;
        b->instrs = keep;
    }
    return s->rm != rm0;
}

/*---------- PHI 简化 ----------*/
static bool phi_pred(void *phi_, void *f_) {
    Instr *p = phi_; Func *f = f_;
    if (p->op != IROP_PHI) return true;
    ValueName first = 0;
    for (int i = 0; i < p->args->len; ++i) {
        ValueName v = *(ValueName *)list_get(p->args, i);
        if (v != p->dest) { if (!first) first = v; else if (v != first) return true; }
    }
    return false;
}

static bool phi_simplify_value(Instr *p, Func *f, Stats *s) {
    if (!p || p->op != IROP_PHI || !p->args || p->args->len == 0) return false;

    ValueName rep = 0;
    bool has_rep = false, rep_is_const = false;
    int64_t rep_const = 0;

    for (int i = 0; i < p->args->len; ++i) {
        ValueName v = *(ValueName *)list_get(p->args, i);
        if (v == p->dest) continue;
        if (!has_rep) {
            rep = v; has_rep = true;
            rep_is_const = get_const_value(f, v, &rep_const);
        } else if (v != rep) {
            if (!rep_is_const) return false;
            int64_t cv = 0;
            if (!get_const_value(f, v, &cv) || cv != rep_const) return false;
        }
    }

    if (!has_rep) return false;

    if (rep_is_const) {
        p->op = IROP_CONST; p->imm.ival = rep_const;
        list_clear(p->args);
        if (p->labels) list_clear(p->labels);
    } else {
        p->op = IROP_TRUNC;
        list_clear(p->args);
        ValueName *pv = pass_alloc(sizeof *pv); *pv = rep;
        list_push(p->args, pv);
        if (p->labels) list_clear(p->labels);
    }
    ++s->fold;
    return true;
}

static bool phi_label_in_preds(Block *b, const char *lbl) {
    if (!b || !lbl || !b->preds || b->preds->len == 0) return false;
    int id = -1;
    if (sscanf(lbl, "block%d", &id) != 1) return true;
    for (Iter it = list_iter(b->preds); !iter_end(it);) {
        Block *pred = iter_next(&it);
        if (pred && (int)pred->id == id) return true;
    }
    return false;
}

static bool phi_prune_dead_edges(Block *b, Instr *p) {
    if (!b || !p || p->op != IROP_PHI || !p->args || !p->labels) return false;
    int n = p->args->len < p->labels->len ? p->args->len : p->labels->len;
    if (n == 0) return false;

    List *args_tmp = make_list(), *labels_tmp = make_list();
    bool changed = false;

    for (int i = 0; i < n; ++i) {
        ValueName *v = list_get(p->args, i);
        char *lbl = list_get(p->labels, i);
        if (!lbl || phi_label_in_preds(b, lbl)) {
            list_push(args_tmp, v);
            list_push(labels_tmp, lbl);
        } else changed = true;
    }

    if (changed) {
        list_clear_shallow(p->args);
        list_clear_shallow(p->labels);
        for (Iter it = list_iter(args_tmp); !iter_end(it);) list_push(p->args, iter_next(&it));
        for (Iter it = list_iter(labels_tmp); !iter_end(it);) list_push(p->labels, iter_next(&it));
    }

    list_clear_shallow(args_tmp);
    list_clear_shallow(labels_tmp);
    free(args_tmp); free(labels_tmp);
    return changed;
}

static bool phi_dedup_edges(Instr *p) {
    if (!p || p->op != IROP_PHI || !p->args || !p->labels) return false;
    int n = p->args->len < p->labels->len ? p->args->len : p->labels->len;
    if (n <= 1) return false;

    List *args_tmp = make_list(), *labels_tmp = make_list();
    bool changed = false;

    for (int i = 0; i < n; ++i) {
        ValueName *v = list_get(p->args, i);
        char *lbl = list_get(p->labels, i);
        bool dup = false;
        for (Iter it = list_iter(labels_tmp); !iter_end(it);) {
            char *existing = iter_next(&it);
            if (existing && lbl && strcmp(existing, lbl) == 0) { dup = true; break; }
        }
        if (dup) { changed = true; continue; }
        list_push(args_tmp, v);
        list_push(labels_tmp, lbl);
    }

    if (changed) {
        list_clear_shallow(p->args);
        list_clear_shallow(p->labels);
        for (Iter it = list_iter(args_tmp); !iter_end(it);) list_push(p->args, iter_next(&it));
        for (Iter it = list_iter(labels_tmp); !iter_end(it);) list_push(p->labels, iter_next(&it));
    }

    list_clear_shallow(args_tmp);
    list_clear_shallow(labels_tmp);
    free(args_tmp); free(labels_tmp);
    return changed;
}

static bool pass_phi(Func *f, Stats *s) {
    int rm0 = s->phi_rm;
    bool changed = false;
    rebuild_preds(f);
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b) continue;
        for (Iter kt = list_iter(b->phis); !iter_end(kt);) {
            Instr *p = iter_next(&kt);
            if (phi_prune_dead_edges(b, p)) changed = true;
            if (phi_simplify_value(p, f, s)) changed = true;
            if (phi_dedup_edges(p)) changed = true;
        }
        List *keep = filter_list(b->phis, phi_pred, f);
        s->phi_rm += b->phis->len - keep->len;
        b->phis = keep;
    }
    return changed || s->phi_rm != rm0;
}

static bool pass_phi_cleanup(Func *f, Stats *s) {
    bool changed = false;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b || !b->phis) continue;
        List *keep = make_list();
        for (Iter kt = list_iter(b->phis); !iter_end(kt);) {
            Instr *p = iter_next(&kt);
            if (p && p->op == IROP_PHI) list_push(keep, p);
            else { changed = true; if (s) s->phi_rm++; }
        }
        b->phis = keep;
    }
    return changed;
}

/*---------- 常量折叠 + store/ret 标记 ----------*/
static bool pass_const_fold(Func *f, Stats *s) {
    bool changed = false;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b) continue;
        for (Iter jt = list_iter(b->instrs); !iter_end(jt);) {
            Instr *i = iter_next(&jt);
            if (!i || i->op == IROP_NOP || i->op == IROP_CONST) continue;

            int64_t a = 0, b_val = 0, r = 0;
            bool ha = get_const_value(f, get_arg(i, 0), &a);
            bool hb = get_const_value(f, get_arg(i, 1), &b_val);
            bool u = is_unsigned_type(i->type);
            bool ok = false;

            switch (i->op) {
            case IROP_ADD: case IROP_SUB: case IROP_MUL: case IROP_DIV: case IROP_MOD:
            case IROP_AND: case IROP_OR: case IROP_XOR:
            case IROP_SHL: case IROP_SHR:
            case IROP_EQ: case IROP_NE: case IROP_LT: case IROP_GT: case IROP_LE: case IROP_GE:
                ok = (ha && hb) && fold_binary_op(i->op, a, b_val, u, &r); break;
            case IROP_NEG: ok = ha; r = u ? (int64_t)(0ULL - (uint64_t)a) : -a; break;
            case IROP_NOT: ok = ha; r = ~a; break;
            case IROP_LNOT: ok = ha; r = !a; break;
            case IROP_TRUNC:
                if (ha) {
                    int sz = i->type ? i->type->size : 1;
                    uint64_t m = sz == 1 ? 0xFF : sz == 2 ? 0xFFFF : sz == 4 ? 0xFFFFFFFF : ~0ULL;
                    r = a & m; ok = true;
                }
                break;
            case IROP_STORE:
                if (i->args->len >= 2) {
                    Instr *addr = find_def_instr(f, get_arg(i, 0));
                    Instr *val = find_def_instr(f, get_arg(i, 1));
                    if (addr && addr->op == IROP_ADDR && val && val->op == IROP_CONST) {
                        const char *gname = (const char *)list_get(addr->labels, 0);
                        if (gname) {
                            i->imm.ival = val->imm.ival;
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
                continue;
            default: break;
            }
            if (ok) {
                i->op = IROP_CONST; i->imm.ival = r;
                if (i->args) list_clear(i->args);
                if (i->labels) list_clear(i->labels);
                ++s->fold; changed = true;
            }
        }
    }
    return changed;
}

/*---------- 复制传播 ----------*/
static bool is_copy_instr(const Instr *i) {
    return i && (i->op == IROP_TRUNC || i->op == IROP_ZEXT || i->op == IROP_SEXT)
           && i->args && i->args->len == 1;
}

static void replace_all_uses(Func *f, ValueName from, ValueName to, bool *changed) {
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b) continue;
        List *lists[2] = {b->phis, b->instrs};
        for (int li = 0; li < 2; li++) {
            if (!lists[li]) continue;
            for (Iter jt = list_iter(lists[li]); !iter_end(jt);) {
                Instr *i = iter_next(&jt);
                if (!i || !i->args) continue;
                for (int k = 0; k < i->args->len; ++k) {
                    ValueName *arg = list_get(i->args, k);
                    if (*arg == from) { *arg = to; *changed = true; }
                }
            }
        }
    }
}

static bool pass_copy_prop(Func *f, Stats *s) {
    bool changed = false;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b) continue;
        for (Iter jt = list_iter(b->instrs); !iter_end(jt);) {
            Instr *i = iter_next(&jt);
            if (!is_copy_instr(i)) continue;

            ValueName src = get_arg(i, 0);
            Instr *src_def = find_def_instr(f, src);
            while (src_def && is_copy_instr(src_def)) {
                src = get_arg(src_def, 0);
                src_def = find_def_instr(f, src);
            }

            if (src != i->dest) {
                replace_all_uses(f, i->dest, src, &changed);
                if (changed) {
                    i->op = IROP_NOP;
                    ++s->fold;
                }
            }
        }
    }
    return changed;
}

/*---------- 常量合并 ----------*/
static bool pass_const_merge(Func *f, Stats *s) {
    bool changed = false;
    #define MAX_CONSTS 64
    int64_t const_vals[MAX_CONSTS];
    ValueName const_names[MAX_CONSTS];
    int const_count = 0;

    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b) continue;
        if (b != f->entry && (!b->preds || b->preds->len == 0)) continue;
        for (Iter jt = list_iter(b->instrs); !iter_end(jt);) {
            Instr *i = iter_next(&jt);
            if (!i || i->op != IROP_CONST) continue;

            int64_t val = i->imm.ival;
            int found = -1;
            for (int k = 0; k < const_count; k++)
                if (const_vals[k] == val) { found = k; break; }

            if (found >= 0) {
                replace_all_uses(f, i->dest, const_names[found], &changed);
                i->op = IROP_NOP;
                ++s->fold;
            } else if (const_count < MAX_CONSTS) {
                const_vals[const_count] = val;
                const_names[const_count] = i->dest;
                const_count++;
            }
        }
    }
    return changed;
}

/*---------- 地址合并 ----------*/
static bool pass_addr_merge(Func *f, Stats *s) {
    bool changed = false;
    #define MAX_ADDRS 64
    typedef struct { const char *label; Ctype *mem_type; ValueName val; } AddrEntry;
    AddrEntry addrs[MAX_ADDRS];
    int addr_count = 0;

    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b) continue;
        for (Iter jt = list_iter(b->instrs); !iter_end(jt);) {
            Instr *i = iter_next(&jt);
            if (!i || i->op != IROP_ADDR || !i->labels || i->labels->len == 0) continue;
            const char *label = (const char *)list_get(i->labels, 0);
            if (!label) continue;

            int found = -1;
            for (int k = 0; k < addr_count; k++)
                if (addrs[k].label && !strcmp(addrs[k].label, label) && addrs[k].mem_type == i->mem_type)
                    { found = k; break; }

            if (found >= 0) {
                replace_all_uses(f, i->dest, addrs[found].val, &changed);
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
        if (!b) continue;
        for (Iter jt = list_iter(b->instrs); !iter_end(jt);) {
            Instr *i = iter_next(&jt);
            if (!i || i->op != IROP_LOAD || is_volatile_mem(i)) continue;
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

/*---------- 代数简化 + 比较链优化 ----------*/
static bool pass_local_opts(Func *f, Stats *s) {
    bool changed = false;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b) continue;
        for (Iter jt = list_iter(b->instrs); !iter_end(jt);) {
            Instr *i = iter_next(&jt);
            if (!i || !i->args) continue;

            ValueName a = get_arg(i, 0), bv = get_arg(i, 1);
            int64_t b_val = 0;
            bool has_b = i->args->len >= 2 && get_const_value(f, bv, &b_val);

            /* x - x = 0, x ^ x = 0 */
            if (i->args->len >= 2 && a == bv) {
                if (i->op == IROP_SUB || i->op == IROP_XOR) {
                    i->op = IROP_CONST; i->imm.ival = 0;
                    list_clear(i->args);
                    ++s->fold; changed = true; continue;
                }
                /* x & x = x, x | x = x */
                if (i->op == IROP_AND || i->op == IROP_OR) {
                    i->op = IROP_TRUNC;
                    list_clear(i->args);
                    ValueName *p = pass_alloc(sizeof *p); *p = a;
                    list_push(i->args, p);
                    ++s->fold; changed = true; continue;
                }
                /* eq x,x = 1; ne x,x = 0 */
                if (i->op == IROP_EQ || i->op == IROP_NE) {
                    bool is_eq = (i->op == IROP_EQ);
                    i->op = IROP_CONST;
                    i->imm.ival = is_eq ? 1 : 0;
                    list_clear(i->args);
                    ++s->fold; changed = true; continue;
                }
            }

            /* 常量比较 */
            if ((i->op == IROP_EQ || i->op == IROP_NE) && i->args->len >= 2) {
                int64_t ca = 0, cb = 0;
                if (get_const_value(f, a, &ca) && get_const_value(f, bv, &cb)) {
                    bool is_eq = (i->op == IROP_EQ);
                    i->op = IROP_CONST;
                    i->imm.ival = is_eq ? (ca == cb) : (ca != cb);
                    list_clear(i->args);
                    ++s->fold; changed = true; continue;
                }
            }

            /* 代数简化：x+0=x, x*1=x, x*0=0等 */
            if (i->args->len >= 1) {
                /* x + 0 = x, x - 0 = x */
                if ((i->op == IROP_ADD || i->op == IROP_SUB) && has_b && b_val == 0) {
                    i->op = IROP_TRUNC;
                    list_clear(i->args);
                    ValueName *p = pass_alloc(sizeof *p); *p = a;
                    list_push(i->args, p);
                    ++s->fold; changed = true; continue;
                }
                /* x * 1 = x, x / 1 = x */
                if ((i->op == IROP_MUL || i->op == IROP_DIV) && has_b && b_val == 1) {
                    i->op = IROP_TRUNC;
                    list_clear(i->args);
                    ValueName *p = pass_alloc(sizeof *p); *p = a;
                    list_push(i->args, p);
                    ++s->fold; changed = true; continue;
                }
                /* x * 0 = 0 */
                if (i->op == IROP_MUL && has_b && b_val == 0) {
                    i->op = IROP_CONST; i->imm.ival = 0;
                    list_clear(i->args);
                    ++s->fold; changed = true; continue;
                }
                /* x * (2^k) = x << k */
                if (i->op == IROP_MUL && has_b && b_val > 0 && (b_val & (b_val - 1)) == 0) {
                    int64_t k = 0;
                    while ((b_val >> k) > 1) ++k;
                    i->op = IROP_SHL; i->imm.ival = k;
                    if (!i->labels) i->labels = make_list();
                    list_clear(i->labels);
                    char *tag = pass_alloc(4); strcpy(tag, "imm");
                    list_push(i->labels, tag);
                    list_clear(i->args);
                    ValueName *p = pass_alloc(sizeof *p); *p = a;
                    list_push(i->args, p);
                    ++s->fold; changed = true; continue;
                }
                /* unsigned x / (2^k) = x >> k */
                if (i->op == IROP_DIV && has_b && b_val > 0 && (b_val & (b_val - 1)) == 0) {
                    bool udiv = is_unsigned_type(i->type);
                    if (!udiv) {
                        Instr *adef = find_def_instr(f, a);
                        udiv = adef && is_unsigned_type(adef->type);
                    }
                    if (udiv) {
                        int64_t k = 0;
                        while ((b_val >> k) > 1) ++k;
                        i->op = IROP_SHR; i->imm.ival = k;
                        if (!i->labels) i->labels = make_list();
                        list_clear(i->labels);
                        char *tag = pass_alloc(4); strcpy(tag, "imm");
                        list_push(i->labels, tag);
                        list_clear(i->args);
                        ValueName *p = pass_alloc(sizeof *p); *p = a;
                        list_push(i->args, p);
                        ++s->fold; changed = true; continue;
                    }
                }
                /* x % (2^k) = x & (2^k - 1) */
                if (i->op == IROP_MOD && has_b && b_val > 0 && (b_val & (b_val - 1)) == 0) {
                    i->op = IROP_AND;
                    i->imm.ival = b_val - 1;
                    if (!i->labels) i->labels = make_list();
                    list_clear(i->labels);
                    char *tag = pass_alloc(4); strcpy(tag, "imm");
                    list_push(i->labels, tag);
                    list_clear(i->args);
                    ValueName *p = pass_alloc(sizeof *p); *p = a;
                    list_push(i->args, p);
                    ++s->fold; changed = true; continue;
                }
                /* x << 0 = x, x >> 0 = x */
                if ((i->op == IROP_SHL || i->op == IROP_SHR) && has_b && b_val == 0) {
                    i->op = IROP_TRUNC;
                    list_clear(i->args);
                    ValueName *p = pass_alloc(sizeof *p); *p = a;
                    list_push(i->args, p);
                    ++s->fold; changed = true; continue;
                }
                /* x & 0 = 0 */
                if (i->op == IROP_AND && has_b && b_val == 0) {
                    i->op = IROP_CONST; i->imm.ival = 0;
                    list_clear(i->args);
                    ++s->fold; changed = true; continue;
                }
                /* x & -1 = x, x | 0 = x, x ^ 0 = x */
                if ((i->op == IROP_AND && has_b && b_val == -1) ||
                    (i->op == IROP_OR && has_b && b_val == 0) ||
                    (i->op == IROP_XOR && has_b && b_val == 0)) {
                    i->op = IROP_TRUNC;
                    list_clear(i->args);
                    ValueName *p = pass_alloc(sizeof *p); *p = a;
                    list_push(i->args, p);
                    ++s->fold; changed = true; continue;
                }
                /* 0 - x = -x */
                if (i->op == IROP_SUB) {
                    int64_t a_val = 0;
                    if (get_const_value(f, a, &a_val) && a_val == 0) {
                        ValueName rhs = get_arg(i, 1);
                        i->op = IROP_NEG;
                        list_clear(i->args);
                        ValueName *p = pass_alloc(sizeof *p); *p = rhs;
                        list_push(i->args, p);
                        ++s->fold; changed = true; continue;
                    }
                }
            }

            /* 比较链优化：ne (cmp x y), 0 -> trunc (cmp x y) */
            if ((i->op == IROP_NE || i->op == IROP_EQ) && i->args->len == 2) {
                Instr *db = find_def_instr(f, bv);
                if (db && db->op == IROP_CONST && db->imm.ival == 0) {
                    Instr *da = find_def_instr(f, a);
                    if (da && (da->op == IROP_GT || da->op == IROP_LT ||
                               da->op == IROP_GE || da->op == IROP_LE ||
                               da->op == IROP_EQ || da->op == IROP_NE)) {
                        if (i->op == IROP_NE) {
                            i->op = IROP_TRUNC;
                            list_clear(i->args);
                            ValueName *p = pass_alloc(sizeof *p); *p = a;
                            list_push(i->args, p);
                            ++s->fold; changed = true; continue;
                        }
                    }
                }
            }

            /* br trunc 消除 */
            if (i->op == IROP_BR && i->args->len >= 1) {
                Instr *c = find_def_instr(f, get_arg(i, 0));
                if (c && c->op == IROP_TRUNC && c->args->len >= 1) {
                    list_clear(i->args);
                    ValueName *p = pass_alloc(sizeof *p); *p = get_arg(c, 0);
                    list_push(i->args, p);
                    ++s->rm; changed = true; continue;
                }
            }

            /* 移位合并：(x << a) << b => x << (a+b) */
            if ((i->op == IROP_SHL || i->op == IROP_SHR) && i->args->len >= 1) {
                ValueName lhs = 0;
                int64_t s1 = 0;
                if (get_shift_imm(f, i, &lhs, &s1)) {
                    Instr *d = find_def_instr(f, lhs);
                    if (d && d->op == i->op) {
                        ValueName base = 0;
                        int64_t s0 = 0;
                        if (get_shift_imm(f, d, &base, &s0)) {
                            i->imm.ival = s0 + s1;
                            if (!i->labels) i->labels = make_list();
                            list_clear(i->labels);
                            char *tag = pass_alloc(4); strcpy(tag, "imm");
                            list_push(i->labels, tag);
                            list_clear(i->args);
                            ValueName *p = pass_alloc(sizeof *p); *p = base;
                            list_push(i->args, p);
                            ++s->fold; changed = true; continue;
                        }
                    }
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
        if (!b) continue;
        typedef struct { bool use_name; const char *name; ValueName base; int64_t offset; ValueName val; } StoreMap;
        StoreMap stores[64];
        int store_count = 0;

        for (Iter jt = list_iter(b->instrs); !iter_end(jt);) {
            Instr *i = iter_next(&jt);
            if (!i) continue;

            if (i->op == IROP_STORE) {
                if (is_volatile_mem(i)) { store_count = 0; continue; }
                ValueName base = 0;
                int64_t off = 0;
                if (resolve_base_offset(f, get_arg(i, 0), &base, &off)) {
                    const char *name = NULL;
                    Instr *bdef = find_def_instr(f, base);
                    if (bdef && bdef->op == IROP_ADDR && bdef->labels && bdef->labels->len > 0)
                        name = (const char *)list_get(bdef->labels, 0);
                    bool found = false;
                    for (int k = 0; k < store_count; k++) {
                        if (stores[k].offset != off) continue;
                        if (name && stores[k].use_name && stores[k].name && !strcmp(stores[k].name, name)) {
                            stores[k].val = get_arg(i, 1); found = true; break;
                        }
                        if (!name && !stores[k].use_name && stores[k].base == base) {
                            stores[k].val = get_arg(i, 1); found = true; break;
                        }
                    }
                    if (!found && store_count < 64) {
                        stores[store_count].use_name = (name != NULL);
                        stores[store_count].name = name;
                        stores[store_count].base = base;
                        stores[store_count].offset = off;
                        stores[store_count].val = get_arg(i, 1);
                        store_count++;
                    }
                }
            } else if (i->op == IROP_LOAD) {
                if (is_volatile_mem(i)) { store_count = 0; continue; }
                ValueName base = 0;
                int64_t off = 0;
                if (resolve_base_offset(f, get_arg(i, 0), &base, &off)) {
                    const char *name = NULL;
                    Instr *bdef = find_def_instr(f, base);
                    if (bdef && bdef->op == IROP_ADDR && bdef->labels && bdef->labels->len > 0)
                        name = (const char *)list_get(bdef->labels, 0);
                    for (int k = 0; k < store_count; k++) {
                        if (stores[k].offset != off) continue;
                        bool match = (name && stores[k].use_name && stores[k].name && !strcmp(stores[k].name, name)) ||
                                     (!name && !stores[k].use_name && stores[k].base == base);
                        if (match) {
                            i->op = IROP_TRUNC;
                            list_clear(i->args);
                            ValueName *p = pass_alloc(sizeof *p); *p = stores[k].val;
                            list_push(i->args, p);
                            changed = true; s->fold++;
                            break;
                        }
                    }
                }
            } else if (i->op == IROP_CALL) {
                store_count = 0;
            }
        }
    }
    return changed;
}

/*---------- 加载到加载转发 ----------*/
static bool pass_load_load_forwarding(Func *f, Stats *s) {
    bool changed = false;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b) continue;
        typedef struct { bool use_name; const char *name; ValueName base; int64_t offset; ValueName val; } LoadMap;
        LoadMap loads[64];
        int load_count = 0;

        for (Iter jt = list_iter(b->instrs); !iter_end(jt);) {
            Instr *i = iter_next(&jt);
            if (!i) continue;

            if (i->op == IROP_STORE || i->op == IROP_CALL || i->op == IROP_ASM) {
                load_count = 0;
                continue;
            }

            if (i->op != IROP_LOAD) continue;
            if (is_volatile_mem(i)) { load_count = 0; continue; }

            ValueName base = 0;
            int64_t off = 0;
            ValueName addr = get_arg(i, 0);
            bool ok = resolve_base_offset(f, addr, &base, &off);
            const char *name = NULL;
            if (!ok) {
                base = addr;
                off = 0;
            } else {
                Instr *bdef = find_def_instr(f, base);
                if (bdef && bdef->op == IROP_ADDR && bdef->labels && bdef->labels->len > 0)
                    name = (const char *)list_get(bdef->labels, 0);
            }

            for (int k = 0; k < load_count; k++) {
                if (loads[k].offset != off) continue;
                bool match = (name && loads[k].use_name && loads[k].name && !strcmp(loads[k].name, name)) ||
                             (!name && !loads[k].use_name && loads[k].base == base);
                if (match) {
                    i->op = IROP_TRUNC;
                    list_clear(i->args);
                    ValueName *p = pass_alloc(sizeof *p); *p = loads[k].val;
                    list_push(i->args, p);
                    changed = true; if (s) s->fold++;
                    goto next_instr;
                }
            }

            if (load_count < 64) {
                loads[load_count].use_name = (name != NULL);
                loads[load_count].name = name;
                loads[load_count].base = base;
                loads[load_count].offset = off;
                loads[load_count].val = i->dest;
                load_count++;
            }
        next_instr:
            ;
        }
    }
    return changed;
}

/*---------- 死局部存储消除 ----------*/
typedef struct { bool use_name; const char *name; ValueName base; bool used, escaped, is_local; } BaseInfo;

static BaseInfo *get_base_info(BaseInfo *bases, int *base_count, ValueName base, Func *f) {
    const char *name = NULL;
    Instr *bdef = find_def_instr(f, base);
    if (bdef && bdef->op == IROP_ADDR && bdef->labels && bdef->labels->len > 0)
        name = (const char *)list_get(bdef->labels, 0);

    for (int i = 0; i < *base_count; ++i) {
        if (name && bases[i].use_name && bases[i].name && !strcmp(bases[i].name, name)) return &bases[i];
        if (!name && !bases[i].use_name && bases[i].base == base) return &bases[i];
    }
    if (*base_count >= 128) return NULL;
    bases[*base_count].use_name = (name != NULL);
    bases[*base_count].name = name;
    bases[*base_count].base = base;
    bases[*base_count].used = false;
    bases[*base_count].escaped = false;
    bases[*base_count].is_local = is_local_addr_base(f, base);
    return &bases[(*base_count)++];
}

static bool pass_dead_local_store_elim(Func *f, Stats *s) {
    if (!f) return false;
    bool changed = false;
    BaseInfo bases[128];
    int base_count = 0;

    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b) continue;
        for (Iter jt = list_iter(b->instrs); !iter_end(jt);) {
            Instr *i = iter_next(&jt);
            if (!i) continue;

            if (i->op == IROP_LOAD) {
                ValueName base = 0;
                int64_t off = 0;
                if (resolve_base_offset(f, get_arg(i, 0), &base, &off)) {
                    BaseInfo *bi = get_base_info(bases, &base_count, base, f);
                    if (bi) bi->used = true;
                }
            }

            if (i->args) {
                for (int k = 0; k < i->args->len; ++k) {
                    ValueName v = *(ValueName *)list_get(i->args, k);
                    Instr *def = find_def_instr(f, v);
                    if (!def || def->op != IROP_ADDR) continue;
                    BaseInfo *bi = get_base_info(bases, &base_count, v, f);
                    if (!bi || !bi->is_local) continue;
                    if (i->op == IROP_CALL || i->op == IROP_RET || (i->op == IROP_STORE && k == 1))
                        bi->escaped = true;
                }
            }
        }
    }

    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b) continue;
        for (Iter jt = list_iter(b->instrs); !iter_end(jt);) {
            Instr *i = iter_next(&jt);
            if (!i || i->op != IROP_STORE || is_volatile_mem(i)) continue;
            ValueName base = 0;
            int64_t off = 0;
            if (!resolve_base_offset(f, get_arg(i, 0), &base, &off)) continue;
            BaseInfo *bi = get_base_info(bases, &base_count, base, f);
            if (bi && bi->is_local && !bi->used && !bi->escaped) {
                i->op = IROP_NOP;
                if (i->args) list_clear(i->args);
                changed = true;
                if (s) s->rm++;
            }
        }
    }

    return changed;
}

/*---------- store 清理 ----------*/
static bool pass_store_cleanup(Func *f, Stats *s) {
    bool changed = false;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b) continue;
        for (Iter jt = list_iter(b->instrs); !iter_end(jt);) {
            Instr *i = iter_next(&jt);
            if (!i || i->op != IROP_STORE) continue;
            if (!i->labels || i->labels->len == 0) continue;
            char *label = (char *)list_get(i->labels, 0);
            if (label && label[0] == '@' && i->args && i->args->len > 0) {
                list_clear(i->args);
                changed = true; s->rm++;
            }
        }
    }
    return changed;
}

/*---------- 取地址再解引用折叠 ----------*/
static bool pass_addr_deref_fold(Func *f, Stats *s) {
    if (!f) return false;
    bool changed = false;

    ParamMapEntry pmap[64];
    int pcount = 0;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b) continue;
        for (Iter jt = list_iter(b->instrs); !iter_end(jt);) {
            Instr *i = iter_next(&jt);
            if (!i || i->op != IROP_PARAM || !i->labels || i->labels->len < 1) continue;
            if (pcount < 64) {
                pmap[pcount].name = (const char *)list_get(i->labels, 0);
                pmap[pcount].val = i->dest;
                pcount++;
            }
        }
    }

    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b) continue;
        for (Iter jt = list_iter(b->instrs); !iter_end(jt);) {
            Instr *i = iter_next(&jt);
            if (!i || i->op != IROP_LOAD || is_volatile_mem(i) || !i->args || i->args->len < 1) continue;
            ValueName base = get_arg(i, 0);
            Instr *def = find_def_instr(f, base);
            if (!def || def->op != IROP_ADDR || !def->labels || def->labels->len < 1) continue;
            const char *name = (const char *)list_get(def->labels, 0);
            bool found = false;
            ValueName pv = pmap_get(pmap, pcount, name, &found);
            if (!found) continue;
            if (!addr_used_only_by_loads(f, base)) continue;

            i->op = IROP_TRUNC;
            if (i->labels) list_clear(i->labels);
            list_clear(i->args);
            ValueName *p = pass_alloc(sizeof(ValueName));
            *p = pv;
            list_push(i->args, p);
            changed = true;
            if (s) s->fold++;
        }
    }

    return changed;
}

/*---------- offset 立即数内联 ----------*/
static bool pass_offset_imm_inline(Func *f, Stats *s) {
    if (!f) return false;
    bool changed = false;

    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b) continue;
        for (Iter jt = list_iter(b->instrs); !iter_end(jt);) {
            Instr *i = iter_next(&jt);
            if (!i || i->op != IROP_OFFSET || !i->args || i->args->len < 2) continue;
            ValueName idx = get_arg(i, 1);
            Instr *def = find_def_instr(f, idx);
            if (!def || def->op != IROP_CONST) continue;

            if (!i->labels) i->labels = make_list();
            list_clear(i->labels);
            char *tag = pass_alloc(4); strcpy(tag, "imm");
            list_push(i->labels, tag);
            char *imm = pass_alloc(32); snprintf(imm, 32, "%ld", (long)def->imm.ival);
            list_push(i->labels, imm);

            changed = true;
            if (s) s->fold++;
        }
    }

    return changed;
}

/*---------- 内联函数调用 ----------*/
static bool inline_single_call(Func *f, Instr *call, int *next_val, Stats *s, List *out_instrs) {
    if (!f || !call || call->op != IROP_CALL || !call->labels || call->labels->len < 1) return false;
    const char *callee_name = (const char *)list_get(call->labels, 0);
    Func *callee = find_func_in_unit(callee_name);
    if (!callee || !callee->is_inline || callee->is_interrupt || callee->is_noreturn) return false;
    if (callee == f) return false; // 递归暂不内联
    if (!callee->blocks || callee->blocks->len != 1 || !callee->entry) return false;
    Block *cb = callee->entry;
    if (cb->phis && cb->phis->len > 0) return false;

    int argc = call->args ? call->args->len : 0;
    ValueName params[32];
    int param_count = 0;
    for (Iter it = list_iter(cb->instrs); !iter_end(it);) {
        Instr *i = iter_next(&it);
        if (!i) continue;
        if (i->op == IROP_PARAM) {
            if (param_count < 32) params[param_count++] = i->dest;
            else return false;
        }
    }
    if (param_count != argc) return false;

    Instr *ret = NULL;
    for (Iter it = list_iter(cb->instrs); !iter_end(it);) {
        Instr *i = iter_next(&it);
        if (!i || i->op == IROP_NOP || i->op == IROP_PARAM) continue;
        if (i->op == IROP_RET) {
            if (ret) return false;
            ret = i;
            continue;
        }
        if (!inline_allowed_op(i->op)) return false;
    }
    if (!ret) return false;

    ValueMapEntry vmap[128];
    int vmap_count = 0;
    for (int i = 0; i < param_count; ++i) {
        ValueName arg = *(ValueName *)list_get(call->args, i);
        if (!vmap_put(vmap, &vmap_count, 128, params[i], arg)) return false;
    }

    List *cloned = make_list();
    for (Iter it = list_iter(cb->instrs); !iter_end(it);) {
        Instr *i = iter_next(&it);
        if (!i || i->op == IROP_NOP || i->op == IROP_PARAM || i->op == IROP_RET) continue;
        Instr *ni = pass_alloc(sizeof(Instr));
        memset(ni, 0, sizeof(*ni));
        ni->op = i->op;
        ni->type = i->type;
        ni->mem_type = i->mem_type;
        ni->imm = i->imm;
        if (i->dest) {
            ni->dest = (*next_val)++;
            if (!vmap_put(vmap, &vmap_count, 128, i->dest, ni->dest)) return false;
        }
        if (i->args && i->args->len > 0) {
            ni->args = make_list();
            for (int k = 0; k < i->args->len; ++k) {
                ValueName v = *(ValueName *)list_get(i->args, k);
                bool found = false;
                ValueName mv = vmap_get(vmap, vmap_count, v, &found);
                if (!found) return false;
                ValueName *p = pass_alloc(sizeof(ValueName));
                *p = mv;
                list_push(ni->args, p);
            }
        }
        if (i->labels && i->labels->len > 0) {
            ni->labels = make_list();
            for (int k = 0; k < i->labels->len; ++k)
                list_push(ni->labels, list_get(i->labels, k));
        }
        list_push(cloned, ni);
    }

    ValueName ret_val = 0;
    if (ret->args && ret->args->len > 0) {
        ValueName rv = *(ValueName *)list_get(ret->args, 0);
        bool found = false;
        ret_val = vmap_get(vmap, vmap_count, rv, &found);
        if (!found) return false;
    }

    if (call->dest && !ret_val) return false;

    for (Iter it = list_iter(cloned); !iter_end(it);)
        list_push(out_instrs, iter_next(&it));

    list_clear_shallow(cloned);

    if (call->dest && ret_val) {
        bool dummy_changed = false;
        replace_all_uses(f, call->dest, ret_val, &dummy_changed);
    }
    call->op = IROP_NOP;
    if (call->args) list_clear(call->args);
    if (call->labels) list_clear(call->labels);
    if (s) s->fold++;
    return true;
}

static bool pass_inline_func_call(Func *f, Stats *s) {
    if (!f) return false;
    bool changed = false;
    int next_val = max_value_in_func(f) + 1;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b || !b->instrs) continue;

        List *new_instrs = make_list();
        bool block_changed = false;
        for (Iter jt = list_iter(b->instrs); !iter_end(jt);) {
            Instr *i = iter_next(&jt);
            if (i && i->op == IROP_CALL) {
                if (inline_single_call(f, i, &next_val, s, new_instrs)) {
                    block_changed = true;
                    continue;
                }
            }
            list_push(new_instrs, i);
        }

        if (block_changed) {
            list_clear_shallow(b->instrs);
            b->instrs = new_instrs;
            changed = true;
        } else {
            list_clear_shallow(new_instrs);
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
        if (!b) continue;
        for (Iter jt = list_iter(b->instrs); !iter_end(jt);) {
            Instr *i = iter_next(&jt);
            if (!i || i->op != IROP_RET || !i->args || i->args->len < 1) continue;
            ValueName v = get_arg(i, 0);
            Instr *def = find_def_instr(f, v);
            if (!def || def->op != IROP_CONST) continue;

            i->imm.ival = def->imm.ival;
            list_clear(i->args); i->args = NULL;
            if (!i->labels) i->labels = make_list();
            list_clear(i->labels);
            char *tag = pass_alloc(4); strcpy(tag, "imm");
            list_push(i->labels, tag);
            if (count_uses(f, def->dest) == 0) def->op = IROP_NOP;
            changed = true; s->fold++;
        }
    }
    return changed;
}

/*---------- 常量store清理 ----------*/
static bool pass_const_store_prune(Func *f, Stats *s) {
    bool changed = false;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b) continue;
        for (Iter jt = list_iter(b->instrs); !iter_end(jt);) {
            Instr *def = iter_next(&jt);
            if (!def || def->op != IROP_CONST || def->dest == 0) continue;

            bool used = false, ok = true;
            for (Iter it2 = list_iter(f->blocks); !iter_end(it2);) {
                Block *bb = iter_next(&it2);
                if (!bb) continue;
                for (Iter jt2 = list_iter(bb->instrs); !iter_end(jt2);) {
                    Instr *use = iter_next(&jt2);
                    if (!use || !use->args) continue;
                    for (int k = 0; k < use->args->len; ++k) {
                        if (*(ValueName *)list_get(use->args, k) != def->dest) continue;
                        used = true;
                        if (use->op != IROP_STORE) ok = false;
                        else if (!use->labels || use->labels->len == 0) ok = false;
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
                if (!bb) continue;
                for (Iter jt2 = list_iter(bb->instrs); !iter_end(jt2);) {
                    Instr *use = iter_next(&jt2);
                    if (!use || !use->args) continue;
                    bool hit = false;
                    for (int k = 0; k < use->args->len; ++k)
                        if (*(ValueName *)list_get(use->args, k) == def->dest) { hit = true; break; }
                    if (hit && use->op == IROP_STORE) list_clear(use->args);
                }
            }

            def->op = IROP_NOP;
            s->rm++; changed = true;
        }
    }
    return changed;
}

/*---------- 二元运算立即数内联 ----------*/
static bool pass_binop_const_inline(Func *f, Stats *s) {
    bool changed = false;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b) continue;
        for (Iter jt = list_iter(b->instrs); !iter_end(jt);) {
            Instr *i = iter_next(&jt);
            if (!i || !i->args || i->args->len < 2) continue;
            bool is_cmp = false;
            switch (i->op) {
            case IROP_ADD: case IROP_SUB: case IROP_MUL: case IROP_DIV: case IROP_MOD:
            case IROP_AND: case IROP_OR: case IROP_XOR:
            case IROP_SHL: case IROP_SHR: break;
            case IROP_EQ: case IROP_NE: case IROP_LT: case IROP_GT: case IROP_LE: case IROP_GE:
                is_cmp = true; break;
            default: continue;
            }
            bool keep_args = is_cmp || (i->type && i->type->size >= 2);

            ValueName lhs = get_arg(i, 0), rhs = get_arg(i, 1);
            Instr *def = find_def_instr(f, rhs);

            if ((!def || def->op != IROP_CONST) &&
                (i->op == IROP_ADD || i->op == IROP_MUL || i->op == IROP_AND ||
                 i->op == IROP_OR || i->op == IROP_XOR || i->op == IROP_EQ || i->op == IROP_NE)) {
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
            char *tag = pass_alloc(4); strcpy(tag, "imm");
            list_push(i->labels, tag);

            if (!keep_args) {
                list_clear(i->args);
                ValueName *p = pass_alloc(sizeof *p); *p = lhs;
                list_push(i->args, p);
            }
            changed = true; s->fold++;
        }
    }
    return changed;
}

/*---------- bool 返回分支折叠 ----------*/
static bool block_only_ret_const(Block *b, int64_t *out_val) {
    if (out_val) *out_val = 0;
    if (!b || !b->instrs) return false;
    Instr *ret = NULL;
    for (Iter it = list_iter(b->instrs); !iter_end(it);) {
        Instr *i = iter_next(&it);
        if (!i || i->op == IROP_NOP || i->op == IROP_PARAM) continue;
        if (ret) return false;
        if (i->op != IROP_RET) return false;
        ret = i;
    }
    if (!ret) return false;
    if (ret->labels && ret->labels->len > 0) {
        char *tag = (char *)list_get(ret->labels, 0);
        if (tag && strcmp(tag, "imm") == 0) {
            if (out_val) *out_val = ret->imm.ival;
            return true;
        }
    }
    return false;
}

static bool pass_bool_return_simplify(Func *f, Stats *s) {
    if (!f || !f->blocks) return false;
    bool changed = false;
    int next_val = max_value_in_func(f) + 1;

    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b || !b->instrs || b->instrs->len == 0) continue;
        Instr *term = (Instr *)list_get(b->instrs, b->instrs->len - 1);
        if (!term || term->op != IROP_BR || !term->labels || term->labels->len < 2 || !term->args) continue;

        char *lbl_t = (char *)list_get(term->labels, 0);
        char *lbl_f = (char *)list_get(term->labels, 1);
        int id_t = -1, id_f = -1;
        if (!lbl_t || !lbl_f) continue;
        if (sscanf(lbl_t, "block%d", &id_t) != 1) continue;
        if (sscanf(lbl_f, "block%d", &id_f) != 1) continue;

        Block *bt = find_block_by_id(f, id_t);
        Block *bf = find_block_by_id(f, id_f);
        if (!bt || !bf) continue;
        if (bt->phis && bt->phis->len > 0) continue;
        if (bf->phis && bf->phis->len > 0) continue;

        int64_t vt = 0, vf = 0;
        if (!block_only_ret_const(bt, &vt)) continue;
        if (!block_only_ret_const(bf, &vf)) continue;
        if (!((vt == 1 && vf == 0) || (vt == 0 && vf == 1))) continue;

        ValueName cond = get_arg(term, 0);
        ValueName ret_val = cond;

        if (vt == 0 && vf == 1) {
            Instr *ln = pass_alloc(sizeof(Instr));
            memset(ln, 0, sizeof(*ln));
            ln->op = IROP_LNOT;
            ln->dest = next_val++;
            Instr *cdef = find_def_instr(f, cond);
            ln->type = cdef ? cdef->type : NULL;
            ln->args = make_list();
            ValueName *p = pass_alloc(sizeof(ValueName));
            *p = cond;
            list_push(ln->args, p);
            list_remove_last(b->instrs, NULL);
            list_push(b->instrs, ln);
            list_push(b->instrs, term);
            ret_val = ln->dest;
        }

        term->op = IROP_RET;
        if (term->labels) list_clear(term->labels);
        if (term->args) list_clear(term->args);
        else term->args = make_list();
        ValueName *pr = pass_alloc(sizeof(ValueName));
        *pr = ret_val;
        list_push(term->args, pr);

        changed = true;
        if (s) s->fold++;
    }

    return changed;
}

/*---------- 基本块合并 ----------*/
static bool pass_block_merge(Func *f, Stats *s) {
    bool changed = false;
    if (!f || !f->blocks) return false;
    rebuild_preds(f);

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

        list_remove_last(b->instrs, NULL);
        for (Iter jt = list_iter(t->instrs); !iter_end(jt);) list_push(b->instrs, iter_next(&jt));

        if (t->instrs && t->instrs->len > 0) {
            Instr *tterm = (Instr *)list_get(t->instrs, t->instrs->len - 1);
            if (tterm && tterm->labels) {
                for (int k = 0; k < tterm->labels->len; k++) {
                    int sid = -1;
                    sscanf((char *)list_get(tterm->labels, k), "block%d", &sid);
                    Block *sblk = find_block_by_id(f, sid);
                    if (sblk) {
                        sblk->preds = preds_remove(sblk->preds, t);
                        list_unique_push(sblk->preds, b, block_ptr_eq);
                        replace_phi_pred_label(sblk, t->id, b->id);
                    }
                }
            }
        }

        replace_label_all(f, t->id, b->id);
        if (f->entry == t) f->entry = b;
        list_clear_shallow(t->instrs);
        t->instrs = make_list();
        list_clear_shallow(t->phis);
        t->phis = make_list();
        t->preds = make_list();
        s->merge++; changed = true;
    }

    rebuild_preds(f);
    return changed;
}

/*---------- 分支目标相同 => jmp ----------*/
static bool pass_br_same_target(Func *f, Stats *s) {
    bool changed = false;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b || !b->instrs || b->instrs->len == 0) continue;
        Instr *term = (Instr *)list_get(b->instrs, b->instrs->len - 1);
        if (!term || term->op != IROP_BR || !term->labels || term->labels->len < 2) continue;
        char *l0 = (char *)list_get(term->labels, 0);
        char *l1 = (char *)list_get(term->labels, 1);
        if (!l0 || !l1 || strcmp(l0, l1) != 0) continue;

        char *lab = pass_alloc(strlen(l0) + 1);
        strcpy(lab, l0);
        term->op = IROP_JMP;
        if (term->args) list_clear(term->args);
        list_clear(term->labels);
        list_push(term->labels, lab);
        s->rm++; changed = true;
    }
    return changed;
}

/*---------- 常量分支消除 ----------*/
static bool pass_const_branch(Func *f, Stats *s) {
    bool changed = false;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b) continue;
        Instr *term = list_empty(b->instrs) ? NULL : list_get(b->instrs, b->instrs->len - 1);
        if (!term || term->op != IROP_BR) continue;
        ValueName cond = get_arg(term, 0);
        int64_t val;
        if (!get_const_value(f, cond, &val)) continue;

        const char *live_label = val ? list_get(term->labels, 0) : list_get(term->labels, 1);
        const char *dead_label = val ? list_get(term->labels, 1) : list_get(term->labels, 0);
        char *live_label_copy = live_label ? pass_alloc(strlen(live_label) + 1) : NULL;
        if (live_label_copy) strcpy(live_label_copy, live_label);

        term->op = IROP_JMP;
        list_clear(term->args);
        list_clear(term->labels);
        if (live_label_copy) list_push(term->labels, live_label_copy);
        s->fold++; changed = true;

        /* 直接内联只有一个 jmp/ret 的死分支块 */
        if (dead_label) {
            int dead_id = -1;
            sscanf(dead_label, "block%d", &dead_id);
            Block *dead_blk = find_block_by_id(f, dead_id);
            if (dead_blk && dead_blk != b) {
                /* 从死块的前驱列表中移除当前块 */
                if (dead_blk->preds) {
                    dead_blk->preds = preds_remove(dead_blk->preds, b);
                    /* 如果死块没有其他前驱了，清空它 */
                    if (dead_blk->preds->len == 0) {
                        list_clear_shallow(dead_blk->instrs);
                        dead_blk->instrs = make_list();
                        list_clear_shallow(dead_blk->phis);
                        dead_blk->phis = make_list();
                    }
                }
            }
        }
    }
    return changed;
}

/*---------- jmp 跳转链折叠 ----------*/
static bool pass_jump_threading(Func *f, Stats *s) {
    bool changed = false;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b || !b->instrs || b->instrs->len == 0) continue;
        Instr *term = (Instr *)list_get(b->instrs, b->instrs->len - 1);
        if (!term || term->op != IROP_JMP || !term->labels || term->labels->len < 1) continue;

        int tid = -1;
        sscanf((char *)list_get(term->labels, 0), "block%d", &tid);
        if (tid < 0) continue;
        Block *t = find_block_by_id(f, tid);
        if (!t || t == b || (t->phis && t->phis->len > 0) || !t->instrs || t->instrs->len != 1) continue;

        Instr *tterm = (Instr *)list_get(t->instrs, t->instrs->len - 1);
        if (!tterm || tterm->op != IROP_JMP || !tterm->labels || tterm->labels->len < 1) continue;

        int sid = -1;
        sscanf((char *)list_get(tterm->labels, 0), "block%d", &sid);
        if (sid < 0 || sid == (int)b->id) continue;

        const char *raw = (const char *)list_get(tterm->labels, 0);
        if (!raw) continue;
        char *new_label = pass_alloc(strlen(raw) + 1);
        strcpy(new_label, raw);

        list_clear(term->labels);
        list_push(term->labels, new_label);

        if (t->preds) t->preds = preds_remove(t->preds, b);
        Block *sblk = find_block_by_id(f, sid);
        if (sblk) {
            list_unique_push(sblk->preds, b, block_ptr_eq);
            replace_phi_pred_label(sblk, t->id, b->id);
        }
        changed = true; s->fold++;
    }
    return changed;
}

/*---------- 不可达块清理 ----------*/
static bool pass_unreachable_block_elim(Func *f, Stats *s) {
    if (!f || !f->blocks || !f->entry) return false;
    rebuild_preds(f);
    bool changed = false;

    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b || b == f->entry) continue;

        if (block_only_ret(b, NULL)) 
            continue;

        if (b->preds && b->preds->len > 0) 
            continue;

        if (block_has_other_preds(f, b, NULL)) 
            continue;

        if (block_referenced_by_any_label(f, b)) 
            continue;

        if ((b->phis && b->phis->len > 0) || (b->instrs && b->instrs->len > 0)) {
            if (b->phis) {
                for (Iter pit = list_iter(b->phis); !iter_end(pit);) {
                    Instr *p = iter_next(&pit);
                    if (p) ssa_print_instr(stdout, p, NULL);
                }
            }
            if (b->instrs) {
                for (Iter iit = list_iter(b->instrs); !iter_end(iit);) {
                    Instr *ii = iter_next(&iit);
                    if (ii) ssa_print_instr(stdout, ii, NULL);
                }
            }

            list_clear_shallow(b->phis);
            b->phis = make_list();
            list_clear_shallow(b->instrs);
            b->instrs = make_list();
            if (b->preds) list_clear_shallow(b->preds);
            b->preds = make_list();
            if (s) s->rm++;
            changed = true;
        }
    }

    if (changed) rebuild_preds(f);
    return changed;
}

/*---------- 入口块空跳转消除 ----------*/
static bool pass_entry_jmp_elim(Func *f, Stats *s) {
    if (!f || !f->entry || !f->blocks) return false;
    rebuild_preds(f);
    Block *b = f->entry;
    if (!b || (b->phis && b->phis->len > 0)) return false;
    Instr *term = NULL;
    if (!block_only_jmp_in_func(f, b, &term)) return false;

    int tid = -1;
    sscanf((char *)list_get(term->labels, 0), "block%d", &tid);
    if (tid < 0) return false;
    Block *t = find_block_by_id(f, tid);
    if (!t || t == b || (t->phis && t->phis->len > 0) || !t->instrs || t->instrs->len == 0) return false;
    Instr *tterm = (Instr *)list_get(t->instrs, t->instrs->len - 1);
    if (!tterm || (tterm->op != IROP_JMP && tterm->op != IROP_BR && tterm->op != IROP_RET)) return false;

    f->entry = t;
    if (t->preds) t->preds = preds_remove(t->preds, b);
    list_clear_shallow(b->instrs);
    b->instrs = make_list();
    b->preds = make_list();
    s->rm++;
    return true;
}

/*---------- 入口块跳转内联 ----------*/
static bool pass_entry_jmp_inline(Func *f, Stats *s) {
    if (!f || !f->entry || !f->blocks) return false;
    rebuild_preds(f);
    Block *b = f->entry;
    if (!b || (b->phis && b->phis->len > 0)) return false;
    Instr *term = NULL;
    if (!block_only_jmp_in_func(f, b, &term)) return false;

    int tid = -1;
    sscanf((char *)list_get(term->labels, 0), "block%d", &tid);
    if (tid < 0) return false;
    Block *t = find_block_by_id(f, tid);
    if (!t || t == b || (t->phis && t->phis->len > 0) || !t->instrs || t->instrs->len == 0) return false;
    Instr *tterm = (Instr *)list_get(t->instrs, t->instrs->len - 1);
    if (!tterm || (tterm->op != IROP_JMP && tterm->op != IROP_BR && tterm->op != IROP_RET)) return false;
    if (block_has_other_preds(f, t, b)) return false;

    list_clear_shallow(b->instrs);
    b->instrs = make_list();
    if (t->instrs) for (Iter it = list_iter(t->instrs); !iter_end(it);) list_push(b->instrs, iter_next(&it));
    b->preds = make_list();
    list_clear_shallow(t->instrs);
    t->instrs = make_list();
    t->preds = make_list();
    s->rm++;
    return true;
}

/*---------- 入口块 jmp->ret 折叠 ----------*/
static bool pass_entry_jmp_ret_fold(Func *f, Stats *s) {
    if (!f || !f->entry || !f->blocks) return false;
    Block *b = f->entry;
    if (!b || (b->phis && b->phis->len > 0)) return false;
    Instr *term = NULL;
    if (!block_only_jmp_in_func(f, b, &term)) return false;

    int tid = -1;
    sscanf((char *)list_get(term->labels, 0), "block%d", &tid);
    if (tid < 0) return false;
    Block *t = find_block_by_id(f, tid);
    if (!t || t == b || (t->phis && t->phis->len > 0)) return false;
    if (block_has_other_preds(f, t, b)) return false;

    Instr *ret = NULL;
    if (!block_only_ret(t, &ret)) return false;

    list_clear_shallow(b->instrs);
    b->instrs = make_list();
    list_push(b->instrs, ret);
    list_clear_shallow(t->instrs);
    t->instrs = make_list();
    t->preds = make_list();
    s->rm++;
    return true;
}

/*---------- 仅含 jmp 的空块消除 ----------*/
static bool pass_jmp_only_elim(Func *f, Stats *s) {
    bool changed = false;
    if (!f || !f->blocks) return false;
    rebuild_preds(f);

    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b || b == f->entry) continue;
        if (b->phis && b->phis->len > 0) continue;
        Instr *term = NULL;
        if (!block_only_jmp_in_func(f, b, &term)) continue;

        int sid = -1;
        sscanf((char *)list_get(term->labels, 0), "block%d", &sid);
        if (sid < 0) continue;
        Block *succ = find_block_by_id(f, sid);
        if (!succ || succ == b) continue;
        if (succ->phis && succ->phis->len > 0 && b->preds && b->preds->len > 1) continue;

        if (b->preds) {
            for (Iter pit = list_iter(b->preds); !iter_end(pit);) {
                Block *pred = iter_next(&pit);
                if (!pred || pred == b) continue;
                replace_term_target(pred, b->id, succ->id);
                if (succ->preds) succ->preds = preds_remove(succ->preds, b);
                list_unique_push(succ->preds, pred, block_ptr_eq);
                replace_phi_pred_label(succ, b->id, pred->id);
            }
        }
        replace_label_all(f, b->id, succ->id);
        b->preds = make_list();
        b->phis = make_list();
        b->instrs = make_list();
        s->rm++; changed = true;
    }
    return changed;
}

/*---------- 循环不变量累加外提 ----------*/
static Block *find_instr_block(Func *f, Instr *inst) {
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b || !b->instrs) continue;
        for (Iter jt = list_iter(b->instrs); !iter_end(jt);)
            if (iter_next(&jt) == inst) return b;
    }
    return NULL;
}

static Instr *block_last_effective_instr(Block *b) {
    if (!b || !b->instrs) return NULL;
    Instr *last = NULL;
    for (Iter it = list_iter(b->instrs); !iter_end(it);) {
        Instr *i = iter_next(&it);
        if (!i) continue;
        if (i->op == IROP_NOP || i->op == IROP_PHI) continue;
        last = i;
    }
    return last;
}

static bool is_cmp_op(IrOp op) {
    return op == IROP_LT || op == IROP_LE || op == IROP_GT || op == IROP_GE ||
           op == IROP_EQ || op == IROP_NE;
}

static bool pass_loop_invariant_accum(Func *f, Stats *s) {
    bool changed = false;
    if (!f || !f->blocks || f->blocks->len < 4) return false;
    rebuild_preds(f);

    Block *b0 = f->entry ? f->entry : (Block *)list_get(f->blocks, 0);
    if (!b0 || !b0->instrs || b0->instrs->len == 0) return false;

    Instr *b0term = block_last_effective_instr(b0);
    if (!b0term || b0term->op != IROP_JMP || !b0term->labels || b0term->labels->len < 1) return false;

    int hid = -1;
    sscanf((char *)list_get(b0term->labels, 0), "block%d", &hid);
    if (hid < 0) return false;
    Block *b1 = find_block_by_id(f, hid);
    if (!b1 || !b1->instrs || b1->instrs->len == 0 || !b1->phis) return false;

    Instr *b1term = block_last_effective_instr(b1);
    if (!b1term || b1term->op != IROP_BR || !b1term->labels || b1term->labels->len < 2) return false;

    int bid_body = -1, bid_exit = -1;
    sscanf((char *)list_get(b1term->labels, 0), "block%d", &bid_body);
    sscanf((char *)list_get(b1term->labels, 1), "block%d", &bid_exit);
    if (bid_body < 0 || bid_exit < 0) return false;

    Block *b2 = find_block_by_id(f, bid_body);
    Block *b4 = find_block_by_id(f, bid_exit);
    if (!b2 || !b4 || !b2->instrs || b2->instrs->len == 0 || !b4->instrs || b4->instrs->len == 0) return false;

    Instr *b2term = block_last_effective_instr(b2);
    if (!b2term || b2term->op != IROP_JMP || !b2term->labels || b2term->labels->len < 1) return false;
    int back_id = -1;
    sscanf((char *)list_get(b2term->labels, 0), "block%d", &back_id);
    if (back_id != (int)b1->id) return false;

    if (!b1->phis || b1->phis->len < 2) return false;
    Instr *phi_i = NULL;
    ValueName n_val = 0;
    ValueName cond = get_arg(b1term, 0);
    Instr *cond_def = find_def_instr(f, cond);
    if (!cond_def || !is_cmp_op(cond_def->op)) return false;

    ValueName c0 = get_arg(cond_def, 0), c1 = get_arg(cond_def, 1);
    for (Iter it = list_iter(b1->phis); !iter_end(it);) {
        Instr *p = iter_next(&it);
        if (!p || p->op != IROP_PHI) continue;
        if (p->dest == c0 || p->dest == c1) {
            phi_i = p;
            n_val = (p->dest == c0) ? c1 : c0;
            break;
        }
    }
    if (!phi_i || n_val == 0) return false;

    Instr *phi_sum = NULL, *add1 = NULL, *add2 = NULL;
    ValueName inv_val = 0;
    for (Iter it = list_iter(b2->instrs); !iter_end(it);) {
        Instr *i = iter_next(&it);
        if (!i || i->op != IROP_ADD || !i->args || i->args->len < 2) continue;
        ValueName a0 = get_arg(i, 0), a1 = get_arg(i, 1);
        for (Iter pit = list_iter(b1->phis); !iter_end(pit);) {
            Instr *p = iter_next(&pit);
            if (!p || p->op != IROP_PHI || p == phi_i) continue;
            if (a0 == p->dest || a1 == p->dest) {
                ValueName cand_inv = (a0 == p->dest) ? a1 : a0;
                Instr *inv_def = find_def_instr(f, cand_inv);
                Block *inv_blk = find_instr_block(f, inv_def);
                if (inv_def && inv_blk == b0) {
                    phi_sum = p; add1 = i; inv_val = cand_inv;
                    break;
                }
            }
        }
        if (add1) break;
    }
    if (!phi_sum || !add1 || inv_val == 0) return false;

    for (Iter it = list_iter(b2->instrs); !iter_end(it);) {
        Instr *i = iter_next(&it);
        if (!i || i->op != IROP_ADD || !i->args || i->args->len < 2) continue;
        ValueName a0 = get_arg(i, 0), a1 = get_arg(i, 1);
        if ((a0 == add1->dest && a1 == phi_i->dest) || (a1 == add1->dest && a0 == phi_i->dest)) {
            add2 = i; break;
        }
    }
    if (!add2) return false;

    bool phi_has_add2 = false;
    if (phi_sum->labels && phi_sum->args) {
        for (int k = 0; k < phi_sum->labels->len && k < phi_sum->args->len; ++k) {
            char *lbl = (char *)list_get(phi_sum->labels, k);
            ValueName v = *(ValueName *)list_get(phi_sum->args, k);
            if (lbl && v == add2->dest) {
                int pid = -1;
                sscanf(lbl, "block%d", &pid);
                if (pid == (int)b2->id) { phi_has_add2 = true; break; }
            }
        }
    }
    if (!phi_has_add2) return false;

    Instr *term0 = NULL;
    list_remove_last(b0->instrs, (void **)&term0);
    if (!term0 || term0->op != IROP_JMP) {
        if (term0) list_push(b0->instrs, term0);
        return false;
    }

    ValueName next_val = max_value_in_func(f) + 1;
    Instr *mul_n_inv = pass_alloc(sizeof(Instr));
    memset(mul_n_inv, 0, sizeof(*mul_n_inv));
    mul_n_inv->op = IROP_MUL;
    mul_n_inv->dest = next_val++;
    mul_n_inv->type = phi_sum->type;
    mul_n_inv->args = make_list();
    ValueName *pn = pass_alloc(sizeof(ValueName)); *pn = n_val; list_push(mul_n_inv->args, pn);
    ValueName *pi = pass_alloc(sizeof(ValueName)); *pi = inv_val; list_push(mul_n_inv->args, pi);
    list_push(b0->instrs, mul_n_inv);
    list_push(b0->instrs, term0);
    ValueName mul_val = mul_n_inv->dest;

    list_clear(add2->args);
    ValueName *ps0 = pass_alloc(sizeof(ValueName)); *ps0 = phi_sum->dest; list_push(add2->args, ps0);
    ValueName *ps1 = pass_alloc(sizeof(ValueName)); *ps1 = phi_i->dest; list_push(add2->args, ps1);
    add1->op = IROP_NOP;
    if (add1->args) list_clear(add1->args);

    Instr *ret = NULL;
    list_remove_last(b4->instrs, (void **)&ret);
    if (!ret || ret->op != IROP_RET) {
        if (ret) list_push(b4->instrs, ret);
        return false;
    }
    Instr *add_exit = pass_alloc(sizeof(Instr));
    memset(add_exit, 0, sizeof(*add_exit));
    add_exit->op = IROP_ADD;
    add_exit->dest = next_val++;
    add_exit->type = phi_sum->type;
    add_exit->args = make_list();
    ValueName *pe0 = pass_alloc(sizeof(ValueName)); *pe0 = phi_sum->dest; list_push(add_exit->args, pe0);
    ValueName *pe1 = pass_alloc(sizeof(ValueName)); *pe1 = mul_val; list_push(add_exit->args, pe1);
    list_push(b4->instrs, add_exit);

    if (ret->args) list_clear(ret->args);
    else ret->args = make_list();
    ValueName *pret = pass_alloc(sizeof(ValueName)); *pret = add_exit->dest; list_push(ret->args, pret);
    list_push(b4->instrs, ret);

    changed = true;
    if (s) s->fold++;
    return changed;
}

/*---------- 单块函数规范化 ----------*/
static bool pass_single_block_normalize(Func *f) {
    if (!f || !f->blocks || f->blocks->len == 0) return false;

    int printable_blocks = 0;
    Block *only = NULL;
    int only_id = -1;

    for (int j = 0; j < f->blocks->len; j++) {
        Block *blk = list_get(f->blocks, j);
        if (!blk) continue;
        bool is_first = (j == 0);
        bool has_preds = blk->preds && blk->preds->len > 0;
        bool has_instrs = (blk->phis && blk->phis->len > 0) || (blk->instrs && blk->instrs->len > 0);
        if (!is_first && !has_preds && !has_instrs) continue;
        printable_blocks++;
        only = blk;
        only_id = blk->id;
    }

    if (printable_blocks != 1 || only == NULL || only_id == 0) return false;

    Block *blk0 = find_block_by_id(f, 0);
    if (!blk0 || blk0 == only) {
        replace_label_all(f, only_id, 0);
        only->id = 0;
        return true;
    }

    int temp_id = max_block_id(f) + 1;
    replace_label_all(f, only_id, temp_id);
    replace_label_all(f, 0, only_id);
    replace_label_all(f, temp_id, 0);

    blk0->id = only_id;
    only->id = 0;
    return true;
}

/*---------- 确保所有跳转目标块存在 ----------*/
static bool ensure_block_targets_exist(Func *f) {
    bool changed = false;
    if (!f || !f->blocks) return false;

    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b) continue;
        List *lists[2] = {b->phis, b->instrs};
        for (int li = 0; li < 2; li++) {
            if (!lists[li]) continue;
            for (Iter jt = list_iter(lists[li]); !iter_end(jt);) {
                Instr *inst = iter_next(&jt);
                if (!inst || !inst->labels) continue;
                for (int k = 0; k < inst->labels->len; ++k) {
                    char *lbl = (char *)list_get(inst->labels, k);
                    int id = -1;
                    if (lbl && sscanf(lbl, "block%d", &id) == 1 && id >= 0 && !find_block_by_id(f, id)) {
                        Block *nb = pass_alloc(sizeof(Block));
                        memset(nb, 0, sizeof(*nb));
                        nb->id = (uint32_t)id;
                        nb->preds = make_list();
                        nb->instrs = make_list();
                        nb->phis = make_list();
                        list_push(f->blocks, nb);
                        changed = true;
                    }
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
#define RUN_PASS(_p) do {  if (_p(f, &st)) { changed = true;  rebuild_preds(f); } } while (0)
        changed = false;
        RUN_PASS(pass_const_fold);
        RUN_PASS(pass_store_load_forwarding);
        RUN_PASS(pass_load_load_forwarding);
        RUN_PASS(pass_addr_deref_fold);
        RUN_PASS(pass_offset_imm_inline);
        RUN_PASS(pass_dead_local_store_elim);
        RUN_PASS(pass_global_load);
        RUN_PASS(pass_copy_prop);
        RUN_PASS(pass_inline_func_call);
        RUN_PASS(pass_addr_merge);
        RUN_PASS(pass_local_opts);
        RUN_PASS(pass_bool_return_simplify);
        RUN_PASS(pass_loop_invariant_accum);
        RUN_PASS(pass_const_branch);
        RUN_PASS(pass_br_same_target);
        RUN_PASS(pass_jump_threading);
        RUN_PASS(pass_jmp_only_elim);
        RUN_PASS(pass_entry_jmp_inline);
        RUN_PASS(pass_entry_jmp_ret_fold);
        RUN_PASS(pass_entry_jmp_elim);
        RUN_PASS(pass_unreachable_block_elim);
        RUN_PASS(pass_const_merge);
        RUN_PASS(pass_phi);
        RUN_PASS(pass_phi_cleanup);
        RUN_PASS(pass_store_cleanup);
        RUN_PASS(pass_binop_const_inline);
        RUN_PASS(pass_ret_const_inline);
        RUN_PASS(pass_const_store_prune);
        RUN_PASS(pass_block_merge);
        RUN_PASS(pass_dce);
#undef RUN_PASS
    } while (changed && ++it < 20);

    ensure_block_targets_exist(f);
    rebuild_preds(f);
    pass_single_block_normalize(f);
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
    // printf("\n=== SSA Before Optimization ===\n");
    // ssa_print(stdout, b->unit);
    ssa_optimize(b->unit, OPT_O1);
    printf("\n=== Optimized SSA Output ===\n");
    ssa_print(stdout, b->unit);
    ssa_build_destroy(b);
    list_free(strings);
    list_free(ctypes);
}
#endif
