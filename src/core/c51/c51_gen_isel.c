#include "c51_gen.h"
#include <ctype.h>

/* ========== 基础工具函数 ========== */
static void trim_ws_inplace(char *s)
{
    if (!s) return;
    char *p = s;
    while (*p && isspace((unsigned char)*p)) p++;
    if (p != s) memmove(s, p, strlen(p) + 1);

    size_t n = strlen(s);
    while (n > 0 && isspace((unsigned char)s[n - 1])) s[--n] = '\0';
}

static void strip_comment_inplace(char *s)
{
    if (!s) return;
    char *sc = strchr(s, ';');
    if (sc) *sc = '\0';

    for (char *p = s; *p; p++) {
        if (p[0] == '/' && p[1] == '/') {
            *p = '\0';
            break;
        }
    }
}

static const char *addrspace_str(Ctype *type)
{
    if (!type) return NULL;
    static const char *spaces[] = {NULL, "data", "idata", "pdata", "xdata", "edata", "code"};
    int data = get_attr(type->attr).ctype_data;
    return (data >= 1 && data <= 6) ? spaces[data] : NULL;
}

static void fmt_block_label(const char *lbl, char *out, size_t n)
{
    if (!out || n == 0) return;
    if (lbl && strncmp(lbl, "block", 5) == 0) {
        snprintf(out, n, "b%d", atoi(lbl + 5));
    } else {
        snprintf(out, n, "%s", lbl ? lbl : "<null>");
    }
}

static bool get_arg_val(const Instr *ins, int idx, ValueName *out)
{
    if (!ins || !ins->args || idx < 0 || idx >= ins->args->len) return false;
    ValueName *p = list_get(ins->args, idx);
    if (p && out) *out = *p;
    return p != NULL;
}

static const char *get_label_at(const Instr *ins, int idx)
{
    if (!ins || !ins->labels || idx < 0 || idx >= ins->labels->len) return NULL;
    return (const char *)list_get(ins->labels, idx);
}

static bool has_imm_tag(const Instr *ins)
{
    const char *tag = get_label_at(ins, 0);
    return tag && strcmp(tag, "imm") == 0;
}

static Instr *find_def_instr(Func *f, ValueName v)
{
    if (!f || v == 0) return NULL;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b) continue;
        for (Iter jt = list_iter(b->instrs); !iter_end(jt);) {
            Instr *i = iter_next(&jt);
            if (i && i->dest == v) return i;
        }
        for (Iter jt = list_iter(b->phis); !iter_end(jt);) {
            Instr *p = iter_next(&jt);
            if (p && p->dest == v) return p;
        }
    }
    return NULL;
}

typedef struct {
    bool valid;
    ValueName dest;
    IrOp op;
    ValueName a;
    ValueName b;
    bool is_signed;
    bool is_16;
} PendingCmp;

static PendingCmp g_pending_cmp;

static int count_value_uses(Func *f, ValueName v)
{
    int cnt = 0;
    if (!f || v == 0) return 0;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (!b) continue;
        if (b->instrs) {
            for (Iter jt = list_iter(b->instrs); !iter_end(jt);) {
                Instr *i = iter_next(&jt);
                if (!i || !i->args) continue;
                for (int k = 0; k < i->args->len; ++k) {
                    ValueName *arg = list_get(i->args, k);
                    if (arg && *arg == v) cnt++;
                }
            }
        }
        if (b->phis) {
            for (Iter jt = list_iter(b->phis); !iter_end(jt);) {
                Instr *p = iter_next(&jt);
                if (!p || !p->args) continue;
                for (int k = 0; k < p->args->len; ++k) {
                    ValueName *arg = list_get(p->args, k);
                    if (arg && *arg == v) cnt++;
                }
            }
        }
    }
    return cnt;
}

static bool cmp_used_by_next_br(Func *f, Block *blk, Instr *cmp, Instr **out_br)
{
    if (!f || !blk || !cmp || !blk->instrs) return false;
    if (cmp->dest <= 0 || count_value_uses(f, cmp->dest) != 1) return false;
    for (int i = 0; i < blk->instrs->len; ++i) {
        Instr *cur = list_get(blk->instrs, i);
        if (cur != cmp) continue;
        if (i + 1 >= blk->instrs->len) return false;
        Instr *nxt = list_get(blk->instrs, i + 1);
        if (!nxt || nxt->op != IROP_BR || !nxt->args || nxt->args->len < 1) return false;
        ValueName *c = list_get(nxt->args, 0);
        if (!c || *c != cmp->dest) return false;
        if (out_br) *out_br = nxt;
        return true;
    }
    return false;
}

static ValueName find_phi_dest_for_edge(Func *func, Block *from, ValueName src)
{
    if (!func || !from || src <= 0 || !from->instrs || from->instrs->len == 0) return 0;
    Instr *term = (Instr *)list_get(from->instrs, from->instrs->len - 1);
    if (!term || !term->labels) return 0;

    char from_label[32];
    snprintf(from_label, sizeof(from_label), "block%d", from->id);

    int label_count = (term->op == IROP_BR) ? 2 : (term->op == IROP_JMP ? 1 : 0);
    for (int l = 0; l < label_count; ++l) {
        char *lbl = list_get(term->labels, l);
        Block *to = find_block_by_label(func, lbl);
        if (!to || !to->phis) continue;
        for (Iter pit = list_iter(to->phis); !iter_end(pit);) {
            Instr *phi = iter_next(&pit);
            if (!phi || phi->op != IROP_PHI || !phi->labels || !phi->args) continue;
            for (int i = 0; i < phi->labels->len && i < phi->args->len; ++i) {
                char *plbl = list_get(phi->labels, i);
                if (!plbl || strcmp(plbl, from_label) != 0) continue;
                ValueName *srcp = list_get(phi->args, i);
                if (srcp && *srcp == src) return phi->dest;
            }
        }
    }
    return 0;
}

/* ========== 16位操作辅助 ========== */

typedef struct { char lo[64], hi[64]; } AddrPair;

static void fmt_addr_pair(AddrPair *p, int addr);

static bool v16_reg_pair(ValueName v, int *lo, int *hi)
{
    if (!g_v16_reg_map || v <= 0) return false;
    ValueName cur = v;
    for (int i = 0; i < 8; ++i) {
        V16RegPair *p = (V16RegPair *)dict_get(g_v16_reg_map, vreg_key(cur));
        if (p) {
            if (lo) *lo = p->lo;
            if (hi) *hi = p->hi;
            return true;
        }
        if (!g_v16_alias) break;
        int *alias = (int *)dict_get(g_v16_alias, vreg_key(cur));
        if (!alias || *alias == cur) break;
        cur = *alias;
    }
    return false;
}

static void fmt_v16_pair(ValueName v, AddrPair *out)
{
    int rlo = -1, rhi = -1;
    if (v16_reg_pair(v, &rlo, &rhi)) {
        snprintf(out->lo, sizeof(out->lo), "r%d", rlo);
        snprintf(out->hi, sizeof(out->hi), "r%d", rhi);
    } else {
        fmt_addr_pair(out, v16_addr(v));
    }
}

static void fmt_addr_pair(AddrPair *p, int addr)
{
    fmt_v16_direct(p->lo, sizeof(p->lo), addr);
    fmt_v16_direct(p->hi, sizeof(p->hi), addr + 1);
}

static void emit_mov16(Section *sec, int dst_addr, int src_addr)
{
    AddrPair d, s;
    fmt_addr_pair(&d, dst_addr);
    fmt_addr_pair(&s, src_addr);
    emit_ins2(sec, "mov", "A", s.lo);
    emit_ins2(sec, "mov", d.lo, "A");
    emit_ins2(sec, "mov", "A", s.hi);
    emit_ins2(sec, "mov", d.hi, "A");
}

static void emit_mov16_val(Section *sec, ValueName dstv, ValueName srcv)
{
    AddrPair d, s;
    fmt_v16_pair(dstv, &d);
    fmt_v16_pair(srcv, &s);
    emit_ins2(sec, "mov", "A", s.lo);
    emit_ins2(sec, "mov", d.lo, "A");
    emit_ins2(sec, "mov", "A", s.hi);
    emit_ins2(sec, "mov", d.hi, "A");
}

static void emit_load_imm16(Section *sec, int dst_addr, int val)
{
    AddrPair d;
    fmt_addr_pair(&d, dst_addr);
    char buf[16];
    snprintf(buf, sizeof(buf), "#%d", val & 0xFF);
    emit_ins2(sec, "mov", d.lo, buf);
    snprintf(buf, sizeof(buf), "#%d", (val >> 8) & 0xFF);
    emit_ins2(sec, "mov", d.hi, buf);
}

static void emit_load_imm16_val(Section *sec, ValueName v, int val)
{
    AddrPair d;
    fmt_v16_pair(v, &d);
    char buf[16];
    snprintf(buf, sizeof(buf), "#%d", val & 0xFF);
    emit_ins2(sec, "mov", d.lo, buf);
    snprintf(buf, sizeof(buf), "#%d", (val >> 8) & 0xFF);
    emit_ins2(sec, "mov", d.hi, buf);
}

/* ========== 比较操作辅助 ========== */

typedef enum { CMP_LT, CMP_LE, CMP_GT, CMP_GE } CmpKind;

static const char *cmp_jmp_true(CmpKind k, bool sign)
{
    (void)sign; // signed handled separately
    switch (k) {
        case CMP_LT: return "jc";
        case CMP_LE: return "jc";  // 或 jz，需组合
        case CMP_GT: return "jnc"; // 且非零
        case CMP_GE: return "jnc";
    }
    return "";
}

static void emit_cmp_branch(Section *sec, CmpKind kind, 
                           const char *l_true, const char *l_false, 
                           bool is_signed, bool include_eq)
{
    if (is_signed) {
        char *l_same = new_label("cmp_same");
        emit_ins2(sec, "mov", "A", "r6");
        emit_ins2(sec, "xrl", "A", "r7");
        emit_ins2(sec, "anl", "A", "#0x80");
        emit_ins1(sec, "jz", l_same);
        // 符号不同：r6<0 则 LT，否则 GT
        emit_ins2(sec, "mov", "A", "r6");
        emit_ins2(sec, "anl", "A", "#0x80");
        bool jump_if_neg = (kind == CMP_LT || kind == CMP_LE);
        emit_ins1(sec, jump_if_neg ? "jnz" : "jz", 
                 jump_if_neg ? l_true : l_false);
        emit_ins1(sec, "sjmp", jump_if_neg ? l_false : l_true);
        emit_label(sec, l_same);
        free(l_same);
    }
    
    emit_ins2(sec, "mov", "A", "r6");
    emit_ins1(sec, "clr", "C");
    emit_ins2(sec, "subb", "A", "r7");
    
    if (kind == CMP_LT) {
        emit_ins1(sec, "jc", l_true);
    } else if (kind == CMP_LE) {
        emit_ins1(sec, "jc", l_true);
        if (include_eq) emit_ins1(sec, "jz", l_true);
    } else if (kind == CMP_GT) {
        emit_ins1(sec, "jc", l_false);
        if (!include_eq) emit_ins1(sec, "jz", l_false);
        else emit_ins1(sec, "sjmp", l_true);
    } else { // GE
        emit_ins1(sec, "jnc", l_true);
    }
}

/* ========== SSA格式化 ========== */

static const char *irop_str(IrOp op)
{
    switch (op) {
        case IROP_NOP: return "nop";
        case IROP_ADD: return "add";
        case IROP_SUB: return "sub";
        case IROP_MUL: return "mul";
        case IROP_DIV: return "div";
        case IROP_MOD: return "mod";
        case IROP_AND: return "and";
        case IROP_OR:  return "or";
        case IROP_XOR: return "xor";
        case IROP_SHL: return "shl";
        case IROP_SHR: return "shr";
        case IROP_NOT: return "not";
        case IROP_LNOT: return "lnot";
        case IROP_NEG: return "neg";
        case IROP_EQ: return "eq";
        case IROP_NE: return "ne";
        case IROP_LT: return "lt";
        case IROP_GT: return "gt";
        case IROP_LE: return "le";
        case IROP_GE: return "ge";
        case IROP_TRUNC: return "trunc";
        case IROP_ZEXT: return "zext";
        case IROP_SEXT: return "sext";
        case IROP_BITCAST: return "bitcast";
        case IROP_INTTOPTR: return "inttoptr";
        case IROP_PTRTOINT: return "ptrtoint";
        default: return NULL;
    }
}

static char *format_ssa_instr(const Instr *ins)
{
    if (!ins) return NULL;
    char buf[512];
    size_t off = 0;
    
    if (ins->dest > 0 && ins->op != IROP_PARAM)
        off += snprintf(buf + off, sizeof(buf) - off, "v%d = ", ins->dest);

    const char *op_str = irop_str(ins->op);
    
    // 处理带立即数的二元操作
    #define FMT_BINOP_IMM() do { \
        ValueName a; \
        if (get_arg_val(ins, 0, &a)) \
            off += snprintf(buf + off, sizeof(buf) - off, "%s v%d", op_str, a); \
        else \
            off += snprintf(buf + off, sizeof(buf) - off, "%s <null>", op_str); \
        if (has_imm_tag(ins)) { \
            snprintf(buf + off, sizeof(buf) - off, ", const %ld", (long)ins->imm.ival); \
            return gen_strdup(buf); \
        } \
        ValueName b; \
        if (get_arg_val(ins, 1, &b)) \
            snprintf(buf + off, sizeof(buf) - off, ", v%d", b); \
    } while(0)

    switch (ins->op) {
    case IROP_NOP:
        snprintf(buf, sizeof(buf), "nop");
        break;
    case IROP_PARAM: {
        const char *pname = get_label_at(ins, 0);
        if (ins->dest > 0)
            snprintf(buf + off, sizeof(buf) - off, "param %s -> v%d", pname ? pname : "<null>", ins->dest);
        else
            snprintf(buf + off, sizeof(buf) - off, "param %s", pname ? pname : "<null>");
        break;
    }
    case IROP_CONST:
        snprintf(buf + off, sizeof(buf) - off, "const %ld", (long)ins->imm.ival);
        break;
    case IROP_NEG: {
        ValueName a;
        if (get_arg_val(ins, 0, &a))
            snprintf(buf + off, sizeof(buf) - off, "neg v%d", a);
        else
            snprintf(buf + off, sizeof(buf) - off, "neg <null>");
        break;
    }
    case IROP_ADD: case IROP_SUB: case IROP_MUL: case IROP_DIV: case IROP_MOD:
    case IROP_AND: case IROP_OR: case IROP_XOR:
    case IROP_SHL: case IROP_SHR:
    case IROP_EQ: case IROP_LT: case IROP_GT: case IROP_LE: case IROP_GE: case IROP_NE:
        FMT_BINOP_IMM();
        break;
    case IROP_NOT: case IROP_LNOT: {
        ValueName a;
        if (get_arg_val(ins, 0, &a))
            snprintf(buf + off, sizeof(buf) - off, "%s v%d", op_str, a);
        else
            snprintf(buf + off, sizeof(buf) - off, "%s <null>", op_str);
        break;
    }
    case IROP_TRUNC: case IROP_ZEXT: case IROP_SEXT:
    case IROP_BITCAST: case IROP_INTTOPTR: case IROP_PTRTOINT: {
        ValueName a;
        if (get_arg_val(ins, 0, &a))
            snprintf(buf + off, sizeof(buf) - off, "%s v%d", op_str, a);
        else
            snprintf(buf + off, sizeof(buf) - off, "%s <null>", op_str);
        break;
    }
    case IROP_OFFSET: {
        ValueName a1, a2;
        if (get_arg_val(ins, 0, &a1) && get_arg_val(ins, 1, &a2))
            snprintf(buf + off, sizeof(buf) - off, "offset v%d, v%d, #%ld", 
                    a1, a2, (long)ins->imm.ival);
        else
            snprintf(buf + off, sizeof(buf) - off, "offset <null>");
        break;
    }
    case IROP_SELECT: {
        ValueName c, t, f;
        if (get_arg_val(ins, 0, &c) && get_arg_val(ins, 1, &t) && get_arg_val(ins, 2, &f))
            snprintf(buf + off, sizeof(buf) - off, "select v%d, v%d, v%d", c, t, f);
        else
            snprintf(buf + off, sizeof(buf) - off, "select <null>");
        break;
    }
    case IROP_ASM: {
        const char *t = get_label_at(ins, 0);
        snprintf(buf + off, sizeof(buf) - off, "asm \"%s\"", t ? t : "");
        break;
    }
    case IROP_LOAD: {
        ValueName p;
        if (get_arg_val(ins, 0, &p))
            off += snprintf(buf + off, sizeof(buf) - off, "load v%d", p);
        else
            off += snprintf(buf + off, sizeof(buf) - off, "load <null>");
        const char *s = addrspace_str(ins->mem_type);
        if (s) snprintf(buf + off, sizeof(buf) - off, " @%s", s);
        break;
    }
    case IROP_STORE: {
        const char *label = get_label_at(ins, 0);
        if (label && label[0] == '@') {
            snprintf(buf + off, sizeof(buf) - off, "store %s, const %ld", 
                    label, (long)ins->imm.ival);
        } else {
            ValueName p, v;
            if (get_arg_val(ins, 0, &p) && get_arg_val(ins, 1, &v))
                off += snprintf(buf + off, sizeof(buf) - off, "store v%d, v%d", p, v);
            else
                off += snprintf(buf + off, sizeof(buf) - off, "store <null>");
        }
        const char *s = addrspace_str(ins->mem_type);
        if (s) snprintf(buf + off, sizeof(buf) - off, " @%s", s);
        break;
    }
    case IROP_ADDR: {
        const char *label = get_label_at(ins, 0);
        off += snprintf(buf + off, sizeof(buf) - off, "addr @%s", label ? label : "<null>");
        const char *s = addrspace_str(ins->mem_type);
        if (s) snprintf(buf + off, sizeof(buf) - off, " @%s", s);
        break;
    }
    case IROP_PHI: {
        off += snprintf(buf + off, sizeof(buf) - off, "phi ");
        bool first = true;
        for (int k = 0; ins->args && k < ins->args->len; ++k) {
            ValueName v = 0;
            if (!get_arg_val(ins, k, &v) || v == ins->dest) continue;
            const char *lbl = get_label_at(ins, k);
            char bbuf[32];
            fmt_block_label(lbl, bbuf, sizeof(bbuf));
            off += snprintf(buf + off, sizeof(buf) - off, "%s[v%d, %s]", 
                           first ? "" : ", ", v, bbuf);
            first = false;
        }
        break;
    }
    case IROP_JMP: {
        char bbuf[32];
        fmt_block_label(get_label_at(ins, 0), bbuf, sizeof(bbuf));
        snprintf(buf + off, sizeof(buf) - off, "jmp %s", bbuf);
        break;
    }
    case IROP_BR: {
        ValueName c;
        char b1[32], b2[32];
        fmt_block_label(get_label_at(ins, 0), b1, sizeof(b1));
        fmt_block_label(get_label_at(ins, 1), b2, sizeof(b2));
        if (get_arg_val(ins, 0, &c))
            snprintf(buf + off, sizeof(buf) - off, "br v%d, %s, %s", c, b1, b2);
        else
            snprintf(buf + off, sizeof(buf) - off, "br <null>, %s, %s", b1, b2);
        break;
    }
    case IROP_CALL: {
        const char *fname = get_label_at(ins, 0);
        off += snprintf(buf + off, sizeof(buf) - off, "call @%s(", fname ? fname : "<null>");
        for (int k = 0; ins->args && k < ins->args->len; ++k) {
            ValueName v;
            if (get_arg_val(ins, k, &v))
                off += snprintf(buf + off, sizeof(buf) - off, "%s v%d", k ? "," : "", v);
        }
        snprintf(buf + off, sizeof(buf) - off, ")");
        break;
    }
    case IROP_RET: {
        if (ins->args && ins->args->len > 0) {
            ValueName v;
            if (get_arg_val(ins, 0, &v))
                snprintf(buf + off, sizeof(buf) - off, "ret v%d", v);
            else
                snprintf(buf + off, sizeof(buf) - off, "ret <null>");
        } else if (has_imm_tag(ins)) {
            snprintf(buf + off, sizeof(buf) - off, "ret const %ld", (long)ins->imm.ival);
        } else {
            snprintf(buf + off, sizeof(buf) - off, "ret");
        }
        break;
    }
    default:
        snprintf(buf + off, sizeof(buf) - off, "op%d", (int)ins->op);
        break;
    }
    #undef FMT_BINOP_IMM

    return gen_strdup(buf);
}

/* ========== 内联汇编 ========== */

static void emit_inline_asm_text(Section *sec, const char *text)
{
    if (!sec || !text) return;

    const char *p = text;
    char linebuf[1024];

    while (*p) {
        size_t n = 0;
        while (*p && *p != '\n' && n + 1 < sizeof(linebuf)) {
            if (*p != '\r') linebuf[n++] = *p;
            p++;
        }
        if (*p == '\n') p++;
        linebuf[n] = '\0';

        strip_comment_inplace(linebuf);
        trim_ws_inplace(linebuf);
        if (!linebuf[0]) continue;

        size_t l = strlen(linebuf);
        if (l > 1 && linebuf[l - 1] == ':') {
            linebuf[l - 1] = '\0';
            trim_ws_inplace(linebuf);
            if (linebuf[0]) emit_label(sec, linebuf);
            continue;
        }

        if (linebuf[0] == '.') {
            if (!strncmp(linebuf, ".label", 6) && isspace((unsigned char)linebuf[6])) {
                char *name = linebuf + 6;
                trim_ws_inplace(name);
                if (name[0]) emit_label(sec, name);
                continue;
            }
            fprintf(stderr, "inline asm: unsupported directive: %s\n", linebuf);
            exit(1);
        }

        char *sp = linebuf, *op = sp;
        while (*sp && !isspace((unsigned char)*sp)) sp++;
        if (*sp) *sp++ = '\0';
        trim_ws_inplace(sp);

        char *args[3] = {0};
        int argc = 0;
        while (*sp && argc < 3) {
            char *comma = strchr(sp, ',');
            if (comma) *comma = '\0';
            trim_ws_inplace(sp);
            if (*sp) args[argc++] = sp;
            if (!comma) break;
            sp = comma + 1;
        }

        switch (argc) {
            case 0: emit_ins0(sec, op); break;
            case 1: emit_ins1(sec, op, args[0]); break;
            case 2: emit_ins2(sec, op, args[0], args[1]); break;
            case 3: emit_ins3(sec, op, args[0], args[1], args[2]); break;
            default:
                fprintf(stderr, "inline asm: too many operands: %s\n", linebuf);
                exit(1);
        }
    }
}

/* ========== 指令选择辅助 ========== */

static bool instr_has_imm(const Instr *ins, int *out) {
    if (!ins || !ins->labels || ins->labels->len < 1) return false;
    char *tag = (char *)list_get(ins->labels, 0);
    if (tag && strcmp(tag, "imm") == 0) {
        if (out) *out = (int)ins->imm.ival;
        return true;
    }
    return false;
}

static void fmt_imm8(char *buf, size_t n, int v)
{
    snprintf(buf, n, "#%d", v & 0xFF);
}

static void emit_binop8(Section *sec, Instr *ins, const char *op, bool clr_carry)
{
    ValueName a = *(ValueName *)list_get(ins->args, 0);
    int imm = 0;
    emit_ins2(sec, "mov", "A", vreg(a));
    if (clr_carry) emit_ins1(sec, "clr", "C");
    if (instr_has_imm(ins, &imm)) {
        char ibuf[16];
        fmt_imm8(ibuf, sizeof(ibuf), imm);
        emit_ins2(sec, op, "A", ibuf);
    } else {
        ValueName b = *(ValueName *)list_get(ins->args, 1);
        emit_ins2(sec, op, "A", vreg(b));
    }
    emit_ins2(sec, "mov", vreg(ins->dest), "A");
}

static void emit_load_b_imm_or_reg(Section *sec, Instr *ins)
{
    int imm = 0;
    if (instr_has_imm(ins, &imm)) {
        char ibuf[16];
        fmt_imm8(ibuf, sizeof(ibuf), imm);
        emit_ins2(sec, "mov", "B", ibuf);
    } else {
        ValueName b = *(ValueName *)list_get(ins->args, 1);
        emit_ins2(sec, "mov", "B", vreg(b));
    }
}

static void emit_promote_to_v16(Section *sec, ValueName v, AddrPair *out)
{
    bool need_promote = !(is_v16_value(v) || val_size(v) >= 2);
    fmt_v16_pair(v, out);
    if (!need_promote) return;

    int cval = 0;
    Ctype *vt = val_type_get(v);
    bool signed_ext = is_signed_type(vt);
    if (const_map_get(v, &cval)) {
        int low = cval & 0xFF;
        char buf[16];
        snprintf(buf, sizeof(buf), "#%d", low);
        emit_ins2(sec, "mov", out->lo, buf);
        snprintf(buf, sizeof(buf), "#%d", signed_ext && (low & 0x80) ? 0xFF : 0x00);
        emit_ins2(sec, "mov", out->hi, buf);
        return;
    }

    emit_ins2(sec, "mov", "A", vreg(v));
    emit_ins2(sec, "mov", out->lo, "A");
    if (signed_ext) {
        char *l_pos = new_label("v16_pos");
        char *l_end = new_label("v16_end");
        emit_ins2(sec, "anl", "A", "#0x80");
        emit_ins1(sec, "jz", l_pos);
        emit_ins2(sec, "mov", out->hi, "#255");
        emit_ins1(sec, "sjmp", l_end);
        emit_label(sec, l_pos);
        emit_ins2(sec, "mov", out->hi, "#0");
        emit_label(sec, l_end);
        free(l_pos); free(l_end);
    } else {
        emit_ins2(sec, "mov", out->hi, "#0");
    }
}

/* 通用16位加减法 */
static void emit_addsub16(Section *sec, Instr *ins, bool is_sub, Func *func, Block *cur_block)
{
    ValueName a = *(ValueName *)list_get(ins->args, 0);
    ValueName b = *(ValueName *)list_get(ins->args, 1);
    AddrPair pa, pb, pd;
    int imm_a = 0, imm_b = 0;
    bool a_const = const_map_get(a, &imm_a);
    bool b_const = const_map_get(b, &imm_b);
    if (a_const && b_const) {
        int res = is_sub ? (imm_a - imm_b) : (imm_a + imm_b);
        emit_load_imm16_val(sec, ins->dest, res);
        if (g_const_map) const_map_put(ins->dest, res);
        return;
    }
    if (!is_sub && a_const && !b_const) {
        ValueName tmpv = a; a = b; b = tmpv;
        int tmpi = imm_a; imm_a = imm_b; imm_b = tmpi;
        bool tmpc = a_const; a_const = b_const; b_const = tmpc;
    }
    if (a_const && is_sub) {
        emit_promote_to_v16(sec, b, &pb);
        fmt_addr_pair(&pd, v16_addr(ins->dest));
        emit_ins1(sec, "clr", "C");
        {
            char ibuf[16];
            fmt_imm8(ibuf, sizeof(ibuf), imm_a);
            emit_ins2(sec, "mov", "A", ibuf);
            emit_ins2(sec, "subb", "A", pb.lo);
        }
        emit_ins2(sec, "mov", pd.lo, "A");
        {
            char ibuf[16];
            fmt_imm8(ibuf, sizeof(ibuf), imm_a >> 8);
            emit_ins2(sec, "mov", "A", ibuf);
            emit_ins2(sec, "subb", "A", pb.hi);
        }
        emit_ins2(sec, "mov", pd.hi, "A");
        return;
    }

    if (func && cur_block && (is_v16_value(ins->dest) || val_size(ins->dest) >= 2)) {
        if (cur_block->instrs && cur_block->instrs->len >= 2) {
            Instr *term = list_get(cur_block->instrs, cur_block->instrs->len - 1);
            Instr *prev = list_get(cur_block->instrs, cur_block->instrs->len - 2);
            if (prev == ins && term && (term->op == IROP_JMP || term->op == IROP_BR)) {
                ValueName phi_dest = find_phi_dest_for_edge(func, cur_block, ins->dest);
                if (phi_dest > 0 && (is_v16_value(phi_dest) || val_size(phi_dest) >= 2)) {
                    v16_alias_put(ins->dest, phi_dest);
                }
            }
        }
    }

    if (b_const && imm_b == 1) {
        int d_lo = -1, d_hi = -1, a_lo = -1, a_hi = -1;
        bool d_reg = v16_reg_pair(ins->dest, &d_lo, &d_hi);
        bool a_reg = v16_reg_pair(a, &a_lo, &a_hi);
        bool same_pair = d_reg && a_reg && d_lo == a_lo && d_hi == a_hi;
        int dst = v16_addr(ins->dest);
        int src = v16_addr(a);
        if (same_pair || (!d_reg && !a_reg && dst == src)) {
            char d0[64], d1[64];
            if (d_reg) {
                snprintf(d0, sizeof(d0), "r%d", d_lo);
                snprintf(d1, sizeof(d1), "r%d", d_hi);
            } else {
                fmt_v16_direct(d0, sizeof(d0), dst);
                fmt_v16_direct(d1, sizeof(d1), dst + 1);
            }
            char *l_skip = new_label(is_sub ? "dec_skip" : "inc_skip");
            emit_ins1(sec, is_sub ? "dec" : "inc", d0);
            emit_ins1(sec, "jnz", l_skip);
            emit_ins1(sec, is_sub ? "dec" : "inc", d1);
            emit_label(sec, l_skip);
            free(l_skip);
            return;
        }
    }

    emit_promote_to_v16(sec, a, &pa);
    if (!b_const) emit_promote_to_v16(sec, b, &pb);
    fmt_v16_pair(ins->dest, &pd);
    
    if (is_sub) emit_ins1(sec, "clr", "C");
    emit_ins2(sec, "mov", "A", pa.lo);
    if (b_const) {
        char ibuf[16];
        fmt_imm8(ibuf, sizeof(ibuf), imm_b);
        emit_ins2(sec, is_sub ? "subb" : "add", "A", ibuf);
    } else {
        emit_ins2(sec, is_sub ? "subb" : "add", "A", pb.lo);
    }
    emit_ins2(sec, "mov", pd.lo, "A");
    emit_ins2(sec, "mov", "A", pa.hi);
    if (b_const) {
        char ibuf[16];
        fmt_imm8(ibuf, sizeof(ibuf), imm_b >> 8);
        emit_ins2(sec, is_sub ? "subb" : "addc", "A", ibuf);
    } else {
        emit_ins2(sec, is_sub ? "subb" : "addc", "A", pb.hi);
    }
    emit_ins2(sec, "mov", pd.hi, "A");
}

/* 通用比较操作（8位） */
static void emit_cmp8(Section *sec, CmpKind kind, bool is_signed, 
                     ValueName a, ValueName b, ValueName dest)
{
    char *l_true = new_label("cmp_true");
    char *l_false = new_label("cmp_false");
    char *l_end = new_label("cmp_end");
    
    emit_ins2(sec, "mov", "r6", vreg(a));
    emit_ins2(sec, "mov", "r7", vreg(b));
    
    emit_cmp_branch(sec, kind, l_true, l_false, is_signed, kind == CMP_LE);
    
    emit_label(sec, l_false);
    emit_ins2(sec, "mov", vreg(dest), "#0");
    emit_ins1(sec, "sjmp", l_end);
    emit_label(sec, l_true);
    emit_ins2(sec, "mov", vreg(dest), "#1");
    emit_label(sec, l_end);
    
    free(l_true); free(l_false); free(l_end);
}

static CmpKind swap_cmp_kind(CmpKind k)
{
    switch (k) {
        case CMP_LT: return CMP_GT;
        case CMP_LE: return CMP_GE;
        case CMP_GT: return CMP_LT;
        case CMP_GE: return CMP_LE;
    }
    return k;
}

static void emit_cmp8_branch(Section *sec, CmpKind kind, bool is_signed,
                             ValueName a, ValueName b,
                             const char *l_true, const char *l_false)
{
    emit_ins2(sec, "mov", "r6", vreg(a));
    emit_ins2(sec, "mov", "r7", vreg(b));
    emit_cmp_branch(sec, kind, l_true, l_false, is_signed, kind == CMP_LE);
}

static void fmt_v16_operand_byte(ValueName v, int byte, char *out, size_t n);

/* 通用比较操作（16位） */
static void emit_cmp16(Section *sec, CmpKind kind, bool is_signed,
                       ValueName a, ValueName b, ValueName dest)
{
    char *l_true = new_label("cmp_true");
    char *l_false = new_label("cmp_false");
    char *l_end = new_label("cmp_end");
    char *l_hi_diff = NULL;
    char *l_lo_diff = NULL;
    char *l_sign_diff = NULL;
    char a_hi[32], a_lo[32], b_hi[32], b_lo[32];

    /* 尝试常量优化 */
    int cval = 0;
    bool a_const = const_map_get(a, &cval);
    if (a_const && !const_map_get(b, &cval)) {
        ValueName tmp = a; a = b; b = tmp;
        kind = swap_cmp_kind(kind);
    }
    if (const_map_get(b, &cval)) {
        /* b 是常量，检查是否可以用 CJNE 优化 */
        /* 对于 16 位，使用 CJNE 比较 */
        fmt_v16_operand_byte(a, 1, a_hi, sizeof(a_hi));
        fmt_v16_operand_byte(a, 0, a_lo, sizeof(a_lo));
        
        int c_hi = (cval >> 8) & 0xFF;
        int c_lo = cval & 0xFF;
        
        /* 高字节比较 */
        char *l_check_lo = new_label("cmp_lo");
        char *l_cmp_done = new_label("cmp_done");
        
        emit_ins2(sec, "mov", "A", a_hi);
        char hi_buf[16];
        snprintf(hi_buf, sizeof(hi_buf), "#%d", c_hi);
        emit_ins3(sec, "cjne", "A", hi_buf, l_check_lo);
        /* 高字节相等，比较低字节 */
        emit_ins2(sec, "mov", "A", a_lo);
        char lo_buf[16];
        snprintf(lo_buf, sizeof(lo_buf), "#%d", c_lo);
        emit_ins3(sec, "cjne", "A", lo_buf, l_check_lo);
        /* 完全相等 */
        if (kind == CMP_LT || kind == CMP_GT) {
            emit_ins2(sec, "mov", vreg(dest), "#0");  /* LT/GT 不相等为假 */
        } else {
            emit_ins2(sec, "mov", vreg(dest), "#1");  /* LE/GE 相等为真 */
        }
        emit_ins1(sec, "sjmp", l_end);
        
        /* 高字节或低字节不等 */
        emit_label(sec, l_check_lo);
        /* CJNE 后 C=1 表示 A < operand */
        if (kind == CMP_LT || kind == CMP_LE) {
            emit_ins1(sec, "jc", l_true);
        } else {
            emit_ins1(sec, "jc", l_false);
        }
        emit_ins1(sec, "sjmp", kind == CMP_LT || kind == CMP_LE ? l_false : l_true);
        
        emit_label(sec, l_true);
        emit_ins2(sec, "mov", vreg(dest), "#1");
        emit_ins1(sec, "sjmp", l_end);
        emit_label(sec, l_false);
        emit_ins2(sec, "mov", vreg(dest), "#0");
        emit_label(sec, l_end);
        
        free(l_check_lo);
        free(l_cmp_done);
        free(l_true);
        free(l_false);
        free(l_end);
        return;
    }

    fmt_v16_operand_byte(a, 1, a_hi, sizeof(a_hi));
    fmt_v16_operand_byte(a, 0, a_lo, sizeof(a_lo));
    fmt_v16_operand_byte(b, 1, b_hi, sizeof(b_hi));
    fmt_v16_operand_byte(b, 0, b_lo, sizeof(b_lo));

    if (!is_signed) {
        char *l_check_lo = new_label("cmp_lo");
        emit_ins2(sec, "mov", "A", a_hi);
        emit_ins3(sec, "cjne", "A", b_hi, l_check_lo);
        emit_ins2(sec, "mov", "A", a_lo);
        emit_ins3(sec, "cjne", "A", b_lo, l_check_lo);

        if (kind == CMP_LT || kind == CMP_GT) {
            emit_ins2(sec, "mov", vreg(dest), "#0");
        } else {
            emit_ins2(sec, "mov", vreg(dest), "#1");
        }
        emit_ins1(sec, "sjmp", l_end);

        emit_label(sec, l_check_lo);
        if (kind == CMP_LT || kind == CMP_LE) {
            emit_ins1(sec, "jc", l_true);
            emit_ins1(sec, "sjmp", l_false);
        } else {
            emit_ins1(sec, "jc", l_false);
            emit_ins1(sec, "sjmp", l_true);
        }

        emit_label(sec, l_true);
        emit_ins2(sec, "mov", vreg(dest), "#1");
        emit_ins1(sec, "sjmp", l_end);
        emit_label(sec, l_false);
        emit_ins2(sec, "mov", vreg(dest), "#0");
        emit_label(sec, l_end);

        free(l_check_lo);
        free(l_true);
        free(l_false);
        free(l_end);
        return;
    }

    l_hi_diff = new_label("cmp_hi_diff");
    l_lo_diff = new_label("cmp_lo_diff");
    l_sign_diff = new_label("cmp_sign_diff");

    emit_ins2(sec, "mov", "A", a_hi);
    emit_ins3(sec, "cjne", "A", b_hi, l_hi_diff);
    emit_ins2(sec, "mov", "A", a_lo);
    emit_ins3(sec, "cjne", "A", b_lo, l_lo_diff);

    if (kind == CMP_LT || kind == CMP_GT) {
        emit_ins2(sec, "mov", vreg(dest), "#0");
    } else {
        emit_ins2(sec, "mov", vreg(dest), "#1");
    }
    emit_ins1(sec, "sjmp", l_end);

    emit_label(sec, l_lo_diff);
    if (kind == CMP_LT || kind == CMP_LE) {
        emit_ins1(sec, "jc", l_true);
        emit_ins1(sec, "sjmp", l_false);
    } else {
        emit_ins1(sec, "jc", l_false);
        emit_ins1(sec, "sjmp", l_true);
    }

    emit_label(sec, l_hi_diff);
    emit_ins2(sec, "mov", "A", a_hi);
    emit_ins2(sec, "xrl", "A", b_hi);
    emit_ins2(sec, "anl", "A", "#0x80");
    emit_ins1(sec, "jnz", l_sign_diff);

    if (kind == CMP_LT || kind == CMP_LE) {
        emit_ins1(sec, "jc", l_true);
        emit_ins1(sec, "sjmp", l_false);
    } else {
        emit_ins1(sec, "jc", l_false);
        emit_ins1(sec, "sjmp", l_true);
    }

    emit_label(sec, l_sign_diff);
    emit_ins2(sec, "mov", "A", a_hi);
    emit_ins2(sec, "anl", "A", "#0x80");
    if (kind == CMP_LT || kind == CMP_LE) {
        emit_ins1(sec, "jnz", l_true);
        emit_ins1(sec, "sjmp", l_false);
    } else {
        emit_ins1(sec, "jnz", l_false);
        emit_ins1(sec, "sjmp", l_true);
    }

    emit_label(sec, l_false);
    emit_ins2(sec, "mov", vreg(dest), "#0");
    emit_ins1(sec, "sjmp", l_end);
    emit_label(sec, l_true);
    emit_ins2(sec, "mov", vreg(dest), "#1");
    emit_label(sec, l_end);

    free(l_hi_diff);
    free(l_lo_diff);
    free(l_sign_diff);
    free(l_true); free(l_false); free(l_end);
}

static void emit_cmp16_branch(Section *sec, CmpKind kind, bool is_signed,
                              ValueName a, ValueName b,
                              const char *l_true, const char *l_false)
{
    char *l_hi_diff = NULL;
    char *l_lo_diff = NULL;
    char *l_sign_diff = NULL;
    char a_hi[32], a_lo[32], b_hi[32], b_lo[32];

    int cval = 0;
    bool a_const = const_map_get(a, &cval);
    if (a_const && !const_map_get(b, &cval)) {
        ValueName tmp = a; a = b; b = tmp;
        kind = swap_cmp_kind(kind);
    }
    if (const_map_get(b, &cval)) {
        fmt_v16_operand_byte(a, 1, a_hi, sizeof(a_hi));
        fmt_v16_operand_byte(a, 0, a_lo, sizeof(a_lo));

        int c_hi = (cval >> 8) & 0xFF;
        int c_lo = cval & 0xFF;

        char *l_check_lo = new_label("cmp_lo");

        emit_ins2(sec, "mov", "A", a_hi);
        char hi_buf[16];
        snprintf(hi_buf, sizeof(hi_buf), "#%d", c_hi);
        emit_ins3(sec, "cjne", "A", hi_buf, l_check_lo);
        emit_ins2(sec, "mov", "A", a_lo);
        char lo_buf[16];
        snprintf(lo_buf, sizeof(lo_buf), "#%d", c_lo);
        emit_ins3(sec, "cjne", "A", lo_buf, l_check_lo);

        emit_ins1(sec, "sjmp", (kind == CMP_LT || kind == CMP_GT) ? l_false : l_true);

        emit_label(sec, l_check_lo);
        if (kind == CMP_LT || kind == CMP_LE) {
            emit_ins1(sec, "jc", l_true);
            emit_ins1(sec, "sjmp", l_false);
        } else {
            emit_ins1(sec, "jc", l_false);
            emit_ins1(sec, "sjmp", l_true);
        }

        free(l_check_lo);
        return;
    }

    fmt_v16_operand_byte(a, 1, a_hi, sizeof(a_hi));
    fmt_v16_operand_byte(a, 0, a_lo, sizeof(a_lo));
    fmt_v16_operand_byte(b, 1, b_hi, sizeof(b_hi));
    fmt_v16_operand_byte(b, 0, b_lo, sizeof(b_lo));

    if (!is_signed) {
        char *l_check_lo = new_label("cmp_lo");
        emit_ins2(sec, "mov", "A", a_hi);
        emit_ins3(sec, "cjne", "A", b_hi, l_check_lo);
        emit_ins2(sec, "mov", "A", a_lo);
        emit_ins3(sec, "cjne", "A", b_lo, l_check_lo);

        emit_ins1(sec, "sjmp", (kind == CMP_LT || kind == CMP_GT) ? l_false : l_true);

        emit_label(sec, l_check_lo);
        if (kind == CMP_LT || kind == CMP_LE) {
            emit_ins1(sec, "jc", l_true);
            emit_ins1(sec, "sjmp", l_false);
        } else {
            emit_ins1(sec, "jc", l_false);
            emit_ins1(sec, "sjmp", l_true);
        }

        free(l_check_lo);
        return;
    }

    l_hi_diff = new_label("cmp_hi_diff");
    l_lo_diff = new_label("cmp_lo_diff");
    l_sign_diff = new_label("cmp_sign_diff");

    emit_ins2(sec, "mov", "A", a_hi);
    emit_ins3(sec, "cjne", "A", b_hi, l_hi_diff);
    emit_ins2(sec, "mov", "A", a_lo);
    emit_ins3(sec, "cjne", "A", b_lo, l_lo_diff);

    emit_ins1(sec, "sjmp", (kind == CMP_LT || kind == CMP_GT) ? l_false : l_true);

    emit_label(sec, l_lo_diff);
    if (kind == CMP_LT || kind == CMP_LE) {
        emit_ins1(sec, "jc", l_true);
        emit_ins1(sec, "sjmp", l_false);
    } else {
        emit_ins1(sec, "jc", l_false);
        emit_ins1(sec, "sjmp", l_true);
    }

    emit_label(sec, l_hi_diff);
    emit_ins2(sec, "mov", "A", a_hi);
    emit_ins2(sec, "xrl", "A", b_hi);
    emit_ins2(sec, "anl", "A", "#0x80");
    emit_ins1(sec, "jnz", l_sign_diff);

    if (kind == CMP_LT || kind == CMP_LE) {
        emit_ins1(sec, "jc", l_true);
        emit_ins1(sec, "sjmp", l_false);
    } else {
        emit_ins1(sec, "jc", l_false);
        emit_ins1(sec, "sjmp", l_true);
    }

    emit_label(sec, l_sign_diff);
    emit_ins2(sec, "mov", "A", a_hi);
    emit_ins2(sec, "anl", "A", "#0x80");
    if (kind == CMP_LT || kind == CMP_LE) {
        emit_ins1(sec, "jnz", l_true);
        emit_ins1(sec, "sjmp", l_false);
    } else {
        emit_ins1(sec, "jnz", l_false);
        emit_ins1(sec, "sjmp", l_true);
    }

    free(l_hi_diff);
    free(l_lo_diff);
    free(l_sign_diff);
}

static void emit_eqne8_branch(Section *sec, bool is_ne, ValueName a, ValueName b,
                              const char *l_true, const char *l_false)
{
    int cval = 0;
    bool b_const = const_map_get(b, &cval);
    bool a_const = !b_const && const_map_get(a, &cval);
    ValueName other = a_const ? b : a;
    emit_ins2(sec, "mov", "A", vreg(other));
    if (a_const || b_const) {
        char ibuf[16];
        fmt_imm8(ibuf, sizeof(ibuf), cval);
        emit_ins3(sec, "cjne", "A", ibuf, is_ne ? l_true : l_false);
    } else {
        emit_ins3(sec, "cjne", "A", vreg(b), is_ne ? l_true : l_false);
    }
    emit_ins1(sec, "sjmp", is_ne ? l_false : l_true);
}

static void emit_eqne16_branch(Section *sec, bool is_ne, ValueName a, ValueName b,
                               const char *l_true, const char *l_false)
{
    char a_hi[32], a_lo[32], b_hi[32], b_lo[32];
    char *l_ne = new_label("cmp_ne");

    fmt_v16_operand_byte(a, 1, a_hi, sizeof(a_hi));
    fmt_v16_operand_byte(a, 0, a_lo, sizeof(a_lo));
    fmt_v16_operand_byte(b, 1, b_hi, sizeof(b_hi));
    fmt_v16_operand_byte(b, 0, b_lo, sizeof(b_lo));

    emit_ins2(sec, "mov", "A", a_hi);
    emit_ins3(sec, "cjne", "A", b_hi, l_ne);
    emit_ins2(sec, "mov", "A", a_lo);
    emit_ins3(sec, "cjne", "A", b_lo, l_ne);

    emit_ins1(sec, "sjmp", is_ne ? l_false : l_true);
    emit_label(sec, l_ne);
    emit_ins1(sec, "sjmp", is_ne ? l_true : l_false);

    free(l_ne);
}

static void fmt_v16_operand_byte(ValueName v, int byte, char *out, size_t n)
{
    int rlo = -1, rhi = -1;
    if (v16_reg_pair(v, &rlo, &rhi)) {
        snprintf(out, n, "r%d", byte == 0 ? rlo : rhi);
        return;
    }
    int cv = 0;
    if (const_map_get(v, &cv)) {
        fmt_imm8(out, n, (cv >> (byte * 8)) & 0xFF);
    } else {
        AddrPair p; fmt_addr_pair(&p, v16_addr(v));
        snprintf(out, n, "%s", byte == 0 ? p.lo : p.hi);
    }
}

/* 通用16位相等/不等比较 */
static void emit_eqne16_check_zero(Section *sec, ValueName v, bool is_a, 
                                    bool a_is_zero, bool b_is_zero,
                                    ValueName a, ValueName b,
                                    char *l_hit)
{
    char v_hi[32], v_lo[32], o_hi[32], o_lo[32];
    
    if ((is_a ? a_is_zero : b_is_zero) && val_size(v) < 2) {
        emit_ins2(sec, "mov", "A", vreg(v));
        emit_ins3(sec, "cjne", "A", "#0", l_hit);
    } else {
        if ((is_a ? b_is_zero : a_is_zero)) {
            fmt_v16_operand_byte(v, 1, v_hi, sizeof(v_hi));
            fmt_v16_operand_byte(v, 0, v_lo, sizeof(v_lo));
            emit_ins2(sec, "mov", "A", v_hi);
            emit_ins3(sec, "cjne", "A", "#0", l_hit);
            emit_ins2(sec, "mov", "A", v_lo);
            emit_ins3(sec, "cjne", "A", "#0", l_hit);
        } else {
            fmt_v16_operand_byte(v, 1, v_hi, sizeof(v_hi));
            fmt_v16_operand_byte(v, 0, v_lo, sizeof(v_lo));
            fmt_v16_operand_byte(is_a ? b : a, 1, o_hi, sizeof(o_hi));
            fmt_v16_operand_byte(is_a ? b : a, 0, o_lo, sizeof(o_lo));
            emit_ins2(sec, "mov", "A", v_hi);
            emit_ins3(sec, "cjne", "A", o_hi, l_hit);
            emit_ins2(sec, "mov", "A", v_lo);
            emit_ins3(sec, "cjne", "A", o_lo, l_hit);
        }
    }
}

static void emit_eqne16(Section *sec, Instr *ins, bool is_ne)
{
    ValueName a = *(ValueName *)list_get(ins->args, 0);
    ValueName b = *(ValueName *)list_get(ins->args, 1);
    char *l_hit = new_label(is_ne ? "ne_hit" : "eq_hit");
    char *l_end = new_label(is_ne ? "ne_end" : "eq_end");
    
    int imm = 0;
    bool b_is_zero = const_map_get(b, &imm) && imm == 0;
    bool a_is_zero = const_map_get(a, &imm) && imm == 0;
    
    emit_eqne16_check_zero(sec, a, true, a_is_zero, b_is_zero, a, b, l_hit);
    
    emit_ins2(sec, "mov", vreg(ins->dest), is_ne ? "#0" : "#1");
    emit_ins1(sec, "sjmp", l_end);
    emit_label(sec, l_hit);
    emit_ins2(sec, "mov", vreg(ins->dest), is_ne ? "#1" : "#0");
    emit_label(sec, l_end);
    
    free(l_hit); free(l_end);
}

/* ========== 主指令选择 ========== */

void emit_instr(Section *sec, Instr *ins, Func *func, Block *cur_block)
{
    if (!ins) return;
    if (ins->op != IROP_NOP) {
        gen_set_pending_ssa(format_ssa_instr(ins));
    }
    char buf[64];
    const char *func_name = func ? func->name : NULL;
    if (ins->dest > 0 && ins->type) {
        val_type_put(ins->dest, ins->type);
    }

    #define IS_16BIT() (ins->type && ins->type->size >= 2)
    #define GET_ARG(n) (*(ValueName *)list_get(ins->args, (n)))
    #define VREG(n) vreg(GET_ARG(n))

    switch (ins->op) {
    case IROP_NOP:
        gen_clear_pending_ssa();
        return;
        
    case IROP_ASM: {
        const char *t = get_label_at(ins, 0);
        emit_inline_asm_text(sec, t);
        gen_clear_pending_ssa();
        return;
    }
    
    case IROP_PARAM: {
        const char *pname = get_label_at(ins, 0);
        if (!pname) break;
        Ctype *pt = NULL;
        int byte_off = param_byte_offset(func, pname, &pt);
        int size = pt ? pt->size : (ins->type ? ins->type->size : 1);
        if (byte_off < 0) {
            int idx = param_index(func, pname);
            if (idx >= 0) byte_off = (size >= 2) ? idx * 2 : idx;
        }
        
        bool use_stack = (byte_off >= 3);
        int stack_off = 2 + (byte_off - 3);
        
        if (size >= 2) {
            int addr = v16_addr(ins->dest);
            for (int b = 0; b < 2; ++b) {
                int byte_idx = byte_off + b;
                if (byte_idx < 3) {
                    char regbuf[8], dst[64];
                    snprintf(regbuf, sizeof(regbuf), "r%d", 1 + byte_idx);
                    fmt_v16_direct(dst, sizeof(dst), addr + b);
                    emit_ins2(sec, "mov", dst, regbuf);
                } else if (use_stack) {
                    emit_load_stack_param_to_direct(sec, 2 + (byte_idx - 3), addr + b, func && func->stack_size > 0);
                }
            }
        } else {
            if (!use_stack && byte_off >= 0 && byte_off < 3) {
                char regbuf[8];
                snprintf(regbuf, sizeof(regbuf), "r%d", 1 + byte_off);
                emit_ins2(sec, "mov", vreg(ins->dest), regbuf);
            } else if (use_stack) {
                emit_load_stack_param(sec, stack_off, vreg(ins->dest), func && func->stack_size > 0);
            }
        }
        gen_clear_pending_ssa();
        return;
    }
    
    case IROP_CONST:
        if (IS_16BIT()) {
            if (g_const_map) const_map_put(ins->dest, (int)ins->imm.ival);
        } else {
            if (g_const_map) const_map_put(ins->dest, (int)ins->imm.ival);
        }
        break;
        
    case IROP_ADD:
        if (IS_16BIT()) emit_addsub16(sec, ins, false, func, cur_block);
        else emit_binop8(sec, ins, "add", false);
        break;
        
    case IROP_SUB:
        if (IS_16BIT()) emit_addsub16(sec, ins, true, func, cur_block);
        else emit_binop8(sec, ins, "subb", true);
        break;
        
    case IROP_MUL:
    case IROP_DIV:
    case IROP_MOD: {
        ValueName a = GET_ARG(0);
        emit_load_b_imm_or_reg(sec, ins);
        emit_ins2(sec, "mov", "A", vreg(a));
        emit_ins1(sec, ins->op == IROP_MUL ? "mul" : "div", "AB");
        emit_ins2(sec, "mov", vreg(ins->dest), 
                 ins->op == IROP_MOD ? "B" : "A");
        break;
    }
    
    case IROP_AND: emit_binop8(sec, ins, "anl", false); break;
    case IROP_OR:  emit_binop8(sec, ins, "orl", false); break;
    case IROP_XOR: emit_binop8(sec, ins, "xrl", false); break;
    
    case IROP_SHL: {
        ValueName a = GET_ARG(0);
        int cnt = 0;
        bool is_const = instr_has_imm(ins, &cnt) || 
                       (!instr_has_imm(ins, &cnt) && const_map_get(GET_ARG(1), &cnt));
        
        if (is_const && cnt >= 1 && cnt <= 4) {
            emit_ins2(sec, "mov", "A", vreg(a));
            for (int i = 0; i < cnt; i++) emit_ins2(sec, "add", "A", "ACC");
            emit_ins2(sec, "mov", vreg(ins->dest), "A");
        } else {
            char *l_loop = new_label("shl_loop");
            char *l_end = new_label("shl_end");
            emit_ins2(sec, "mov", "A", vreg(a));
            if (is_const) {
                char ibuf[16]; fmt_imm8(ibuf, sizeof(ibuf), cnt);
                emit_ins2(sec, "mov", "r7", ibuf);
            } else {
                emit_ins2(sec, "mov", "r7", VREG(1));
            }
            emit_ins3(sec, "cjne", "r7", "#0", l_loop);
            emit_ins1(sec, "sjmp", l_end);
            emit_label(sec, l_loop);
            emit_ins2(sec, "add", "A", "ACC");
            emit_ins2(sec, "djnz", "r7", l_loop);
            emit_label(sec, l_end);
            free(l_loop); free(l_end);
        }
        break;
    }
    
    case IROP_SHR: {
        ValueName a = GET_ARG(0);
        int cnt = 0;
        bool is_const = instr_has_imm(ins, &cnt) || 
                       (!instr_has_imm(ins, &cnt) && const_map_get(GET_ARG(1), &cnt));
        bool signed_shift = is_signed_type(ins->type);
        
        if (is_const && !signed_shift) {
            emit_ins2(sec, "mov", "A", vreg(a));
            if (cnt == 1) {
                emit_ins1(sec, "clr", "C");
                emit_ins1(sec, "rrc", "A");
            } else if (cnt == 4) {
                emit_ins1(sec, "swap", "A");
                emit_ins2(sec, "anl", "A", "#0x0F");
            } else if (cnt == 7) {
                emit_ins1(sec, "swap", "A");
                emit_ins1(sec, "rrc", "A");
                emit_ins1(sec, "rrc", "A");
                emit_ins1(sec, "rrc", "A");
                emit_ins2(sec, "anl", "A", "#0x01");
            } else {
                for (int i = 0; i < cnt; i++) {
                    emit_ins1(sec, "clr", "C");
                    emit_ins1(sec, "rrc", "A");
                }
            }
            emit_ins2(sec, "mov", vreg(ins->dest), "A");
        } else {
            // 循环移位实现（带符号或无符号）
            char *l_loop = new_label("shr_loop");
            char *l_end = new_label("shr_end");
            emit_ins2(sec, "mov", "A", vreg(a));
            emit_ins2(sec, "mov", "r7", is_const ? (snprintf(buf, sizeof(buf), "#%d", cnt), buf) : vreg(GET_ARG(1)));
            if (!is_const) {
                emit_ins3(sec, "cjne", "r7", "#0", l_loop);
                emit_ins1(sec, "sjmp", l_end);
            }
            emit_label(sec, l_loop);
            if (signed_shift) {
                char *l_pos = new_label("shr_pos");
                char *l_cont = new_label("shr_cont");
                emit_ins2(sec, "mov", "r6", "A");
                emit_ins2(sec, "anl", "A", "#0x80");
                emit_ins1(sec, "jz", l_pos);
                emit_ins2(sec, "mov", "A", "r6");
                emit_ins1(sec, "clr", "C");
                emit_ins1(sec, "rrc", "A");
                emit_ins2(sec, "orl", "A", "#0x80");
                emit_ins1(sec, "sjmp", l_cont);
                emit_label(sec, l_pos);
                emit_ins2(sec, "mov", "A", "r6");
                emit_ins1(sec, "clr", "C");
                emit_ins1(sec, "rrc", "A");
                emit_label(sec, l_cont);
                free(l_pos); free(l_cont);
            } else {
                emit_ins1(sec, "clr", "C");
                emit_ins1(sec, "rrc", "A");
            }
            emit_ins2(sec, "djnz", "r7", l_loop);
            emit_label(sec, l_end);
            emit_ins2(sec, "mov", vreg(ins->dest), "A");
            free(l_loop); free(l_end);
        }
        break;
    }
    
    case IROP_NEG:
        emit_ins1(sec, "clr", "C");
        emit_ins2(sec, "mov", "A", "#0");
        emit_ins2(sec, "subb", "A", VREG(0));
        emit_ins2(sec, "mov", vreg(ins->dest), "A");
        break;
        
    case IROP_NOT:
        emit_ins2(sec, "mov", "A", VREG(0));
        emit_ins1(sec, "cpl", "A");
        emit_ins2(sec, "mov", vreg(ins->dest), "A");
        break;
        
    case IROP_TRUNC: {
        ValueName src = GET_ARG(0);
        int val;
        if (const_map_get(src, &val)) {
            snprintf(buf, sizeof(buf), "#%d", val & 0xFF);
            emit_ins2(sec, "mov", vreg(ins->dest), buf);
            if (g_const_map) const_map_put(ins->dest, val & 0xFF);
        } else if (is_v16_value(src) || val_size(src) >= 2) {
            char src0[16];
            fmt_v16_operand_byte(src, 0, src0, sizeof(src0));
            emit_ins2(sec, "mov", "A", src0);
            emit_ins2(sec, "mov", vreg(ins->dest), "A");
        } else {
            emit_ins2(sec, "mov", vreg(ins->dest), vreg(src));
        }
        break;
    }
    
    case IROP_ZEXT: {
        ValueName src = GET_ARG(0);
        AddrPair d; fmt_v16_pair(ins->dest, &d);
        int val;
        
        if (const_map_get(src, &val)) {
            snprintf(buf, sizeof(buf), "#%d", val & 0xFF);
            emit_ins2(sec, "mov", d.lo, buf);
            emit_ins2(sec, "mov", d.hi, "#0");
            if (g_const_map) const_map_put(ins->dest, val & 0xFF);
        } else if (is_v16_value(src) || val_size(src) >= 2) {
            emit_mov16_val(sec, ins->dest, src);
        } else {
            emit_ins2(sec, "mov", "A", vreg(src));
            emit_ins2(sec, "mov", d.lo, "A");
            emit_ins2(sec, "mov", d.hi, "#0");
        }
        break;
    }
    
    case IROP_SEXT: {
        ValueName src = GET_ARG(0);
        AddrPair d; fmt_v16_pair(ins->dest, &d);
        int val;
        
        if (const_map_get(src, &val)) {
            int low = val & 0xFF;
            snprintf(buf, sizeof(buf), "#%d", low);
            emit_ins2(sec, "mov", d.lo, buf);
            snprintf(buf, sizeof(buf), "#%d", (low & 0x80) ? 0xFF : 0x00);
            emit_ins2(sec, "mov", d.hi, buf);
            if (g_const_map) const_map_put(ins->dest, ((low & 0x80) ? 0xFF00 : 0) | low);
        } else if (is_v16_value(src) || val_size(src) >= 2) {
            emit_mov16_val(sec, ins->dest, src);
        } else {
            char *l_pos = new_label("sext_pos");
            char *l_end = new_label("sext_end");
            emit_ins2(sec, "mov", "A", vreg(src));
            emit_ins2(sec, "mov", d.lo, "A");
            emit_ins2(sec, "anl", "A", "#0x80");
            emit_ins1(sec, "jz", l_pos);
            emit_ins2(sec, "mov", d.hi, "#255");
            emit_ins1(sec, "sjmp", l_end);
            emit_label(sec, l_pos);
            emit_ins2(sec, "mov", d.hi, "#0");
            emit_label(sec, l_end);
            free(l_pos); free(l_end);
        }
        break;
    }
    
    case IROP_EQ:
        if (cmp_used_by_next_br(func, cur_block, ins, NULL)) {
            g_pending_cmp.valid = true;
            g_pending_cmp.dest = ins->dest;
            g_pending_cmp.op = ins->op;
            g_pending_cmp.a = GET_ARG(0);
            g_pending_cmp.b = GET_ARG(1);
            g_pending_cmp.is_signed = is_signed_type(ins->type);
            g_pending_cmp.is_16 = IS_16BIT() || val_size(GET_ARG(0)) >= 2 || val_size(GET_ARG(1)) >= 2 ||
                                 is_v16_value(GET_ARG(0)) || is_v16_value(GET_ARG(1));
            break;
        }
        if (IS_16BIT() || val_size(GET_ARG(0)) >= 2 || val_size(GET_ARG(1)) >= 2)
            emit_eqne16(sec, ins, false);
        else {
            char *l_f = new_label("eq_f"), *l_e = new_label("eq_e");
            int cval = 0;
            bool b_const = const_map_get(GET_ARG(1), &cval);
            bool a_const = const_map_get(GET_ARG(0), &cval);
            if (a_const || b_const) {
                ValueName v = a_const ? GET_ARG(1) : GET_ARG(0);
                char ibuf[16];
                fmt_imm8(ibuf, sizeof(ibuf), cval);
                emit_ins2(sec, "mov", "A", vreg(v));
                emit_ins3(sec, "cjne", "A", ibuf, l_f);
            } else {
                emit_ins2(sec, "mov", "A", VREG(0));
                emit_ins3(sec, "cjne", "A", VREG(1), l_f);
            }
            emit_ins2(sec, "mov", vreg(ins->dest), "#1");
            emit_ins1(sec, "sjmp", l_e);
            emit_label(sec, l_f);
            emit_ins2(sec, "mov", vreg(ins->dest), "#0");
            emit_label(sec, l_e);
            free(l_f); free(l_e);
        }
        break;
        
    case IROP_NE:
        if (cmp_used_by_next_br(func, cur_block, ins, NULL)) {
            g_pending_cmp.valid = true;
            g_pending_cmp.dest = ins->dest;
            g_pending_cmp.op = ins->op;
            g_pending_cmp.a = GET_ARG(0);
            g_pending_cmp.b = GET_ARG(1);
            g_pending_cmp.is_signed = is_signed_type(ins->type);
            g_pending_cmp.is_16 = IS_16BIT() || val_size(GET_ARG(0)) >= 2 || val_size(GET_ARG(1)) >= 2 ||
                                 is_v16_value(GET_ARG(0)) || is_v16_value(GET_ARG(1));
            break;
        }
        if (IS_16BIT() || val_size(GET_ARG(0)) >= 2 || val_size(GET_ARG(1)) >= 2)
            emit_eqne16(sec, ins, true);
        else {
            char *l_t = new_label("ne_t"), *l_e = new_label("ne_e");
            int cval = 0;
            bool b_const = const_map_get(GET_ARG(1), &cval);
            bool a_const = const_map_get(GET_ARG(0), &cval);
            if (a_const || b_const) {
                ValueName v = a_const ? GET_ARG(1) : GET_ARG(0);
                char ibuf[16];
                fmt_imm8(ibuf, sizeof(ibuf), cval);
                emit_ins2(sec, "mov", "A", vreg(v));
                emit_ins3(sec, "cjne", "A", ibuf, l_t);
            } else {
                emit_ins2(sec, "mov", "A", VREG(0));
                emit_ins3(sec, "cjne", "A", VREG(1), l_t);
            }
            emit_ins2(sec, "mov", vreg(ins->dest), "#0");
            emit_ins1(sec, "sjmp", l_e);
            emit_label(sec, l_t);
            emit_ins2(sec, "mov", vreg(ins->dest), "#1");
            emit_label(sec, l_e);
            free(l_t); free(l_e);
        }
        break;
        
    case IROP_LT:
        if (cmp_used_by_next_br(func, cur_block, ins, NULL)) {
            g_pending_cmp.valid = true;
            g_pending_cmp.dest = ins->dest;
            g_pending_cmp.op = ins->op;
            g_pending_cmp.a = GET_ARG(0);
            g_pending_cmp.b = GET_ARG(1);
            g_pending_cmp.is_signed = is_signed_type(ins->type);
            g_pending_cmp.is_16 = IS_16BIT() || val_size(GET_ARG(0)) >= 2 || val_size(GET_ARG(1)) >= 2 ||
                                 is_v16_value(GET_ARG(0)) || is_v16_value(GET_ARG(1));
            break;
        }
        if (IS_16BIT() || val_size(GET_ARG(0)) >= 2 || val_size(GET_ARG(1)) >= 2 ||
            is_v16_value(GET_ARG(0)) || is_v16_value(GET_ARG(1)))
            emit_cmp16(sec, CMP_LT, is_signed_type(ins->type), GET_ARG(0), GET_ARG(1), ins->dest);
        else
            emit_cmp8(sec, CMP_LT, is_signed_type(ins->type), GET_ARG(0), GET_ARG(1), ins->dest);
        break;
    case IROP_LE:
        if (cmp_used_by_next_br(func, cur_block, ins, NULL)) {
            g_pending_cmp.valid = true;
            g_pending_cmp.dest = ins->dest;
            g_pending_cmp.op = ins->op;
            g_pending_cmp.a = GET_ARG(0);
            g_pending_cmp.b = GET_ARG(1);
            g_pending_cmp.is_signed = is_signed_type(ins->type);
            g_pending_cmp.is_16 = IS_16BIT() || val_size(GET_ARG(0)) >= 2 || val_size(GET_ARG(1)) >= 2 ||
                                 is_v16_value(GET_ARG(0)) || is_v16_value(GET_ARG(1));
            break;
        }
        if (IS_16BIT() || val_size(GET_ARG(0)) >= 2 || val_size(GET_ARG(1)) >= 2 ||
            is_v16_value(GET_ARG(0)) || is_v16_value(GET_ARG(1)))
            emit_cmp16(sec, CMP_LE, is_signed_type(ins->type), GET_ARG(0), GET_ARG(1), ins->dest);
        else
            emit_cmp8(sec, CMP_LE, is_signed_type(ins->type), GET_ARG(0), GET_ARG(1), ins->dest);
        break;
    case IROP_GT:
        if (cmp_used_by_next_br(func, cur_block, ins, NULL)) {
            g_pending_cmp.valid = true;
            g_pending_cmp.dest = ins->dest;
            g_pending_cmp.op = ins->op;
            g_pending_cmp.a = GET_ARG(0);
            g_pending_cmp.b = GET_ARG(1);
            g_pending_cmp.is_signed = is_signed_type(ins->type);
            g_pending_cmp.is_16 = IS_16BIT() || val_size(GET_ARG(0)) >= 2 || val_size(GET_ARG(1)) >= 2 ||
                                 is_v16_value(GET_ARG(0)) || is_v16_value(GET_ARG(1));
            break;
        }
        if (IS_16BIT() || val_size(GET_ARG(0)) >= 2 || val_size(GET_ARG(1)) >= 2 ||
            is_v16_value(GET_ARG(0)) || is_v16_value(GET_ARG(1)))
            emit_cmp16(sec, CMP_GT, is_signed_type(ins->type), GET_ARG(0), GET_ARG(1), ins->dest);
        else
            emit_cmp8(sec, CMP_GT, is_signed_type(ins->type), GET_ARG(0), GET_ARG(1), ins->dest);
        break;
    case IROP_GE:
        if (cmp_used_by_next_br(func, cur_block, ins, NULL)) {
            g_pending_cmp.valid = true;
            g_pending_cmp.dest = ins->dest;
            g_pending_cmp.op = ins->op;
            g_pending_cmp.a = GET_ARG(0);
            g_pending_cmp.b = GET_ARG(1);
            g_pending_cmp.is_signed = is_signed_type(ins->type);
            g_pending_cmp.is_16 = IS_16BIT() || val_size(GET_ARG(0)) >= 2 || val_size(GET_ARG(1)) >= 2 ||
                                 is_v16_value(GET_ARG(0)) || is_v16_value(GET_ARG(1));
            break;
        }
        if (IS_16BIT() || val_size(GET_ARG(0)) >= 2 || val_size(GET_ARG(1)) >= 2 ||
            is_v16_value(GET_ARG(0)) || is_v16_value(GET_ARG(1)))
            emit_cmp16(sec, CMP_GE, is_signed_type(ins->type), GET_ARG(0), GET_ARG(1), ins->dest);
        else
            emit_cmp8(sec, CMP_GE, is_signed_type(ins->type), GET_ARG(0), GET_ARG(1), ins->dest);
        break;
    
    case IROP_LNOT: {
        char *l_t = new_label("lnot_t"), *l_e = new_label("lnot_e");
        emit_ins2(sec, "mov", "A", VREG(0));
        emit_ins1(sec, "jz", l_t);
        emit_ins2(sec, "mov", vreg(ins->dest), "#0");
        emit_ins1(sec, "sjmp", l_e);
        emit_label(sec, l_t);
        emit_ins2(sec, "mov", vreg(ins->dest), "#1");
        emit_label(sec, l_e);
        free(l_t); free(l_e);
        break;
    }
    
    case IROP_ADDR: {
        const char *name = get_label_at(ins, 0);
        if (!name) break;
        int off;
        if (func_stack_offset(func, name, &off)) {
            char obuf[16];
            emit_ins2(sec, "mov", "A", "0x2E");
            snprintf(obuf, sizeof(obuf), "#%d", off + 1);
            emit_ins2(sec, "add", "A", obuf);
            emit_ins2(sec, "mov", vreg(ins->dest), "A");
            addr_map_put_stack(ins->dest, off, ins->mem_type);
        } else {
            MmioInfo *mmio = mmio_map_get(name);
            addr_map_put(ins->dest, mmio ? name : name, ins->mem_type);
        }
        gen_clear_pending_ssa();
        return;
    }
    
    case IROP_OFFSET: {
        ValueName base = GET_ARG(0), idx = GET_ARG(1);
        int elem = (int)ins->imm.ival, cidx;
        emit_ins2(sec, "mov", "A", vreg(base));
        if (const_map_get(idx, &cidx)) {
            snprintf(buf, sizeof(buf), "#%d", cidx * elem);
            emit_ins2(sec, "add", "A", buf);
        } else {
            emit_ins2(sec, "mov", "A", vreg(idx));
            if (elem != 1) {
                snprintf(buf, sizeof(buf), "#%d", elem);
                emit_ins2(sec, "mov", "B", buf);
                emit_ins1(sec, "mul", "AB");
            }
            emit_ins2(sec, "mov", "r6", "A");
            emit_ins2(sec, "mov", "A", vreg(base));
            emit_ins2(sec, "add", "A", "r6");
        }
        emit_ins2(sec, "mov", vreg(ins->dest), "A");
        gen_clear_pending_ssa();
        return;
    }
    
    case IROP_LOAD: {
        ValueName ptr = GET_ARG(0);
        struct AddrInfo *info = addr_map_get(ptr);
        Ctype *mtype = ins->mem_type ? ins->mem_type : (info ? info->mem_type : NULL);
        int space = data_space_kind(mtype);
        
        if (info && info->is_stack) {
            emit_stack_addr(sec, info->stack_off);
            emit_ins2(sec, "mov", "A", "@r0");
        } else if (info && info->label && is_register_bit(mtype)) {
            emit_ins2(sec, "mov", "C", info->label);
            emit_ins2(sec, "mov", "A", "#0");
            emit_ins1(sec, "rlc", "A");
        } else if (info && info->label) {
            if (space == 6) { // code
                snprintf(buf, sizeof(buf), "#%s", info->label);
                emit_ins2(sec, "mov", "DPTR", buf);
                emit_ins2(sec, "mov", "A", "#0");
                emit_ins2(sec, "movc", "A", "@A+DPTR");
            } else if (space == 4 || space == 5) { // xdata/edata
                snprintf(buf, sizeof(buf), "#%s", info->label);
                emit_ins2(sec, "mov", "DPTR", buf);
                emit_ins2(sec, "movx", "A", "@DPTR");
            } else if (space == 2) { // idata
                snprintf(buf, sizeof(buf), "#%s", info->label);
                emit_ins2(sec, "mov", "r0", buf);
                emit_ins2(sec, "mov", "A", "@r0");
            } else {
                emit_ins2(sec, "mov", "A", info->label);
            }
        } else if (space == 6) {
            if (is_v16_value(ptr) || val_size(ptr) >= 2) {
                AddrPair p; fmt_addr_pair(&p, v16_addr(ptr));
                emit_ins2(sec, "mov", "0x82", p.lo);
                emit_ins2(sec, "mov", "0x83", p.hi);
            } else {
                emit_ins2(sec, "mov", "0x82", vreg(ptr));
                emit_ins2(sec, "mov", "0x83", "#0");
            }
            emit_ins2(sec, "mov", "A", "#0");
            emit_ins2(sec, "movc", "A", "@A+DPTR");
        } else if (space == 4 || space == 5) {
            if (is_v16_value(ptr) || val_size(ptr) >= 2) {
                AddrPair p; fmt_addr_pair(&p, v16_addr(ptr));
                emit_ins2(sec, "mov", "0x82", p.lo);
                emit_ins2(sec, "mov", "0x83", p.hi);
            } else {
                emit_ins2(sec, "mov", "0x82", vreg(ptr));
                emit_ins2(sec, "mov", "0x83", "#0");
            }
            emit_ins2(sec, "movx", "A", "@DPTR");
        } else {
            snprintf(buf, sizeof(buf), "@%s", vreg(ptr));
            emit_ins2(sec, "mov", "A", buf);
        }
        emit_ins2(sec, "mov", vreg(ins->dest), "A");
        break;
    }
    
    case IROP_STORE: {
        if (!ins->args || ins->args->len == 0) {
            // 优化格式: store @g, const
            if (ins->labels && ins->labels->len > 0) {
                char *label = (char*)list_get(ins->labels, 0);
                const char *varname = (label[0] == '@') ? label + 1 : label;
                int val = ins->imm.ival & 0xFF;
                if (is_register_bit(ins->mem_type)) {
                    emit_ins1(sec, val ? "setb" : "clr", varname);
                } else {
                    snprintf(buf, sizeof(buf), "#%d", val);
                    emit_ins2(sec, "mov", varname, buf);
                }
            }
            break;
        }
        
        ValueName ptr = GET_ARG(0), val = GET_ARG(1);
        struct AddrInfo *info = addr_map_get(ptr);
        Ctype *mtype = ins->mem_type ? ins->mem_type : (info ? info->mem_type : NULL);
        int space = data_space_kind(mtype);
        int cval; 
        bool val_is_const = const_map_get(val, &cval);
        #define MOV_A_VAL() do { \
            if (val_is_const) { snprintf(buf, sizeof(buf), "#%d", cval & 0xFF); emit_ins2(sec, "mov", "A", buf); } \
            else if (val_size(val) >= 2 || is_v16_value(val)) { \
                char d0[64]; fmt_v16_direct(d0, sizeof(d0), v16_addr(val)); \
                emit_ins2(sec, "mov", "A", d0); \
            } else emit_ins2(sec, "mov", "A", vreg(val)); \
        } while(0)
        
        if (info && info->is_stack) {
            MOV_A_VAL();
            emit_stack_addr(sec, info->stack_off);
            emit_ins2(sec, "mov", "@r0", "A");
        } else if (info && info->label) {
            if (strncmp(info->label, "0x", 2) == 0) {
                if (val_is_const) {
                    snprintf(buf, sizeof(buf), "#%d", cval & 0xFF);
                    emit_ins2(sec, "mov", info->label, buf);
                } else {
                    MOV_A_VAL();
                    emit_ins2(sec, "mov", info->label, "A");
                }
            } else if (is_register_bit(mtype)) {
                if (val_is_const) emit_ins1(sec, cval ? "setb" : "clr", info->label);
                else {
                    MOV_A_VAL();
                    emit_ins1(sec, "rrc", "A");
                    emit_ins2(sec, "mov", info->label, "C");
                }
            } else if (space == 4 || space == 5) {
                snprintf(buf, sizeof(buf), "#%s", info->label);
                emit_ins2(sec, "mov", "DPTR", buf);
                MOV_A_VAL();
                emit_ins2(sec, "movx", "@DPTR", "A");
            } else if (space == 2) {
                snprintf(buf, sizeof(buf), "#%s", info->label);
                emit_ins2(sec, "mov", "r0", buf);
                MOV_A_VAL();
                emit_ins2(sec, "mov", "@r0", "A");
            } else {
                if (val_is_const) {
                    snprintf(buf, sizeof(buf), "#%d", cval & 0xFF);
                    emit_ins2(sec, "mov", info->label, buf);
                } else {
                    MOV_A_VAL();
                    emit_ins2(sec, "mov", info->label, "A");
                }
            }
        } else if (space == 4 || space == 5) {
            if (is_v16_value(ptr) || val_size(ptr) >= 2) {
                AddrPair p; fmt_addr_pair(&p, v16_addr(ptr));
                emit_ins2(sec, "mov", "0x82", p.lo);
                emit_ins2(sec, "mov", "0x83", p.hi);
            } else {
                emit_ins2(sec, "mov", "0x82", vreg(ptr));
                emit_ins2(sec, "mov", "0x83", "#0");
            }
            MOV_A_VAL();
            emit_ins2(sec, "movx", "@DPTR", "A");
        } else {
            MOV_A_VAL();
            snprintf(buf, sizeof(buf), "@%s", vreg(ptr));
            emit_ins2(sec, "mov", buf, "A");
        }
        #undef MOV_A_VAL
        break;
    }
    
    case IROP_JMP: {
        char *label = list_get(ins->labels, 0);
        emit_phi_moves_for_edge(sec, func, cur_block, label);
        emit_ins1(sec, "sjmp", map_block_label(func_name, label));
        break;
    }
    
    case IROP_BR: {
        char *t = list_get(ins->labels, 0), *f = list_get(ins->labels, 1);
        ValueName condv = GET_ARG(0);
        char *l_true = new_label("br_true");
        bool handled_bit = false;
        if (g_pending_cmp.valid && g_pending_cmp.dest == condv) {
            char *l_false = new_label("br_false");
            switch (g_pending_cmp.op) {
            case IROP_LT:
                if (g_pending_cmp.is_16)
                    emit_cmp16_branch(sec, CMP_LT, g_pending_cmp.is_signed,
                                      g_pending_cmp.a, g_pending_cmp.b, l_true, l_false);
                else
                    emit_cmp8_branch(sec, CMP_LT, g_pending_cmp.is_signed,
                                     g_pending_cmp.a, g_pending_cmp.b, l_true, l_false);
                break;
            case IROP_LE:
                if (g_pending_cmp.is_16)
                    emit_cmp16_branch(sec, CMP_LE, g_pending_cmp.is_signed,
                                      g_pending_cmp.a, g_pending_cmp.b, l_true, l_false);
                else
                    emit_cmp8_branch(sec, CMP_LE, g_pending_cmp.is_signed,
                                     g_pending_cmp.a, g_pending_cmp.b, l_true, l_false);
                break;
            case IROP_GT:
                if (g_pending_cmp.is_16)
                    emit_cmp16_branch(sec, CMP_GT, g_pending_cmp.is_signed,
                                      g_pending_cmp.a, g_pending_cmp.b, l_true, l_false);
                else
                    emit_cmp8_branch(sec, CMP_GT, g_pending_cmp.is_signed,
                                     g_pending_cmp.a, g_pending_cmp.b, l_true, l_false);
                break;
            case IROP_GE:
                if (g_pending_cmp.is_16)
                    emit_cmp16_branch(sec, CMP_GE, g_pending_cmp.is_signed,
                                      g_pending_cmp.a, g_pending_cmp.b, l_true, l_false);
                else
                    emit_cmp8_branch(sec, CMP_GE, g_pending_cmp.is_signed,
                                     g_pending_cmp.a, g_pending_cmp.b, l_true, l_false);
                break;
            case IROP_EQ:
                if (g_pending_cmp.is_16)
                    emit_eqne16_branch(sec, false, g_pending_cmp.a, g_pending_cmp.b, l_true, l_false);
                else
                    emit_eqne8_branch(sec, false, g_pending_cmp.a, g_pending_cmp.b, l_true, l_false);
                break;
            case IROP_NE:
                if (g_pending_cmp.is_16)
                    emit_eqne16_branch(sec, true, g_pending_cmp.a, g_pending_cmp.b, l_true, l_false);
                else
                    emit_eqne8_branch(sec, true, g_pending_cmp.a, g_pending_cmp.b, l_true, l_false);
                break;
            default:
                break;
            }

            emit_label(sec, l_false);
            emit_phi_moves_for_edge(sec, func, cur_block, f);
            emit_ins1(sec, "sjmp", map_block_label(func_name, f));
            emit_label(sec, l_true);
            emit_phi_moves_for_edge(sec, func, cur_block, t);
            emit_ins1(sec, "sjmp", map_block_label(func_name, t));

            g_pending_cmp.valid = false;
            free(l_false);
            free(l_true);
            break;
        }
        Instr *cdef = find_def_instr(func, condv);
        if (cdef && (cdef->op == IROP_NE || cdef->op == IROP_EQ) && cdef->args && cdef->args->len >= 2) {
            ValueName a = *(ValueName *)list_get(cdef->args, 0);
            ValueName b = *(ValueName *)list_get(cdef->args, 1);
            int cval = 0;
            bool a_const = const_map_get(a, &cval);
            bool b_const = !a_const && const_map_get(b, &cval);
            if (a_const || b_const) {
                ValueName other = a_const ? b : a;
                if (cval == 0 || cval == 1) {
                    Instr *ld = find_def_instr(func, other);
                    if (ld && ld->op == IROP_LOAD && is_register_bit(ld->mem_type)) {
                        ValueName addr = *(ValueName *)list_get(ld->args, 0);
                        AddrInfo *ainfo = addr_map_get(addr);
                        if (ainfo && ainfo->label) {
                            bool jump_when_set = (cdef->op == IROP_NE) ? (cval == 0) : (cval != 0);
                            emit_ins2(sec, jump_when_set ? "jb" : "jnb", ainfo->label, l_true);
                            handled_bit = true;
                        }
                    }
                }
            }
        }
        if (!handled_bit) {
            emit_ins2(sec, "mov", "A", vreg(condv));
            emit_ins1(sec, "jnz", l_true);
        }
        /* 条件为假时跳转到 false 分支 (fall-through) */
        emit_phi_moves_for_edge(sec, func, cur_block, f);
        emit_ins1(sec, "sjmp", map_block_label(func_name, f));
        /* 条件为真时跳转到 true 分支 */
        emit_label(sec, l_true);
        emit_phi_moves_for_edge(sec, func, cur_block, t);
        emit_ins1(sec, "sjmp", map_block_label(func_name, t));
        free(l_true);
        break;
    }
    
    case IROP_CALL: {
        char *fname = list_get(ins->labels, 0);
        int nargs = ins->args ? ins->args->len : 0, total_bytes = 0;
        int *arg_off = nargs > 0 ? gen_alloc(sizeof(int) * nargs) : NULL;
        
        // 计算参数字节数
        for (int i = 0; i < nargs; i++) {
            ValueName v = GET_ARG(i);
            if (arg_off) arg_off[i] = total_bytes;
            total_bytes += (val_size(v) >= 2) ? 2 : 1;
        }
        int extra = total_bytes > 3 ? total_bytes - 3 : 0;
        
        // 保存寄存器
        for (int r = 0; r <= 3; r++) {
            snprintf(buf, sizeof(buf), "r%d", r);
            emit_ins1(sec, "push", buf);
        }
        
        // 装载寄存器参数（R1-R3，按字节顺序）
        for (int i = 0; i < nargs; i++) {
            ValueName v = GET_ARG(i);
            int sz = val_size(v);
            int cval = 0;
            bool is_const = const_map_get(v, &cval);
            for (int b = 0; b < sz; ++b) {
                int byte_idx = arg_off ? (arg_off[i] + b) : 0;
                if (byte_idx >= 3) continue;
                char rbuf[8];
                snprintf(rbuf, sizeof(rbuf), "r%d", 1 + byte_idx);
                if (is_const) {
                    snprintf(buf, sizeof(buf), "#%d", (b == 0) ? (cval & 0xFF) : ((cval >> 8) & 0xFF));
                    emit_ins2(sec, "mov", rbuf, buf);
                } else if (sz >= 2) {
                    AddrPair p; fmt_addr_pair(&p, v16_addr(v));
                    emit_ins2(sec, "mov", rbuf, b == 0 ? p.lo : p.hi);
                } else {
                    emit_ins2(sec, "mov", rbuf, vreg(v));
                }
            }
        }
        
        // 压栈多余参数（超过 R1-R3 的字节）
        if (total_bytes > 3) {
            for (int i = nargs - 1; i >= 0; i--) {
                ValueName v = GET_ARG(i);
                int sz = val_size(v);
                int cval = 0;
                bool is_const = const_map_get(v, &cval);
                if (sz >= 2) {
                    AddrPair p; fmt_addr_pair(&p, v16_addr(v));
                    for (int b = sz - 1; b >= 0; --b) {
                        int byte_idx = arg_off ? (arg_off[i] + b) : 0;
                        if (byte_idx < 3) continue;
                        if (is_const) {
                            snprintf(buf, sizeof(buf), "#%d", (b == 0) ? (cval & 0xFF) : ((cval >> 8) & 0xFF));
                            emit_ins2(sec, "mov", "A", buf);
                        } else {
                            emit_ins2(sec, "mov", "A", b == 0 ? p.lo : p.hi);
                        }
                        emit_ins1(sec, "push", "A");
                    }
                } else {
                    int byte_idx = arg_off ? arg_off[i] : 0;
                    if (byte_idx >= 3) {
                        if (is_const) {
                            snprintf(buf, sizeof(buf), "#%d", cval & 0xFF);
                            emit_ins2(sec, "mov", "A", buf);
                        } else {
                            emit_ins2(sec, "mov", "A", vreg(v));
                        }
                        emit_ins1(sec, "push", "A");
                    }
                }
            }
        }
        
        emit_ins1(sec, "lcall", fname ? fname : "<null>");
        
        // 清理栈
        for (int i = 0; i < extra; i++) emit_ins1(sec, "pop", "r0");
        for (int r = 3; r >= 0; r--) {
            snprintf(buf, sizeof(buf), "r%d", r);
            emit_ins1(sec, "pop", buf);
        }
        
        // 保存返回值
        if (ins->dest != 0) {
            if (IS_16BIT()) {
                AddrPair d; fmt_addr_pair(&d, v16_addr(ins->dest));
                emit_ins2(sec, "mov", d.lo, "r7");
                emit_ins2(sec, "mov", d.hi, "r6");
            } else {
                emit_ins2(sec, "mov", vreg(ins->dest), "r7");
            }
        }
        break;
    }
    
    case IROP_RET: {
        if (ins->args && ins->args->len > 0) {
            ValueName v = GET_ARG(0);
            if (func && func->ret_type && func->ret_type->size >= 2) {
                int cval;
                if (const_map_get(v, &cval)) {
                    snprintf(buf, sizeof(buf), "#%d", cval & 0xFF);
                    emit_ins2(sec, "mov", "r7", buf);
                    snprintf(buf, sizeof(buf), "#%d", (cval >> 8) & 0xFF);
                    emit_ins2(sec, "mov", "r6", buf);
                } else if (is_v16_value(v)) {
                    AddrPair s; fmt_addr_pair(&s, v16_addr(v));
                    emit_ins2(sec, "mov", "r7", s.lo);
                    emit_ins2(sec, "mov", "r6", s.hi);
                } else {
                    emit_ins2(sec, "mov", "r7", vreg(v));
                    emit_ins2(sec, "mov", "r6", "#0");
                }
            } else {
                int cval;
                if (const_map_get(v, &cval)) {
                    snprintf(buf, sizeof(buf), "#%d", cval & 0xFF);
                    emit_ins2(sec, "mov", "r7", buf);
                } else {
                    emit_ins2(sec, "mov", "r7", vreg(v));
                }
                emit_ins2(sec, "mov", "r6", "#0");
            }
        } else if (has_imm_tag(ins)) {
            if (func && func->ret_type && func->ret_type->size >= 2) {
                int v = (int)ins->imm.ival;
                snprintf(buf, sizeof(buf), "#%d", v & 0xFF);
                emit_ins2(sec, "mov", "r7", buf);
                snprintf(buf, sizeof(buf), "#%d", (v >> 8) & 0xFF);
                emit_ins2(sec, "mov", "r6", buf);
            } else {
                snprintf(buf, sizeof(buf), "#%ld", ins->imm.ival & 0xFF);
                emit_ins2(sec, "mov", "r7", buf);
                emit_ins2(sec, "mov", "r6", "#0");
            }
        } else {
            emit_ins2(sec, "mov", "r7", "#0");
            emit_ins2(sec, "mov", "r6", "#0");
        }
        
        if (func && func->stack_size > 0) emit_frame_epilogue(sec, func->stack_size);
        
        if (func && func->is_interrupt) {
            emit_interrupt_epilogue(sec);
            emit_ins0(sec, "reti");
        } else {
            emit_ins0(sec, "ret");
        }
        break;
    }
    
    case IROP_PHI:
        gen_clear_pending_ssa();
        return;
        
    default:
        break;
    }

    gen_clear_pending_ssa();
    #undef IS_16BIT
    #undef GET_ARG
    #undef VREG
}
