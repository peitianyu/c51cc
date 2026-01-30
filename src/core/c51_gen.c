#include "c51_obj.h"
#include "ssa.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void *gen_alloc(size_t size)
{
    void *p = calloc(1, size);
    if (!p) {
        fprintf(stderr, "c51_gen: out of memory\n");
        exit(1);
    }
    return p;
}

static char *gen_strdup(const char *s)
{
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char *d = gen_alloc(len);
    memcpy(d, s, len);
    return d;
}

static const char *vreg(ValueName v)
{
    static char buf[4][32];
    static int idx = 0;
    idx = (idx + 1) % 4;
    snprintf(buf[idx], sizeof(buf[idx]), "v%d", v);
    return buf[idx];
}

static AsmInstr *gen_instr_new(const char *op)
{
    AsmInstr *ins = gen_alloc(sizeof(AsmInstr));
    ins->op = gen_strdup(op);
    ins->args = make_list();
    return ins;
}

static void gen_instr_add_arg(AsmInstr *ins, const char *arg)
{
    if (!ins || !arg) return;
    list_push(ins->args, gen_strdup(arg));
}

static void emit_ins0(Section *sec, const char *op)
{
    AsmInstr *ins = gen_instr_new(op);
    list_push(sec->asminstrs, ins);
}

static void emit_ins1(Section *sec, const char *op, const char *a0)
{
    AsmInstr *ins = gen_instr_new(op);
    gen_instr_add_arg(ins, a0);
    list_push(sec->asminstrs, ins);
}

static void emit_ins2(Section *sec, const char *op, const char *a0, const char *a1)
{
    AsmInstr *ins = gen_instr_new(op);
    gen_instr_add_arg(ins, a0);
    gen_instr_add_arg(ins, a1);
    list_push(sec->asminstrs, ins);
}

static void emit_ins3(Section *sec, const char *op, const char *a0, const char *a1, const char *a2)
{
    AsmInstr *ins = gen_instr_new(op);
    gen_instr_add_arg(ins, a0);
    gen_instr_add_arg(ins, a1);
    gen_instr_add_arg(ins, a2);
    list_push(sec->asminstrs, ins);
}

static void emit_label(Section *sec, const char *name)
{
    if (!sec || !name) return;
    emit_ins1(sec, ".label", name);
}

static void free_asminstr(AsmInstr *ins)
{
    if (!ins) return;
    if (ins->args) {
        list_free(ins->args);
        free(ins->args);
    }
    free(ins->op);
    free(ins);
}

static SectionKind map_data_space(Ctype *type)
{
    if (!type) return SEC_DATA;
    CtypeAttr a = get_attr(type->attr);
    switch (a.ctype_data) {
    case 1: return SEC_DATA;
    case 2: return SEC_IDATA;
    case 3: return SEC_PDATA;
    case 4: return SEC_XDATA;
    case 5: return SEC_XDATA;
    case 6: return SEC_CODE;
    default: return SEC_DATA;
    }
}

static Section *get_or_create_section(ObjFile *obj, const char *name, SectionKind kind)
{
    int idx = 0;
    for (Iter it = list_iter(obj->sections); !iter_end(it); ++idx) {
        Section *sec = iter_next(&it);
        if (sec && sec->name && !strcmp(sec->name, name))
            return sec;
    }
    idx = objfile_add_section(obj, name, kind, 0, 1);
    return objfile_get_section(obj, idx);
}

static int section_index_from_ptr(ObjFile *obj, Section *sec)
{
    int idx = 0;
    for (Iter it = list_iter(obj->sections); !iter_end(it); ++idx) {
        if (iter_next(&it) == sec)
            return idx;
    }
    return -1;
}

static void emit_global_data(ObjFile *obj, GlobalVar *g)
{
    if (!g || !g->name) return;
    if (g->is_extern) {
        objfile_add_symbol(obj, g->name, SYM_DATA, -1, 0, g->type ? g->type->size : 0, SYM_FLAG_EXTERN);
        return;
    }

    SectionKind kind = map_data_space(g->type);
    const char *sec_name = g->has_init ? ".data" : ".bss";
    Section *sec = get_or_create_section(obj, sec_name, kind);
    int offset = sec->bytes_len;
    int size = g->type ? g->type->size : 1;

    if (g->has_init) {
        long v = g->init_value;
        if (size == 1) {
            unsigned char b = (unsigned char)(v & 0xFF);
            section_append_bytes(sec, &b, 1);
        } else if (size == 2) {
            unsigned char b[2] = {(unsigned char)(v & 0xFF), (unsigned char)((v >> 8) & 0xFF)};
            section_append_bytes(sec, b, 2);
        } else if (size == 4) {
            unsigned char b[4] = {
                (unsigned char)(v & 0xFF),
                (unsigned char)((v >> 8) & 0xFF),
                (unsigned char)((v >> 16) & 0xFF),
                (unsigned char)((v >> 24) & 0xFF)
            };
            section_append_bytes(sec, b, 4);
        } else {
            section_append_zeros(sec, size);
        }
    } else {
        section_append_zeros(sec, size);
    }

    unsigned flags = g->is_static ? SYM_FLAG_LOCAL : SYM_FLAG_GLOBAL;
    objfile_add_symbol(obj, g->name, SYM_DATA, section_index_from_ptr(obj, sec), offset, size, flags);
}

static void regalloc_stub(Func *f)
{
    (void)f;
    /* TODO: linear scan register allocation */
}

static int parse_vreg_id(const char *arg, bool *is_indirect)
{
    if (is_indirect) *is_indirect = false;
    if (!arg) return -1;
    if (arg[0] == 'v' && arg[1] >= '0' && arg[1] <= '9')
        return atoi(arg + 1);
    if (arg[0] == '@' && arg[1] == 'v' && arg[2] >= '0' && arg[2] <= '9') {
        if (is_indirect) *is_indirect = true;
        return atoi(arg + 2);
    }
    return -1;
}

static bool is_mov_def(const AsmInstr *ins, int arg_idx, const char *arg)
{
    if (!ins || !ins->op || !arg) return false;
    if (strcmp(ins->op, "mov") != 0) return false;
    if (arg_idx != 0) return false;
    if (arg[0] == 'v') return true;
    return false;
}

static int alloc_reg(bool prefer_r01, bool used[8])
{
    if (prefer_r01) {
        if (!used[0]) { used[0] = true; return 0; }
        if (!used[1]) { used[1] = true; return 1; }
    }
    for (int i = 0; i < 8; ++i) {
        if (!used[i]) { used[i] = true; return i; }
    }
    return -1;
}

static void regalloc_section_asminstrs(Section *sec)
{
    if (!sec || !sec->asminstrs) return;

    int max_v = -1;
    for (Iter it = list_iter(sec->asminstrs); !iter_end(it);) {
        AsmInstr *ins = iter_next(&it);
        if (!ins || !ins->args) continue;
        for (Iter ait = list_iter(ins->args); !iter_end(ait);) {
            char *arg = iter_next(&ait);
            int v = parse_vreg_id(arg, NULL);
            if (v > max_v) max_v = v;
        }
    }
    if (max_v < 0) return;

    int count = max_v + 1;
    int *use_cnt = gen_alloc(sizeof(int) * count);
    bool *need_indirect = gen_alloc(sizeof(bool) * count);

    for (Iter it = list_iter(sec->asminstrs); !iter_end(it);) {
        AsmInstr *ins = iter_next(&it);
        if (!ins || !ins->args) continue;
        int idx = 0;
        for (Iter ait = list_iter(ins->args); !iter_end(ait); ++idx) {
            char *arg = iter_next(&ait);
            bool indir = false;
            int v = parse_vreg_id(arg, &indir);
            if (v < 0 || v >= count) continue;
            if (is_mov_def(ins, idx, arg)) continue;
            use_cnt[v]++;
            if (indir) need_indirect[v] = true;
        }
    }

    int *map = gen_alloc(sizeof(int) * count);
    int *spill = gen_alloc(sizeof(int) * count);
    for (int i = 0; i < count; ++i) { map[i] = -1; spill[i] = -1; }
    bool used[8] = {0};
    int spill_next = 0x30;

    for (Iter it = list_iter(sec->asminstrs); !iter_end(it);) {
        AsmInstr *ins = iter_next(&it);
        if (!ins || !ins->args) continue;

        int use_len = ins->args->len;
        int *uses = use_len ? malloc(sizeof(int) * use_len) : NULL;
        int use_n = 0;

        int idx = 0;
        for (Iter ait = list_iter(ins->args); !iter_end(ait); ++idx) {
            char *arg = iter_next(&ait);
            bool indir = false;
            int v = parse_vreg_id(arg, &indir);
            if (v < 0 || v >= count) continue;
            if (!is_mov_def(ins, idx, arg))
                uses[use_n++] = v;

            if (map[v] < 0 && spill[v] < 0) {
                map[v] = alloc_reg(need_indirect[v], used);
                if (map[v] < 0) {
                    if (need_indirect[v]) {
                        map[v] = 0;
                        used[0] = true;
                    } else {
                        spill[v] = spill_next++;
                    }
                }
            }

            char buf[16];
            if (spill[v] >= 0 && !indir) {
                snprintf(buf, sizeof(buf), "0x%02X", spill[v] & 0xFF);
            } else {
                if (map[v] < 0) {
                    map[v] = 0;
                    used[0] = true;
                }
                if (indir) snprintf(buf, sizeof(buf), "@r%d", map[v]);
                else snprintf(buf, sizeof(buf), "r%d", map[v]);
            }
            list_set(ins->args, idx, gen_strdup(buf));
            free(arg);
        }

        for (int i = 0; i < use_n; ++i) {
            int v = uses[i];
            if (v < 0 || v >= count) continue;
            if (use_cnt[v] > 0) {
                use_cnt[v]--;
                if (use_cnt[v] == 0 && map[v] >= 0) {
                    used[map[v]] = false;
                }
            }
        }
        if (uses) free(uses);
    }
}

static bool is_reg_eq(const char *a, const char *b)
{
    return a && b && !strcmp(a, b);
}

static void peephole_section_asminstrs(Section *sec)
{
    if (!sec || !sec->asminstrs) return;
    List *out = make_list();

    for (Iter it = list_iter(sec->asminstrs); !iter_end(it);) {
        AsmInstr *ins = iter_next(&it);
        if (!ins || !ins->op) {
            list_push(out, ins);
            continue;
        }

        if (!strcmp(ins->op, "mov") && ins->args && ins->args->len >= 2) {
            char *dst = list_get(ins->args, 0);
            char *src = list_get(ins->args, 1);
            if (is_reg_eq(dst, src)) {
                free_asminstr(ins);
                continue;
            }
        }

        list_push(out, ins);
    }

    free(sec->asminstrs);
    sec->asminstrs = out;
}

static void encode_section_bytes(Section *sec)
{
    if (!sec || !sec->asminstrs) return;
    for (Iter it = list_iter(sec->asminstrs); !iter_end(it);) {
        AsmInstr *ins = iter_next(&it);
        if (!ins || !ins->op) continue;

        unsigned char b = 0x00;
        if (!strcmp(ins->op, "mov")) b = 0x01;
        else if (!strcmp(ins->op, "add")) b = 0x02;
        else if (!strcmp(ins->op, "subb")) b = 0x03;
        else if (!strcmp(ins->op, "anl")) b = 0x04;
        else if (!strcmp(ins->op, "orl")) b = 0x05;
        else if (!strcmp(ins->op, "xrl")) b = 0x06;
        else if (!strcmp(ins->op, "cpl")) b = 0x07;
        else if (!strcmp(ins->op, "clr")) b = 0x08;
        else if (!strcmp(ins->op, "mul")) b = 0x09;
        else if (!strcmp(ins->op, "div")) b = 0x0A;
        else if (!strcmp(ins->op, "cjne")) b = 0x0B;
        else if (!strcmp(ins->op, "jnz")) b = 0x0C;
        else if (!strcmp(ins->op, "jz")) b = 0x0D;
        else if (!strcmp(ins->op, "sjmp")) b = 0x0E;
        else if (!strcmp(ins->op, "lcall")) b = 0x0F;
        else if (!strcmp(ins->op, "ret")) b = 0x10;
        else if (!strcmp(ins->op, "jc")) b = 0x11;
        else if (!strcmp(ins->op, "jnc")) b = 0x12;
        else if (!strcmp(ins->op, "djnz")) b = 0x13;
        else if (!strcmp(ins->op, "rrc")) b = 0x14;
        else if (!strcmp(ins->op, "rlc")) b = 0x15;
        else if (!strcmp(ins->op, "rl")) b = 0x16;
        else if (!strcmp(ins->op, "rr")) b = 0x17;
        else if (!strcmp(ins->op, "swap")) b = 0x18;
        else if (!strcmp(ins->op, "setb")) b = 0x19;
        else if (!strcmp(ins->op, "push")) b = 0x1A;
        else if (!strcmp(ins->op, "pop")) b = 0x1B;
        else if (!strcmp(ins->op, "reti")) b = 0x1C;
        else if (!strcmp(ins->op, "ljmp")) b = 0x1D;
        else if (!strcmp(ins->op, "ajmp")) b = 0x1E;
        else if (!strcmp(ins->op, "acall")) b = 0x1F;
        else if (!strcmp(ins->op, "addc")) b = 0x20;
        else if (!strcmp(ins->op, "da")) b = 0x21;
        else if (!strcmp(ins->op, "inc")) b = 0x22;
        else if (!strcmp(ins->op, "dec")) b = 0x23;
        else if (!strcmp(ins->op, "movc")) b = 0x24;
        else if (!strcmp(ins->op, "movx")) b = 0x25;
        else if (!strcmp(ins->op, "xch")) b = 0x26;
        else if (!strcmp(ins->op, "xchd")) b = 0x27;
        else if (!strcmp(ins->op, "jb")) b = 0x28;
        else if (!strcmp(ins->op, "jnb")) b = 0x29;
        else if (!strcmp(ins->op, "jbc")) b = 0x2A;
        else if (!strcmp(ins->op, "nop")) b = 0x2B;
        else if (!strcmp(ins->op, ".label")) continue;

        section_append_bytes(sec, &b, 1);
    }
}

static int g_lower_id = 0;

static char *new_label(const char *prefix)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "L%s_%d", prefix, g_lower_id++);
    return gen_strdup(buf);
}

static const char *map_block_label(const char *func_name, const char *label)
{
    if (!label) return "<null>";
    if (strncmp(label, "block", 5) == 0) {
        int id = atoi(label + 5);
        static char buf[96];
        snprintf(buf, sizeof(buf), "L%s_%d", func_name ? func_name : "fn", id);
        return buf;
    }
    return label;
}

static int param_index(Func *f, const char *name)
{
    if (!f || !f->params || !name) return -1;
    int idx = 0;
    for (Iter it = list_iter(f->params); !iter_end(it); ++idx) {
        char *p = iter_next(&it);
        if (p && !strcmp(p, name)) return idx;
    }
    return -1;
}

static void emit_instr(Section *sec, Instr *ins, Func *func)
{
    if (!ins) return;
    char buf[64];
    const char *func_name = func ? func->name : NULL;

    switch (ins->op) {
    case IROP_NOP:
        return;
    case IROP_PARAM:
        if (ins->labels && ins->labels->len > 0) {
            char *pname = list_get(ins->labels, 0);
            int idx = param_index(func, pname);
            if (idx >= 0 && idx < 8) {
                char regbuf[8];
                snprintf(regbuf, sizeof(regbuf), "r%d", 7 - idx);
                emit_ins2(sec, "mov", vreg(ins->dest), regbuf);
            }
        }
        return;
    case IROP_CONST:
        snprintf(buf, sizeof(buf), "#%lld", (long long)ins->imm.ival);
        emit_ins2(sec, "mov", vreg(ins->dest), buf);
        break;
    case IROP_ADD:
        emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins2(sec, "add", "A", vreg(*(ValueName *)list_get(ins->args, 1)));
        emit_ins2(sec, "mov", vreg(ins->dest), "A");
        break;
    case IROP_SUB:
        emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins1(sec, "clr", "C");
        emit_ins2(sec, "subb", "A", vreg(*(ValueName *)list_get(ins->args, 1)));
        emit_ins2(sec, "mov", vreg(ins->dest), "A");
        break;
    case IROP_MUL:
        emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins2(sec, "mov", "B", vreg(*(ValueName *)list_get(ins->args, 1)));
        emit_ins1(sec, "mul", "AB");
        emit_ins2(sec, "mov", vreg(ins->dest), "A");
        break;
    case IROP_DIV:
        emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins2(sec, "mov", "B", vreg(*(ValueName *)list_get(ins->args, 1)));
        emit_ins1(sec, "div", "AB");
        emit_ins2(sec, "mov", vreg(ins->dest), "A");
        break;
    case IROP_MOD:
        emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins2(sec, "mov", "B", vreg(*(ValueName *)list_get(ins->args, 1)));
        emit_ins1(sec, "div", "AB");
        emit_ins2(sec, "mov", vreg(ins->dest), "B");
        break;
    case IROP_AND:
        emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins2(sec, "anl", "A", vreg(*(ValueName *)list_get(ins->args, 1)));
        emit_ins2(sec, "mov", vreg(ins->dest), "A");
        break;
    case IROP_OR:
        emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins2(sec, "orl", "A", vreg(*(ValueName *)list_get(ins->args, 1)));
        emit_ins2(sec, "mov", vreg(ins->dest), "A");
        break;
    case IROP_XOR:
        emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins2(sec, "xrl", "A", vreg(*(ValueName *)list_get(ins->args, 1)));
        emit_ins2(sec, "mov", vreg(ins->dest), "A");
        break;
    case IROP_SHL: {
        char *l_loop = new_label("shl_loop");
        char *l_end = new_label("shl_end");
        emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins2(sec, "mov", "B", vreg(*(ValueName *)list_get(ins->args, 1)));
        emit_ins3(sec, "cjne", "B", "#0", l_loop);
        emit_ins1(sec, "sjmp", l_end);
        emit_label(sec, l_loop);
        emit_ins2(sec, "add", "A", "A");
        emit_ins2(sec, "djnz", "B", l_loop);
        emit_label(sec, l_end);
        emit_ins2(sec, "mov", vreg(ins->dest), "A");
        free(l_loop);
        free(l_end);
        break;
    }
    case IROP_SHR: {
        char *l_loop = new_label("shr_loop");
        char *l_end = new_label("shr_end");
        emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins2(sec, "mov", "B", vreg(*(ValueName *)list_get(ins->args, 1)));
        emit_ins3(sec, "cjne", "B", "#0", l_loop);
        emit_ins1(sec, "sjmp", l_end);
        emit_label(sec, l_loop);
        emit_ins1(sec, "clr", "C");
        emit_ins1(sec, "rrc", "A");
        emit_ins2(sec, "djnz", "B", l_loop);
        emit_label(sec, l_end);
        emit_ins2(sec, "mov", vreg(ins->dest), "A");
        free(l_loop);
        free(l_end);
        break;
    }
    case IROP_NEG:
        emit_ins1(sec, "clr", "C");
        emit_ins2(sec, "mov", "A", "#0");
        emit_ins2(sec, "subb", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins2(sec, "mov", vreg(ins->dest), "A");
        break;
    case IROP_NOT:
        emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins1(sec, "cpl", "A");
        emit_ins2(sec, "mov", vreg(ins->dest), "A");
        break;
    case IROP_EQ: {
        char *l_false = new_label("eq_false");
        char *l_end = new_label("eq_end");
        emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins3(sec, "cjne", "A", vreg(*(ValueName *)list_get(ins->args, 1)), l_false);
        emit_ins2(sec, "mov", vreg(ins->dest), "#1");
        emit_ins1(sec, "sjmp", l_end);
        emit_label(sec, l_false);
        emit_ins2(sec, "mov", vreg(ins->dest), "#0");
        emit_label(sec, l_end);
        free(l_false);
        free(l_end);
        break;
    }
    case IROP_NE: {
        char *l_true = new_label("ne_true");
        char *l_end = new_label("ne_end");
        emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins3(sec, "cjne", "A", vreg(*(ValueName *)list_get(ins->args, 1)), l_true);
        emit_ins2(sec, "mov", vreg(ins->dest), "#0");
        emit_ins1(sec, "sjmp", l_end);
        emit_label(sec, l_true);
        emit_ins2(sec, "mov", vreg(ins->dest), "#1");
        emit_label(sec, l_end);
        free(l_true);
        free(l_end);
        break;
    }
    case IROP_LT: {
        char *l_true = new_label("lt_true");
        char *l_end = new_label("lt_end");
        emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins1(sec, "clr", "C");
        emit_ins2(sec, "subb", "A", vreg(*(ValueName *)list_get(ins->args, 1)));
        emit_ins1(sec, "jc", l_true);
        emit_ins2(sec, "mov", vreg(ins->dest), "#0");
        emit_ins1(sec, "sjmp", l_end);
        emit_label(sec, l_true);
        emit_ins2(sec, "mov", vreg(ins->dest), "#1");
        emit_label(sec, l_end);
        free(l_true);
        free(l_end);
        break;
    }
    case IROP_LE: {
        char *l_true = new_label("le_true");
        char *l_end = new_label("le_end");
        emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins1(sec, "clr", "C");
        emit_ins2(sec, "subb", "A", vreg(*(ValueName *)list_get(ins->args, 1)));
        emit_ins1(sec, "jc", l_true);
        emit_ins1(sec, "jz", l_true);
        emit_ins2(sec, "mov", vreg(ins->dest), "#0");
        emit_ins1(sec, "sjmp", l_end);
        emit_label(sec, l_true);
        emit_ins2(sec, "mov", vreg(ins->dest), "#1");
        emit_label(sec, l_end);
        free(l_true);
        free(l_end);
        break;
    }
    case IROP_GT: {
        char *l_true = new_label("gt_true");
        char *l_false = new_label("gt_false");
        char *l_end = new_label("gt_end");
        emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins1(sec, "clr", "C");
        emit_ins2(sec, "subb", "A", vreg(*(ValueName *)list_get(ins->args, 1)));
        emit_ins1(sec, "jc", l_false);
        emit_ins1(sec, "jz", l_false);
        emit_label(sec, l_true);
        emit_ins2(sec, "mov", vreg(ins->dest), "#1");
        emit_ins1(sec, "sjmp", l_end);
        emit_label(sec, l_false);
        emit_ins2(sec, "mov", vreg(ins->dest), "#0");
        emit_label(sec, l_end);
        free(l_true);
        free(l_false);
        free(l_end);
        break;
    }
    case IROP_GE: {
        char *l_true = new_label("ge_true");
        char *l_end = new_label("ge_end");
        emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins1(sec, "clr", "C");
        emit_ins2(sec, "subb", "A", vreg(*(ValueName *)list_get(ins->args, 1)));
        emit_ins1(sec, "jnc", l_true);
        emit_ins2(sec, "mov", vreg(ins->dest), "#0");
        emit_ins1(sec, "sjmp", l_end);
        emit_label(sec, l_true);
        emit_ins2(sec, "mov", vreg(ins->dest), "#1");
        emit_label(sec, l_end);
        free(l_true);
        free(l_end);
        break;
    }
    case IROP_LNOT: {
        char *l_true = new_label("lnot_true");
        char *l_end = new_label("lnot_end");
        emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins1(sec, "jz", l_true);
        emit_ins2(sec, "mov", vreg(ins->dest), "#0");
        emit_ins1(sec, "sjmp", l_end);
        emit_label(sec, l_true);
        emit_ins2(sec, "mov", vreg(ins->dest), "#1");
        emit_label(sec, l_end);
        free(l_true);
        free(l_end);
        break;
    }
    case IROP_LOAD:
        snprintf(buf, sizeof(buf), "@%s", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins2(sec, "mov", "A", buf);
        emit_ins2(sec, "mov", vreg(ins->dest), "A");
        break;
    case IROP_STORE:
        snprintf(buf, sizeof(buf), "@%s", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 1)));
        emit_ins2(sec, "mov", buf, "A");
        break;
    case IROP_JMP: {
        char *label = list_get(ins->labels, 0);
        emit_ins1(sec, "sjmp", map_block_label(func_name, label));
        break;
    }
    case IROP_BR: {
        char *t = list_get(ins->labels, 0);
        char *f = list_get(ins->labels, 1);
        emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins1(sec, "jnz", map_block_label(func_name, t));
        emit_ins1(sec, "sjmp", map_block_label(func_name, f));
        break;
    }
    case IROP_CALL: {
        char *fname = list_get(ins->labels, 0);
        if (ins->args && ins->args->len > 0) {
            int idx = 0;
            for (Iter ait = list_iter(ins->args); !iter_end(ait) && idx < 8; ++idx) {
                ValueName v = *(ValueName *)iter_next(&ait);
                char regbuf[8];
                snprintf(regbuf, sizeof(regbuf), "r%d", 7 - idx);
                emit_ins2(sec, "mov", regbuf, vreg(v));
            }
        }
        emit_ins1(sec, "lcall", fname ? fname : "<null>");
        if (ins->dest != 0)
            emit_ins2(sec, "mov", vreg(ins->dest), "A");
        break;
    }
    case IROP_RET:
        if (ins->args && ins->args->len > 0)
            emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins0(sec, "ret");
        break;
    case IROP_PHI:
        return;
    default:
        return;
    }
}

static void lower_section_asminstrs(Section *sec)
{
    if (!sec || !sec->asminstrs) return;
    List *out = make_list();
    for (Iter it = list_iter(sec->asminstrs); !iter_end(it);) {
        AsmInstr *ins = iter_next(&it);
        if (!ins || !ins->op) {
            list_push(out, ins);
            continue;
        }
        list_push(out, ins);
    }
    free(sec->asminstrs);
    sec->asminstrs = out;
}

ObjFile *c51_gen_from_ssa(void *ssa)
{
    SSAUnit *unit = (SSAUnit *)ssa;
    if (!unit) return NULL;

    ObjFile *obj = objfile_new();

    for (Iter git = list_iter(unit->globals); !iter_end(git);) {
        GlobalVar *g = iter_next(&git);
        emit_global_data(obj, g);
    }

    for (Iter fit = list_iter(unit->funcs); !iter_end(fit);) {
        Func *f = iter_next(&fit);
        if (!f || !f->name) continue;
        regalloc_stub(f);
        char sec_name[128];
        snprintf(sec_name, sizeof(sec_name), ".text.%s", f->name);
        Section *sec = get_or_create_section(obj, sec_name, SEC_CODE);

        objfile_add_symbol(obj, (char *)f->name, SYM_FUNC, section_index_from_ptr(obj, sec), 0, 0, SYM_FLAG_GLOBAL);
        emit_label(sec, f->name);

        for (Iter bit = list_iter(f->blocks); !iter_end(bit);) {
            Block *b = iter_next(&bit);
            if (!b) continue;
            char label[64];
            snprintf(label, sizeof(label), "L%s_%u", f->name, b->id);
            emit_label(sec, label);

            for (Iter it = list_iter(b->instrs); !iter_end(it);) {
                Instr *ins = iter_next(&it);
                emit_instr(sec, ins, f);
            }
        }

        lower_section_asminstrs(sec);
        regalloc_section_asminstrs(sec);
        peephole_section_asminstrs(sec);
        encode_section_bytes(sec);
    }

    return obj;
}

#ifdef MINITEST_IMPLEMENTATION
#include "minitest.h"

extern List *ctypes;
extern List *strings;
extern List *read_toplevels(void);
extern void set_current_filename(const char *filename);
extern char *ast_to_string(Ast *ast);

TEST(test, c51_gen) {
    char infile[256];
    printf("file path for C51 gen test: ");
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

    ObjFile *obj = c51_gen_from_ssa(b->unit);
    ASSERT(obj);
    ASSERT(obj->sections && obj->sections->len > 0);
    Section *code_sec = NULL;
    for (Iter it = list_iter(obj->sections); !iter_end(it);) {
        Section *sec = iter_next(&it);
        if (sec && sec->kind == SEC_CODE) { code_sec = sec; break; }
    }
    ASSERT(code_sec);
    ASSERT(code_sec->asminstrs && code_sec->asminstrs->len > 0);
    ASSERT(code_sec->bytes_len > 0);

    for (Iter it = list_iter(code_sec->asminstrs); !iter_end(it);) {
        AsmInstr *ins = iter_next(&it);
        if (ins && ins->op) {
            ASSERT(strcmp(ins->op, "br") != 0);
            ASSERT(strcmp(ins->op, ".warn") != 0);
            ASSERT(strcmp(ins->op, "gt") != 0);
            ASSERT(strcmp(ins->op, "ne") != 0);
            ASSERT(strcmp(ins->op, "lnot") != 0);
            ASSERT(strcmp(ins->op, "param") != 0);
            ASSERT(strcmp(ins->op, "phi") != 0);
        }
        if (ins && ins->args) {
            for (Iter ait = list_iter(ins->args); !iter_end(ait);) {
                char *arg = iter_next(&ait);
                if (arg && arg[0] == 'v')
                    ASSERT(0);
                if (arg && arg[0] == '[' && arg[1] == 'v')
                    ASSERT(0);
            }
        }
        if (ins && ins->op && !strcmp(ins->op, "mov") && ins->args && ins->args->len >= 2) {
            char *dst = list_get(ins->args, 0);
            char *src = list_get(ins->args, 1);
            ASSERT(!(dst && src && !strcmp(dst, src)));
        }
    }

    printf("\n=== ASM Output (gen) ===\n");
    ASSERT_EQ(c51_write_asm(stdout, obj), 0);

    objfile_free(obj);
    ssa_build_destroy(b);
    list_free(strings);
    list_free(ctypes);
}
#endif
