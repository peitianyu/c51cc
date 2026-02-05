#include "c51_gen.h"

char *g_pending_ssa = NULL;

void gen_set_pending_ssa(char *ssa)
{
    if (g_pending_ssa) {
        free(g_pending_ssa);
    }
    g_pending_ssa = ssa;
}

void gen_clear_pending_ssa(void)
{
    if (g_pending_ssa) {
        free(g_pending_ssa);
        g_pending_ssa = NULL;
    }
}

void gen_instr_copy_ssa(AsmInstr *dst, const AsmInstr *src)
{
    if (!dst) return;
    if (dst->ssa) {
        free(dst->ssa);
        dst->ssa = NULL;
    }
    if (src && src->ssa) {
        dst->ssa = gen_strdup(src->ssa);
    }
}

/* === Asm instruction builders === */
const char *vreg(ValueName v)
{
    static char buf[4][32];
    static int idx = 0;
    idx = (idx + 1) % 4;
    snprintf(buf[idx], sizeof(buf[idx]), "v%d", v);
    return buf[idx];
}

AsmInstr *gen_instr_new(const char *op)
{
    AsmInstr *ins = gen_alloc(sizeof(AsmInstr));
    ins->op = gen_strdup(op);
    ins->args = make_list();
    ins->ssa = NULL;
    return ins;
}

void gen_instr_add_arg(AsmInstr *ins, const char *arg)
{
    if (!ins || !arg) return;
    list_push(ins->args, gen_strdup(arg));
}

void emit_ins0(Section *sec, const char *op)
{
    AsmInstr *ins = gen_instr_new(op);
    if (g_pending_ssa) {
        ins->ssa = g_pending_ssa;
        g_pending_ssa = NULL;
    }
    list_push(sec->asminstrs, ins);
}

void emit_ins1(Section *sec, const char *op, const char *a0)
{
    AsmInstr *ins = gen_instr_new(op);
    gen_instr_add_arg(ins, a0);
    if (g_pending_ssa) {
        ins->ssa = g_pending_ssa;
        g_pending_ssa = NULL;
    }
    list_push(sec->asminstrs, ins);
}

void emit_ins2(Section *sec, const char *op, const char *a0, const char *a1)
{
    AsmInstr *ins = gen_instr_new(op);
    gen_instr_add_arg(ins, a0);
    gen_instr_add_arg(ins, a1);
    if (g_pending_ssa) {
        ins->ssa = g_pending_ssa;
        g_pending_ssa = NULL;
    }
    list_push(sec->asminstrs, ins);
}

void emit_ins3(Section *sec, const char *op, const char *a0, const char *a1, const char *a2)
{
    AsmInstr *ins = gen_instr_new(op);
    gen_instr_add_arg(ins, a0);
    gen_instr_add_arg(ins, a1);
    gen_instr_add_arg(ins, a2);
    if (g_pending_ssa) {
        ins->ssa = g_pending_ssa;
        g_pending_ssa = NULL;
    }
    list_push(sec->asminstrs, ins);
}

void emit_label(Section *sec, const char *name)
{
    if (!sec || !name) return;
    emit_ins1(sec, ".label", name);
}

void free_asminstr(AsmInstr *ins)
{
    if (!ins) return;
    if (ins->args) {
        list_free(ins->args);
        free(ins->args);
    }
    free(ins->op);
    free(ins->ssa);
    free(ins);
}

/* === Encoding helpers === */
void emit_u8(Section *sec, unsigned char b)
{
    section_append_bytes(sec, &b, 1);
}

void emit_u16(Section *sec, int v)
{
    unsigned char b[2] = {(unsigned char)(v & 0xFF), (unsigned char)((v >> 8) & 0xFF)};
    section_append_bytes(sec, b, 2);
}

void emit_rel8(ObjFile *obj, Section *sec, const char *label)
{
    int sec_index = section_index_from_ptr(obj, sec);
    int offset = sec->bytes_len;
    emit_u8(sec, 0);
    if (label && is_ident(label))
        objfile_add_reloc(obj, sec_index, offset, RELOC_REL8, label, 0);
}

void emit_abs16(ObjFile *obj, Section *sec, const char *label)
{
    int sec_index = section_index_from_ptr(obj, sec);
    int offset = sec->bytes_len;
    emit_u16(sec, 0);
    if (label && is_ident(label))
        objfile_add_reloc(obj, sec_index, offset, RELOC_ABS16, label, 0);
}

void emit_abs8(ObjFile *obj, Section *sec, const char *label)
{
    int sec_index = section_index_from_ptr(obj, sec);
    int offset = sec->bytes_len;
    emit_u8(sec, 0);
    if (label && is_ident(label))
        objfile_add_reloc(obj, sec_index, offset, RELOC_ABS8, label, 0);
}

/* === Stack operations === */
void emit_load_stack_param(Section *sec, int offset, const char *dst, bool use_fp)
{
    if (!sec || !dst) return;
    char buf[16];
    emit_ins2(sec, "mov", "A", use_fp ? "0x2E" : "0x81");
    snprintf(buf, sizeof(buf), "#0x%02X", (unsigned char)(0 - offset));
    emit_ins2(sec, "add", "A", buf);
    emit_ins2(sec, "mov", "r0", "A");
    emit_ins2(sec, "mov", "A", "@r0");
    emit_ins2(sec, "mov", dst, "A");
}

void emit_load_stack_param_to_direct(Section *sec, int offset, int addr, bool use_fp)
{
    if (!sec) return;
    char buf[16];
    char dst[16];
    emit_ins2(sec, "mov", "A", use_fp ? "0x2E" : "0x81");
    snprintf(buf, sizeof(buf), "#0x%02X", (unsigned char)(0 - offset));
    emit_ins2(sec, "add", "A", buf);
    emit_ins2(sec, "mov", "r0", "A");
    emit_ins2(sec, "mov", "A", "@r0");
    fmt_direct(dst, sizeof(dst), addr);
    emit_ins2(sec, "mov", dst, "A");
}

void emit_stack_addr(Section *sec, int offset)
{
    char buf[16];
    emit_ins2(sec, "mov", "A", "0x2E");
    snprintf(buf, sizeof(buf), "#%d", offset + 1);
    emit_ins2(sec, "add", "A", buf);
    emit_ins2(sec, "mov", "r0", "A");
}

void emit_frame_prologue(Section *sec, int stack_size)
{
    if (!sec || stack_size <= 0) return;
    char buf[16];
    emit_ins2(sec, "mov", "0x2E", "0x81");
    emit_ins2(sec, "mov", "A", "0x81");
    snprintf(buf, sizeof(buf), "#%d", stack_size);
    emit_ins2(sec, "add", "A", buf);
    emit_ins2(sec, "mov", "0x81", "A");
}

void emit_frame_epilogue(Section *sec, int stack_size)
{
    if (!sec || stack_size <= 0) return;
    emit_ins2(sec, "mov", "0x81", "0x2E");
}

void emit_interrupt_prologue(Section *sec)
{
    if (!sec) return;
    emit_ins1(sec, "push", "A");
    emit_ins1(sec, "push", "0xD0");
    emit_ins1(sec, "push", "0x82");
    emit_ins1(sec, "push", "0x83");
}

void emit_interrupt_epilogue(Section *sec)
{
    if (!sec) return;
    emit_ins1(sec, "pop", "0x83");
    emit_ins1(sec, "pop", "0x82");
    emit_ins1(sec, "pop", "0xD0");
    emit_ins1(sec, "pop", "A");
}

/* === SSA lowering helpers === */
char *new_label(const char *prefix)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "L%s_%d", prefix, g_lower_id++);
    return gen_strdup(buf);
}

const char *map_block_label(const char *func_name, const char *label)
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

int param_index(Func *f, const char *name)
{
    if (!f || !f->params || !name) return -1;
    int idx = 0;
    for (Iter it = list_iter(f->params); !iter_end(it); ++idx) {
        char *p = iter_next(&it);
        if (p && !strcmp(p, name)) return idx;
    }
    return -1;
}

Ctype *param_type(Func *f, const char *name)
{
    if (!f || !f->params || !f->param_types || !name) return NULL;
    int idx = 0;
    for (Iter it = list_iter(f->params); !iter_end(it); ++idx) {
        char *p = iter_next(&it);
        if (p && !strcmp(p, name)) {
            return (Ctype *)list_get(f->param_types, idx);
        }
    }
    return NULL;
}

int param_byte_offset(Func *f, const char *name, Ctype **out_type)
{
    if (!f || !f->params || !name) return -1;
    int offset = 0;
    int idx = 0;
    for (Iter it = list_iter(f->params); !iter_end(it); ++idx) {
        char *p = iter_next(&it);
        Ctype *t = (f->param_types && idx < f->param_types->len) ? (Ctype *)list_get(f->param_types, idx) : NULL;
        int sz = t ? t->size : 1;
        if (p && !strcmp(p, name)) {
            if (out_type) *out_type = t;
            return offset;
        }
        offset += (sz >= 2) ? 2 : 1;
    }
    return -1;
}

Block *find_block_by_label(Func *f, const char *label)
{
    if (!f || !label) return NULL;
    int id = -1;
    if (strncmp(label, "block", 5) == 0)
        id = atoi(label + 5);
    if (id < 0) return NULL;
    for (Iter it = list_iter(f->blocks); !iter_end(it);) {
        Block *b = iter_next(&it);
        if (b && (int)b->id == id) return b;
    }
    return NULL;
}

const char *find_var_for_value(Block *blk, ValueName v)
{
    if (!blk || !blk->var_map || v == 0) return NULL;
    for (Iter it = list_iter(blk->var_map->list); !iter_end(it);) {
        DictEntry *e = iter_next(&it);
        if (!e || !e->val) continue;
        ValueName *val = (ValueName *)e->val;
        if (*val == v) return e->key;
    }
    return NULL;
}

bool value_defined_in_block(Block *blk, ValueName v)
{
    if (!blk || v == 0) return false;
    for (Iter it = list_iter(blk->instrs); !iter_end(it);) {
        Instr *ins = iter_next(&it);
        if (ins && ins->dest == v && ins->op != IROP_NOP && ins->op != IROP_PHI)
            return true;
    }
    return false;
}
