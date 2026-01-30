#ifndef C51_GEN_H
#define C51_GEN_H

#include "c51_obj.h"
#include "../ssa.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

/* === Structure definitions === */
typedef struct MmioInfo {
    int addr;
    bool is_bit;
} MmioInfo;

typedef struct AddrInfo {
    const char *label;
    Ctype *mem_type;
    bool is_stack;
    int stack_off;
} AddrInfo;

/* === Forward declarations === */
typedef struct Interval Interval;

/* === Global state (extern) === */
extern Dict *g_addr_map;
extern Dict *g_const_map;
extern Dict *g_mmio_map;
extern Dict *g_val_type;
extern Dict *g_v16_map;
extern int g_v16_next;
extern int g_lower_id;

/* === Core utilities === */
void *gen_alloc(size_t size);
char *gen_strdup(const char *s);

/* === Asm instruction builders === */
const char *vreg(ValueName v);
AsmInstr *gen_instr_new(const char *op);
void gen_instr_add_arg(AsmInstr *ins, const char *arg);
void emit_ins0(Section *sec, const char *op);
void emit_ins1(Section *sec, const char *op, const char *a0);
void emit_ins2(Section *sec, const char *op, const char *a0, const char *a1);
void emit_ins3(Section *sec, const char *op, const char *a0, const char *a1, const char *a2);
void emit_label(Section *sec, const char *name);
void free_asminstr(AsmInstr *ins);

/* === Type/section helpers === */
SectionKind map_data_space(Ctype *type);
bool is_signed_type(Ctype *type);
bool is_register_mmio(Ctype *type);
bool is_register_bit(Ctype *type);

/* === Section management === */
Section *get_or_create_section(ObjFile *obj, const char *name, SectionKind kind);
int section_index_from_ptr(ObjFile *obj, Section *sec);

/* === Global data emission === */
void emit_global_data(ObjFile *obj, GlobalVar *g);

/* === Register allocation === */
int parse_vreg_id(const char *arg, bool *is_indirect);
void regalloc_section_asminstrs(Section *sec);

/* === Peephole optimization === */
bool is_reg_eq(const char *a, const char *b);
unsigned reg_bit(int r);
unsigned reg_mask_from_arg(const char *arg);
void reg_use_def(const AsmInstr *ins, unsigned *use, unsigned *def);
void shrink_call_saves(Section *sec);
const char *invert_jcc(const char *op);
void peephole_section_asminstrs(Section *sec);

/* === Symbol helpers === */
Symbol *find_symbol_by_name(ObjFile *obj, const char *name);
void define_label_symbol(ObjFile *obj, const char *name, int section, int value);

/* === Parsing helpers === */
bool is_ident(const char *s);
bool parse_int_val(const char *s, int *out);
int parse_reg_rn(const char *s);
int parse_indirect_rn(const char *s);
bool parse_immediate(const char *s, int *out);
bool parse_direct(const char *s, int *out);
bool parse_direct_symbol(const char *s, int *out, const char **label);
bool parse_bit_symbol(const char *s, int *out, const char **label);
bool parse_immediate_label(const char *s, int *out, const char **label);

/* === Encoding helpers === */
void emit_u8(Section *sec, unsigned char b);
void emit_u16(Section *sec, int v);
void emit_rel8(ObjFile *obj, Section *sec, const char *label);
void emit_abs16(ObjFile *obj, Section *sec, const char *label);
void emit_abs8(ObjFile *obj, Section *sec, const char *label);

/* === Instruction encoding === */
void encode_section_bytes(ObjFile *obj, Section *sec);

/* === SSA lowering helpers === */
char *new_label(const char *prefix);
const char *map_block_label(const char *func_name, const char *label);
int param_index(Func *f, const char *name);
Ctype *param_type(Func *f, const char *name);
int param_byte_offset(Func *f, const char *name, Ctype **out_type);
Block *find_block_by_label(Func *f, const char *label);
const char *find_var_for_value(Block *blk, ValueName v);
bool value_defined_in_block(Block *blk, ValueName v);

/* === Address/Value maps === */
char *vreg_key(ValueName v);
void mmio_map_put(const char *name, int addr, bool is_bit);
MmioInfo *mmio_map_get(const char *name);
void addr_map_put(ValueName v, const char *label, Ctype *mem_type);
AddrInfo *addr_map_get(ValueName v);
void addr_map_put_stack(ValueName v, int offset, Ctype *mem_type);
void const_map_put(ValueName v, int val);
bool const_map_get(ValueName v, int *out);
void val_type_put(ValueName v, Ctype *t);
Ctype *val_type_get(ValueName v);
int val_size(ValueName v);
int v16_addr(ValueName v);
bool is_v16_value(ValueName v);
void fmt_direct(char *buf, size_t n, int addr);
void emit_set_v16(Section *sec, int addr, int val);

/* === Data space === */
int data_space_kind(Ctype *type);
bool func_stack_offset(Func *f, const char *name, int *out);

/* === Block analysis === */
List *collect_block_defs(Block *blk);

/* === Phi moves === */
void emit_phi_moves_for_edge(Section *sec, Func *func, Block *from, const char *to_label);

/* === Stack operations === */
void emit_load_stack_param(Section *sec, int offset, const char *dst, bool use_fp);
void emit_load_stack_param_to_direct(Section *sec, int offset, int addr, bool use_fp);
void emit_stack_addr(Section *sec, int offset);
void emit_frame_prologue(Section *sec, int stack_size);
void emit_frame_epilogue(Section *sec, int stack_size);
void emit_interrupt_prologue(Section *sec);
void emit_interrupt_epilogue(Section *sec);

/* === Instruction selection === */
void emit_instr(Section *sec, Instr *ins, Func *func, Block *cur_block);

/* === Lowering/cleanup passes === */
void lower_section_asminstrs(Section *sec);
int instr_estimated_size(const AsmInstr *ins);
void fixup_short_jumps(Section *sec);

/* === Entry point === */
ObjFile *c51_gen_from_ssa(void *ssa);

#endif /* C51_GEN_H */
