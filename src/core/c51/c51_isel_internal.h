#ifndef C51_ISEL_INTERNAL_H
#define C51_ISEL_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "c51_isel.h"

typedef struct BrBitInfo {
    char *bit;
    bool invert;
} BrBitInfo;

typedef struct {
    int dst;
    int src; /* -2 表示 A */
} RegMove;

void free_br_bitinfo(void* p);
void br_invert_put(ISelContext* isel, Instr* br, bool invert);
bool br_invert_get(ISelContext* isel, Instr* br, bool* out_invert);
void br_bitinfo_put(ISelContext* isel, Instr* br, const char* bit, bool invert);
BrBitInfo* br_bitinfo_get(ISelContext* isel, Instr* br);

int reg_index_from_name(const char* s);
int alloc_temp_reg(ISelContext* isel, ValueName val, int size);
void free_temp_reg(ISelContext* isel, int reg, int size);
void emit_parallel_reg_moves(ISelContext* isel, RegMove* moves, int n, Instr* ins);

void emit_mov(ISelContext* isel, const char* dst, const char* src, Instr* ins);
void emit_set_bool_result(ISelContext* isel, Instr* ins, int dst_reg, int size, bool one);
void emit_copy_value(ISelContext* isel, Instr* ins, ValueName src, int dst_reg, int size);
void emit_add16_regs(ISelContext* isel,
                     const char* dst_hi, const char* dst_lo,
                     const char* src_hi, const char* src_lo,
                     Instr* ins);
void emit_sub16_regs(ISelContext* isel,
                     const char* dst_hi, const char* dst_lo,
                     const char* src_hi, const char* src_lo,
                     Instr* ins);

bool is_memory_operand_local(const char* op);
SectionKind get_symbol_section_kind(ISelContext* isel, const char* var_name);
int isel_reload_spill(ISelContext* isel, ValueName val, int size, Instr* ins);

int get_value_size(ISelContext* isel, ValueName val);
Ctype* get_value_type(ISelContext* isel, ValueName val);
int get_mem_space(Ctype* mem_type);
bool is_sbit_type(Ctype* mem_type);
const char* get_sbit_var_name(ISelContext* isel, Instr* ins);

const char* resolve_addr_symbol_in_block(Instr** instrs, int n, ValueName ptr);
bool instr_uses_value(Instr* ins, ValueName v);
int count_value_uses(Instr** instrs, int n, ValueName v);
bool find_const_in_block(Instr** instrs, int n, ValueName v, int64_t* out_val);
bool ne_is_compare_zero(Instr** instrs, int n, Instr* ne, ValueName* out_other);
Instr* find_def_instr_in_func(Func* f, ValueName v);
bool is_const_zero_def(Func* f, ValueName v);
bool ne_is_compare_zero_def(Func* f, Instr* ne, ValueName* out_other);

int parse_block_id(const char* label);
void block_label_name(char* out, size_t out_len, int id);

ValueName get_src1_value(Instr* ins);
ValueName get_src2_value(Instr* ins);
bool is_imm_operand(Instr* ins, int64_t* out_val);

int safe_alloc_reg_for_value(ISelContext* isel, ValueName val, int size);
int alloc_dest_reg(ISelContext* isel, Instr* ins, Instr* next, int size, bool try_bind);

Block* find_block_by_id(Func* f, int id);
int try_bind_result_to_phi_target(ISelContext* isel, Instr* ins, Instr* next, int size);
void emit_phi_copies_for_edge(ISelContext* isel, int pred_id, int succ_id, Instr* ins);
void precompute_sbit_br(ISelContext* isel, Instr** instrs, int n);
void precompute_br_simplify(ISelContext* isel, Instr** instrs, int n);

void emit_const(ISelContext* isel, Instr* ins);
void emit_add(ISelContext* isel, Instr* ins, Instr* next);
void emit_sub(ISelContext* isel, Instr* ins, Instr* next);
void emit_bitwise(ISelContext* isel, Instr* ins, Instr* next, const char* op_mnem);
void emit_not(ISelContext* isel, Instr* ins, Instr* next);
void emit_ne(ISelContext* isel, Instr* ins, Instr* next);
void emit_lnot(ISelContext* isel, Instr* ins, Instr* next);
void emit_cmp_eq(ISelContext* isel, Instr* ins, Instr* next);
void emit_cmp_lt_gt(ISelContext* isel, Instr* ins, Instr* next, bool is_gt);
void emit_cmp_le_ge(ISelContext* isel, Instr* ins, Instr* next, bool is_ge);

/* Signed compare helper codes used by C51 isel */
enum {
    SIGNED_CMP_LT = 0,
    SIGNED_CMP_GT = 1,
    SIGNED_CMP_LE = 2,
    SIGNED_CMP_GE = 3,
};

void emit_signed_cmp8_result(ISelContext* isel, Instr* ins, int dst_reg, int size, ValueName lhs, ValueName rhs, int cmp_type);
bool is_unsigned_compare(ISelContext* isel, ValueName a, ValueName b);
void emit_neg(ISelContext* isel, Instr* ins);
void emit_shift(ISelContext* isel, Instr* ins, bool is_shr);
void emit_mul(ISelContext* isel, Instr* ins, Instr* next);
void emit_div_mod(ISelContext* isel, Instr* ins, bool want_mod);
void emit_select(ISelContext* isel, Instr* ins);
void emit_simple_cast(ISelContext* isel, Instr* ins, bool sign_extend);
void emit_trunc(ISelContext* isel, Instr* ins);

void emit_offset(ISelContext* isel, Instr* ins);
void emit_store(ISelContext* isel, Instr* ins);
void emit_addr(ISelContext* isel, Instr* ins);
void emit_load(ISelContext* isel, Instr* ins);

void emit_ret(ISelContext* isel, Instr* ins);
void emit_jmp(ISelContext* isel, Instr* ins);
void emit_br(ISelContext* isel, Instr* ins);
void emit_inline_asm_instr(ISelContext* isel, Instr* ins);
void emit_call_instr(ISelContext* isel, Instr* ins, Instr* next);

#endif
