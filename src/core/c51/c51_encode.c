#include "c51_encode.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../dict.h"

typedef struct {
	ObjFile *obj;
	Section *sec;
	int sec_idx;
	int start_offset;
	Dict *labels;
	int current_pc;
	int current_scope;
	int failed;
} EncodeState;

typedef struct {
	int value;
	int is_symbolic;
	char symbol[128];
	int addend;
} ExprValue;

typedef struct {
	const AsmInstr *ins;
	const char *op;
	const char *arg1;
	const char *arg2;
	int pc;
	int size;
	int next_pc;
} InstrView;

typedef struct {
	int value;
	int scope;
} LabelLocation;

typedef struct {
	const char *name;
	int value;
} BuiltinDirect;

typedef struct {
	const char *op;
	const char *arg1;
	const char *arg2;
	unsigned char opcode;
	int size;
} FixedEncoding;

typedef struct {
	const char *op;
	unsigned char opcode;
	int size;
} OperandEncoding;

typedef struct {
	const char *op;
	unsigned char acc_opcode;
	unsigned char carry_opcode;
	unsigned char bit_opcode;
} BitUnaryEncoding;

typedef struct {
	const char *op;
	unsigned char acc_opcode;
	unsigned char direct_opcode;
	unsigned char reg_base;
	unsigned char dptr_opcode;
	int supports_dptr;
} IncDecEncoding;

typedef enum {
	OPERAND_KIND_NONE = 0,
	OPERAND_KIND_IMMEDIATE,
	OPERAND_KIND_ACC,
	OPERAND_KIND_CARRY,
	OPERAND_KIND_DPTR,
	OPERAND_KIND_REGISTER,
	OPERAND_KIND_INDIRECT_REG,
	OPERAND_KIND_OTHER
} OperandKind;

typedef struct {
	const char *op;
	unsigned char imm_opcode;
	unsigned char direct_opcode;
	unsigned char reg_base;
	unsigned char indir_r0_opcode;
	unsigned char indir_r1_opcode;
	unsigned char carry_bit_opcode;
	unsigned char direct_acc_opcode;
	int supports_carry_bit;
	int supports_direct_acc;
} AluEncoding;

typedef struct {
	unsigned char reg_base;
	unsigned char direct_opcode;
} DjnzEncoding;

#define OPERAND_ANY ((const char *)1)

static const BuiltinDirect builtin_directs[] = {
	{"P0", 0x80}, {"SP", 0x81}, {"DPL", 0x82}, {"DPH", 0x83},
	{"PCON", 0x87}, {"TCON", 0x88}, {"TMOD", 0x89}, {"TL0", 0x8A},
	{"TL1", 0x8B}, {"TH0", 0x8C}, {"TH1", 0x8D}, {"P1", 0x90},
	{"SCON", 0x98}, {"SBUF", 0x99}, {"P2", 0xA0}, {"IE", 0xA8},
	{"P3", 0xB0}, {"IP", 0xB8}, {"PSW", 0xD0}, {"ACC", 0xE0},
	{"B", 0xF0}, {NULL, 0}
};

static const FixedEncoding fixed_simple_encodings[] = {
	{"NOP", NULL, NULL, 0x00, 1},
	{"RET", NULL, NULL, 0x22, 1},
	{"RETI", NULL, NULL, 0x32, 1},
	{"MUL", "AB", NULL, 0xA4, 1},
	{"DIV", "AB", NULL, 0x84, 1},
	{"RLC", "A", NULL, 0x33, 1},
	{"RRC", "A", NULL, 0x13, 1},
	{"JMP", "@A+DPTR", NULL, 0x73, 1},
	{NULL, NULL, NULL, 0, 0}
};

static const FixedEncoding fixed_rel_jump_encodings[] = {
	{"SJMP", OPERAND_ANY, NULL, 0x80, 2},
	{"JNZ", OPERAND_ANY, NULL, 0x70, 2},
	{"JZ", OPERAND_ANY, NULL, 0x60, 2},
	{"JC", OPERAND_ANY, NULL, 0x40, 2},
	{"JNC", OPERAND_ANY, NULL, 0x50, 2},
	{NULL, NULL, NULL, 0, 0}
};

static const FixedEncoding fixed_abs16_encodings[] = {
	{"LCALL", OPERAND_ANY, NULL, 0x12, 3},
	{"LJMP", OPERAND_ANY, NULL, 0x02, 3},
	{NULL, NULL, NULL, 0, 0}
};

static const FixedEncoding fixed_bit_branch_encodings[] = {
	{"JB", OPERAND_ANY, OPERAND_ANY, 0x20, 3},
	{"JNB", OPERAND_ANY, OPERAND_ANY, 0x30, 3},
	{"JBC", OPERAND_ANY, OPERAND_ANY, 0x10, 3},
	{NULL, NULL, NULL, 0, 0}
};

static const FixedEncoding fixed_mem_acc_encodings[] = {
	{"MOVX", "@DPTR", "A", 0xF0, 1},
	{"MOVX", "A", "@DPTR", 0xE0, 1},
	{"MOVC", "A", "@A+DPTR", 0x93, 1},
	{NULL, NULL, NULL, 0, 0}
};

static const OperandEncoding direct_operand_encodings[] = {
	{"PUSH", 0xC0, 2},
	{"POP", 0xD0, 2},
	{NULL, 0, 0}
};

static const BitUnaryEncoding bit_unary_encodings[] = {
	{"SETB", 0x00, 0xD3, 0xD2},
	{"CLR", 0xE4, 0xC3, 0xC2},
	{"CPL", 0xF4, 0xB3, 0xB2},
	{NULL, 0, 0, 0}
};

static const IncDecEncoding inc_dec_encodings[] = {
	{"INC", 0x04, 0x05, 0x08, 0xA3, 1},
	{"DEC", 0x14, 0x15, 0x18, 0x00, 0},
	{NULL, 0, 0, 0, 0, 0}
};

static const AluEncoding alu_encodings[] = {
	{"ADD", 0x24, 0x25, 0x28, 0x26, 0x27, 0x00, 0x00, 0, 0},
	{"ADDC", 0x34, 0x35, 0x38, 0x36, 0x37, 0x00, 0x00, 0, 0},
	{"SUBB", 0x94, 0x95, 0x98, 0x96, 0x97, 0x00, 0x00, 0, 0},
	{"ANL", 0x54, 0x55, 0x58, 0x56, 0x57, 0x82, 0x52, 1, 1},
	{"ORL", 0x44, 0x45, 0x48, 0x46, 0x47, 0x72, 0x42, 1, 1},
	{"XRL", 0x64, 0x65, 0x68, 0x66, 0x67, 0x00, 0x62, 0, 1},
	{NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0}
};

static const DjnzEncoding djnz_encoding = {0xD8, 0xD5};

static char *dup_trim(const char *text)
{
	size_t start = 0;
	size_t end;
	char *out;

	if (!text) return strdup("");
	end = strlen(text);
	while (text[start] && isspace((unsigned char)text[start])) start++;
	while (end > start && isspace((unsigned char)text[end - 1])) end--;

	out = malloc(end - start + 1);
	if (!out) return NULL;
	memcpy(out, text + start, end - start);
	out[end - start] = '\0';
	return out;
}

static int is_label_instr(const AsmInstr *ins)
{
	size_t len;
	if (!ins || !ins->op) return 0;
	len = strlen(ins->op);
	return len > 0 && ins->op[len - 1] == ':';
}

static int is_comment_instr(const AsmInstr *ins)
{
	return ins && ins->op && ins->op[0] == ';';
}

static int is_function_local_label_name(const char *name)
{
	return name && name[0] == 'L';
}

static int reg_index(const char *name)
{
	if (!name || name[0] != 'R' || name[1] < '0' || name[1] > '7' || name[2] != '\0') {
		return -1;
	}
	return name[1] - '0';
}

static int is_immediate(const char *operand)
{
	return operand && operand[0] == '#';
}

static int is_acc(const char *operand)
{
	return operand && strcmp(operand, "A") == 0;
}

static int is_carry(const char *operand)
{
	return operand && strcmp(operand, "C") == 0;
}

static int is_dptr(const char *operand)
{
	return operand && strcmp(operand, "DPTR") == 0;
}

static int is_indirect_reg(const char *operand);

static OperandKind operand_kind(const char *operand)
{
	if (!operand) return OPERAND_KIND_NONE;
	if (is_immediate(operand)) return OPERAND_KIND_IMMEDIATE;
	if (is_acc(operand)) return OPERAND_KIND_ACC;
	if (is_carry(operand)) return OPERAND_KIND_CARRY;
	if (is_dptr(operand)) return OPERAND_KIND_DPTR;
	if (reg_index(operand) >= 0) return OPERAND_KIND_REGISTER;
	if (is_indirect_reg(operand)) return OPERAND_KIND_INDIRECT_REG;
	return OPERAND_KIND_OTHER;
}

static int is_indirect_reg(const char *operand)
{
	return operand && (strcmp(operand, "@R0") == 0 || strcmp(operand, "@R1") == 0);
}

static int indirect_reg_index(const char *operand)
{
	if (!operand || operand[0] != '@' || operand[1] != 'R' || operand[3] != '\0') return -1;
	if (operand[2] < '0' || operand[2] > '7') return -1;
	return operand[2] - '0';
}

static int is_movx_at_dptr(const char *operand)
{
	return operand && strcmp(operand, "@DPTR") == 0;
}

static int is_movc_at_a_dptr(const char *operand)
{
	return operand && strcmp(operand, "@A+DPTR") == 0;
}

static Symbol *find_symbol_exact(const ObjFile *obj, const char *name)
{
	Iter it;
	if (!obj || !name) return NULL;
	for (it = list_iter(obj->symbols); !iter_end(it);) {
		Symbol *sym = iter_next(&it);
		if (sym && sym->name && strcmp(sym->name, name) == 0) return sym;
	}
	return NULL;
}

static Symbol *find_symbol_for_asm(const ObjFile *obj, const char *name)
{
	Symbol *sym;
	if (!name) return NULL;
	sym = find_symbol_exact(obj, name);
	if (sym) return sym;
	if (name[0] == '_') {
		sym = find_symbol_exact(obj, name + 1);
		if (sym && sym->kind == SYM_FUNC) return sym;
	}
	return NULL;
}

static int lookup_builtin_direct(const char *name, int *value)
{
	int i;
	if (!name) return 0;
	for (i = 0; builtin_directs[i].name; i++) {
		if (strcmp(name, builtin_directs[i].name) == 0) {
			if (value) *value = builtin_directs[i].value;
			return 1;
		}
	}
	return 0;
}

static int parse_number(const char *text, int *value)
{
	char *trimmed;
	char *endptr;
	long parsed;
	size_t len;

	if (!text || !value) return 0;
	trimmed = dup_trim(text);
	if (!trimmed || !*trimmed) {
		free(trimmed);
		return 0;
	}

	len = strlen(trimmed);
	if (len > 1 && (trimmed[len - 1] == 'H' || trimmed[len - 1] == 'h')) {
		trimmed[len - 1] = '\0';
		parsed = strtol(trimmed, &endptr, 16);
	} else {
		parsed = strtol(trimmed, &endptr, 0);
	}

	if (*endptr != '\0') {
		free(trimmed);
		return 0;
	}

	*value = (int)parsed;
	free(trimmed);
	return 1;
}

static int strip_outer_parens_inplace(char *text)
{
	size_t len;
	int depth;
	size_t i;
	if (!text) return 0;
	len = strlen(text);
	if (len < 2 || text[0] != '(' || text[len - 1] != ')') return 0;

	depth = 0;
	for (i = 0; i + 1 < len; i++) {
		if (text[i] == '(') depth++;
		else if (text[i] == ')') depth--;
		if (depth == 0 && i + 1 < len - 1) return 0;
	}

	memmove(text, text + 1, len - 2);
	text[len - 2] = '\0';
	return 1;
}

static int lookup_local_label(EncodeState *state, const char *name, int *value)
{
	List *found;
	Iter it;
	int best_value = 0;
	int best_distance = 0x7fffffff;
	int require_scope;
	char *key;
	if (!state || !state->labels || !name) return 0;
	key = dup_trim(name);
	if (!key) return 0;
	found = dict_get(state->labels, key);
	require_scope = is_function_local_label_name(key);
	free(key);
	if (!found) return 0;
	for (it = list_iter(found); !iter_end(it);) {
		LabelLocation *candidate = iter_next(&it);
		int distance;
		if (!candidate) continue;
		if (require_scope && candidate->scope != state->current_scope) continue;
		distance = candidate->value - state->current_pc;
		if (distance < 0) distance = -distance;
		if (distance < best_distance) {
			best_distance = distance;
			best_value = candidate->value;
		}
	}
	if (best_distance == 0x7fffffff) return 0;
	if (value) *value = best_value;
	return 1;
}

static void free_label_positions(void *value)
{
	List *positions = value;
	if (!positions) return;
	while (!list_empty(positions)) {
		free(list_shift(positions));
	}
	free(positions);
}

static int eval_expr_internal(EncodeState *state, const char *text, ExprValue *out)
{
	char *expr;
	size_t len;
	int depth;
	int i;
	int number;
	int local_value;
	int builtin_value;
	Symbol *sym;

	if (!text || !out) return 0;
	expr = dup_trim(text);
	if (!expr) return 0;
	while (strip_outer_parens_inplace(expr)) {
	}

	len = strlen(expr);
	depth = 0;
	for (i = (int)len - 1; i >= 0; i--) {
		if (expr[i] == ')') depth++;
		else if (expr[i] == '(') depth--;
		else if (depth == 0 && i > 0 && (expr[i] == '+' || expr[i] == '-')) {
			ExprValue lhs;
			ExprValue rhs;
			char op = expr[i];
			expr[i] = '\0';
			memset(&lhs, 0, sizeof(lhs));
			memset(&rhs, 0, sizeof(rhs));
			if (!eval_expr_internal(state, expr, &lhs) || !eval_expr_internal(state, expr + i + 1, &rhs)) {
				free(expr);
				return 0;
			}
			if (lhs.is_symbolic && rhs.is_symbolic) {
				free(expr);
				return 0;
			}
			if (lhs.is_symbolic) {
				*out = lhs;
				out->addend += (op == '+') ? rhs.value : -rhs.value;
				free(expr);
				return 1;
			}
			if (rhs.is_symbolic) {
				if (op != '+') {
					free(expr);
					return 0;
				}
				*out = rhs;
				out->addend += lhs.value;
				free(expr);
				return 1;
			}
			out->value = (op == '+') ? (lhs.value + rhs.value) : (lhs.value - rhs.value);
			out->is_symbolic = 0;
			out->symbol[0] = '\0';
			out->addend = 0;
			free(expr);
			return 1;
		}
	}

	memset(out, 0, sizeof(*out));
	if (parse_number(expr, &number)) {
		out->value = number;
		free(expr);
		return 1;
	}
	if (lookup_local_label(state, expr, &local_value)) {
		out->value = local_value;
		free(expr);
		return 1;
	}
	if (lookup_builtin_direct(expr, &builtin_value)) {
		out->value = builtin_value;
		free(expr);
		return 1;
	}

	sym = find_symbol_for_asm(state->obj, expr);
	if (sym) {
		if (sym->section < 0 && !(sym->flags & SYM_FLAG_EXTERN)) {
			out->value = sym->value;
		} else {
			out->is_symbolic = 1;
			strncpy(out->symbol, sym->name, sizeof(out->symbol) - 1);
			out->symbol[sizeof(out->symbol) - 1] = '\0';
		}
		free(expr);
		return 1;
	}

	out->is_symbolic = 1;
	strncpy(out->symbol, expr, sizeof(out->symbol) - 1);
	out->symbol[sizeof(out->symbol) - 1] = '\0';
	free(expr);
	return 1;
}

static int eval_expr(EncodeState *state, const char *text, ExprValue *out)
{
	if (!eval_expr_internal(state, text, out)) return 0;
	if (!out->is_symbolic) out->value += out->addend;
	return 1;
}

static int eval_immediate(EncodeState *state, const char *operand, ExprValue *out)
{
	if (!is_immediate(operand)) return 0;
	return eval_expr(state, operand + 1, out);
}

static int eval_direct(EncodeState *state, const char *operand, ExprValue *out)
{
	return eval_expr(state, operand, out);
}

static int eval_bit(EncodeState *state, const char *operand, ExprValue *out)
{
	char *dot;
	char *base;
	int bit;
	ExprValue base_expr;

	if (!operand || !out) return 0;
	base = dup_trim(operand);
	if (!base) return 0;
	dot = strrchr(base, '.');
	if (dot) {
		*dot++ = '\0';
		if (*dot >= '0' && *dot <= '7' && dot[1] == '\0') {
			bit = *dot - '0';
			if (!eval_expr(state, base, &base_expr) || base_expr.is_symbolic) {
				free(base);
				return 0;
			}
			*out = base_expr;
			out->value = base_expr.value + bit;
			out->is_symbolic = 0;
			free(base);
			return 1;
		}
	}
	free(base);
	return eval_expr(state, operand, out);
}

static int split_cjne_arg2(const char *arg2, char **cmp_operand, char **label)
{
	char *copy;
	char *comma;
	if (!arg2 || !cmp_operand || !label) return 0;
	copy = dup_trim(arg2);
	if (!copy) return 0;
	comma = strchr(copy, ',');
	if (!comma) {
		free(copy);
		return 0;
	}
	*comma = '\0';
	*cmp_operand = dup_trim(copy);
	*label = dup_trim(comma + 1);
	free(copy);
	return *cmp_operand && *label;
}

static InstrView make_instr_view(const AsmInstr *ins, int pc)
{
	InstrView view;
	memset(&view, 0, sizeof(view));
	view.ins = ins;
	view.op = ins ? ins->op : NULL;
	view.arg1 = (ins && ins->args && ins->args->len > 0) ? list_get(ins->args, 0) : NULL;
	view.arg2 = (ins && ins->args && ins->args->len > 1) ? list_get(ins->args, 1) : NULL;
	view.pc = pc;
	return view;
}

static int operand_matches(const char *actual, const char *expected)
{
	if (expected == OPERAND_ANY) return actual != NULL;
	if (!expected) return !actual;
	return actual && strcmp(actual, expected) == 0;
}

static const FixedEncoding *find_fixed_encoding(const FixedEncoding *table, const InstrView *view)
{
	const FixedEncoding *entry;
	if (!table || !view || !view->op) return NULL;
	for (entry = table; entry->op; entry++) {
		if (strcmp(view->op, entry->op) != 0) continue;
		if (!operand_matches(view->arg1, entry->arg1)) continue;
		if (!operand_matches(view->arg2, entry->arg2)) continue;
		return entry;
	}
	return NULL;
}

static const OperandEncoding *find_operand_encoding(const OperandEncoding *table, const char *op)
{
	const OperandEncoding *entry;
	if (!table || !op) return NULL;
	for (entry = table; entry->op; entry++) {
		if (strcmp(op, entry->op) == 0) return entry;
	}
	return NULL;
}

static const BitUnaryEncoding *find_bit_unary_encoding(const char *op)
{
	const BitUnaryEncoding *entry;
	if (!op) return NULL;
	for (entry = bit_unary_encodings; entry->op; entry++) {
		if (strcmp(op, entry->op) == 0) return entry;
	}
	return NULL;
}

static const IncDecEncoding *find_inc_dec_encoding(const char *op)
{
	const IncDecEncoding *entry;
	if (!op) return NULL;
	for (entry = inc_dec_encodings; entry->op; entry++) {
		if (strcmp(op, entry->op) == 0) return entry;
	}
	return NULL;
}

static const AluEncoding *find_alu_encoding(const char *op)
{
	const AluEncoding *entry;
	if (!op) return NULL;
	for (entry = alu_encodings; entry->op; entry++) {
		if (strcmp(op, entry->op) == 0) return entry;
	}
	return NULL;
}

static int size_simple_op(const InstrView *view)
{
	const FixedEncoding *entry;
	if (!view || !view->op) return 0;
	entry = find_fixed_encoding(fixed_simple_encodings, view);
	if (entry) return entry->size;
	return 0;
}

static int size_cjne_view(const InstrView *view)
{
	char *cmp_operand = NULL;
	char *label = NULL;
	int size = -1;
	if (!view || !view->op || strcmp(view->op, "CJNE") != 0) return 0;
	if (view->arg1 && is_acc(view->arg1) && split_cjne_arg2(view->arg2, &cmp_operand, &label)) {
		if (is_immediate(cmp_operand)) size = 3;
		else if (reg_index(cmp_operand) >= 0 || is_indirect_reg(cmp_operand)) size = 5;
		else size = 3;
	}
	free(cmp_operand);
	free(label);
	return size;
}

static int size_long_jump_view(const InstrView *view)
{
	const FixedEncoding *entry;
	if (!view || !view->op) return 0;
	entry = find_fixed_encoding(fixed_abs16_encodings, view);
	if (entry) return entry->size;
	return 0;
}

static int size_rel_jump_view(const InstrView *view)
{
	const FixedEncoding *entry;
	if (!view || !view->op) return 0;
	entry = find_fixed_encoding(fixed_rel_jump_encodings, view);
	if (entry) return entry->size;
	return 0;
}

static int size_bit_branch_view(const InstrView *view)
{
	const FixedEncoding *entry;
	if (!view || !view->op) return 0;
	entry = find_fixed_encoding(fixed_bit_branch_encodings, view);
	if (entry) return entry->size;
	return 0;
}

static int size_stack_view(const InstrView *view)
{
	const OperandEncoding *entry;
	if (!view || !view->op) return 0;
	entry = find_operand_encoding(direct_operand_encodings, view->op);
	if (entry && view->arg1 && !view->arg2) return entry->size;
	return 0;
}

static int size_bit_op_view(const InstrView *view)
{
	const BitUnaryEncoding *entry;
	if (!view || !view->op) return 0;
	entry = find_bit_unary_encoding(view->op);
	if (!entry || !view->arg1 || view->arg2) return 0;
	if (is_acc(view->arg1) || is_carry(view->arg1)) return 1;
	return 2;
	return 0;
}

static int size_inc_dec_view(const InstrView *view)
{
	const IncDecEncoding *entry;
	if (!view || !view->op) return 0;
	entry = find_inc_dec_encoding(view->op);
	if (!entry || !view->arg1 || view->arg2) return 0;
	if (is_acc(view->arg1) || reg_index(view->arg1) >= 0) return 1;
	if (entry->supports_dptr && is_dptr(view->arg1)) return 1;
	return 2;
	return 0;
}

static int size_movx_movc_view(const InstrView *view)
{
	const FixedEncoding *entry;
	if (!view || !view->op) return 0;
	entry = find_fixed_encoding(fixed_mem_acc_encodings, view);
	if (entry) return entry->size;
	return 0;
}

static int size_djnz_view(const InstrView *view)
{
	if (!view || !view->op || strcmp(view->op, "DJNZ") != 0) return 0;
	if (operand_kind(view->arg1) == OPERAND_KIND_REGISTER) return 2;
	return 3;
}

static int size_mov_view(const InstrView *view)
{
	int reg;
	if (!view || !view->op || strcmp(view->op, "MOV") != 0) return 0;
	if (view->arg1 && view->arg2 && is_dptr(view->arg1) && is_immediate(view->arg2)) return 3;
	if (view->arg1 && view->arg2 && (is_carry(view->arg1) || is_carry(view->arg2))) return 2;
	if (view->arg1 && view->arg2 && is_acc(view->arg1)) {
		if (is_immediate(view->arg2)) return 2;
		if (reg_index(view->arg2) >= 0 || is_indirect_reg(view->arg2)) return 1;
		return 2;
	}
	reg = reg_index(view->arg1);
	if (view->arg1 && reg >= 0) {
		if (reg_index(view->arg2) >= 0) return 2;
		if (is_acc(view->arg2) || is_indirect_reg(view->arg2)) return 1;
		return is_immediate(view->arg2) ? 2 : 2;
	}
	if (view->arg1 && view->arg2 && is_indirect_reg(view->arg1)) {
		if (is_immediate(view->arg2)) return 2;
		if (reg_index(view->arg2) >= 0) return 2;
		if (is_acc(view->arg2)) return 1;
		return 2;
	}
	if (view->arg1 && view->arg2) {
		if (is_indirect_reg(view->arg2)) return 2;
		if (is_acc(view->arg2) || reg_index(view->arg2) >= 0 || is_indirect_reg(view->arg2)) return 2;
		if (is_immediate(view->arg2)) return 3;
		return 3;
	}
	return -1;
}

static int size_alu_view(const InstrView *view)
{
	const AluEncoding *entry;
	entry = find_alu_encoding(view ? view->op : NULL);
	if (!entry || !view || !view->arg1 || !view->arg2) return 0;
	if (operand_kind(view->arg1) == OPERAND_KIND_ACC) {
		switch (operand_kind(view->arg2)) {
		case OPERAND_KIND_IMMEDIATE:
		case OPERAND_KIND_OTHER:
			return 2;
		case OPERAND_KIND_REGISTER:
		case OPERAND_KIND_INDIRECT_REG:
			return 1;
		default:
			return 0;
		}
	}
	if (entry->supports_carry_bit && operand_kind(view->arg1) == OPERAND_KIND_CARRY) return 2;
	if (entry->supports_direct_acc && operand_kind(view->arg2) == OPERAND_KIND_ACC) return 2;
	return 0;
}

static int instruction_size(const AsmInstr *ins)
{
	InstrView view;
	int size;

	if (!ins || is_comment_instr(ins) || is_label_instr(ins)) return 0;
	view = make_instr_view(ins, 0);
	if ((size = size_simple_op(&view)) > 0) return size;
	if ((size = size_cjne_view(&view)) != 0) return size;
	if ((size = size_long_jump_view(&view)) > 0) return size;
	if ((size = size_rel_jump_view(&view)) > 0) return size;
	if ((size = size_bit_branch_view(&view)) > 0) return size;
	if ((size = size_stack_view(&view)) > 0) return size;
	if ((size = size_bit_op_view(&view)) > 0) return size;
	if ((size = size_inc_dec_view(&view)) > 0) return size;
	if ((size = size_movx_movc_view(&view)) > 0) return size;
	if ((size = size_djnz_view(&view)) > 0) return size;
	if ((size = size_mov_view(&view)) != 0) return size;
	if ((size = size_alu_view(&view)) > 0) return size;
	return -1;
}

static void report_encode_error(EncodeState *state, const AsmInstr *ins, const char *message)
{
	fprintf(stderr, "c51_encode: %s (section=%d, op=%s)\n",
			message ? message : "encode error",
			state ? state->sec_idx : -1,
			(ins && ins->op) ? ins->op : "<null>");
	if (state) state->failed = 1;
}

static int checked_rel8(EncodeState *state, const AsmInstr *ins, int from, int target)
{
	int rel = target - from;
	if (rel < -128 || rel > 127) {
		report_encode_error(state, ins, "relative branch out of range");
		return 0;
	}
	return rel & 0xFF;
}

static int emit_abs8_or_reloc(EncodeState *state, unsigned char *out, int pos,
							  const AsmInstr *ins, const ExprValue *expr)
{
	if (!expr) return 0;
	if (expr->is_symbolic) {
		obj_add_reloc(state->obj, state->sec_idx, pos, RELOC_ABS8, expr->symbol, expr->addend);
		out[pos - state->start_offset] = 0;
		return 1;
	}
	if (expr->value < 0 || expr->value > 0xFF) {
		report_encode_error(state, ins, "8-bit operand out of range");
		return 0;
	}
	out[pos - state->start_offset] = (unsigned char)(expr->value & 0xFF);
	return 1;
}

static int emit_abs16_or_reloc(EncodeState *state, unsigned char *out, int pos,
							   const AsmInstr *ins, const ExprValue *expr)
{
	if (!expr) return 0;
	if (expr->is_symbolic) {
		obj_add_reloc(state->obj, state->sec_idx, pos, RELOC_ABS16, expr->symbol, expr->addend);
		out[pos - state->start_offset] = 0;
		out[pos - state->start_offset + 1] = 0;
		return 1;
	}
	out[pos - state->start_offset] = (unsigned char)((expr->value >> 8) & 0xFF);
	out[pos - state->start_offset + 1] = (unsigned char)(expr->value & 0xFF);
	return 1;
}

static int encode_simple_op(EncodeState *state, const InstrView *view, unsigned char *out)
{
	const FixedEncoding *entry;
	if (!view || !view->op) return 0;
	entry = find_fixed_encoding(fixed_simple_encodings, view);
	if (entry) {
		out[view->pc - state->start_offset] = entry->opcode;
		return view->size;
	}
	return 0;
}

static int encode_long_jump(EncodeState *state, const InstrView *view, unsigned char *out)
{
	const FixedEncoding *entry;
	ExprValue expr;
	if (!view || !view->op) return 0;
	entry = find_fixed_encoding(fixed_abs16_encodings, view);
	if (!entry) return 0;
	out[view->pc - state->start_offset] = entry->opcode;
	if (!eval_expr(state, view->arg1, &expr) || !emit_abs16_or_reloc(state, out, view->pc + 1, view->ins, &expr)) return -1;
	return view->size;
}

static int encode_cjne(EncodeState *state, const InstrView *view, unsigned char *out)
{
	ExprValue expr;
	char *cmp_operand = NULL;
	char *label = NULL;
	int reg;
	int target;
	if (!view || !view->op || strcmp(view->op, "CJNE") != 0) return 0;
	if (!(view->arg1 && is_acc(view->arg1) && split_cjne_arg2(view->arg2, &cmp_operand, &label))) {
		report_encode_error(state, view->ins, "unsupported CJNE form");
		free(cmp_operand);
		free(label);
		return -1;
	}
	if (!eval_expr(state, label, &expr) || expr.is_symbolic) {
		report_encode_error(state, view->ins, "CJNE requires local label target");
		free(cmp_operand);
		free(label);
		return -1;
	}
	target = expr.value;
	if (is_immediate(cmp_operand)) {
		out[view->pc - state->start_offset] = 0xB4;
		if (!eval_immediate(state, cmp_operand, &expr) || !emit_abs8_or_reloc(state, out, view->pc + 1, view->ins, &expr)) {
			free(cmp_operand);
			free(label);
			return -1;
		}
		out[view->pc - state->start_offset + 2] = (unsigned char)checked_rel8(state, view->ins, view->next_pc, target);
		free(cmp_operand);
		free(label);
		return view->size;
	}
	reg = reg_index(cmp_operand);
	if (reg >= 0) {
		out[view->pc - state->start_offset] = 0x88 + reg;
		out[view->pc - state->start_offset + 1] = 0xF0;
		out[view->pc - state->start_offset + 2] = 0xB5;
		out[view->pc - state->start_offset + 3] = 0xF0;
		out[view->pc - state->start_offset + 4] = (unsigned char)checked_rel8(state, view->ins, view->pc + view->size, target);
		free(cmp_operand);
		free(label);
		return view->size;
	}
	if (is_indirect_reg(cmp_operand)) {
		out[view->pc - state->start_offset] = (strcmp(cmp_operand, "@R0") == 0) ? 0x86 : 0x87;
		out[view->pc - state->start_offset + 1] = 0xF0;
		out[view->pc - state->start_offset + 2] = 0xB5;
		out[view->pc - state->start_offset + 3] = 0xF0;
		out[view->pc - state->start_offset + 4] = (unsigned char)checked_rel8(state, view->ins, view->pc + view->size, target);
		free(cmp_operand);
		free(label);
		return view->size;
	}
	out[view->pc - state->start_offset] = 0xB5;
	if (!eval_direct(state, cmp_operand, &expr) || !emit_abs8_or_reloc(state, out, view->pc + 1, view->ins, &expr)) {
		free(cmp_operand);
		free(label);
		return -1;
	}
	out[view->pc - state->start_offset + 2] = (unsigned char)checked_rel8(state, view->ins, view->next_pc, target);
	free(cmp_operand);
	free(label);
	return view->size;
}

static int encode_rel_jump(EncodeState *state, const InstrView *view, unsigned char *out)
{
	const FixedEncoding *entry;
	ExprValue expr;
	int target;
	if (!view || !view->op) return 0;
	entry = find_fixed_encoding(fixed_rel_jump_encodings, view);
	if (!entry) return 0;
	out[view->pc - state->start_offset] = entry->opcode;
	if (!eval_expr(state, view->arg1, &expr) || expr.is_symbolic) {
		report_encode_error(state, view->ins, "relative jump requires local label");
		return -1;
	}
	target = expr.value;
	out[view->pc - state->start_offset + 1] = (unsigned char)checked_rel8(state, view->ins, view->next_pc, target);
	return view->size;
}

static int encode_bit_branch(EncodeState *state, const InstrView *view, unsigned char *out)
{
	const FixedEncoding *entry;
	ExprValue expr;
	int target;
	if (!view || !view->op) return 0;
	entry = find_fixed_encoding(fixed_bit_branch_encodings, view);
	if (!entry) return 0;
	out[view->pc - state->start_offset] = entry->opcode;
	if (!eval_bit(state, view->arg1, &expr) || expr.is_symbolic || !emit_abs8_or_reloc(state, out, view->pc + 1, view->ins, &expr)) return -1;
	if (!eval_expr(state, view->arg2, &expr) || expr.is_symbolic) {
		report_encode_error(state, view->ins, "bit branch requires local label");
		return -1;
	}
	target = expr.value;
	out[view->pc - state->start_offset + 2] = (unsigned char)checked_rel8(state, view->ins, view->next_pc, target);
	return view->size;
}

static int encode_stack_op(EncodeState *state, const InstrView *view, unsigned char *out)
{
	const OperandEncoding *entry;
	ExprValue expr;
	if (!view || !view->op) return 0;
	entry = find_operand_encoding(direct_operand_encodings, view->op);
	if (!entry || !view->arg1 || view->arg2) return 0;
	out[view->pc - state->start_offset] = entry->opcode;
	if (!eval_direct(state, view->arg1, &expr) || !emit_abs8_or_reloc(state, out, view->pc + 1, view->ins, &expr)) return -1;
	return view->size;
}

static int encode_bit_op(EncodeState *state, const InstrView *view, unsigned char *out)
{
	const BitUnaryEncoding *entry;
	ExprValue expr;
	if (!view || !view->op) return 0;
	entry = find_bit_unary_encoding(view->op);
	if (!entry || !view->arg1 || view->arg2) return 0;
	if (view->arg1 && is_acc(view->arg1)) {
		out[view->pc - state->start_offset] = entry->acc_opcode;
		return view->size;
	}
	if (view->arg1 && is_carry(view->arg1)) {
		out[view->pc - state->start_offset] = entry->carry_opcode;
		return view->size;
	}
	out[view->pc - state->start_offset] = entry->bit_opcode;
	if (!eval_bit(state, view->arg1, &expr) || !emit_abs8_or_reloc(state, out, view->pc + 1, view->ins, &expr)) return -1;
	return view->size;
}

static int encode_inc_dec(EncodeState *state, const InstrView *view, unsigned char *out)
{
	const IncDecEncoding *entry;
	ExprValue expr;
	int reg;
	if (!view || !view->op) return 0;
	entry = find_inc_dec_encoding(view->op);
	if (!entry || !view->arg1 || view->arg2) return 0;
	if (view->arg1 && is_acc(view->arg1)) {
		out[view->pc - state->start_offset] = entry->acc_opcode;
		return view->size;
	}
	if (entry->supports_dptr && view->arg1 && is_dptr(view->arg1)) {
		out[view->pc - state->start_offset] = entry->dptr_opcode;
		return view->size;
	}
	reg = reg_index(view->arg1);
	if (reg >= 0) {
		out[view->pc - state->start_offset] = entry->reg_base + reg;
		return view->size;
	}
	out[view->pc - state->start_offset] = entry->direct_opcode;
	if (!eval_direct(state, view->arg1, &expr) || !emit_abs8_or_reloc(state, out, view->pc + 1, view->ins, &expr)) return -1;
	return view->size;
}

static int encode_movx_movc(EncodeState *state, const InstrView *view, unsigned char *out)
{
	const FixedEncoding *entry;
	if (!view || !view->op) return 0;
	entry = find_fixed_encoding(fixed_mem_acc_encodings, view);
	if (entry) {
		out[view->pc - state->start_offset] = entry->opcode;
		return view->size;
	}
	if (!strcmp(view->op, "MOVX")) {
		report_encode_error(state, view->ins, "unsupported MOVX form");
		return -1;
	}
	if (!strcmp(view->op, "MOVC")) {
		report_encode_error(state, view->ins, "unsupported MOVC form");
		return -1;
	}
	return 0;
}

static int encode_djnz(EncodeState *state, const InstrView *view, unsigned char *out)
{
	ExprValue expr;
	int reg;
	int target;
	if (!view || !view->op || strcmp(view->op, "DJNZ") != 0) return 0;
	reg = reg_index(view->arg1);
	if (reg >= 0) {
		out[view->pc - state->start_offset] = djnz_encoding.reg_base + reg;
		if (!eval_expr(state, view->arg2, &expr) || expr.is_symbolic) {
			report_encode_error(state, view->ins, "DJNZ requires local label");
			return -1;
		}
		target = expr.value;
		out[view->pc - state->start_offset + 1] = (unsigned char)checked_rel8(state, view->ins, view->next_pc, target);
		return view->size;
	}
	out[view->pc - state->start_offset] = djnz_encoding.direct_opcode;
	if (!eval_direct(state, view->arg1, &expr) || !emit_abs8_or_reloc(state, out, view->pc + 1, view->ins, &expr)) return -1;
	if (!eval_expr(state, view->arg2, &expr) || expr.is_symbolic) {
		report_encode_error(state, view->ins, "DJNZ requires local label");
		return -1;
	}
	target = expr.value;
	out[view->pc - state->start_offset + 2] = (unsigned char)checked_rel8(state, view->ins, view->next_pc, target);
	return view->size;
}

static int encode_mov(EncodeState *state, const InstrView *view, unsigned char *out)
{
	ExprValue expr;
	int reg;
	if (!view || !view->op || strcmp(view->op, "MOV") != 0) return 0;
	reg = reg_index(view->arg1);
	if (view->arg1 && view->arg2 && is_dptr(view->arg1) && is_immediate(view->arg2)) {
		out[view->pc - state->start_offset] = 0x90;
		if (!eval_immediate(state, view->arg2, &expr) || !emit_abs16_or_reloc(state, out, view->pc + 1, view->ins, &expr)) return -1;
		return view->size;
	}
	if (view->arg1 && view->arg2 && is_carry(view->arg1)) {
		out[view->pc - state->start_offset] = 0xA2;
		if (!eval_bit(state, view->arg2, &expr) || !emit_abs8_or_reloc(state, out, view->pc + 1, view->ins, &expr)) return -1;
		return view->size;
	}
	if (view->arg1 && view->arg2 && is_carry(view->arg2)) {
		out[view->pc - state->start_offset] = 0x92;
		if (!eval_bit(state, view->arg1, &expr) || !emit_abs8_or_reloc(state, out, view->pc + 1, view->ins, &expr)) return -1;
		return view->size;
	}
	if (view->arg1 && view->arg2 && is_acc(view->arg1)) {
		if (is_immediate(view->arg2)) {
			out[view->pc - state->start_offset] = 0x74;
			if (!eval_immediate(state, view->arg2, &expr) || !emit_abs8_or_reloc(state, out, view->pc + 1, view->ins, &expr)) return -1;
			return view->size;
		}
		reg = reg_index(view->arg2);
		if (reg >= 0) {
			out[view->pc - state->start_offset] = 0xE8 + reg;
			return view->size;
		}
		if (is_indirect_reg(view->arg2)) {
			out[view->pc - state->start_offset] = (strcmp(view->arg2, "@R0") == 0) ? 0xE6 : 0xE7;
			return view->size;
		}
		out[view->pc - state->start_offset] = 0xE5;
		if (!eval_direct(state, view->arg2, &expr) || !emit_abs8_or_reloc(state, out, view->pc + 1, view->ins, &expr)) return -1;
		return view->size;
	}
	reg = reg_index(view->arg1);
	if (view->arg1 && reg >= 0) {
		int src_reg = reg_index(view->arg2);
		if (is_acc(view->arg2)) {
			out[view->pc - state->start_offset] = 0xF8 + reg;
			return view->size;
		}
		if (src_reg >= 0) {
			out[view->pc - state->start_offset] = 0xE8 + src_reg;
			out[view->pc - state->start_offset + 1] = 0xF8 + reg;
			return view->size;
		}
		if (is_immediate(view->arg2)) {
			out[view->pc - state->start_offset] = 0x78 + reg;
			if (!eval_immediate(state, view->arg2, &expr) || !emit_abs8_or_reloc(state, out, view->pc + 1, view->ins, &expr)) return -1;
			return view->size;
		}
		if (is_indirect_reg(view->arg2)) {
			out[view->pc - state->start_offset] = (strcmp(view->arg2, "@R0") == 0) ? 0xE6 : 0xE7;
			out[view->pc - state->start_offset + 1] = 0xF8 + reg;
			return view->size;
		}
		out[view->pc - state->start_offset] = 0xA8 + reg;
		if (!eval_direct(state, view->arg2, &expr) || !emit_abs8_or_reloc(state, out, view->pc + 1, view->ins, &expr)) return -1;
		return view->size;
	}
	if (view->arg1 && view->arg2 && is_indirect_reg(view->arg1)) {
		if (is_immediate(view->arg2)) {
			out[view->pc - state->start_offset] = (strcmp(view->arg1, "@R0") == 0) ? 0x76 : 0x77;
			if (!eval_immediate(state, view->arg2, &expr) || !emit_abs8_or_reloc(state, out, view->pc + 1, view->ins, &expr)) return -1;
			return view->size;
		}
		if (is_acc(view->arg2)) {
			out[view->pc - state->start_offset] = (strcmp(view->arg1, "@R0") == 0) ? 0xF6 : 0xF7;
			return view->size;
		}
		reg = reg_index(view->arg2);
		if (reg >= 0) {
			out[view->pc - state->start_offset] = 0xE8 + reg;
			out[view->pc - state->start_offset + 1] = (strcmp(view->arg1, "@R0") == 0) ? 0xF6 : 0xF7;
			return view->size;
		}
		out[view->pc - state->start_offset] = (strcmp(view->arg1, "@R0") == 0) ? 0xA6 : 0xA7;
		if (!eval_direct(state, view->arg2, &expr) || !emit_abs8_or_reloc(state, out, view->pc + 1, view->ins, &expr)) return -1;
		return view->size;
	}
	if (view->arg1 && view->arg2) {
		reg = reg_index(view->arg2);
		if (is_acc(view->arg2)) {
			out[view->pc - state->start_offset] = 0xF5;
			if (!eval_direct(state, view->arg1, &expr) || !emit_abs8_or_reloc(state, out, view->pc + 1, view->ins, &expr)) return -1;
			return view->size;
		}
		if (reg >= 0) {
			out[view->pc - state->start_offset] = 0x88 + reg;
			if (!eval_direct(state, view->arg1, &expr) || !emit_abs8_or_reloc(state, out, view->pc + 1, view->ins, &expr)) return -1;
			return view->size;
		}
		if (is_indirect_reg(view->arg2)) {
			out[view->pc - state->start_offset] = (strcmp(view->arg2, "@R0") == 0) ? 0x86 : 0x87;
			if (!eval_direct(state, view->arg1, &expr) || !emit_abs8_or_reloc(state, out, view->pc + 1, view->ins, &expr)) return -1;
			return view->size;
		}
		if (is_immediate(view->arg2)) {
			out[view->pc - state->start_offset] = 0x75;
			if (!eval_direct(state, view->arg1, &expr) || !emit_abs8_or_reloc(state, out, view->pc + 1, view->ins, &expr)) return -1;
			if (!eval_immediate(state, view->arg2, &expr) || !emit_abs8_or_reloc(state, out, view->pc + 2, view->ins, &expr)) return -1;
			return view->size;
		}
		out[view->pc - state->start_offset] = 0x85;
		if (!eval_direct(state, view->arg2, &expr) || !emit_abs8_or_reloc(state, out, view->pc + 1, view->ins, &expr)) return -1;
		if (!eval_direct(state, view->arg1, &expr) || !emit_abs8_or_reloc(state, out, view->pc + 2, view->ins, &expr)) return -1;
		return view->size;
	}
	return -1;
}

static int encode_alu(EncodeState *state, const InstrView *view, unsigned char *out)
{
	const AluEncoding *entry;
	ExprValue expr;
	int reg;
	entry = find_alu_encoding(view ? view->op : NULL);
	if (!entry || !view || !view->arg1 || !view->arg2) return 0;
	if (operand_kind(view->arg1) == OPERAND_KIND_ACC) {
		switch (operand_kind(view->arg2)) {
		case OPERAND_KIND_IMMEDIATE:
			out[view->pc - state->start_offset] = entry->imm_opcode;
			if (!eval_immediate(state, view->arg2, &expr) || !emit_abs8_or_reloc(state, out, view->pc + 1, view->ins, &expr)) return -1;
			return view->size;
		case OPERAND_KIND_REGISTER:
			reg = reg_index(view->arg2);
			out[view->pc - state->start_offset] = entry->reg_base + reg;
			return view->size;
		case OPERAND_KIND_INDIRECT_REG:
			out[view->pc - state->start_offset] = (strcmp(view->arg2, "@R0") == 0) ? entry->indir_r0_opcode : entry->indir_r1_opcode;
			return view->size;
		case OPERAND_KIND_OTHER:
			out[view->pc - state->start_offset] = entry->direct_opcode;
		if (!eval_direct(state, view->arg2, &expr) || !emit_abs8_or_reloc(state, out, view->pc + 1, view->ins, &expr)) return -1;
		return view->size;
		default:
			return -1;
		}
	}
	if (entry->supports_carry_bit && operand_kind(view->arg1) == OPERAND_KIND_CARRY) {
		out[view->pc - state->start_offset] = entry->carry_bit_opcode;
		if (!eval_bit(state, view->arg2, &expr) || !emit_abs8_or_reloc(state, out, view->pc + 1, view->ins, &expr)) return -1;
		return view->size;
	}
	if (entry->supports_direct_acc && operand_kind(view->arg2) == OPERAND_KIND_ACC) {
		out[view->pc - state->start_offset] = entry->direct_acc_opcode;
		if (!eval_direct(state, view->arg1, &expr) || !emit_abs8_or_reloc(state, out, view->pc + 1, view->ins, &expr)) return -1;
		return view->size;
	}
	return -1;
}

static int encode_instruction(EncodeState *state, const AsmInstr *ins, unsigned char *out, int pc)
{
	InstrView view;
	int size;
	int written;

	if (!ins || is_comment_instr(ins) || is_label_instr(ins)) return 0;
	size = instruction_size(ins);
	if (size <= 0) {
		report_encode_error(state, ins, "unsupported instruction");
		return -1;
	}
	state->current_pc = pc;
	view = make_instr_view(ins, pc);
	view.size = size;
	view.next_pc = pc + size;
	if ((written = encode_simple_op(state, &view, out)) != 0) return written;
	if ((written = encode_long_jump(state, &view, out)) != 0) return written;
	if ((written = encode_cjne(state, &view, out)) != 0) return written;
	if ((written = encode_rel_jump(state, &view, out)) != 0) return written;
	if ((written = encode_bit_branch(state, &view, out)) != 0) return written;
	if ((written = encode_stack_op(state, &view, out)) != 0) return written;
	if ((written = encode_bit_op(state, &view, out)) != 0) return written;
	if ((written = encode_inc_dec(state, &view, out)) != 0) return written;
	if ((written = encode_movx_movc(state, &view, out)) != 0) return written;
	if ((written = encode_djnz(state, &view, out)) != 0) return written;
	if ((written = encode_mov(state, &view, out)) != 0) return written;
	if ((written = encode_alu(state, &view, out)) != 0) return written;
	report_encode_error(state, ins, "unsupported instruction form");
	return -1;
}

static void record_labels(EncodeState *state)
{
	Iter it;
	int offset;
	int scope = 0;
	if (!state || !state->sec || !state->sec->asminstrs) return;
	offset = state->start_offset;
	for (it = list_iter(state->sec->asminstrs); !iter_end(it);) {
		AsmInstr *ins = iter_next(&it);
		if (is_label_instr(ins)) {
			size_t len = strlen(ins->op);
			char *name = malloc(len);
			List *positions;
			LabelLocation *location = malloc(sizeof(LabelLocation));
			if (!name || !location) {
				free(name);
				free(location);
				state->failed = 1;
				return;
			}
			memcpy(name, ins->op, len - 1);
			name[len - 1] = '\0';
			if (!is_function_local_label_name(name)) scope++;
			location->value = offset;
			location->scope = scope;
			positions = dict_get(state->labels, name);
			if (!positions) {
				positions = make_list();
				if (!positions) {
					free(name);
					free(location);
					state->failed = 1;
					return;
				}
				dict_put(state->labels, name, positions);
			} else {
				free(name);
			}
			list_push(positions, location);
			continue;
		}
		if (!is_comment_instr(ins)) {
			int size = instruction_size(ins);
			if (size < 0) {
				report_encode_error(state, ins, "unsupported instruction during sizing");
				return;
			}
			offset += size;
		}
	}
}

static void encode_section(ObjFile *obj, int sec_idx, Section *sec)
{
	EncodeState state;
	Iter it;
	int pc;
	int end_offset;
	unsigned char *code;

	if (!obj || !sec || !sec->asminstrs || sec->asminstrs->len == 0) return;

	memset(&state, 0, sizeof(state));
	state.obj = obj;
	state.sec = sec;
	state.sec_idx = sec_idx;
	state.start_offset = sec->bytes_len;
	state.labels = make_dict(NULL);

	record_labels(&state);
	if (state.failed) {
		dict_free(state.labels, free_label_positions);
		return;
	}

	end_offset = state.start_offset;
	for (it = list_iter(sec->asminstrs); !iter_end(it);) {
		AsmInstr *ins = iter_next(&it);
		if (!is_comment_instr(ins) && !is_label_instr(ins)) {
			end_offset += instruction_size(ins);
		}
	}

	if (end_offset <= state.start_offset) {
		dict_free(state.labels, free_label_positions);
		return;
	}

	code = calloc((size_t)(end_offset - state.start_offset), 1);
	if (!code) {
		dict_free(state.labels, free_label_positions);
		return;
	}

	pc = state.start_offset;
	for (it = list_iter(sec->asminstrs); !iter_end(it);) {
		AsmInstr *ins = iter_next(&it);
		if (is_label_instr(ins)) {
			size_t len = strlen(ins->op);
			char *name = malloc(len);
			if (!name) {
				state.failed = 1;
				break;
			}
			memcpy(name, ins->op, len - 1);
			name[len - 1] = '\0';
			if (!is_function_local_label_name(name)) state.current_scope++;
			free(name);
		}
		int written = encode_instruction(&state, ins, code, pc);
		if (written < 0) break;
		pc += written;
	}

	if (!state.failed) {
		section_append_bytes(sec, code, end_offset - state.start_offset);
	}

	free(code);
	dict_free(state.labels, free_label_positions);
}

void c51_encode(C51GenContext* ctx, ObjFile* obj)
{
	Iter it;
	int sec_idx;

	(void)ctx;
	if (!obj) return;

	sec_idx = 0;
	for (it = list_iter(obj->sections); !iter_end(it); sec_idx++) {
		Section *sec = iter_next(&it);
		if (!sec || sec->kind != SEC_CODE) continue;
		encode_section(obj, sec_idx, sec);
	}
}