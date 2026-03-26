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
	int failed;
} EncodeState;

typedef struct {
	int value;
	int is_symbolic;
	char symbol[128];
	int addend;
} ExprValue;

typedef struct {
	const char *name;
	int value;
} BuiltinDirect;

static const BuiltinDirect builtin_directs[] = {
	{"P0", 0x80}, {"SP", 0x81}, {"DPL", 0x82}, {"DPH", 0x83},
	{"PCON", 0x87}, {"TCON", 0x88}, {"TMOD", 0x89}, {"TL0", 0x8A},
	{"TL1", 0x8B}, {"TH0", 0x8C}, {"TH1", 0x8D}, {"P1", 0x90},
	{"SCON", 0x98}, {"SBUF", 0x99}, {"P2", 0xA0}, {"IE", 0xA8},
	{"P3", 0xB0}, {"IP", 0xB8}, {"PSW", 0xD0}, {"ACC", 0xE0},
	{"B", 0xF0}, {NULL, 0}
};

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
	int *found;
	char *key;
	if (!state || !state->labels || !name) return 0;
	key = dup_trim(name);
	if (!key) return 0;
	found = dict_get(state->labels, key);
	free(key);
	if (!found) return 0;
	if (value) *value = *found;
	return 1;
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

static int instruction_size(const AsmInstr *ins)
{
	const char *op;
	const char *arg1;
	const char *arg2;
	int reg;

	if (!ins || is_comment_instr(ins) || is_label_instr(ins)) return 0;
	op = ins->op;
	arg1 = (ins->args && ins->args->len > 0) ? list_get(ins->args, 0) : NULL;
	arg2 = (ins->args && ins->args->len > 1) ? list_get(ins->args, 1) : NULL;

	if (!strcmp(op, "RET") || !strcmp(op, "RETI") || !strcmp(op, "NOP") || !strcmp(op, "RLC") || !strcmp(op, "RRC") ||
		!strcmp(op, "MUL") || !strcmp(op, "DIV")) return 1;
	if (!strcmp(op, "JMP") && arg1 && strcmp(arg1, "@A+DPTR") == 0) return 1;
	if (!strcmp(op, "CJNE")) {
		char *cmp_operand = NULL;
		char *label = NULL;
		int sz = -1;
		if (arg1 && is_acc(arg1) && split_cjne_arg2(arg2, &cmp_operand, &label)) {
			if (is_immediate(cmp_operand)) sz = 3;
			else if (reg_index(cmp_operand) >= 0 || is_indirect_reg(cmp_operand)) sz = 5;
			else sz = 3;
		}
		free(cmp_operand);
		free(label);
		return sz;
	}
	if (!strcmp(op, "LCALL") || !strcmp(op, "LJMP")) return 3;
	if (!strcmp(op, "SJMP") || !strcmp(op, "JNZ") || !strcmp(op, "JZ") ||
		!strcmp(op, "JC") || !strcmp(op, "JNC")) return 2;
	if (!strcmp(op, "JB") || !strcmp(op, "JNB") || !strcmp(op, "JBC")) return 3;
	if (!strcmp(op, "PUSH") || !strcmp(op, "POP")) return 2;
	if (!strcmp(op, "SETB") || !strcmp(op, "CLR") || !strcmp(op, "CPL")) {
		if (arg1 && (is_acc(arg1) || is_carry(arg1))) return 1;
		return 2;
	}
	if (!strcmp(op, "INC") || !strcmp(op, "DEC")) {
		if (arg1 && (is_acc(arg1) || is_dptr(arg1) || reg_index(arg1) >= 0)) return 1;
		return 2;
	}
	if (!strcmp(op, "MOVX")) return 1;
	if (!strcmp(op, "MOVC")) return 1;

	if (!strcmp(op, "MOV")) {
		if (arg1 && arg2 && is_dptr(arg1) && is_immediate(arg2)) return 3;
		if (arg1 && arg2 && (is_carry(arg1) || is_carry(arg2))) return 2;
		if (arg1 && arg2 && is_acc(arg1)) {
			if (is_immediate(arg2)) return 2;
			if (reg_index(arg2) >= 0 || is_indirect_reg(arg2)) return 1;
			return 2;
		}
		reg = reg_index(arg1);
		if (arg1 && reg >= 0) {
			if (reg_index(arg2) >= 0) return 2;
			if (is_acc(arg2) || is_indirect_reg(arg2)) return 1;
			return is_immediate(arg2) ? 2 : 2;
		}
		if (arg1 && arg2 && is_indirect_reg(arg1)) {
			if (is_immediate(arg2)) return 2;
			if (reg_index(arg2) >= 0) return 2;
			if (is_acc(arg2)) return 1;
			return 2;
		}
		if (arg1 && arg2) {
			if (is_indirect_reg(arg2)) return 2;
			if (is_acc(arg2) || reg_index(arg2) >= 0 || is_indirect_reg(arg2)) return 2;
			if (is_immediate(arg2)) return 3;
			return 3;
		}
	}

	if (!strcmp(op, "ADD") || !strcmp(op, "ADDC") || !strcmp(op, "SUBB") ||
		!strcmp(op, "ANL") || !strcmp(op, "ORL") || !strcmp(op, "XRL")) {
		if (arg1 && is_acc(arg1)) {
			if (is_immediate(arg2)) return 2;
			if (reg_index(arg2) >= 0 || is_indirect_reg(arg2)) return 1;
			return 2;
		}
		if (arg1 && is_carry(arg1) && arg2) return 2;
		if (arg1 && arg2 && is_acc(arg2)) return 2;
	}

	if (!strcmp(op, "DJNZ")) {
		if (arg1 && reg_index(arg1) >= 0) return 2;
		return 3;
	}

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

static int encode_instruction(EncodeState *state, const AsmInstr *ins, unsigned char *out, int pc)
{
	const char *op;
	const char *arg1;
	const char *arg2;
	ExprValue expr;
	int reg;
	int size;
	int next_pc;

	if (!ins || is_comment_instr(ins) || is_label_instr(ins)) return 0;
	size = instruction_size(ins);
	if (size <= 0) {
		report_encode_error(state, ins, "unsupported instruction");
		return -1;
	}

	op = ins->op;
	arg1 = (ins->args && ins->args->len > 0) ? list_get(ins->args, 0) : NULL;
	arg2 = (ins->args && ins->args->len > 1) ? list_get(ins->args, 1) : NULL;
	next_pc = pc + size;

	if (!strcmp(op, "NOP")) { out[pc - state->start_offset] = 0x00; return size; }
	if (!strcmp(op, "JMP") && arg1 && strcmp(arg1, "@A+DPTR") == 0) { out[pc - state->start_offset] = 0x73; return size; }
	if (!strcmp(op, "RLC") && arg1 && is_acc(arg1)) { out[pc - state->start_offset] = 0x33; return size; }
	if (!strcmp(op, "RRC") && arg1 && is_acc(arg1)) { out[pc - state->start_offset] = 0x13; return size; }
	if (!strcmp(op, "RET")) { out[pc - state->start_offset] = 0x22; return size; }
	if (!strcmp(op, "RETI")) { out[pc - state->start_offset] = 0x32; return size; }
	if (!strcmp(op, "MUL") && arg1 && strcmp(arg1, "AB") == 0) { out[pc - state->start_offset] = 0xA4; return size; }
	if (!strcmp(op, "DIV") && arg1 && strcmp(arg1, "AB") == 0) { out[pc - state->start_offset] = 0x84; return size; }

	if (!strcmp(op, "LCALL") || !strcmp(op, "LJMP")) {
		out[pc - state->start_offset] = !strcmp(op, "LCALL") ? 0x12 : 0x02;
		if (!eval_expr(state, arg1, &expr) || !emit_abs16_or_reloc(state, out, pc + 1, ins, &expr)) return -1;
		return size;
	}

	if (!strcmp(op, "CJNE")) {
		char *cmp_operand = NULL;
		char *label = NULL;
		int target;
		if (!(arg1 && is_acc(arg1) && split_cjne_arg2(arg2, &cmp_operand, &label))) {
			report_encode_error(state, ins, "unsupported CJNE form");
			free(cmp_operand);
			free(label);
			return -1;
		}
		if (!eval_expr(state, label, &expr) || expr.is_symbolic) {
			report_encode_error(state, ins, "CJNE requires local label target");
			free(cmp_operand);
			free(label);
			return -1;
		}
		target = expr.value;
		if (is_immediate(cmp_operand)) {
			out[pc - state->start_offset] = 0xB4;
			if (!eval_immediate(state, cmp_operand, &expr) || !emit_abs8_or_reloc(state, out, pc + 1, ins, &expr)) {
				free(cmp_operand);
				free(label);
				return -1;
			}
			out[pc - state->start_offset + 2] = (unsigned char)checked_rel8(state, ins, next_pc, target);
			free(cmp_operand);
			free(label);
			return size;
		}
		reg = reg_index(cmp_operand);
		if (reg >= 0) {
			out[pc - state->start_offset] = 0x88 + reg;
			out[pc - state->start_offset + 1] = 0xF0;
			out[pc - state->start_offset + 2] = 0xB5;
			out[pc - state->start_offset + 3] = 0xF0;
			out[pc - state->start_offset + 4] = (unsigned char)checked_rel8(state, ins, pc + size, target);
			free(cmp_operand);
			free(label);
			return size;
		}
		if (is_indirect_reg(cmp_operand)) {
			out[pc - state->start_offset] = (strcmp(cmp_operand, "@R0") == 0) ? 0x86 : 0x87;
			out[pc - state->start_offset + 1] = 0xF0;
			out[pc - state->start_offset + 2] = 0xB5;
			out[pc - state->start_offset + 3] = 0xF0;
			out[pc - state->start_offset + 4] = (unsigned char)checked_rel8(state, ins, pc + size, target);
			free(cmp_operand);
			free(label);
			return size;
		}
		out[pc - state->start_offset] = 0xB5;
		if (!eval_direct(state, cmp_operand, &expr) || !emit_abs8_or_reloc(state, out, pc + 1, ins, &expr)) {
			free(cmp_operand);
			free(label);
			return -1;
		}
		out[pc - state->start_offset + 2] = (unsigned char)checked_rel8(state, ins, next_pc, target);
		free(cmp_operand);
		free(label);
		return size;
	}

	if (!strcmp(op, "SJMP") || !strcmp(op, "JNZ") || !strcmp(op, "JZ") || !strcmp(op, "JC") || !strcmp(op, "JNC")) {
		int target;
		out[pc - state->start_offset] = !strcmp(op, "SJMP") ? 0x80 :
										!strcmp(op, "JNZ") ? 0x70 :
										!strcmp(op, "JZ") ? 0x60 :
										!strcmp(op, "JC") ? 0x40 : 0x50;
		if (!eval_expr(state, arg1, &expr) || expr.is_symbolic) {
			report_encode_error(state, ins, "relative jump requires local label");
			return -1;
		}
		target = expr.value;
		out[pc - state->start_offset + 1] = (unsigned char)checked_rel8(state, ins, next_pc, target);
		return size;
	}

	if (!strcmp(op, "JB") || !strcmp(op, "JNB") || !strcmp(op, "JBC")) {
		int target;
		out[pc - state->start_offset] = !strcmp(op, "JB") ? 0x20 : !strcmp(op, "JNB") ? 0x30 : 0x10;
		if (!eval_bit(state, arg1, &expr) || expr.is_symbolic || !emit_abs8_or_reloc(state, out, pc + 1, ins, &expr)) return -1;
		if (!eval_expr(state, arg2, &expr) || expr.is_symbolic) {
			report_encode_error(state, ins, "bit branch requires local label");
			return -1;
		}
		target = expr.value;
		out[pc - state->start_offset + 2] = (unsigned char)checked_rel8(state, ins, next_pc, target);
		return size;
	}

	if (!strcmp(op, "PUSH") || !strcmp(op, "POP")) {
		out[pc - state->start_offset] = !strcmp(op, "PUSH") ? 0xC0 : 0xD0;
		if (!eval_direct(state, arg1, &expr) || !emit_abs8_or_reloc(state, out, pc + 1, ins, &expr)) return -1;
		return size;
	}

	if (!strcmp(op, "SETB") || !strcmp(op, "CLR") || !strcmp(op, "CPL")) {
		if (arg1 && is_acc(arg1)) {
			out[pc - state->start_offset] = !strcmp(op, "CLR") ? 0xE4 : !strcmp(op, "CPL") ? 0xF4 : 0x00;
			return size;
		}
		if (arg1 && is_carry(arg1)) {
			out[pc - state->start_offset] = !strcmp(op, "CLR") ? 0xC3 : !strcmp(op, "CPL") ? 0xB3 : 0xD3;
			return size;
		}
		out[pc - state->start_offset] = !strcmp(op, "SETB") ? 0xD2 : !strcmp(op, "CLR") ? 0xC2 : 0xB2;
		if (!eval_bit(state, arg1, &expr) || !emit_abs8_or_reloc(state, out, pc + 1, ins, &expr)) return -1;
		return size;
	}

	if (!strcmp(op, "INC") || !strcmp(op, "DEC")) {
		if (arg1 && is_acc(arg1)) {
			out[pc - state->start_offset] = !strcmp(op, "INC") ? 0x04 : 0x14;
			return size;
		}
		if (arg1 && is_dptr(arg1)) {
			out[pc - state->start_offset] = 0xA3;
			return size;
		}
		reg = reg_index(arg1);
		if (reg >= 0) {
			out[pc - state->start_offset] = (!strcmp(op, "INC") ? 0x08 : 0x18) + reg;
			return size;
		}
		out[pc - state->start_offset] = !strcmp(op, "INC") ? 0x05 : 0x15;
		if (!eval_direct(state, arg1, &expr) || !emit_abs8_or_reloc(state, out, pc + 1, ins, &expr)) return -1;
		return size;
	}

	if (!strcmp(op, "MOVX")) {
		if (arg1 && arg2 && is_movx_at_dptr(arg1) && is_acc(arg2)) {
			out[pc - state->start_offset] = 0xF0;
			return size;
		}
		if (arg1 && arg2 && is_acc(arg1) && is_movx_at_dptr(arg2)) {
			out[pc - state->start_offset] = 0xE0;
			return size;
		}
		report_encode_error(state, ins, "unsupported MOVX form");
		return -1;
	}

	if (!strcmp(op, "MOVC")) {
		if (arg1 && arg2 && is_acc(arg1) && is_movc_at_a_dptr(arg2)) {
			out[pc - state->start_offset] = 0x93;
			return size;
		}
		report_encode_error(state, ins, "unsupported MOVC form");
		return -1;
	}

	if (!strcmp(op, "DJNZ")) {
		int target;
		reg = reg_index(arg1);
		if (reg >= 0) {
			out[pc - state->start_offset] = 0xD8 + reg;
			if (!eval_expr(state, arg2, &expr) || expr.is_symbolic) {
				report_encode_error(state, ins, "DJNZ requires local label");
				return -1;
			}
			target = expr.value;
			out[pc - state->start_offset + 1] = (unsigned char)checked_rel8(state, ins, next_pc, target);
			return size;
		}
		out[pc - state->start_offset] = 0xD5;
		if (!eval_direct(state, arg1, &expr) || !emit_abs8_or_reloc(state, out, pc + 1, ins, &expr)) return -1;
		if (!eval_expr(state, arg2, &expr) || expr.is_symbolic) {
			report_encode_error(state, ins, "DJNZ requires local label");
			return -1;
		}
		target = expr.value;
		out[pc - state->start_offset + 2] = (unsigned char)checked_rel8(state, ins, next_pc, target);
		return size;
	}

	if (!strcmp(op, "MOV")) {
		reg = reg_index(arg1);
		if (arg1 && arg2 && is_dptr(arg1) && is_immediate(arg2)) {
			out[pc - state->start_offset] = 0x90;
			if (!eval_immediate(state, arg2, &expr) || !emit_abs16_or_reloc(state, out, pc + 1, ins, &expr)) return -1;
			return size;
		}
		if (arg1 && arg2 && is_carry(arg1)) {
			out[pc - state->start_offset] = 0xA2;
			if (!eval_bit(state, arg2, &expr) || !emit_abs8_or_reloc(state, out, pc + 1, ins, &expr)) return -1;
			return size;
		}
		if (arg1 && arg2 && is_carry(arg2)) {
			out[pc - state->start_offset] = 0x92;
			if (!eval_bit(state, arg1, &expr) || !emit_abs8_or_reloc(state, out, pc + 1, ins, &expr)) return -1;
			return size;
		}
		if (arg1 && arg2 && is_acc(arg1)) {
			if (is_immediate(arg2)) {
				out[pc - state->start_offset] = 0x74;
				if (!eval_immediate(state, arg2, &expr) || !emit_abs8_or_reloc(state, out, pc + 1, ins, &expr)) return -1;
				return size;
			}
			reg = reg_index(arg2);
			if (reg >= 0) {
				out[pc - state->start_offset] = 0xE8 + reg;
				return size;
			}
			if (is_indirect_reg(arg2)) {
				out[pc - state->start_offset] = (strcmp(arg2, "@R0") == 0) ? 0xE6 : 0xE7;
				return size;
			}
			out[pc - state->start_offset] = 0xE5;
			if (!eval_direct(state, arg2, &expr) || !emit_abs8_or_reloc(state, out, pc + 1, ins, &expr)) return -1;
			return size;
		}
		reg = reg_index(arg1);
		if (reg >= 0) {
			int src_reg = reg_index(arg2);
			if (is_acc(arg2)) {
				out[pc - state->start_offset] = 0xF8 + reg;
				return size;
			}
			if (src_reg >= 0) {
				out[pc - state->start_offset] = 0xE8 + src_reg;
				out[pc - state->start_offset + 1] = 0xF8 + reg;
				return size;
			}
			if (is_immediate(arg2)) {
				out[pc - state->start_offset] = 0x78 + reg;
				if (!eval_immediate(state, arg2, &expr) || !emit_abs8_or_reloc(state, out, pc + 1, ins, &expr)) return -1;
				return size;
			}
			if (is_indirect_reg(arg2)) {
				out[pc - state->start_offset] = (strcmp(arg2, "@R0") == 0) ? 0xE6 : 0xE7;
				out[pc - state->start_offset + 1] = 0xF8 + reg;
				return size;
			}
			out[pc - state->start_offset] = 0xA8 + reg;
			if (!eval_direct(state, arg2, &expr) || !emit_abs8_or_reloc(state, out, pc + 1, ins, &expr)) return -1;
			return size;
		}
		if (arg1 && arg2 && is_indirect_reg(arg1)) {
			if (is_immediate(arg2)) {
				out[pc - state->start_offset] = (strcmp(arg1, "@R0") == 0) ? 0x76 : 0x77;
				if (!eval_immediate(state, arg2, &expr) || !emit_abs8_or_reloc(state, out, pc + 1, ins, &expr)) return -1;
				return size;
			}
			if (is_acc(arg2)) {
				out[pc - state->start_offset] = (strcmp(arg1, "@R0") == 0) ? 0xF6 : 0xF7;
				return size;
			}
			reg = reg_index(arg2);
			if (reg >= 0) {
				out[pc - state->start_offset] = 0xE8 + reg;
				out[pc - state->start_offset + 1] = (strcmp(arg1, "@R0") == 0) ? 0xF6 : 0xF7;
				return size;
			}
			out[pc - state->start_offset] = (strcmp(arg1, "@R0") == 0) ? 0xA6 : 0xA7;
			if (!eval_direct(state, arg2, &expr) || !emit_abs8_or_reloc(state, out, pc + 1, ins, &expr)) return -1;
			return size;
		}
		if (arg1 && arg2) {
			reg = reg_index(arg2);
			if (is_acc(arg2)) {
				out[pc - state->start_offset] = 0xF5;
				if (!eval_direct(state, arg1, &expr) || !emit_abs8_or_reloc(state, out, pc + 1, ins, &expr)) return -1;
				return size;
			}
			if (reg >= 0) {
				out[pc - state->start_offset] = 0x88 + reg;
				if (!eval_direct(state, arg1, &expr) || !emit_abs8_or_reloc(state, out, pc + 1, ins, &expr)) return -1;
				return size;
			}
			if (is_indirect_reg(arg2)) {
				out[pc - state->start_offset] = (strcmp(arg2, "@R0") == 0) ? 0x86 : 0x87;
				if (!eval_direct(state, arg1, &expr) || !emit_abs8_or_reloc(state, out, pc + 1, ins, &expr)) return -1;
				return size;
			}
			if (is_immediate(arg2)) {
				out[pc - state->start_offset] = 0x75;
				if (!eval_direct(state, arg1, &expr) || !emit_abs8_or_reloc(state, out, pc + 1, ins, &expr)) return -1;
				if (!eval_immediate(state, arg2, &expr) || !emit_abs8_or_reloc(state, out, pc + 2, ins, &expr)) return -1;
				return size;
			}
			out[pc - state->start_offset] = 0x85;
			if (!eval_direct(state, arg2, &expr) || !emit_abs8_or_reloc(state, out, pc + 1, ins, &expr)) return -1;
			if (!eval_direct(state, arg1, &expr) || !emit_abs8_or_reloc(state, out, pc + 2, ins, &expr)) return -1;
			return size;
		}
	}

	if (!strcmp(op, "ADD") || !strcmp(op, "ADDC") || !strcmp(op, "SUBB") ||
		!strcmp(op, "ANL") || !strcmp(op, "ORL") || !strcmp(op, "XRL")) {
		int base_imm = !strcmp(op, "ADD") ? 0x24 : !strcmp(op, "ADDC") ? 0x34 :
					   !strcmp(op, "SUBB") ? 0x94 : !strcmp(op, "ANL") ? 0x54 :
					   !strcmp(op, "ORL") ? 0x44 : 0x64;
		int base_dir = !strcmp(op, "ADD") ? 0x25 : !strcmp(op, "ADDC") ? 0x35 :
					   !strcmp(op, "SUBB") ? 0x95 : !strcmp(op, "ANL") ? 0x55 :
					   !strcmp(op, "ORL") ? 0x45 : 0x65;
		int base_reg = !strcmp(op, "ADD") ? 0x28 : !strcmp(op, "ADDC") ? 0x38 :
					   !strcmp(op, "SUBB") ? 0x98 : !strcmp(op, "ANL") ? 0x58 :
					   !strcmp(op, "ORL") ? 0x48 : 0x68;
		if (arg1 && is_acc(arg1)) {
			if (is_immediate(arg2)) {
				out[pc - state->start_offset] = base_imm;
				if (!eval_immediate(state, arg2, &expr) || !emit_abs8_or_reloc(state, out, pc + 1, ins, &expr)) return -1;
				return size;
			}
			reg = reg_index(arg2);
			if (reg >= 0) {
				out[pc - state->start_offset] = base_reg + reg;
				return size;
			}
			out[pc - state->start_offset] = base_dir;
			if (!eval_direct(state, arg2, &expr) || !emit_abs8_or_reloc(state, out, pc + 1, ins, &expr)) return -1;
			return size;
		}
		if (!strcmp(op, "ORL") && arg1 && arg2 && is_carry(arg1)) {
			out[pc - state->start_offset] = 0x72;
			if (!eval_bit(state, arg2, &expr) || !emit_abs8_or_reloc(state, out, pc + 1, ins, &expr)) return -1;
			return size;
		}
		if (!strcmp(op, "ANL") && arg1 && arg2 && is_carry(arg1)) {
			out[pc - state->start_offset] = 0x82;
			if (!eval_bit(state, arg2, &expr) || !emit_abs8_or_reloc(state, out, pc + 1, ins, &expr)) return -1;
			return size;
		}
		if (arg1 && arg2 && is_acc(arg2)) {
			out[pc - state->start_offset] = !strcmp(op, "ANL") ? 0x52 : !strcmp(op, "ORL") ? 0x42 : 0x62;
			if (!eval_direct(state, arg1, &expr) || !emit_abs8_or_reloc(state, out, pc + 1, ins, &expr)) return -1;
			return size;
		}
	}

	report_encode_error(state, ins, "unsupported instruction form");
	return -1;
}

static void record_labels(EncodeState *state)
{
	Iter it;
	int offset;
	if (!state || !state->sec || !state->sec->asminstrs) return;
	offset = state->start_offset;
	for (it = list_iter(state->sec->asminstrs); !iter_end(it);) {
		AsmInstr *ins = iter_next(&it);
		if (is_label_instr(ins)) {
			size_t len = strlen(ins->op);
			char *name = malloc(len);
			int *value = malloc(sizeof(int));
			if (!name || !value) {
				free(name);
				free(value);
				state->failed = 1;
				return;
			}
			memcpy(name, ins->op, len - 1);
			name[len - 1] = '\0';
			*value = offset;
			dict_put(state->labels, name, value);
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
		dict_free(state.labels, free);
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
		dict_free(state.labels, free);
		return;
	}

	code = calloc((size_t)(end_offset - state.start_offset), 1);
	if (!code) {
		dict_free(state.labels, free);
		return;
	}

	pc = state.start_offset;
	for (it = list_iter(sec->asminstrs); !iter_end(it);) {
		AsmInstr *ins = iter_next(&it);
		int written = encode_instruction(&state, ins, code, pc);
		if (written < 0) break;
		pc += written;
	}

	if (!state.failed) {
		section_append_bytes(sec, code, end_offset - state.start_offset);
	}

	free(code);
	dict_free(state.labels, free);
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