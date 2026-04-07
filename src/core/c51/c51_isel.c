#include "c51_isel_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "c51_isel_regalloc.h"

/* open_memstream 兼容层：Windows 上使�?tmpfile 模拟 */
#ifdef _WIN32
#include <io.h>
#endif

char* int_to_key(int n) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%02XH", n);
    return strdup(buf);
}

/* 默认推断的整型类型（用于比较类指令） */
static const Ctype g_inferred_int_type  = {0, CTYPE_INT,  2, NULL};
/* 默认推断的无符号字节类型（用于小常量，attr=32 = ctype_unsigned=1 在第5位） */
static const Ctype g_inferred_uchar_type = {32, CTYPE_CHAR, 1, NULL};

char* instr_to_ssa_str(Instr *ins) {
    if (!ins) return strdup("");

    char *buf = NULL;
    size_t len = 0;
#ifdef _WIN32
    /* Windows: �?tmpfile() 模拟 open_memstream */
    FILE *f = tmpfile();
#else
    FILE *f = open_memstream(&buf, &len);
#endif
    if (!f) return strdup("");
    ssa_print_instr(f, ins, NULL);
#ifdef _WIN32
    fflush(f);
    len = (size_t)ftell(f);
    rewind(f);
    buf = malloc(len + 1);
    if (buf) { fread(buf, 1, len, f); buf[len] = '\0'; }
    fclose(f);
#else
    fclose(f);
#endif
    if (!buf) return strdup("");
    char *p = buf;
    while (*p == ' ' || *p == '\t') p++;
    size_t blen = strlen(p);
    while (blen > 0 && (p[blen - 1] == '\n' || p[blen - 1] == '\r')) p[--blen] = '\0';
    char *out = malloc(blen + 3);
    if (out) sprintf(out, "; %s", p);
    free(buf);
    return out ? out : strdup("");
}

const char* isel_reg_name(int reg) {
    static const char* names[] = {"R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7"};
    if (reg >= 0 && reg < 8) return names[reg];
    return "R7";
}

int isel_get_value_reg(ISelContext* isel, ValueName val) {
    if (!isel || !isel->ctx || !isel->ctx->value_to_reg) return -1;
    char* key = int_to_key(val);
    int* reg_ptr = (int*)dict_get(isel->ctx->value_to_reg, key);
    free(key);
    if (reg_ptr && *reg_ptr >= 0) return *reg_ptr;
    if (reg_ptr && *reg_ptr == ACC_REG) return *reg_ptr;
    if (isel) {
        for (int reg = 0; reg < 8; reg++) {
            if (isel->reg_val[reg] == val) return reg;
        }
    }
    if (reg_ptr) return *reg_ptr;
    return -1;
}

const char* isel_get_value_reg_at(ISelContext* isel, ValueName val, int offset) {
    int base_reg = isel_get_value_reg(isel, val);
    if (base_reg == ACC_REG) return "A";
    if (base_reg < 0) {
        if (offset == 0) return "R6";
        else return "R7";
    }
    if (base_reg + offset < 8) return isel_reg_name(base_reg + offset);
    return isel_reg_name(7);
}

const char* isel_get_lo_reg(ISelContext* isel, ValueName val) {
    /* Fast-path: if the value is a compile-time constant, return "#imm" directly.
     * We use a small rotating static buffer so callers do not need to free. */
    {
        int64_t imm_val = 0;
        if (try_get_value_const(isel, val, &imm_val)) {
            static char imm_bufs[4][20];
            static int  imm_buf_idx = 0;
            char* buf = imm_bufs[imm_buf_idx & 3];
            imm_buf_idx++;
            snprintf(buf, 20, "#%d", (int)(imm_val & 0xFF));
            return buf;
        }
    }

    int size = get_value_size(isel, val);
    int base_reg = isel_get_value_reg(isel, val);

    if (base_reg == ACC_REG) return "A";
    if (base_reg < 0) {
        if (base_reg == SPILL_REG) {
            int r = isel_reload_spill(isel, val, size, NULL);
            if (r >= 0) {
                if (size == 2) return isel_reg_name(r + 1);
                return isel_reg_name(r);
            }
            /* Prefer value_to_spill for the spill slot symbol to avoid
             * picking up a sbit/ADDR name that shares the value_to_addr entry. */
            const char* sym = NULL;
            if (isel->ctx && isel->ctx->value_to_spill) {
                char* k = int_to_key(val);
                sym = (const char*)dict_get(isel->ctx->value_to_spill, k);
                free(k);
            }
            if (!sym) sym = lookup_value_addr_symbol(isel, val);
            if (sym) {
                emit_load_symbol_byte(isel, sym, 0, "A", NULL);
                return "A";
            }
            return "A";
        }
        return "R7";
    }

    if (size == 1) {
        return isel_reg_name(base_reg);
    } else if (size == 2) {
        return isel_reg_name(base_reg + 1);
    } else {
        return isel_reg_name(base_reg);
    }
}

const char* isel_get_hi_reg(ISelContext* isel, ValueName val) {
    int base_reg = isel_get_value_reg(isel, val);
    int size = get_value_size(isel, val);
    if (base_reg == SPILL_REG) {
        int r = isel_reload_spill(isel, val, size, NULL);
        if (r >= 0) {
            if (size == 2) return isel_reg_name(r);
            if (size >= 3) return isel_reg_name(r + 1);
            return isel_reg_name(r);
        }
        /* Prefer value_to_spill for the spill slot symbol */
        const char* sym = NULL;
        if (isel->ctx && isel->ctx->value_to_spill) {
            char* k = int_to_key(val);
            sym = (const char*)dict_get(isel->ctx->value_to_spill, k);
            free(k);
        }
        if (!sym) sym = lookup_value_addr_symbol(isel, val);
        if (sym) {
            emit_load_symbol_byte(isel, sym, size == 2 ? 1 : 0, "A", NULL);
            return "A";
        }
        return "A";
    }
    if (base_reg >= 0 && size >= 3) return isel_reg_name(base_reg + 1);
    return isel_get_value_reg_at(isel, val, 0);
}

static void mark_value_regs_busy(ISelContext* isel, ValueName val) {
    if (!isel || val <= 0) return;
    int base_reg = isel_get_value_reg(isel, val);
    int size = get_value_size(isel, val);
    if (base_reg < 0 || size <= 0) return;
    for (int i = 0; i < size && base_reg + i < 8; i++) {
        isel->reg_busy[base_reg + i] = true;
        isel->reg_val[base_reg + i] = val;
    }
}

static void prepare_reg_state_for_instr(ISelContext* isel, Instr* ins, Instr* next) {
    if (!isel) return;
    for (int i = 0; i < 8; i++) {
        isel->reg_busy[i] = false;
        isel->reg_val[i] = -1;
    }
    if (ins && ins->args) {
        for (int i = 0; i < ins->args->len; i++) {
            ValueName* pv = list_get(ins->args, i);
            if (pv) mark_value_regs_busy(isel, *pv);
        }
    }
    if (next && next->args) {
        for (int i = 0; i < next->args->len; i++) {
            ValueName* pv = list_get(next->args, i);
            if (pv) mark_value_regs_busy(isel, *pv);
        }
    }
    isel->acc_busy = false;
    isel->acc_val = -1;
}

int alloc_dest_reg(ISelContext* isel, Instr* ins, Instr* next, int size, bool try_bind) {
    /* First try to bind to a PHI target register (avoids copies at loop edges).
     * If successful, allocate ins->dest directly to that register. */
    if (try_bind && next) {
        int bound = try_bind_result_to_phi_target(isel, ins, next, size);
        if (bound >= 0) return bound;
    }
    int reg = alloc_reg_for_value(isel, ins->dest, size);
    return reg;
}

char* isel_new_label(ISelContext* isel, const char* prefix) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%s_%d", prefix, isel->label_counter++);
    return strdup(buf);
}

static void append_asm_instr(Section* sec, const char* op, const char* arg1, const char* arg2, const char* ssa,
                             bool infer_label) {
    if (!sec || !op) return;

    AsmInstr* ins = calloc(1, sizeof(AsmInstr));
    bool is_label_candidate = infer_label && (arg1 == NULL && arg2 == NULL && ssa == NULL);
    if (is_label_candidate) {
        size_t oplen = strlen(op);
        if (oplen == 0 || op[0] == ';' || op[oplen - 1] == ':') {
            ins->op = strdup(op);
        } else {
            char *lbl = malloc(oplen + 2);
            if (lbl) {
                strcpy(lbl, op);
                lbl[oplen] = ':';
                lbl[oplen + 1] = '\0';
                ins->op = lbl;
            } else {
                ins->op = strdup(op);
            }
        }
    } else {
        ins->op = strdup(op);
    }
    ins->args = make_list();
    if (arg1) list_push(ins->args, strdup(arg1));
    if (arg2) list_push(ins->args, strdup(arg2));
    if (ssa) ins->ssa = strdup(ssa);
    list_push(sec->asminstrs, ins);
}

static void emit_raw_asm_line(Section* sec, const char* line) {
    if (!sec || !line) return;

    char* copy = strdup(line);
    if (!copy) return;

    char* start = copy;
    while (*start == ' ' || *start == '\t' || *start == '\r' || *start == '\n') start++;
    if (*start == '\0') {
        free(copy);
        return;
    }

    char* end = start + strlen(start);
    while (end > start && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' || end[-1] == '\n')) {
        *--end = '\0';
    }
    if (*start == '\0') {
        free(copy);
        return;
    }

    if (*start == ';' || end[-1] == ':') {
        append_asm_instr(sec, start, NULL, NULL, NULL, true);
        free(copy);
        return;
    }

    char* op = start;
    char* rest = NULL;
    while (*start && !isspace((unsigned char)*start)) start++;
    if (*start) {
        *start++ = '\0';
        while (*start == ' ' || *start == '\t') start++;
        if (*start) rest = start;
    }

    if (op[0] != '.') {
        for (char* p = op; *p; p++) *p = (char)toupper((unsigned char)*p);
    }

    if (!rest) {
        append_asm_instr(sec, op, NULL, NULL, NULL, false);
        free(copy);
        return;
    }

    char* arg1 = rest;
    char* arg2 = NULL;
    char* comma = strchr(rest, ',');
    if (comma) {
        *comma = '\0';
        arg2 = comma + 1;
        while (*arg2 == ' ' || *arg2 == '\t') arg2++;
        char* tail2 = arg2 + strlen(arg2);
        while (tail2 > arg2 && (tail2[-1] == ' ' || tail2[-1] == '\t')) *--tail2 = '\0';
    }
    while (*arg1 == ' ' || *arg1 == '\t') arg1++;
    char* tail1 = arg1 + strlen(arg1);
    while (tail1 > arg1 && (tail1[-1] == ' ' || tail1[-1] == '\t')) *--tail1 = '\0';

    append_asm_instr(sec, op, arg1, arg2, NULL, false);
    free(copy);
}

void c51_emit_asm_text(Section* sec, const char* asm_text) {
    if (!sec || !asm_text) return;

    const char* cur = asm_text;
    while (*cur) {
        const char* next = cur;
        while (*next && *next != '\n' && *next != '\r') next++;

        size_t len = (size_t)(next - cur);
        char* line = malloc(len + 1);
        if (!line) return;
        memcpy(line, cur, len);
        line[len] = '\0';
        emit_raw_asm_line(sec, line);
        free(line);

        if (*next == '\r' && next[1] == '\n') next += 2;
        else if (*next == '\r' || *next == '\n') next++;
        cur = next;
    }
}

void isel_emit(ISelContext* isel, const char* op, const char* arg1, const char* arg2, const char* ssa) {
    if (!isel || !isel->sec) return;
    append_asm_instr(isel->sec, op, arg1, arg2, ssa, true);
}

void isel_emit3(ISelContext* isel, const char* op, const char* arg1, const char* arg2, const char* arg3, const char* ssa) {
    if (!isel || !isel->sec || !op) return;
    AsmInstr* ins = calloc(1, sizeof(AsmInstr));
    ins->op = strdup(op);
    ins->args = make_list();
    if (arg1) list_push(ins->args, strdup(arg1));
    if (arg2) list_push(ins->args, strdup(arg2));
    if (arg3) list_push(ins->args, strdup(arg3));
    if (ssa) ins->ssa = strdup(ssa);
    list_push(isel->sec->asminstrs, ins);
}

void isel_emit_label(ISelContext* isel, const char* label) {
    if (!isel || !isel->sec || !label) return;
    isel_emit(isel, label, NULL, NULL, NULL);
}

void isel_ensure_in_acc(ISelContext* isel, ValueName val) {
    if (!isel || val <= 0) return;

    if (isel->acc_busy && isel->acc_val == val) return;

    const char* reg = isel_get_lo_reg(isel, val);
    if (strcmp(reg, "A") != 0) {
        isel_emit(isel, "MOV", "A", reg, NULL);
    }

    isel->acc_busy = true;
    isel->acc_val = val;
}

bool isel_can_keep_in_acc(ISelContext* isel, Instr* ins, Instr* next) {
    (void)isel;
    if (!ins || !next || ins->dest <= 0) return false;

    if (next->args) {
        for (int i = 0; i < next->args->len; i++) {
            ValueName* p = list_get(next->args, i);
            if (p && *p == ins->dest) return true;
        }
    }
    return false;
}

static Ctype* infer_dest_type(ISelContext* isel, Instr* ins) {
    if (!isel || !ins) return NULL;
    /* 对于值在 0-255 范围内的常量，推断为 unsigned char（节省寄存器） */
    if (ins->op == IROP_CONST) {
        if (ins->imm.ival >= 0 && ins->imm.ival <= 255) {
            return (Ctype*)&g_inferred_uchar_type;
        }
        if (ins->type) return ins->type;
        return (Ctype*)&g_inferred_int_type;
    }
    if (ins->type) return ins->type;

    if (ins->op == IROP_SELECT && ins->args && ins->args->len >= 3) {
        ValueName tv = *(ValueName*)list_get(ins->args, 1);
        ValueName fv = *(ValueName*)list_get(ins->args, 2);
        Ctype* tv_type = get_value_type(isel, tv);
        Ctype* fv_type = get_value_type(isel, fv);
        if (tv_type) return tv_type;
        if (fv_type) return fv_type;
    }

    if (ins->op == IROP_PHI && ins->args && ins->args->len > 0) {
        /* 取所有 arms 中最窄的类型（优先使用 1 字节类型，避免 phi 被推断为 int）。
         * 若 arm 是 int 类型的常量但值在 0-255 范围内，视为不影响宽度（跳过）。 */
        Ctype* narrowest = NULL;
        int narrowest_size = 999;
        Func* phi_func = isel && isel->ctx ? isel->ctx->current_func : NULL;
        for (int ai = 0; ai < ins->args->len; ai++) {
            ValueName src = *(ValueName*)list_get(ins->args, ai);
            Ctype* t = get_value_type(isel, src);
            if (t) {
                int sz = c51_abi_type_size(t);
                /* 若该 arm 是 int 类型的常量且值 <= 255，跳过（不让它扩宽 phi 类型） */
                if (sz >= 2 && phi_func) {
                    Instr* arm_def = find_def_instr_in_func(phi_func, src);
                    if (arm_def && arm_def->op == IROP_CONST &&
                        arm_def->imm.ival >= 0 && arm_def->imm.ival <= 255) {
                        continue; /* 小常量不扩宽 phi 类型 */
                    }
                }
                if (sz < narrowest_size) {
                    narrowest_size = sz;
                    narrowest = t;
                }
            }
        }
        if (narrowest) return narrowest;
        /* 若所有 arms 类型未知或均被跳过，回退到第一个 arm */
        ValueName src = *(ValueName*)list_get(ins->args, 0);
        return get_value_type(isel, src);
    }

    if (ins->args && ins->args->len > 0) {
        ValueName src0 = *(ValueName*)list_get(ins->args, 0);
        Ctype* src0_type = get_value_type(isel, src0);

        switch (ins->op) {
            case IROP_ADD:
            case IROP_SUB:
            case IROP_MUL:
            case IROP_DIV:
            case IROP_MOD:
            case IROP_NEG:
            case IROP_AND:
            case IROP_OR:
            case IROP_XOR:
            case IROP_NOT:
            case IROP_SHL:
            case IROP_SHR:
                return src0_type;
            case IROP_EQ:
            case IROP_NE:
            case IROP_LT:
            case IROP_LE:
            case IROP_GT:
            case IROP_GE:
            case IROP_LNOT:
                return (Ctype*)&g_inferred_int_type;
            default:
                break;
        }
    }

    return NULL;
}

static void isel_record_dest_type(ISelContext* isel, Instr* ins) {
    if (!isel || !ins || ins->dest <= 0 || !isel->ctx || !isel->ctx->value_type) return;

    Ctype* type = infer_dest_type(isel, ins);
    if (type) {
        char* key = int_to_key(ins->dest);
        dict_put(isel->ctx->value_type, key, type);
    }
}

static void seed_value_types_for_func(C51GenContext* ctx, Func* func) {
    if (!ctx || !func || !ctx->value_type) return;

    ISelContext probe = {0};
    probe.ctx = ctx;

    bool changed;
    do {
        changed = false;

        for (Iter bit = list_iter(func->blocks); !iter_end(bit);) {
            Block* block = iter_next(&bit);
            for (int phase = 0; phase < 2; phase++) {
                List* lst = (phase == 0) ? block->phis : block->instrs;
                if (!lst) continue;

                for (Iter it = list_iter(lst); !iter_end(it);) {
                    Instr* ins = iter_next(&it);
                    if (!ins || ins->dest <= 0) continue;

                    char* key = int_to_key(ins->dest);
                    Ctype* old_type = (Ctype*)dict_get(ctx->value_type, key);
                    Ctype* new_type = infer_dest_type(&probe, ins);
                    if (new_type) {
                        /* 允许类型向更窄方向更新（如 int→uchar），以减少寄存器压力 */
                        int old_size = old_type ? c51_abi_type_size(old_type) : 999;
                        int new_size = c51_abi_type_size(new_type);
                        if (!old_type || new_size < old_size) {
                            dict_put(ctx->value_type, key, new_type);
                            changed = true;
                        } else {
                            free(key);
                        }
                    } else {
                        free(key);
                    }
                }
            }
        }
    } while (changed);
}

static Ctype* clone_type_with_attr_for_isel(Ctype* type, int attr) {
    if (!type) return NULL;
    Ctype* copy = malloc(sizeof(Ctype));
    if (!copy) return type;
    memcpy(copy, type, sizeof(Ctype));
    copy->attr = attr;
    return copy;
}

static Ctype* find_call_arg_type(Func* caller, ValueName value) {
    if (!caller || value <= 0) return NULL;
    Instr* def = find_def_instr_in_func(caller, value);
    if (def && def->type) return def->type;
    return NULL;
}

static void refine_param_pointer_spaces(C51GenContext* ctx, Func* func) {
    if (!ctx || !ctx->unit || !func || !func->params || !func->param_types) return;

    for (int param_index = 0; param_index < func->param_types->len; param_index++) {
        Ctype* declared = list_get(func->param_types, param_index);
        if (!declared || declared->type != CTYPE_PTR) continue;

        int inferred_attr = -1;
        bool found_call = false;
        bool conflict = false;

        for (Iter fit = list_iter(ctx->unit->funcs); !iter_end(fit) && !conflict;) {
            Func* caller = iter_next(&fit);
            if (!caller || !caller->blocks) continue;
            for (Iter bit = list_iter(caller->blocks); !iter_end(bit) && !conflict;) {
                Block* block = iter_next(&bit);
                if (!block || !block->instrs) continue;
                for (Iter iit = list_iter(block->instrs); !iter_end(iit) && !conflict;) {
                    Instr* ins = iter_next(&iit);
                    if (!ins || ins->op != IROP_CALL || !ins->labels || ins->labels->len < 1) continue;
                    const char* callee = list_get(ins->labels, 0);
                    bool indirect = ins->labels->len > 1 && strcmp((const char*)list_get(ins->labels, 1), "indirect") == 0;
                    if (indirect || !callee || strcmp(callee, func->name) != 0) continue;

                    int arg_index = param_index;
                    if (!ins->args || arg_index >= ins->args->len) continue;
                    ValueName actual = *(ValueName*)list_get(ins->args, arg_index);
                    Ctype* actual_type = find_call_arg_type(caller, actual);
                    if (!actual_type || actual_type->type != CTYPE_PTR) {
                        conflict = true;
                        break;
                    }

                    int actual_attr = actual_type->attr;
                    if (!found_call) {
                        inferred_attr = actual_attr;
                        found_call = true;
                    } else if (inferred_attr != actual_attr) {
                        conflict = true;
                        break;
                    }
                }
            }
        }

        if (!found_call || conflict || inferred_attr < 0 || inferred_attr == declared->attr) {
            continue;
        }

        Ctype* refined = clone_type_with_attr_for_isel(declared, inferred_attr);
        list_set(func->param_types, param_index, refined);
        if (func->entry && func->entry->instrs) {
            int seen = 0;
            for (Iter iit = list_iter(func->entry->instrs); !iter_end(iit);) {
                Instr* ins = iter_next(&iit);
                if (!ins || ins->op != IROP_PARAM) continue;
                if (seen == param_index) {
                    ins->type = refined;
                    break;
                }
                seen++;
            }
        }
    }
}

static bool const_used_only_as_add_rhs(ISelContext* isel, Instr* ins) {
    if (!isel || !ins || ins->op != IROP_CONST || ins->dest <= 0 || !isel->ctx || !isel->ctx->current_func) {
        return false;
    }
    bool has_use = false;
    Func *func = isel->ctx->current_func;
    for (Iter bit = list_iter(func->blocks); !iter_end(bit);) {
        Block *block = iter_next(&bit);
        if (!block || !block->instrs) continue;
        for (Iter iit = list_iter(block->instrs); !iter_end(iit);) {
            Instr *user = iter_next(&iit);
            if (!user || user == ins || !user->args || user->args->len < 1) continue;
            for (int i = 0; i < user->args->len; i++) {
                ValueName *arg = list_get(user->args, i);
                if (!arg || *arg != ins->dest) continue;
                has_use = true;
                if (user->op != IROP_ADD || i != 1) {
                    return false;
                }
            }
        }
    }
    return has_use;
}

void isel_instr(ISelContext* isel, Instr* ins, Instr* next) {
    if (!isel || !ins) return;
    isel_record_dest_type(isel, ins);
    prepare_reg_state_for_instr(isel, ins, next);

    switch (ins->op) {
        case IROP_NOP:
            break;
        case IROP_CONST:
            if (const_used_only_as_add_rhs(isel, ins)) {
                break;
            }
            emit_const(isel, ins, next);
            break;
        case IROP_PARAM:
            break;
        case IROP_ADD:
            emit_add(isel, ins, next);
            break;
        case IROP_SUB:
            emit_sub(isel, ins, next);
            break;
        case IROP_MUL:
            emit_mul(isel, ins, next);
            break;
        case IROP_DIV:
            emit_div_mod(isel, ins, false);
            break;
        case IROP_MOD:
            emit_div_mod(isel, ins, true);
            break;
        case IROP_NEG:
            emit_neg(isel, ins);
            break;
        case IROP_AND:
            emit_bitwise(isel, ins, next, "ANL");
            break;
        case IROP_OR:
            emit_bitwise(isel, ins, next, "ORL");
            break;
        case IROP_XOR:
            emit_bitwise(isel, ins, next, "XRL");
            break;
        case IROP_NOT:
            emit_not(isel, ins, next);
            break;
        case IROP_SHL:
            emit_shift(isel, ins, next, false);
            break;
        case IROP_SHR:
            emit_shift(isel, ins, next, true);
            break;
        case IROP_EQ:
            emit_cmp_eq(isel, ins, next);
            break;
        case IROP_LT:
            emit_cmp_lt_gt(isel, ins, next, false);
            break;
        case IROP_GT:
            emit_cmp_lt_gt(isel, ins, next, true);
            break;
        case IROP_LE:
            emit_cmp_le_ge(isel, ins, next, false);
            break;
        case IROP_GE:
            emit_cmp_le_ge(isel, ins, next, true);
            break;
        case IROP_NE:
            emit_ne(isel, ins, next);
            break;
        case IROP_LNOT:
            emit_lnot(isel, ins, next);
            break;
        case IROP_LAND:
            emit_land(isel, ins, next);
            break;
        case IROP_LOR:
            emit_lor(isel, ins, next);
            break;
        case IROP_TRUNC:
            emit_trunc(isel, ins);
            break;
        case IROP_ZEXT:
            emit_simple_cast(isel, ins, false);
            break;
        case IROP_SEXT:
            emit_simple_cast(isel, ins, true);
            break;
        case IROP_BITCAST:
        case IROP_INTTOPTR:
        case IROP_PTRTOINT:
            emit_simple_cast(isel, ins, false);
            break;
        case IROP_OFFSET:
            emit_offset(isel, ins);
            break;
        case IROP_SELECT:
            emit_select(isel, ins, next);
            break;
        case IROP_PHI:
            break;
        case IROP_RET:
            emit_ret(isel, ins);
            break;
        case IROP_STORE:
            emit_store(isel, ins);
            break;
        case IROP_LOAD:
            emit_load(isel, ins);
            break;
        case IROP_JMP:
            emit_jmp(isel, ins);
            break;
        case IROP_BR:
            emit_br(isel, ins);
            break;
        case IROP_ADDR:
            emit_addr(isel, ins);
            break;
        case IROP_ASM:
            emit_inline_asm_instr(isel, ins);
            break;
        case IROP_CALL:
            emit_call_instr(isel, ins, next);
            break;
        default:
            break;
    }
}

void isel_block(ISelContext* isel, Block* block) {
    if (!isel || !block || !block->instrs) return;
    isel->current_block_id = (int)block->id;

    if (block->id > 0) {
        char label[32];
        snprintf(label, sizeof(label), "L%d:", block->id);
        isel_emit(isel, label, NULL, NULL, NULL);
    }

    int num_instrs = block->instrs->len;
    Instr** instrs = malloc(sizeof(Instr*) * num_instrs);
    int idx = 0;
    for (Iter it = list_iter(block->instrs); !iter_end(it);) {
        instrs[idx++] = iter_next(&it);
    }

    precompute_sbit_br(isel, instrs, num_instrs);
    precompute_sbit_cpl(isel, instrs, num_instrs);
    precompute_br_simplify(isel, instrs, num_instrs);

    for (int i = 0; i < num_instrs; i++) {
        /* 寻找下一条有意义的指令（跳过CONST/NOP，它们不产生代码，不阻断BR-aware路径�?*/
        Instr* next = NULL;
        for (int j = i + 1; j < num_instrs; j++) {
            Instr* cand = instrs[j];
            if (!cand) continue;
            if (cand->op == IROP_NOP) continue;
            if (cand->op == IROP_CONST) continue;
            next = cand;
            break;
        }
        isel_instr(isel, instrs[i], next);
    }

    free(instrs);
}

void isel_function(C51GenContext* ctx, Func* func) {
    if (!ctx || !func) return;

    if (ctx->value_to_reg) {
        dict_free(ctx->value_to_reg, free);
        ctx->value_to_reg = make_dict(NULL);
    }

    int sec_idx = obj_add_section(ctx->obj, "?PR?", SEC_CODE, 0, 1);
    Section* sec = obj_get_section(ctx->obj, sec_idx);

    int flags = SYM_FLAG_GLOBAL;
    obj_add_symbol(ctx->obj, func->name, SYM_FUNC, sec_idx, sec->size, 0, flags);

    ctx->current_func = func;

    ISelContext isel = {0};
    isel.ctx = ctx;
    isel.sec = sec;
    isel.label_counter = 0;
    isel.br_bitinfo = make_dict(NULL);
    isel.br_invert = make_dict(NULL);
    isel.sbit_cpl_stores = make_dict(NULL);
    isel.last_const_reg = -100;
    isel.last_const_val = 0;
    isel.last_const_size = 0;

    for (int i = 0; i < 8; i++) {
        isel.reg_val[i] = -1;
    }

    char label[256];
    snprintf(label, sizeof(label), "_%s:", func->name);
    isel_emit(&isel, label, NULL, NULL, NULL);

    if (func->is_interrupt) {
        isel_emit(&isel, "PUSH", "PSW", NULL, NULL);
        isel_emit(&isel, "PUSH", "ACC", NULL, NULL);
        isel_emit(&isel, "PUSH", "B", NULL, NULL);
        isel_emit(&isel, "PUSH", "DPL", NULL, NULL);
        isel_emit(&isel, "PUSH", "DPH", NULL, NULL);
        if (func->bank_id >= 0) {
            char bank_imm[16];
            snprintf(bank_imm, sizeof(bank_imm), "#%d", (func->bank_id & 0x3) << 3);
            isel_emit(&isel, "MOV", "PSW", bank_imm, NULL);
        }
    }

    refine_param_pointer_spaces(ctx, func);

    alloc_param_regs(&isel, func);
    seed_value_types_for_func(ctx, func);

    LinearScanContext* lsc = linscan_create();
    linscan_compute_intervals(lsc, func, ctx);
    linscan_allocate(lsc, ctx);

    for (Iter it = list_iter(func->blocks); !iter_end(it);) {
        Block* block = iter_next(&it);
        isel_block(&isel, block);
    }

    if (isel.br_bitinfo) {
        dict_free(isel.br_bitinfo, free_br_bitinfo);
        isel.br_bitinfo = NULL;
    }
    if (isel.br_invert) {
        dict_free(isel.br_invert, free);
        isel.br_invert = NULL;
    }
    if (isel.sbit_cpl_stores) {
        dict_free(isel.sbit_cpl_stores, free);
        isel.sbit_cpl_stores = NULL;
    }

    linscan_destroy(lsc);
}
