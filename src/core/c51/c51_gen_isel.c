#include "c51_gen.h"

/* === Instruction selection === */
void emit_instr(Section *sec, Instr *ins, Func *func, Block *cur_block)
{
    if (!ins) return;
    char buf[64];
    const char *func_name = func ? func->name : NULL;
    if (ins->dest > 0 && ins->type) {
        val_type_put(ins->dest, ins->type);
    }

    switch (ins->op) {
    case IROP_NOP:
        return;
    case IROP_PARAM:
        if (ins->labels && ins->labels->len > 0) {
            char *pname = list_get(ins->labels, 0);
            Ctype *pt = NULL;
            int byte_off = param_byte_offset(func, pname, &pt);
            int size = pt ? pt->size : (ins->type ? ins->type->size : 1);
            if (byte_off < 0) {
                int idx = param_index(func, pname);
                if (idx >= 0) byte_off = (size >= 2) ? idx * 2 : idx;
            }
            if (size >= 2) {
                int addr = v16_addr(ins->dest);
                if (byte_off >= 0 && byte_off + 1 < 8) {
                    char reglo[8];
                    char reghi[8];
                    snprintf(reglo, sizeof(reglo), "r%d", 7 - byte_off);
                    snprintf(reghi, sizeof(reghi), "r%d", 7 - (byte_off + 1));
                    char dst0[16];
                    char dst1[16];
                    fmt_direct(dst0, sizeof(dst0), addr);
                    fmt_direct(dst1, sizeof(dst1), addr + 1);
                    emit_ins2(sec, "mov", dst0, reglo);
                    emit_ins2(sec, "mov", dst1, reghi);
                } else if (byte_off >= 8) {
                    int offset = 2 + (byte_off - 8);
                    emit_load_stack_param_to_direct(sec, offset, addr, func && func->stack_size > 0);
                    emit_load_stack_param_to_direct(sec, offset + 1, addr + 1, func && func->stack_size > 0);
                }
            } else {
                if (byte_off >= 0 && byte_off < 8) {
                    char regbuf[8];
                    snprintf(regbuf, sizeof(regbuf), "r%d", 7 - byte_off);
                    emit_ins2(sec, "mov", vreg(ins->dest), regbuf);
                } else if (byte_off >= 8) {
                    int offset = 2 + (byte_off - 8);
                    emit_load_stack_param(sec, offset, vreg(ins->dest), func && func->stack_size > 0);
                }
            }
        }
        return;
    case IROP_CONST:
        if (ins->type && ins->type->size >= 2) {
            int addr = v16_addr(ins->dest);
            char dst0[16];
            char dst1[16];
            fmt_direct(dst0, sizeof(dst0), addr);
            fmt_direct(dst1, sizeof(dst1), addr + 1);
            
            snprintf(buf, sizeof(buf), "#%d", (int)(ins->imm.ival & 0xFF));
            emit_ins2(sec, "mov", dst0, buf);
            
            snprintf(buf, sizeof(buf), "#%d", (int)((ins->imm.ival >> 8) & 0xFF));
            emit_ins2(sec, "mov", dst1, buf);
            
            if (g_const_map)
                const_map_put(ins->dest, (int)ins->imm.ival);
        } else {
            if (g_const_map)
                const_map_put(ins->dest, (int)ins->imm.ival);
        }
        break;
    case IROP_ADD:
        if (ins->type && ins->type->size >= 2) {
            ValueName a = *(ValueName *)list_get(ins->args, 0);
            ValueName b = *(ValueName *)list_get(ins->args, 1);
            int da = v16_addr(a);
            int db = v16_addr(b);
            int dd = v16_addr(ins->dest);
            char a0[16], a1[16], b0[16], b1[16], d0[16], d1[16];
            fmt_direct(a0, sizeof(a0), da);
            fmt_direct(a1, sizeof(a1), da + 1);
            fmt_direct(b0, sizeof(b0), db);
            fmt_direct(b1, sizeof(b1), db + 1);
            fmt_direct(d0, sizeof(d0), dd);
            fmt_direct(d1, sizeof(d1), dd + 1);
            emit_ins2(sec, "mov", "A", a0);
            emit_ins2(sec, "add", "A", b0);
            emit_ins2(sec, "mov", d0, "A");
            emit_ins2(sec, "mov", "A", a1);
            emit_ins2(sec, "addc", "A", b1);
            emit_ins2(sec, "mov", d1, "A");
        } else {
            emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
            emit_ins2(sec, "add", "A", vreg(*(ValueName *)list_get(ins->args, 1)));
            emit_ins2(sec, "mov", vreg(ins->dest), "A");
        }
        break;
    case IROP_SUB:
        if (ins->type && ins->type->size >= 2) {
            ValueName a = *(ValueName *)list_get(ins->args, 0);
            ValueName b = *(ValueName *)list_get(ins->args, 1);
            int da = v16_addr(a);
            int db = v16_addr(b);
            int dd = v16_addr(ins->dest);
            char a0[16], a1[16], b0[16], b1[16], d0[16], d1[16];
            fmt_direct(a0, sizeof(a0), da);
            fmt_direct(a1, sizeof(a1), da + 1);
            fmt_direct(b0, sizeof(b0), db);
            fmt_direct(b1, sizeof(b1), db + 1);
            fmt_direct(d0, sizeof(d0), dd);
            fmt_direct(d1, sizeof(d1), dd + 1);
            emit_ins1(sec, "clr", "C");
            emit_ins2(sec, "mov", "A", a0);
            emit_ins2(sec, "subb", "A", b0);
            emit_ins2(sec, "mov", d0, "A");
            emit_ins2(sec, "mov", "A", a1);
            emit_ins2(sec, "subb", "A", b1);
            emit_ins2(sec, "mov", d1, "A");
        } else {
            emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
            emit_ins1(sec, "clr", "C");
            emit_ins2(sec, "subb", "A", vreg(*(ValueName *)list_get(ins->args, 1)));
            emit_ins2(sec, "mov", vreg(ins->dest), "A");
        }
        break;
    case IROP_MUL:
        emit_ins2(sec, "mov", "B", vreg(*(ValueName *)list_get(ins->args, 1)));
        emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins1(sec, "mul", "AB");
        emit_ins2(sec, "mov", vreg(ins->dest), "A");
        break;
    case IROP_DIV:
        emit_ins2(sec, "mov", "B", vreg(*(ValueName *)list_get(ins->args, 1)));
        emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins1(sec, "div", "AB");
        emit_ins2(sec, "mov", vreg(ins->dest), "A");
        break;
    case IROP_MOD:
        emit_ins2(sec, "mov", "B", vreg(*(ValueName *)list_get(ins->args, 1)));
        emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
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
        ValueName a = *(ValueName *)list_get(ins->args, 0);
        ValueName b = *(ValueName *)list_get(ins->args, 1);
        int shift_cnt = 0;
        bool b_is_const = const_map_get(b, &shift_cnt);
        
        if (b_is_const && shift_cnt == 1) {
            emit_ins2(sec, "mov", "A", vreg(a));
            emit_ins2(sec, "add", "A", "ACC");
            emit_ins2(sec, "mov", vreg(ins->dest), "A");
        } else if (b_is_const && shift_cnt > 0 && shift_cnt <= 4) {
            emit_ins2(sec, "mov", "A", vreg(a));
            for (int i = 0; i < shift_cnt; i++) {
                emit_ins2(sec, "add", "A", "ACC");
            }
            emit_ins2(sec, "mov", vreg(ins->dest), "A");
        } else {
            char *l_loop = new_label("shl_loop");
            char *l_end = new_label("shl_end");
            emit_ins2(sec, "mov", "A", vreg(a));
            if (b_is_const) {
                char ibuf[16];
                snprintf(ibuf, sizeof(ibuf), "#%d", shift_cnt & 0xFF);
                emit_ins2(sec, "mov", "r7", ibuf);
            } else {
                emit_ins2(sec, "mov", "r7", vreg(b));
            }
            emit_ins3(sec, "cjne", "r7", "#0", l_loop);
            emit_ins1(sec, "sjmp", l_end);
            emit_label(sec, l_loop);
            emit_ins2(sec, "add", "A", "ACC");
            emit_ins2(sec, "djnz", "r7", l_loop);
            emit_label(sec, l_end);
            free(l_loop);
            free(l_end);
        }
        break;
    }
    case IROP_SHR: {
        ValueName a = *(ValueName *)list_get(ins->args, 0);
        ValueName b = *(ValueName *)list_get(ins->args, 1);
        int shift_cnt = 0;
        bool b_is_const = const_map_get(b, &shift_cnt);
        bool is_signed = is_signed_type(ins->type);
        
        if (b_is_const && !is_signed) {
            if (shift_cnt == 1) {
                emit_ins2(sec, "mov", "A", vreg(a));
                emit_ins1(sec, "clr", "C");
                emit_ins1(sec, "rrc", "A");
                emit_ins2(sec, "mov", vreg(ins->dest), "A");
            } else if (shift_cnt == 7) {
                emit_ins2(sec, "mov", "A", vreg(a));
                emit_ins1(sec, "swap", "A");
                emit_ins1(sec, "rrc", "A");
                emit_ins1(sec, "rrc", "A");
                emit_ins1(sec, "rrc", "A");
                emit_ins2(sec, "anl", "A", "#0x01");
                emit_ins2(sec, "mov", vreg(ins->dest), "A");
            } else if (shift_cnt == 4) {
                emit_ins2(sec, "mov", "A", vreg(a));
                emit_ins1(sec, "swap", "A");
                emit_ins2(sec, "anl", "A", "#0x0F");
                emit_ins2(sec, "mov", vreg(ins->dest), "A");
            } else if (shift_cnt > 0 && shift_cnt <= 4) {
                emit_ins2(sec, "mov", "A", vreg(a));
                for (int i = 0; i < shift_cnt; i++) {
                    emit_ins1(sec, "clr", "C");
                    emit_ins1(sec, "rrc", "A");
                }
                emit_ins2(sec, "mov", vreg(ins->dest), "A");
            } else {
                emit_ins2(sec, "mov", "A", vreg(a));
                for (int i = 0; i < shift_cnt; i++) {
                    emit_ins1(sec, "clr", "C");
                    emit_ins1(sec, "rrc", "A");
                }
                emit_ins2(sec, "mov", vreg(ins->dest), "A");
            }
        } else if (b_is_const && is_signed) {
            emit_ins2(sec, "mov", "A", vreg(a));
            for (int i = 0; i < shift_cnt; i++) {
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
                free(l_pos);
                free(l_cont);
            }
            emit_ins2(sec, "mov", vreg(ins->dest), "A");
        } else {
            char *l_loop = new_label("shr_loop");
            char *l_end = new_label("shr_end");
            emit_ins2(sec, "mov", "A", vreg(a));
            emit_ins2(sec, "mov", "r7", vreg(b));
            emit_ins3(sec, "cjne", "r7", "#0", l_loop);
            emit_ins1(sec, "sjmp", l_end);
            emit_label(sec, l_loop);
            if (is_signed) {
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
                free(l_pos);
                free(l_cont);
            } else {
                emit_ins1(sec, "clr", "C");
                emit_ins1(sec, "rrc", "A");
            }
            emit_ins2(sec, "djnz", "r7", l_loop);
            emit_label(sec, l_end);
            emit_ins2(sec, "mov", vreg(ins->dest), "A");
            free(l_loop);
            free(l_end);
        }
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
        ValueName a = *(ValueName *)list_get(ins->args, 0);
        ValueName b = *(ValueName *)list_get(ins->args, 1);
        if ((ins->type && ins->type->size >= 2) || val_size(a) >= 2 || val_size(b) >= 2) {
            char *l_false = new_label("eq_false");
            char *l_end = new_label("eq_end");
            int da = v16_addr(a);
            int db = v16_addr(b);
            char a0[16], a1[16], b0[16], b1[16];
            fmt_direct(a0, sizeof(a0), da);
            fmt_direct(a1, sizeof(a1), da + 1);
            int imm = 0;
            bool b_is_zero = const_map_get(b, &imm) && imm == 0;
            bool a_is_zero = const_map_get(a, &imm) && imm == 0;
            if (b_is_zero) {
                emit_ins2(sec, "mov", "A", a1);
                emit_ins3(sec, "cjne", "A", "#0", l_false);
                emit_ins2(sec, "mov", "A", a0);
                emit_ins3(sec, "cjne", "A", "#0", l_false);
            } else if (a_is_zero) {
                fmt_direct(b0, sizeof(b0), db);
                fmt_direct(b1, sizeof(b1), db + 1);
                emit_ins2(sec, "mov", "A", b1);
                emit_ins3(sec, "cjne", "A", "#0", l_false);
                emit_ins2(sec, "mov", "A", b0);
                emit_ins3(sec, "cjne", "A", "#0", l_false);
            } else {
                fmt_direct(b0, sizeof(b0), db);
                fmt_direct(b1, sizeof(b1), db + 1);
                emit_ins2(sec, "mov", "A", a1);
                emit_ins3(sec, "cjne", "A", b1, l_false);
                emit_ins2(sec, "mov", "A", a0);
                emit_ins3(sec, "cjne", "A", b0, l_false);
            }
            emit_ins2(sec, "mov", vreg(ins->dest), "#1");
            emit_ins1(sec, "sjmp", l_end);
            emit_label(sec, l_false);
            emit_ins2(sec, "mov", vreg(ins->dest), "#0");
            emit_label(sec, l_end);
            free(l_false);
            free(l_end);
        } else {
            char *l_false = new_label("eq_false");
            char *l_end = new_label("eq_end");
            emit_ins2(sec, "mov", "A", vreg(a));
            emit_ins3(sec, "cjne", "A", vreg(b), l_false);
            emit_ins2(sec, "mov", vreg(ins->dest), "#1");
            emit_ins1(sec, "sjmp", l_end);
            emit_label(sec, l_false);
            emit_ins2(sec, "mov", vreg(ins->dest), "#0");
            emit_label(sec, l_end);
            free(l_false);
            free(l_end);
        }
        break;
    }
    case IROP_NE: {
        ValueName a = *(ValueName *)list_get(ins->args, 0);
        ValueName b = *(ValueName *)list_get(ins->args, 1);
        if ((ins->type && ins->type->size >= 2) || val_size(a) >= 2 || val_size(b) >= 2) {
            char *l_true = new_label("ne_true");
            char *l_end = new_label("ne_end");
            int da = v16_addr(a);
            int db = v16_addr(b);
            char a0[16], a1[16], b0[16], b1[16];
            fmt_direct(a0, sizeof(a0), da);
            fmt_direct(a1, sizeof(a1), da + 1);
            int imm = 0;
            bool b_is_zero = const_map_get(b, &imm) && imm == 0;
            bool a_is_zero = const_map_get(a, &imm) && imm == 0;
            if (b_is_zero) {
                emit_ins2(sec, "mov", "A", a1);
                emit_ins3(sec, "cjne", "A", "#0", l_true);
                emit_ins2(sec, "mov", "A", a0);
                emit_ins3(sec, "cjne", "A", "#0", l_true);
            } else if (a_is_zero) {
                fmt_direct(b0, sizeof(b0), db);
                fmt_direct(b1, sizeof(b1), db + 1);
                emit_ins2(sec, "mov", "A", b1);
                emit_ins3(sec, "cjne", "A", "#0", l_true);
                emit_ins2(sec, "mov", "A", b0);
                emit_ins3(sec, "cjne", "A", "#0", l_true);
            } else {
                fmt_direct(b0, sizeof(b0), db);
                fmt_direct(b1, sizeof(b1), db + 1);
                emit_ins2(sec, "mov", "A", a1);
                emit_ins3(sec, "cjne", "A", b1, l_true);
                emit_ins2(sec, "mov", "A", a0);
                emit_ins3(sec, "cjne", "A", b0, l_true);
            }
            emit_ins2(sec, "mov", vreg(ins->dest), "#0");
            emit_ins1(sec, "sjmp", l_end);
            emit_label(sec, l_true);
            emit_ins2(sec, "mov", vreg(ins->dest), "#1");
            emit_label(sec, l_end);
            free(l_true);
            free(l_end);
        } else {
            char *l_true = new_label("ne_true");
            char *l_end = new_label("ne_end");
            emit_ins2(sec, "mov", "A", vreg(a));
            emit_ins3(sec, "cjne", "A", vreg(b), l_true);
            emit_ins2(sec, "mov", vreg(ins->dest), "#0");
            emit_ins1(sec, "sjmp", l_end);
            emit_label(sec, l_true);
            emit_ins2(sec, "mov", vreg(ins->dest), "#1");
            emit_label(sec, l_end);
            free(l_true);
            free(l_end);
        }
        break;
    }
    case IROP_LT: {
        char *l_true = new_label("lt_true");
        char *l_false = new_label("lt_false");
        char *l_same = new_label("lt_same");
        char *l_end = new_label("lt_end");
        emit_ins2(sec, "mov", "r6", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins2(sec, "mov", "r7", vreg(*(ValueName *)list_get(ins->args, 1)));
        if (is_signed_type(ins->type)) {
            emit_ins2(sec, "mov", "A", "r6");
            emit_ins2(sec, "xrl", "A", "r7");
            emit_ins2(sec, "anl", "A", "#0x80");
            emit_ins1(sec, "jz", l_same);
            emit_ins2(sec, "mov", "A", "r6");
            emit_ins2(sec, "anl", "A", "#0x80");
            emit_ins1(sec, "jz", l_false);
            emit_ins1(sec, "sjmp", l_true);
            emit_label(sec, l_same);
        }
        emit_ins2(sec, "mov", "A", "r6");
        emit_ins1(sec, "clr", "C");
        emit_ins2(sec, "subb", "A", "r7");
        emit_ins1(sec, "jc", l_true);
        emit_label(sec, l_false);
        emit_ins2(sec, "mov", vreg(ins->dest), "#0");
        emit_ins1(sec, "sjmp", l_end);
        emit_label(sec, l_true);
        emit_ins2(sec, "mov", vreg(ins->dest), "#1");
        emit_label(sec, l_end);
        free(l_true);
        free(l_false);
        free(l_same);
        free(l_end);
        break;
    }
    case IROP_LE: {
        char *l_true = new_label("le_true");
        char *l_false = new_label("le_false");
        char *l_same = new_label("le_same");
        char *l_end = new_label("le_end");
        emit_ins2(sec, "mov", "r6", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins2(sec, "mov", "r7", vreg(*(ValueName *)list_get(ins->args, 1)));
        if (is_signed_type(ins->type)) {
            emit_ins2(sec, "mov", "A", "r6");
            emit_ins2(sec, "xrl", "A", "r7");
            emit_ins2(sec, "anl", "A", "#0x80");
            emit_ins1(sec, "jz", l_same);
            emit_ins2(sec, "mov", "A", "r6");
            emit_ins2(sec, "anl", "A", "#0x80");
            emit_ins1(sec, "jz", l_false);
            emit_ins1(sec, "sjmp", l_true);
            emit_label(sec, l_same);
        }
        emit_ins2(sec, "mov", "A", "r6");
        emit_ins1(sec, "clr", "C");
        emit_ins2(sec, "subb", "A", "r7");
        emit_ins1(sec, "jc", l_true);
        emit_ins1(sec, "jz", l_true);
        emit_label(sec, l_false);
        emit_ins2(sec, "mov", vreg(ins->dest), "#0");
        emit_ins1(sec, "sjmp", l_end);
        emit_label(sec, l_true);
        emit_ins2(sec, "mov", vreg(ins->dest), "#1");
        emit_label(sec, l_end);
        free(l_true);
        free(l_false);
        free(l_same);
        free(l_end);
        break;
    }
    case IROP_GT: {
        char *l_true = new_label("gt_true");
        char *l_false = new_label("gt_false");
        char *l_same = new_label("gt_same");
        char *l_end = new_label("gt_end");
        emit_ins2(sec, "mov", "r6", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins2(sec, "mov", "r7", vreg(*(ValueName *)list_get(ins->args, 1)));
        if (is_signed_type(ins->type)) {
            emit_ins2(sec, "mov", "A", "r6");
            emit_ins2(sec, "xrl", "A", "r7");
            emit_ins2(sec, "anl", "A", "#0x80");
            emit_ins1(sec, "jz", l_same);
            emit_ins2(sec, "mov", "A", "r6");
            emit_ins2(sec, "anl", "A", "#0x80");
            emit_ins1(sec, "jz", l_true);
            emit_ins1(sec, "sjmp", l_false);
            emit_label(sec, l_same);
        }
        emit_ins2(sec, "mov", "A", "r6");
        emit_ins1(sec, "clr", "C");
        emit_ins2(sec, "subb", "A", "r7");
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
        free(l_same);
        free(l_end);
        break;
    }
    case IROP_GE: {
        char *l_true = new_label("ge_true");
        char *l_false = new_label("ge_false");
        char *l_same = new_label("ge_same");
        char *l_end = new_label("ge_end");
        emit_ins2(sec, "mov", "r6", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins2(sec, "mov", "r7", vreg(*(ValueName *)list_get(ins->args, 1)));
        if (is_signed_type(ins->type)) {
            emit_ins2(sec, "mov", "A", "r6");
            emit_ins2(sec, "xrl", "A", "r7");
            emit_ins2(sec, "anl", "A", "#0x80");
            emit_ins1(sec, "jz", l_same);
            emit_ins2(sec, "mov", "A", "r6");
            emit_ins2(sec, "anl", "A", "#0x80");
            emit_ins1(sec, "jz", l_true);
            emit_ins1(sec, "sjmp", l_false);
            emit_label(sec, l_same);
        }
        emit_ins2(sec, "mov", "A", "r6");
        emit_ins1(sec, "clr", "C");
        emit_ins2(sec, "subb", "A", "r7");
        emit_ins1(sec, "jnc", l_true);
        emit_label(sec, l_false);
        emit_ins2(sec, "mov", vreg(ins->dest), "#0");
        emit_ins1(sec, "sjmp", l_end);
        emit_label(sec, l_true);
        emit_ins2(sec, "mov", vreg(ins->dest), "#1");
        emit_label(sec, l_end);
        free(l_true);
        free(l_false);
        free(l_same);
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
    case IROP_ADDR: {
        if (ins->labels && ins->labels->len > 0) {
            const char *name = list_get(ins->labels, 0);
            int off = 0;
            
            if (func_stack_offset(func, name, &off)) {
                char obuf[16];
                emit_ins2(sec, "mov", "A", "0x2E");
                snprintf(obuf, sizeof(obuf), "#%d", off + 1);
                emit_ins2(sec, "add", "A", obuf);
                emit_ins2(sec, "mov", vreg(ins->dest), "A");
                
                addr_map_put_stack(ins->dest, off, ins->mem_type);
            } else {
                MmioInfo *mmio = mmio_map_get(name);
                
                if (mmio) {
                    char buf[32];
                    snprintf(buf, sizeof(buf), "0x%02X", mmio->addr & 0xFF);
                    addr_map_put(ins->dest, buf, ins->mem_type);
                } else {
                    addr_map_put(ins->dest, name, ins->mem_type);
                }
            }
        }
        return; 
    }
    case IROP_OFFSET: {
        ValueName base = *(ValueName *)list_get(ins->args, 0);
        ValueName idx = *(ValueName *)list_get(ins->args, 1);
        int elem = (int)ins->imm.ival;
        int cidx = 0;
        if (const_map_get(idx, &cidx)) {
            int off = cidx * elem;
            char obuf[16];
            emit_ins2(sec, "mov", "A", vreg(base));
            snprintf(obuf, sizeof(obuf), "#%d", off);
            emit_ins2(sec, "add", "A", obuf);
            emit_ins2(sec, "mov", vreg(ins->dest), "A");
        } else {
            emit_ins2(sec, "mov", "A", vreg(idx));
            if (elem != 1) {
                char ebuf[16];
                snprintf(ebuf, sizeof(ebuf), "#%d", elem);
                emit_ins2(sec, "mov", "B", ebuf);
                emit_ins1(sec, "mul", "AB");
            }
            emit_ins2(sec, "mov", "r6", "A");
            emit_ins2(sec, "mov", "A", vreg(base));
            emit_ins2(sec, "add", "A", "r6");
            emit_ins2(sec, "mov", vreg(ins->dest), "A");
        }
        return;
    }
    case IROP_LOAD:
    {
        ValueName ptr = *(ValueName *)list_get(ins->args, 0);
        struct AddrInfo *info = addr_map_get(ptr);
        Ctype *mtype = ins->mem_type ? ins->mem_type : (info ? info->mem_type : NULL);
        int space = data_space_kind(mtype);
        if (info && info->is_stack) {
            emit_stack_addr(sec, info->stack_off);
            emit_ins2(sec, "mov", "A", "@r0");
            emit_ins2(sec, "mov", vreg(ins->dest), "A");
            break;
        }
        if (info && info->label && is_register_bit(mtype)) {
            emit_ins2(sec, "mov", "C", info->label);
            emit_ins2(sec, "mov", "A", "#0");
            emit_ins1(sec, "rlc", "A");
            emit_ins2(sec, "mov", vreg(ins->dest), "A");
            break;
        }
        if (info && info->label) {
            if (space == 6) {
                char imm[128];
                snprintf(imm, sizeof(imm), "#%s", info->label);
                emit_ins2(sec, "mov", "DPTR", imm);
                emit_ins2(sec, "mov", "A", "#0");
                emit_ins2(sec, "movc", "A", "@A+DPTR");
            } else if (space == 4 || space == 5) {
                char imm[128];
                snprintf(imm, sizeof(imm), "#%s", info->label);
                emit_ins2(sec, "mov", "DPTR", imm);
                emit_ins2(sec, "movx", "A", "@DPTR");
            } else {
                emit_ins2(sec, "mov", "A", info->label);
            }
        } else if (space == 6) {
            emit_ins2(sec, "mov", "0x82", vreg(ptr));
            emit_ins2(sec, "mov", "0x83", "#0");
            emit_ins2(sec, "mov", "A", "#0");
            emit_ins2(sec, "movc", "A", "@A+DPTR");
        } else if (space == 4 || space == 5) {
            emit_ins2(sec, "mov", "0x82", vreg(ptr));
            emit_ins2(sec, "mov", "0x83", "#0");
            emit_ins2(sec, "movx", "A", "@DPTR");
        } else {
            snprintf(buf, sizeof(buf), "@%s", vreg(ptr));
            emit_ins2(sec, "mov", "A", buf);
        }
        emit_ins2(sec, "mov", vreg(ins->dest), "A");
        break;
    }
    case IROP_STORE: {
        ValueName ptr = *(ValueName *)list_get(ins->args, 0);
        ValueName val = *(ValueName *)list_get(ins->args, 1);
        struct AddrInfo *info = addr_map_get(ptr);
        Ctype *mtype = ins->mem_type ? ins->mem_type : (info ? info->mem_type : NULL);
        int space = data_space_kind(mtype);
        
        int const_val = 0;
        bool val_is_const = const_map_get(val, &const_val);
        
        if (info && info->is_stack) {
            if (val_is_const) {
                char ibuf[16];
                snprintf(ibuf, sizeof(ibuf), "#%d", const_val & 0xFF);
                emit_ins2(sec, "mov", "A", ibuf);
            } else {
                emit_ins2(sec, "mov", "A", vreg(val));
            }
            emit_stack_addr(sec, info->stack_off);
            emit_ins2(sec, "mov", "@r0", "A");
            break;
        }
        
        if (info && info->label) {
            if (strncmp(info->label, "0x", 2) == 0) {
                if (val_is_const) {
                    char ibuf[16];
                    snprintf(ibuf, sizeof(ibuf), "#%d", const_val & 0xFF);
                    emit_ins2(sec, "mov", info->label, ibuf);
                } else {
                    emit_ins2(sec, "mov", "A", vreg(val));
                    emit_ins2(sec, "mov", info->label, "A");
                }
                break;
            }
            
            if (is_register_bit(mtype)) {
                if (val_is_const) {
                    if (const_val) {
                        emit_ins1(sec, "setb", info->label);
                    } else {
                        emit_ins1(sec, "clr", info->label);
                    }
                } else {
                    emit_ins2(sec, "mov", "A", vreg(val));
                    emit_ins1(sec, "rrc", "A");
                    emit_ins2(sec, "mov", info->label, "C");
                }
                break;
            }
        }
        
        if (space == 6) {
            /* CODE space - shouldn't have store */
        } else if (space == 4 || space == 5) {
            if (info && info->label) {
                char imm[128];
                snprintf(imm, sizeof(imm), "#%s", info->label);
                emit_ins2(sec, "mov", "DPTR", imm);
            } else {
                emit_ins2(sec, "mov", "0x82", vreg(ptr));
                emit_ins2(sec, "mov", "0x83", "#0");
            }
            
            if (val_is_const) {
                char ibuf[16];
                snprintf(ibuf, sizeof(ibuf), "#%d", const_val & 0xFF);
                emit_ins2(sec, "mov", "A", ibuf);
            } else {
                emit_ins2(sec, "mov", "A", vreg(val));
            }
            emit_ins2(sec, "movx", "@DPTR", "A");
        } else {
            if (info && info->label) {
                if (val_is_const) {
                    char ibuf[16];
                    snprintf(ibuf, sizeof(ibuf), "#%d", const_val & 0xFF);
                    emit_ins2(sec, "mov", info->label, ibuf);
                } else {
                    emit_ins2(sec, "mov", "A", vreg(val));
                    emit_ins2(sec, "mov", info->label, "A");
                }
            } else {
                if (val_is_const) {
                    char ibuf[16];
                    snprintf(ibuf, sizeof(ibuf), "#%d", const_val & 0xFF);
                    snprintf(buf, sizeof(buf), "@%s", vreg(ptr));
                    emit_ins2(sec, "mov", buf, ibuf);
                } else {
                    emit_ins2(sec, "mov", "A", vreg(val));
                    snprintf(buf, sizeof(buf), "@%s", vreg(ptr));
                    emit_ins2(sec, "mov", buf, "A");
                }
            }
        }
        break;
    }
    case IROP_JMP: {
        char *label = list_get(ins->labels, 0);
        emit_phi_moves_for_edge(sec, func, cur_block, label);
        emit_ins1(sec, "sjmp", map_block_label(func_name, label));
        break;
    }
    case IROP_BR: {
        char *t = list_get(ins->labels, 0);
        char *f = list_get(ins->labels, 1);
        char *l_true = new_label("phi_true");
        emit_ins2(sec, "mov", "A", vreg(*(ValueName *)list_get(ins->args, 0)));
        emit_ins1(sec, "jnz", l_true);
        emit_phi_moves_for_edge(sec, func, cur_block, f);
        emit_ins1(sec, "sjmp", map_block_label(func_name, f));
        emit_label(sec, l_true);
        emit_phi_moves_for_edge(sec, func, cur_block, t);
        emit_ins1(sec, "sjmp", map_block_label(func_name, t));
        free(l_true);
        break;
    }
    case IROP_CALL: {
        char *fname = list_get(ins->labels, 0);
        int nargs = ins->args ? ins->args->len : 0;
        int total_bytes = 0;
        typedef struct { ValueName v; int byte_idx; int byte_off; int size; } ArgByte;
        ArgByte *bytes = NULL;
        if (ins->args) {
            for (int idx = 0; idx < nargs; ++idx) {
                ValueName v = *(ValueName *)list_get(ins->args, idx);
                int sz = val_size(v);
                total_bytes += (sz >= 2) ? 2 : 1;
            }
        }
        int extra = total_bytes > 8 ? (total_bytes - 8) : 0;

        if (total_bytes > 0)
            bytes = gen_alloc(sizeof(ArgByte) * total_bytes);
        int bi = 0;
        int byte_idx = 0;
        if (ins->args) {
            for (int idx = 0; idx < nargs; ++idx) {
                ValueName v = *(ValueName *)list_get(ins->args, idx);
                int sz = val_size(v);
                int cnt = (sz >= 2) ? 2 : 1;
                for (int j = 0; j < cnt; ++j) {
                    bytes[bi++] = (ArgByte){v, byte_idx + j, j, sz};
                }
                byte_idx += cnt;
            }
        }

        for (int r = 0; r <= 3; ++r) {
            char regbuf[8];
            snprintf(regbuf, sizeof(regbuf), "r%d", r);
            emit_ins1(sec, "push", regbuf);
        }

        if (total_bytes > 0) {
            for (int i = total_bytes - 1; i >= 0; --i) {
                if (bytes[i].byte_idx < 8) continue;
                if (bytes[i].size >= 2) {
                    char src[16];
                    fmt_direct(src, sizeof(src), v16_addr(bytes[i].v) + bytes[i].byte_off);
                    emit_ins2(sec, "mov", "A", src);
                } else {
                    emit_ins2(sec, "mov", "A", vreg(bytes[i].v));
                }
                emit_ins1(sec, "push", "A");
            }

            for (int i = 0; i < total_bytes; ++i) {
                if (bytes[i].byte_idx >= 8) continue;
                char regbuf[8];
                snprintf(regbuf, sizeof(regbuf), "r%d", 7 - bytes[i].byte_idx);
                if (bytes[i].size >= 2) {
                    char src[16];
                    fmt_direct(src, sizeof(src), v16_addr(bytes[i].v) + bytes[i].byte_off);
                    emit_ins2(sec, "mov", regbuf, src);
                } else {
                    emit_ins2(sec, "mov", regbuf, vreg(bytes[i].v));
                }
            }
        }
        emit_ins1(sec, "lcall", fname ? fname : "<null>");

        for (int i = 0; i < extra; ++i)
            emit_ins1(sec, "pop", "r0");

        for (int r = 3; r >= 0; --r) {
            char regbuf[8];
            snprintf(regbuf, sizeof(regbuf), "r%d", r);
            emit_ins1(sec, "pop", regbuf);
        }

        if (ins->dest != 0) {
            if (ins->type && ins->type->size >= 2) {
                int addr = v16_addr(ins->dest);
                char dst0[16];
                char dst1[16];
                fmt_direct(dst0, sizeof(dst0), addr);
                fmt_direct(dst1, sizeof(dst1), addr + 1);
                emit_ins2(sec, "mov", "A", "0x82");
                emit_ins2(sec, "mov", dst0, "A");
                emit_ins2(sec, "mov", "A", "0x83");
                emit_ins2(sec, "mov", dst1, "A");
            } else {
                emit_ins2(sec, "mov", vreg(ins->dest), "A");
            }
        }
        break;
    }
    case IROP_RET:
        if (ins->args && ins->args->len > 0) {
            ValueName v = *(ValueName *)list_get(ins->args, 0);
            
            if (func && func->ret_type && func->ret_type->size >= 2) {
                int const_val = 0;
                if (const_map_get(v, &const_val)) {
                    char buf0[16], buf1[16];
                    snprintf(buf0, sizeof(buf0), "#%d", const_val & 0xFF);
                    snprintf(buf1, sizeof(buf1), "#%d", (const_val >> 8) & 0xFF);
                    emit_ins2(sec, "mov", "0x82", buf0);
                    emit_ins2(sec, "mov", "0x83", buf1);
                } else if (is_v16_value(v)) {
                    int addr = v16_addr(v);
                    char src0[16], src1[16];
                    fmt_direct(src0, sizeof(src0), addr);
                    fmt_direct(src1, sizeof(src1), addr + 1);
                    emit_ins2(sec, "mov", "A", src0);
                    emit_ins2(sec, "mov", "0x82", "A");
                    emit_ins2(sec, "mov", "A", src1);
                    emit_ins2(sec, "mov", "0x83", "A");
                } else {
                    emit_ins2(sec, "mov", "0x82", vreg(v));
                    emit_ins2(sec, "mov", "0x83", "#0");
                }
            } else {
                int const_val = 0;
                if (const_map_get(v, &const_val)) {
                    char buf[16];
                    snprintf(buf, sizeof(buf), "#%d", const_val & 0xFF);
                    emit_ins2(sec, "mov", "A", buf);
                } else {
                    emit_ins2(sec, "mov", "A", vreg(v));
                }
            }
        } else {
            emit_ins2(sec, "mov", "A", "#0");
        }
        
        if (func && func->stack_size > 0)
            emit_frame_epilogue(sec, func->stack_size);
        
        if (func && func->is_interrupt) {
            emit_interrupt_epilogue(sec);
            emit_ins0(sec, "reti");
        } else {
            emit_ins0(sec, "ret");
        }
        break;
    case IROP_PHI:
        return;
    default:
        return;
    }
}
