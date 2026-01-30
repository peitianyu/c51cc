#include "c51_gen.h"

/* === Instruction encoding === */
void encode_section_bytes(ObjFile *obj, Section *sec)
{
    if (!sec || !sec->asminstrs) return;
    int sec_index = section_index_from_ptr(obj, sec);
    for (Iter it = list_iter(sec->asminstrs); !iter_end(it);) {
        AsmInstr *ins = iter_next(&it);
        if (!ins || !ins->op) continue;

        if (!strcmp(ins->op, ".label")) {
            char *name = (ins->args && ins->args->len > 0) ? list_get(ins->args, 0) : NULL;
            if (name) define_label_symbol(obj, name, sec_index, sec->bytes_len);
            continue;
        }

        if (!strcmp(ins->op, "nop")) {
            emit_u8(sec, 0x00);
            continue;
        }
        if (!strcmp(ins->op, "ret")) {
            emit_u8(sec, 0x22);
            continue;
        }
        if (!strcmp(ins->op, "reti")) {
            emit_u8(sec, 0x32);
            continue;
        }
        if (!strcmp(ins->op, "clr") && ins->args && ins->args->len == 1) {
            char *a0 = list_get(ins->args, 0);
            if (a0 && !strcmp(a0, "C")) {
                emit_u8(sec, 0xC3);
                continue;
            }
            if (a0 && !strcmp(a0, "A")) {
                emit_u8(sec, 0xE4);
                continue;
            }
        }
        if (!strcmp(ins->op, "cpl") && ins->args && ins->args->len == 1) {
            char *a0 = list_get(ins->args, 0);
            if (a0 && !strcmp(a0, "A")) {
                emit_u8(sec, 0xF4);
                continue;
            }
        }
        if (!strcmp(ins->op, "rrc") && (!ins->args || ins->args->len == 0 || (ins->args->len == 1 && !strcmp(list_get(ins->args, 0), "A")))) {
            emit_u8(sec, 0x13);
            continue;
        }
        if (!strcmp(ins->op, "rlc") && (!ins->args || ins->args->len == 0 || (ins->args->len == 1 && !strcmp(list_get(ins->args, 0), "A")))) {
            emit_u8(sec, 0x33);
            continue;
        }
        if (!strcmp(ins->op, "rl") && (!ins->args || ins->args->len == 0 || (ins->args->len == 1 && !strcmp(list_get(ins->args, 0), "A")))) {
            emit_u8(sec, 0x23);
            continue;
        }
        if (!strcmp(ins->op, "rr") && (!ins->args || ins->args->len == 0 || (ins->args->len == 1 && !strcmp(list_get(ins->args, 0), "A")))) {
            emit_u8(sec, 0x03);
            continue;
        }
        if (!strcmp(ins->op, "swap") && ins->args && ins->args->len == 1 && !strcmp(list_get(ins->args, 0), "A")) {
            emit_u8(sec, 0xC4);
            continue;
        }
        if (!strcmp(ins->op, "mul") && ins->args && ins->args->len == 1 && !strcmp(list_get(ins->args, 0), "AB")) {
            emit_u8(sec, 0xA4);
            continue;
        }
        if (!strcmp(ins->op, "div") && ins->args && ins->args->len == 1 && !strcmp(list_get(ins->args, 0), "AB")) {
            emit_u8(sec, 0x84);
            continue;
        }

        if (!strcmp(ins->op, "sjmp") && ins->args && ins->args->len == 1) {
            emit_u8(sec, 0x80);
            emit_rel8(obj, sec, list_get(ins->args, 0));
            continue;
        }
        if (!strcmp(ins->op, "jnz") && ins->args && ins->args->len == 1) {
            emit_u8(sec, 0x70);
            emit_rel8(obj, sec, list_get(ins->args, 0));
            continue;
        }
        if (!strcmp(ins->op, "jz") && ins->args && ins->args->len == 1) {
            emit_u8(sec, 0x60);
            emit_rel8(obj, sec, list_get(ins->args, 0));
            continue;
        }
        if (!strcmp(ins->op, "jc") && ins->args && ins->args->len == 1) {
            emit_u8(sec, 0x40);
            emit_rel8(obj, sec, list_get(ins->args, 0));
            continue;
        }
        if (!strcmp(ins->op, "jnc") && ins->args && ins->args->len == 1) {
            emit_u8(sec, 0x50);
            emit_rel8(obj, sec, list_get(ins->args, 0));
            continue;
        }
        if (!strcmp(ins->op, "lcall") && ins->args && ins->args->len == 1) {
            emit_u8(sec, 0x12);
            emit_abs16(obj, sec, list_get(ins->args, 0));
            continue;
        }
        if (!strcmp(ins->op, "ljmp") && ins->args && ins->args->len == 1) {
            emit_u8(sec, 0x02);
            emit_abs16(obj, sec, list_get(ins->args, 0));
            continue;
        }

        if (!strcmp(ins->op, "djnz") && ins->args && ins->args->len == 2) {
            char *a0 = list_get(ins->args, 0);
            char *a1 = list_get(ins->args, 1);
            int r = parse_reg_rn(a0);
            if (r >= 0) {
                emit_u8(sec, (unsigned char)(0xD8 + r));
                emit_rel8(obj, sec, a1);
                continue;
            }
            int direct = 0;
            if (parse_direct(a0, &direct)) {
                emit_u8(sec, 0xD5);
                emit_u8(sec, (unsigned char)(direct & 0xFF));
                emit_rel8(obj, sec, a1);
                continue;
            }
        }

        if (!strcmp(ins->op, "cjne") && ins->args && ins->args->len == 3) {
            char *a0 = list_get(ins->args, 0);
            char *a1 = list_get(ins->args, 1);
            char *a2 = list_get(ins->args, 2);
            int imm = 0;
            if (a0 && !strcmp(a0, "A")) {
                if (parse_immediate(a1, &imm)) {
                    emit_u8(sec, 0xB4);
                    emit_u8(sec, (unsigned char)(imm & 0xFF));
                    emit_rel8(obj, sec, a2);
                    continue;
                }
                int direct = 0;
                int r = parse_reg_rn(a1);
                if (r >= 0) direct = r;
                else if (!parse_direct(a1, &direct)) direct = -1;
                if (direct >= 0) {
                    emit_u8(sec, 0xB5);
                    emit_u8(sec, (unsigned char)(direct & 0xFF));
                    emit_rel8(obj, sec, a2);
                    continue;
                }
            }
            int r = parse_reg_rn(a0);
            if (r >= 0 && parse_immediate(a1, &imm)) {
                emit_u8(sec, (unsigned char)(0xB8 + r));
                emit_u8(sec, (unsigned char)(imm & 0xFF));
                emit_rel8(obj, sec, a2);
                continue;
            }
            int ir = parse_indirect_rn(a0);
            if ((ir == 0 || ir == 1) && parse_immediate(a1, &imm)) {
                emit_u8(sec, (unsigned char)(ir == 0 ? 0xB6 : 0xB7));
                emit_u8(sec, (unsigned char)(imm & 0xFF));
                emit_rel8(obj, sec, a2);
                continue;
            }
        }

        if ((!strcmp(ins->op, "push") || !strcmp(ins->op, "pop")) && ins->args && ins->args->len == 1) {
            char *a0 = list_get(ins->args, 0);
            int direct = 0;
            int r = parse_reg_rn(a0);
            if (r >= 0) direct = r;
            else if (!parse_direct(a0, &direct)) direct = -1;
            if (direct >= 0) {
                emit_u8(sec, (unsigned char)(!strcmp(ins->op, "push") ? 0xC0 : 0xD0));
                emit_u8(sec, (unsigned char)(direct & 0xFF));
                continue;
            }
        }

        if (!strcmp(ins->op, "mov") && ins->args && ins->args->len == 2) {
            char *dst = list_get(ins->args, 0);
            char *src = list_get(ins->args, 1);
            int imm = 0;
            int rdst = parse_reg_rn(dst);
            int rsrc = parse_reg_rn(src);
            int idst = parse_indirect_rn(dst);
            int isrc = parse_indirect_rn(src);
            int direct_dst = 0;
            int direct_src = 0;
            const char *dst_label = NULL;
            const char *src_label = NULL;
            bool dst_direct_ok = parse_direct_symbol(dst, &direct_dst, &dst_label);
            bool src_direct_ok = parse_direct_symbol(src, &direct_src, &src_label);

            if (dst && !strcmp(dst, "C")) {
                int bit = 0;
                const char *bit_label = NULL;
                if (parse_bit_symbol(src, &bit, &bit_label)) {
                    emit_u8(sec, 0xA2);
                    if (bit_label) emit_abs8(obj, sec, bit_label);
                    else emit_u8(sec, (unsigned char)(bit & 0xFF));
                    continue;
                }
            }
            if (src && !strcmp(src, "C")) {
                int bit = 0;
                const char *bit_label = NULL;
                if (parse_bit_symbol(dst, &bit, &bit_label)) {
                    emit_u8(sec, 0x92);
                    if (bit_label) emit_abs8(obj, sec, bit_label);
                    else emit_u8(sec, (unsigned char)(bit & 0xFF));
                    continue;
                }
            }

            if (dst && !strcmp(dst, "DPTR")) {
                const char *imm_label = NULL;
                if (parse_immediate_label(src, &imm, &imm_label)) {
                    emit_u8(sec, 0x90);
                    if (imm_label) emit_abs16(obj, sec, imm_label);
                    else emit_u16(sec, imm);
                    continue;
                }
            }

            if (dst && !strcmp(dst, "A")) {
                if (parse_immediate(src, &imm)) {
                    emit_u8(sec, 0x74);
                    emit_u8(sec, (unsigned char)(imm & 0xFF));
                    continue;
                }
                if (rsrc >= 0) {
                    emit_u8(sec, (unsigned char)(0xE8 + rsrc));
                    continue;
                }
                if (isrc == 0 || isrc == 1) {
                    emit_u8(sec, (unsigned char)(isrc == 0 ? 0xE6 : 0xE7));
                    continue;
                }
                if (src_direct_ok) {
                    emit_u8(sec, 0xE5);
                    if (src_label) emit_abs8(obj, sec, src_label);
                    else emit_u8(sec, (unsigned char)(direct_src & 0xFF));
                    continue;
                }
            }
            if (rdst >= 0) {
                if (parse_immediate(src, &imm)) {
                    emit_u8(sec, (unsigned char)(0x78 + rdst));
                    emit_u8(sec, (unsigned char)(imm & 0xFF));
                    continue;
                }
                if (src && !strcmp(src, "A")) {
                    emit_u8(sec, (unsigned char)(0xF8 + rdst));
                    continue;
                }
                if (src_direct_ok) {
                    emit_u8(sec, (unsigned char)(0xA8 + rdst));
                    if (src_label) emit_abs8(obj, sec, src_label);
                    else emit_u8(sec, (unsigned char)(direct_src & 0xFF));
                    continue;
                }
                if (rsrc >= 0) {
                    emit_u8(sec, (unsigned char)(0xE8 + rsrc));
                    emit_u8(sec, (unsigned char)(0xF8 + rdst));
                    continue;
                }
                if (isrc == 0 || isrc == 1) {
                    emit_u8(sec, (unsigned char)(isrc == 0 ? 0xE6 : 0xE7));
                    emit_u8(sec, (unsigned char)(0xF8 + rdst));
                    continue;
                }
            }
            if (idst == 0 || idst == 1) {
                if (src && !strcmp(src, "A")) {
                    emit_u8(sec, (unsigned char)(idst == 0 ? 0xF6 : 0xF7));
                    continue;
                }
                if (parse_immediate(src, &imm)) {
                    emit_u8(sec, (unsigned char)(idst == 0 ? 0x76 : 0x77));
                    emit_u8(sec, (unsigned char)(imm & 0xFF));
                    continue;
                }
                if (src_direct_ok) {
                    emit_u8(sec, (unsigned char)(idst == 0 ? 0xA6 : 0xA7));
                    if (src_label) emit_abs8(obj, sec, src_label);
                    else emit_u8(sec, (unsigned char)(direct_src & 0xFF));
                    continue;
                }
                if (rsrc >= 0) {
                    emit_u8(sec, (unsigned char)(0xE8 + rsrc));
                    emit_u8(sec, (unsigned char)(idst == 0 ? 0xF6 : 0xF7));
                    continue;
                }
            }
            if (dst_direct_ok) {
                if (parse_immediate(src, &imm)) {
                    emit_u8(sec, 0x75);
                    if (dst_label) emit_abs8(obj, sec, dst_label);
                    else emit_u8(sec, (unsigned char)(direct_dst & 0xFF));
                    emit_u8(sec, (unsigned char)(imm & 0xFF));
                    continue;
                }
                if (src && !strcmp(src, "A")) {
                    emit_u8(sec, 0xF5);
                    if (dst_label) emit_abs8(obj, sec, dst_label);
                    else emit_u8(sec, (unsigned char)(direct_dst & 0xFF));
                    continue;
                }
                if (rsrc >= 0) {
                    emit_u8(sec, (unsigned char)(0x88 + rsrc));
                    if (dst_label) emit_abs8(obj, sec, dst_label);
                    else emit_u8(sec, (unsigned char)(direct_dst & 0xFF));
                    continue;
                }
                if (src_direct_ok) {
                    emit_u8(sec, 0xE5);
                    if (src_label) emit_abs8(obj, sec, src_label);
                    else emit_u8(sec, (unsigned char)(direct_src & 0xFF));
                    emit_u8(sec, 0xF5);
                    if (dst_label) emit_abs8(obj, sec, dst_label);
                    else emit_u8(sec, (unsigned char)(direct_dst & 0xFF));
                    continue;
                }
                if (isrc == 0 || isrc == 1) {
                    emit_u8(sec, (unsigned char)(isrc == 0 ? 0x86 : 0x87));
                    if (dst_label) emit_abs8(obj, sec, dst_label);
                    else emit_u8(sec, (unsigned char)(direct_dst & 0xFF));
                    continue;
                }
            }
        }

        if (!strcmp(ins->op, "movx") && ins->args && ins->args->len == 2) {
            char *dst = list_get(ins->args, 0);
            char *src = list_get(ins->args, 1);
            if (dst && src && !strcmp(dst, "A") && !strcmp(src, "@DPTR")) {
                emit_u8(sec, 0xE0);
                continue;
            }
            if (dst && src && !strcmp(dst, "@DPTR") && !strcmp(src, "A")) {
                emit_u8(sec, 0xF0);
                continue;
            }
        }

        if (!strcmp(ins->op, "movc") && ins->args && ins->args->len == 2) {
            char *dst = list_get(ins->args, 0);
            char *src = list_get(ins->args, 1);
            if (dst && src && !strcmp(dst, "A") && !strcmp(src, "@A+DPTR")) {
                emit_u8(sec, 0x93);
                continue;
            }
        }

        if (!strcmp(ins->op, "add") && ins->args && ins->args->len == 2) {
            char *a0 = list_get(ins->args, 0);
            char *a1 = list_get(ins->args, 1);
            if (a0 && !strcmp(a0, "A")) {
                int imm = 0;
                int r = parse_reg_rn(a1);
                int ir = parse_indirect_rn(a1);
                int direct = 0;
                if (parse_immediate(a1, &imm)) {
                    emit_u8(sec, 0x24); emit_u8(sec, (unsigned char)(imm & 0xFF)); continue;
                }
                if (r >= 0) { emit_u8(sec, (unsigned char)(0x28 + r)); continue; }
                if (ir == 0 || ir == 1) { emit_u8(sec, (unsigned char)(ir == 0 ? 0x26 : 0x27)); continue; }
                if (parse_direct(a1, &direct)) { emit_u8(sec, 0x25); emit_u8(sec, (unsigned char)(direct & 0xFF)); continue; }
            }
        }
        if (!strcmp(ins->op, "addc") && ins->args && ins->args->len == 2) {
            char *a0 = list_get(ins->args, 0);
            char *a1 = list_get(ins->args, 1);
            if (a0 && !strcmp(a0, "A")) {
                int imm = 0;
                int r = parse_reg_rn(a1);
                int ir = parse_indirect_rn(a1);
                int direct = 0;
                if (parse_immediate(a1, &imm)) { emit_u8(sec, 0x34); emit_u8(sec, (unsigned char)(imm & 0xFF)); continue; }
                if (r >= 0) { emit_u8(sec, (unsigned char)(0x38 + r)); continue; }
                if (ir == 0 || ir == 1) { emit_u8(sec, (unsigned char)(ir == 0 ? 0x36 : 0x37)); continue; }
                if (parse_direct(a1, &direct)) { emit_u8(sec, 0x35); emit_u8(sec, (unsigned char)(direct & 0xFF)); continue; }
            }
        }
        if (!strcmp(ins->op, "subb") && ins->args && ins->args->len == 2) {
            char *a0 = list_get(ins->args, 0);
            char *a1 = list_get(ins->args, 1);
            if (a0 && !strcmp(a0, "A")) {
                int imm = 0;
                int r = parse_reg_rn(a1);
                int ir = parse_indirect_rn(a1);
                int direct = 0;
                if (parse_immediate(a1, &imm)) { emit_u8(sec, 0x94); emit_u8(sec, (unsigned char)(imm & 0xFF)); continue; }
                if (r >= 0) { emit_u8(sec, (unsigned char)(0x98 + r)); continue; }
                if (ir == 0 || ir == 1) { emit_u8(sec, (unsigned char)(ir == 0 ? 0x96 : 0x97)); continue; }
                if (parse_direct(a1, &direct)) { emit_u8(sec, 0x95); emit_u8(sec, (unsigned char)(direct & 0xFF)); continue; }
            }
        }
        if (!strcmp(ins->op, "anl") && ins->args && ins->args->len == 2) {
            char *a0 = list_get(ins->args, 0);
            char *a1 = list_get(ins->args, 1);
            if (a0 && !strcmp(a0, "A")) {
                int imm = 0;
                int r = parse_reg_rn(a1);
                int ir = parse_indirect_rn(a1);
                int direct = 0;
                if (parse_immediate(a1, &imm)) { emit_u8(sec, 0x54); emit_u8(sec, (unsigned char)(imm & 0xFF)); continue; }
                if (r >= 0) { emit_u8(sec, (unsigned char)(0x58 + r)); continue; }
                if (ir == 0 || ir == 1) { emit_u8(sec, (unsigned char)(ir == 0 ? 0x56 : 0x57)); continue; }
                if (parse_direct(a1, &direct)) { emit_u8(sec, 0x55); emit_u8(sec, (unsigned char)(direct & 0xFF)); continue; }
            }
        }
        if (!strcmp(ins->op, "orl") && ins->args && ins->args->len == 2) {
            char *a0 = list_get(ins->args, 0);
            char *a1 = list_get(ins->args, 1);
            if (a0 && !strcmp(a0, "A")) {
                int imm = 0;
                int r = parse_reg_rn(a1);
                int ir = parse_indirect_rn(a1);
                int direct = 0;
                if (parse_immediate(a1, &imm)) { emit_u8(sec, 0x44); emit_u8(sec, (unsigned char)(imm & 0xFF)); continue; }
                if (r >= 0) { emit_u8(sec, (unsigned char)(0x48 + r)); continue; }
                if (ir == 0 || ir == 1) { emit_u8(sec, (unsigned char)(ir == 0 ? 0x46 : 0x47)); continue; }
                if (parse_direct(a1, &direct)) { emit_u8(sec, 0x45); emit_u8(sec, (unsigned char)(direct & 0xFF)); continue; }
            }
        }
        if (!strcmp(ins->op, "xrl") && ins->args && ins->args->len == 2) {
            char *a0 = list_get(ins->args, 0);
            char *a1 = list_get(ins->args, 1);
            if (a0 && !strcmp(a0, "A")) {
                int imm = 0;
                int r = parse_reg_rn(a1);
                int ir = parse_indirect_rn(a1);
                int direct = 0;
                if (parse_immediate(a1, &imm)) { emit_u8(sec, 0x64); emit_u8(sec, (unsigned char)(imm & 0xFF)); continue; }
                if (r >= 0) { emit_u8(sec, (unsigned char)(0x68 + r)); continue; }
                if (ir == 0 || ir == 1) { emit_u8(sec, (unsigned char)(ir == 0 ? 0x66 : 0x67)); continue; }
                if (parse_direct(a1, &direct)) { emit_u8(sec, 0x65); emit_u8(sec, (unsigned char)(direct & 0xFF)); continue; }
            }
        }
        if (!strcmp(ins->op, "inc") && ins->args && ins->args->len == 1) {
            char *a0 = list_get(ins->args, 0);
            int r = parse_reg_rn(a0);
            int ir = parse_indirect_rn(a0);
            int direct = 0;
            if (a0 && !strcmp(a0, "A")) { emit_u8(sec, 0x04); continue; }
            if (r >= 0) { emit_u8(sec, (unsigned char)(0x08 + r)); continue; }
            if (ir == 0 || ir == 1) { emit_u8(sec, (unsigned char)(ir == 0 ? 0x06 : 0x07)); continue; }
            if (parse_direct(a0, &direct)) { emit_u8(sec, 0x05); emit_u8(sec, (unsigned char)(direct & 0xFF)); continue; }
        }
        if (!strcmp(ins->op, "dec") && ins->args && ins->args->len == 1) {
            char *a0 = list_get(ins->args, 0);
            int r = parse_reg_rn(a0);
            int ir = parse_indirect_rn(a0);
            int direct = 0;
            if (a0 && !strcmp(a0, "A")) { emit_u8(sec, 0x14); continue; }
            if (r >= 0) { emit_u8(sec, (unsigned char)(0x18 + r)); continue; }
            if (ir == 0 || ir == 1) { emit_u8(sec, (unsigned char)(ir == 0 ? 0x16 : 0x17)); continue; }
            if (parse_direct(a0, &direct)) { emit_u8(sec, 0x15); emit_u8(sec, (unsigned char)(direct & 0xFF)); continue; }
        }
    }
}
