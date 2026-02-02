#include "c51_gen.h"

/* ---------- 辅助 ---------- */
static bool reg_eq(const char *a, const char *b)
{ return a && b && !strcmp(a, b); }

unsigned reg_bit(int r)
{ return (r < 0 || r > 7) ? 0 : 1u << r; }

/* 解析寄存器编号，支持 Rn 和 @Rn */
static int reg_no(const char *s)
{
    int r = parse_reg_rn(s);
    return r >= 0 ? r : parse_indirect_rn(s);
}

/* 从参数得到寄存器掩码 */
static unsigned reg_mask(const char *arg)
{ return reg_bit(reg_no(arg)); }

/* ---------- 1. 指令语义：use/def 集合 ---------- */
void reg_use_def(const AsmInstr *ins, unsigned *use, unsigned *def)
{
    if (use) *use = 0;
    if (def) *def = 0;
    if (!ins || !ins->op || !ins->args) return;

    const char *op   = ins->op;
    const char *a0   = ins->args->len > 0 ? list_get(ins->args, 0) : NULL;
    const char *a1   = ins->args->len > 1 ? list_get(ins->args, 1) : NULL;

    /* mov */
    if (!strcmp(op, "mov") && a0 && a1) {
        int rd = parse_reg_rn(a0);
        int rs = parse_reg_rn(a1);
        if (def && rd >= 0) *def |= reg_bit(rd);
        if (use && rs >= 0) *use |= reg_bit(rs);
        *use |= reg_mask(a0);   /* @Rn */
        *use |= reg_mask(a1);
        return;
    }

    /* inc/dec */
    if ((!strcmp(op, "inc") || !strcmp(op, "dec")) && a0) {
        int r = parse_reg_rn(a0);
        if (r >= 0) {
            if (use) *use |= reg_bit(r);
            if (def) *def |= reg_bit(r);
        } else {
            if (use) *use |= reg_mask(a0); /* @Rn */
        }
        return;
    }

    /* djnz */
    if (!strcmp(op, "djnz") && a0) {
        int r = parse_reg_rn(a0);
        if (r >= 0) {
            if (use) *use |= reg_bit(r);
            if (def) *def |= reg_bit(r);
        }
        return;
    }

    /* cjne */
    if (!strcmp(op, "cjne") && a0) {
        if (use) *use |= reg_mask(a0) | (a1 ? reg_mask(a1) : 0);
        return;
    }

    /* push / pop */
    if (!strcmp(op, "push") && a0) { if (use) *use |= reg_mask(a0); return; }
    if (!strcmp(op, "pop")  && a0) { int r = parse_reg_rn(a0);
                                     if (def && r >= 0) *def |= reg_bit(r); return; }

    /* 双操作数 ALU：add,subb,anl,orl,xrl */
    static const char *alu[] = {"add","subb","anl","orl","xrl",NULL};
    for (const char **p = alu; *p; ++p)
        if (!strcmp(op, *p) && a0 && a1) {
            int r0 = parse_reg_rn(a0);
            if (r0 >= 0) {
                if (use) *use |= reg_bit(r0);
                if (def) *def |= reg_bit(r0);
            } else {
                if (use) *use |= reg_mask(a0);
            }
            if (use) *use |= reg_mask(a1);
            return;
        }

    /* 默认：两个参数都当 use */
    if (use) *use |= reg_mask(a0) | reg_mask(a1);
}

/* ---------- 2. lcall 前后 push/pop 消除 ---------- */
void shrink_call_saves(Section *sec)
{
    if (!sec || !sec->asminstrs || sec->asminstrs->len <= 0) return;
    int n = sec->asminstrs->len;
    unsigned *live = gen_alloc(sizeof(unsigned) * n);

    /* 逆序算出 live-after 集合 */
    unsigned l = 0;
    for (int i = n - 1; i >= 0; --i) {
        live[i] = l;
        unsigned u, d;
        reg_use_def(list_get(sec->asminstrs, i), &u, &d);
        l = (l & ~d) | u;
    }

    for (int i = 0; i < n; ++i) {
        AsmInstr *ins = list_get(sec->asminstrs, i);
        if (!ins || !ins->op || strcmp(ins->op, "lcall")) continue;

        unsigned need = live[i];
        int push[8], pop[8];
        for (int r = 0; r < 8; ++r) push[r] = pop[r] = -1;

        /* 向前找 push */
        for (int j = i - 1, f = 0; j >= 0 && f < 8; --j) {
            AsmInstr *p = list_get(sec->asminstrs, j);
            if (!p || !p->op) continue;
            if (!strcmp(p->op, ".label")) break;
            if (!strcmp(p->op, "push") && p->args && p->args->len == 1) {
                int r = parse_reg_rn(list_get(p->args, 0));
                if (r >= 0 && push[r] < 0) { push[r] = j; ++f; }
            }
        }

        /* 向后找 pop（按 r7…r0 顺序）*/
        int pos = -1;
        for (int j = i + 1; j < n; ++j) {
            AsmInstr *p = list_get(sec->asminstrs, j);
            if (!p || !p->op) continue;
            if (!strcmp(p->op, "pop") && p->args && p->args->len == 1
                && parse_reg_rn(list_get(p->args, 0)) == 7) {
                pop[7] = pos = j; break;
            }
            if (!strcmp(p->op, ".label")) break;
        }
        if (pos >= 0)
            for (int r = 6; r >= 0; --r)
                for (int j = pos + 1; j < n; ++j) {
                    AsmInstr *p = list_get(sec->asminstrs, j);
                    if (!p || !p->op) continue;
                    if (!strcmp(p->op, "pop") && p->args && p->args->len == 1
                        && parse_reg_rn(list_get(p->args, 0)) == r) {
                        pop[r] = j; pos = j; break;
                    }
                    if (!strcmp(p->op, ".label")) break;
                }

        /* 如果寄存器不 live 且 push/pop 都找到了，就删掉它们 */
        for (int r = 0; r < 8; ++r)
            if (!(need & reg_bit(r)) && push[r] >= 0 && pop[r] >= 0) {
                free_asminstr(list_get(sec->asminstrs, push[r]));
                free_asminstr(list_get(sec->asminstrs, pop[r]));
                list_set(sec->asminstrs, push[r], NULL);
                list_set(sec->asminstrs, pop[r], NULL);
            }
    }
}

/* ---------- 3. 窥孔主入口 ---------- */
const char *invert_jcc(const char *op)
{
    if (!op) return NULL;
    if (!strcmp(op, "jz"))  return "jnz";
    if (!strcmp(op, "jnz")) return "jz";
    if (!strcmp(op, "jc"))  return "jnc";
    if (!strcmp(op, "jnc")) return "jc";
    return NULL;
}

void peephole_section_asminstrs(Section *sec)
{
    if (!sec || !sec->asminstrs) return;
    List *out = make_list();

    for (int i = 0; i < sec->asminstrs->len; ++i) {
        AsmInstr *cur  = list_get(sec->asminstrs, i);
        AsmInstr *nxt  = i + 1 < sec->asminstrs->len ? list_get(sec->asminstrs, i + 1) : NULL;
        AsmInstr *nnxt = i + 2 < sec->asminstrs->len ? list_get(sec->asminstrs, i + 2) : NULL;
        if (!cur || !cur->op) { list_push(out, cur); continue; }

        const char *op = cur->op;
        const char *a0 = cur->args && cur->args->len > 0 ? list_get(cur->args, 0) : NULL;
        const char *a1 = cur->args && cur->args->len > 1 ? list_get(cur->args, 1) : NULL;

        /* (1) 跳到下一条 label 的跳转 */
        if ((reg_eq(op, "sjmp") || reg_eq(op, "ljmp") ||
             reg_eq(op, "jz")  || reg_eq(op, "jnz") ||
             reg_eq(op, "jc")  || reg_eq(op, "jnc")) &&
            cur->args && cur->args->len == 1 && nxt &&
            reg_eq(nxt->op, ".label") && nxt->args && nxt->args->len >= 1 &&
            reg_eq(a0, list_get(nxt->args, 0))) {
            free_asminstr(cur); continue;
        }

        /* (2) push r / pop r 抵消 */
        if (reg_eq(op, "push") && nxt && reg_eq(nxt->op, "pop") &&
            cur->args && cur->args->len == 1 && nxt->args && nxt->args->len == 1 &&
            reg_eq(a0, list_get(nxt->args, 0))) {
            free_asminstr(cur); free_asminstr(nxt); ++i; continue;
        }

        /* (3) 对 A 的无效 ALU 立即数操作 */
        int imm;
        if ((reg_eq(op, "anl") || reg_eq(op, "orl") || reg_eq(op, "xrl")) &&
            a0 && reg_eq(a0, "A") && a1 && parse_immediate(a1, &imm)) {
            if ((reg_eq(op, "anl") && (imm & 0xFF) == 0xFF) ||
                (reg_eq(op, "orl") && (imm & 0xFF) == 0x00) ||
                (reg_eq(op, "xrl") && (imm & 0xFF) == 0x00)) {
                free_asminstr(cur); continue;
            }
        }

        /* (4) add/subb A,#0 删掉；add A,#1 → inc A */
        if ((reg_eq(op, "add") || reg_eq(op, "subb")) &&
            a0 && reg_eq(a0, "A") && a1 && parse_immediate(a1, &imm) && imm == 0) {
            if (reg_eq(op, "add")) {
                AsmInstr *inc = gen_instr_new("inc");
                gen_instr_add_arg(inc, "A");
                list_push(out, inc);
            }
            free_asminstr(cur); continue;
        }

        /* (5) jcc L / sjmp M / L:  → 反向条件到 M */
        if (nxt && nnxt &&
            (reg_eq(op, "jz") || reg_eq(op, "jnz") ||
             reg_eq(op, "jc") || reg_eq(op, "jnc")) &&
            cur->args && cur->args->len == 1 &&
            reg_eq(nxt->op, "sjmp") && nxt->args && nxt->args->len == 1 &&
            reg_eq(nnxt->op, ".label") && nnxt->args && nnxt->args->len >= 1 &&
            reg_eq(a0, list_get(nnxt->args, 0))) {
            const char *inv = invert_jcc(op);
            if (inv) {
                AsmInstr *j = gen_instr_new(inv);
                gen_instr_add_arg(j, list_get(nxt->args, 0));
                list_push(out, j);
                free_asminstr(cur); free_asminstr(nxt); ++i; continue;
            }
        }

        /* (6) cjne A,#0,L / sjmp M / L: → jz M */
        if (nxt && nnxt && reg_eq(op, "cjne") && cur->args && cur->args->len == 3 &&
            reg_eq(nxt->op, "sjmp") && nxt->args && nxt->args->len == 1 &&
            reg_eq(nnxt->op, ".label") && nnxt->args && nnxt->args->len >= 1 &&
            reg_eq(a0, "A") && parse_immediate(a1, &imm) && imm == 0 &&
            reg_eq(list_get(cur->args, 2), list_get(nnxt->args, 0))) {
            AsmInstr *j = gen_instr_new("jz");
            gen_instr_add_arg(j, list_get(nxt->args, 0));
            list_push(out, j);
            free_asminstr(cur); free_asminstr(nxt); ++i; continue;
        }

        /* (7) mov r,r / mov A,A 删掉 */
        if (reg_eq(op, "mov") && a0 && a1 && reg_eq(a0, a1)) {
            free_asminstr(cur); continue;
        }

        /* (8) 合并连续 mov */
        if (nxt && reg_eq(nxt->op, "mov") && nxt->args && nxt->args->len >= 2) {
            const char *ndst = list_get(nxt->args, 0);
            const char *nsrc = list_get(nxt->args, 1);
            /* mov A,#imm / mov r,A → mov r,#imm */
            if (reg_eq(a0, "A") && parse_immediate(a1, &imm) &&
                reg_eq(nsrc, "A") && parse_reg_rn(ndst) >= 0) {
                char buf[16]; snprintf(buf, sizeof(buf), "#%d", imm);
                list_set(nxt->args, 1, gen_strdup(buf)); free((void*)nsrc);
                list_push(out, nxt); free_asminstr(cur); ++i; continue;
            }
            /* mov r,#imm / mov A,r → mov A,#imm */
            if (parse_reg_rn(a0) >= 0 && parse_immediate(a1, &imm) &&
                reg_eq(ndst, "A") && reg_eq(nsrc, a0)) {
                char buf[16]; snprintf(buf, sizeof(buf), "#%d", imm);
                list_set(nxt->args, 1, gen_strdup(buf)); free((void*)nsrc);
                list_push(out, nxt); free_asminstr(cur); ++i; continue;
            }
            /* 冗余中转寄存器消除 */
            if ((reg_eq(a0, "A") && parse_reg_rn(a1) >= 0 &&
                 reg_eq(ndst, "A") && reg_eq(nsrc, a1)) ||
                (parse_reg_rn(a0) >= 0 && reg_eq(a1, "A") &&
                 reg_eq(ndst, "A") && reg_eq(nsrc, a0)) ||
                (reg_eq(a0, "A") && parse_reg_rn(a1) >= 0 &&
                 reg_eq(ndst, "A") && reg_eq(nsrc, a1))) {++i; continue;
            }
        }

        /* (9) mov A,#0 / add A,#imm → 保留后一条立即数 */
        if (nxt && reg_eq(nxt->op, "add") && nxt->args && nxt->args->len >= 2) {
            const char *na0 = list_get(nxt->args, 0);
            const char *na1 = list_get(nxt->args, 1);
            if (reg_eq(a0, "A") && parse_immediate(a1, &imm) && imm == 0 &&
                reg_eq(na0, "A") && parse_immediate(na1, &imm)) {
                char buf[16]; snprintf(buf, sizeof(buf), "#%d", imm);
                list_set(cur->args, 1, gen_strdup(buf)); free((void*)a1);
                list_push(out, cur); free_asminstr(nxt); ++i; continue;
            }
        }

        /* 默认保留 */
        list_push(out, cur);
    }

    free(sec->asminstrs);
    sec->asminstrs = out;
}

