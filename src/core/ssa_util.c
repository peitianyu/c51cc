#include "ssa.h"

static const char *ir_op_to_str(IrOp op) {
    static const char *ir_op_str[] = {
        "nop", "const", "add", "mul", "sub", "div",
        "eq", "lt", "gt", "le", "ge",
        "not", "and", "or",
        "jmp", "br", "call", "ret", "print",
        "phi", "alloc", "free", "store", "load", "ptradd",
        "fadd", "fmul", "fsub", "fdiv",
        "feq", "flt", "fle", "fgt", "fge",
        "lconst"
    };
    if (op < sizeof(ir_op_str)/sizeof(ir_op_str[0])) return ir_op_str[op];
    return "unknown";
}

static void print_bril_type(Ctype *ctype, FILE *out) {
    if (!ctype) { fprintf(out, "void"); return; }
    switch (ctype->type) {
    case CTYPE_INT: case CTYPE_LONG: case CTYPE_CHAR: case CTYPE_BOOL: fprintf(out, "int"); break;
    case CTYPE_FLOAT: case CTYPE_DOUBLE: fprintf(out, "float"); break;
    case CTYPE_VOID: fprintf(out, "void"); break;
    case CTYPE_PTR: fprintf(out, "ptr"); break;
    default: fprintf(out, "int"); break;
    }
}

/* ---------------- 1. 单条指令打印 ---------------- */
static void ssa_print_instr(const Instr *in, FILE *out)
{
    if (!in) return;

    if (in->dest) {                    /* dest : type = */
        fprintf(out, "%s: ", in->dest);
        print_bril_type(in->type, out);
        fprintf(out, " = ");
    }

    const char *opname = ir_op_to_str(in->op);

    switch (in->op) {                  /* 特殊格式先处理 */
    case IROP_JMP:
        fprintf(out, "jmp");
        for (int i = 0; i < in->labels->len; ++i)
            fprintf(out, " .%s", (char*)list_get(in->labels, i));
        fprintf(out, ";\n");
        return;
    case IROP_BR:
        fprintf(out, "br");
        if (in->args->len) fprintf(out, " %s", (char*)list_get(in->args, 0));
        for (int i = 0; i < in->labels->len; ++i)
            fprintf(out, " .%s", (char*)list_get(in->labels, i));
        fprintf(out, ";\n");
        return;
    case IROP_RET:
        fprintf(out, "ret");
        if (in->args->len) fprintf(out, " %s", (char*)list_get(in->args, 0));
        fprintf(out, ";\n");
        return;
    case IROP_CALL:
        fprintf(out, "call");
        for (int i = 0; i < in->args->len; ++i)
            fprintf(out, " %s", (char*)list_get(in->args, i));
        fprintf(out, ";\n");
        return;
    case IROP_PHI:
        fprintf(out, "%s", opname);
        for (int i = 0; i < in->args->len; ++i)
            fprintf(out, " %s", (char*)list_get(in->args, i));
        fprintf(out, ";\n");
        return;
    default:                           /* 普通指令 */
        fprintf(out, "%s", opname);
        for (int i = 0; i < in->args->len; ++i)
            fprintf(out, " %s", (char*)list_get(in->args, i));
        if (in->op == IROP_CONST) fprintf(out, " %ld", in->ival);
        fprintf(out, ";\n");
    }
}

/* ---------------- 2. 单个 Block 打印 ---------------- */
static void ssa_print_block(const Block *blk, FILE *out)
{
    if (!blk) return;
    if (blk->id != 0 && blk->instrs->len)
        fprintf(out, "  .block%u:\n", blk->id);

    for (int i = 0; i < blk->instrs->len; ++i) {
        fprintf(out, "    ");
        ssa_print_instr(list_get(blk->instrs, i), out);
    }
}

/* ---------------- 3. Global 区打印 ---------------- */
static void ssa_print_globals(const SSAUnit *unit, FILE *out)
{
    if (!unit || !unit->globals) return;
    for (int i = 0; i < unit->globals->len; ++i) {
        const Global *g = list_get(unit->globals, i);
        fprintf(out, "@%s: ", g->name);
        print_bril_type(g->type, out);

        if (g->is_extern)
            fprintf(out, " = extern;\n");
        else {
            if (g->type->type == CTYPE_FLOAT || g->type->type == CTYPE_DOUBLE)
                fprintf(out, " = %.17g;\n", g->init.f);
            else
                fprintf(out, " = %ld;\n", g->init.i);
        }
    }
    if (unit->globals->len) fprintf(out, "\n");
}

/* ---------------- 4. 顶层统一接口 ---------------- */
static void ssa_print(const SSABuild *b, FILE *out)
{
    if (!b || !b->unit) return;

    ssa_print_globals(b->unit, out);          /* 先打印全局量 */

    for (int i = 0; i < b->unit->funcs->len; ++i) {
        Func *f = list_get(b->unit->funcs, i);

        /* 函数头 */
        fprintf(out, "@%s(", f->name);
        for (int j = 0; j < f->param_names->len; ++j) {
            if (j) fprintf(out, ", ");
            fprintf(out, "%s: int", (char*)list_get(f->param_names, j));
        }
        fprintf(out, ") {\n");

        /* 依次打印每个 block */
        for (int j = 0; j < f->blocks->len; ++j)
            ssa_print_block(list_get(f->blocks, j), out);

        fprintf(out, "}\n\n");
    }
}