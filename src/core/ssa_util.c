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

static void ssa_print_bril_exact(SSABuild *b, FILE *out) {
    if (!b || !b->unit) return;
    
    for (int i = 0; i < b->unit->funcs->len; i++) {
        Func *f = list_get(b->unit->funcs, i);
        fprintf(out, "@%s", f->name);
        fprintf(out, "(");
        for (int j = 0; j < f->param_names->len; j++) {
            const char *param = list_get(f->param_names, j);
            if (j > 0) fprintf(out, ", ");
            fprintf(out, "%s: int", param);
        }
        fprintf(out, ") {\n");
        
        for (int j = 0; j < f->blocks->len; j++) {
            Block *blk = list_get(f->blocks, j);
            if (blk->id != 0 && blk->instrs->len)
                fprintf(out, "  .block%u:\n", blk->id);
            
            for (int k = 0; k < blk->instrs->len; k++) {
                Instr *in = list_get(blk->instrs, k);
                fprintf(out, "    ");
                
                if (in->dest) {
                    fprintf(out, "%s: ", in->dest);
                    if (in->type) print_bril_type(in->type, out);
                    else fprintf(out, "int");
                    fprintf(out, " = ");
                }
                
                const char *opname = ir_op_to_str(in->op);
                if (in->op == IROP_JMP) {
                    fprintf(out, "jmp");
                    for (int m = 0; m < in->labels->len; m++) 
                        fprintf(out, " .%s", (char*)list_get(in->labels, m));
                    fprintf(out, ";\n");
                    continue;
                }
                if (in->op == IROP_BR) {
                    fprintf(out, "br");
                    if (in->args->len > 0) 
                        fprintf(out, " %s", (char*)list_get(in->args, 0));
                    for (int m = 0; m < in->labels->len; m++) 
                        fprintf(out, " .%s", (char*)list_get(in->labels, m));
                    fprintf(out, ";\n");
                    continue;
                }
                if (in->op == IROP_RET) {
                    fprintf(out, "ret");
                    if (in->args->len > 0) 
                        fprintf(out, " %s", (char*)list_get(in->args, 0));
                    fprintf(out, ";\n");
                    continue;
                }
                if (in->op == IROP_CALL) {
                    fprintf(out, "call");
                    if (in->args->len > 0) 
                        fprintf(out, " %s", (char*)list_get(in->args, 0));
                    fprintf(out, ";\n");
                    continue;
                }
                if (in->op == IROP_PHI) {
                    fprintf(out, "%s", opname);
                    for (int m = 0; m < in->args->len; m++) 
                        fprintf(out, " %s", (char*)list_get(in->args, m));
                    fprintf(out, ";\n");
                    continue;
                }
                
                fprintf(out, "%s", opname);
                for (int m = 0; m < in->args->len; m++) 
                    fprintf(out, " %s", (char*)list_get(in->args, m));
                if (in->op == IROP_CONST) 
                    fprintf(out, " %ld", in->ival);
                fprintf(out, ";\n");
            }
        }
        fprintf(out, "}\n\n");
    }
}

static void ssa_print(SSABuild *b, FILE *out) { 
    ssa_print_bril_exact(b, out); 
}