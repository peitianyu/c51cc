#include "ssa.h"
#include "cc.h"
#include <stdint.h>
#include <string.h>

static uint32_t g_vid = 1;
static SSABuild *current_build = NULL;

static const char *ast_to_ssa_expr(SSABuild *b, Ast *ast);
static void ast_to_ssa_stmt(SSABuild *b, Ast *ast);
static void process_if_stmt(Ast *ast);
static void process_while_stmt(Ast *ast);
static void process_return(Ast *ast);
static const char *process_func_call(Ast *ast);
static const char *process_unary_op(Ast *ast);
static const char *process_binary_op(Ast *ast);
static const char *process_variable(Ast *ast);
static const char *process_literal(Ast *ast);
static void ast_to_ssa_func_def(SSABuild *b, Ast *ast);
static void ast_to_ssa_global_var(SSABuild *b, Ast *ast);
static Global *create_global(const char *name, Ctype *type, bool is_extern);
static SSABuild *ssa_new(void);

static const char *make_ssa_name(void) {
    static char buf[32];
    snprintf(buf, sizeof(buf), "v%u", g_vid++);
    return strdup(buf);
}

static Instr *create_instr(IrOp op, const char *dest, Ctype *ctype) {
    Instr *instr = malloc(sizeof(Instr));
    instr->op = op;
    instr->dest = dest ? strdup(dest) : NULL;
    instr->type = ctype;
    instr->args = make_list();
    instr->labels = make_list();
    instr->ival = 0;
    instr->fval = 0.0;
    instr->attr.restrict_ = 0;
    instr->attr.volatile_ = 0;
    instr->attr.reg = 0;
    instr->attr.mem = 0;
    return instr;
}

static void add_arg_to_instr(Instr *instr, const char *arg) {
    if (arg) list_push(instr->args, (void *)strdup(arg));
}

static void add_label_to_instr(Instr *instr, const char *label) {
    if (label) list_push(instr->labels, (void *)strdup(label));
}

static Block *create_block(uint32_t id) {
    Block *block = malloc(sizeof(Block));
    block->id = id;
    block->sealed = false;
    block->instrs = make_list();
    block->pred_ids = make_list();
    block->succ_ids = make_list();
    return block;
}

static Func *create_func(const char *name, Ctype *ret_type) {
    Func *func = malloc(sizeof(Func));
    func->name = strdup(name);
    func->ret_type = ret_type;
    func->param_names = make_list();
    func->blocks = make_list();
    func->entry_id = 0;
    return func;
}

static void add_instr_to_current_block(Instr *instr) {
    if (!current_build || !current_build->cur_block) error("No current block to add instruction");
    list_push(current_build->cur_block->instrs, instr);
    list_push(current_build->instr_buf, instr);
}

static void add_name_to_build(const char *name) {
    if (current_build) list_push(current_build->name_buf, (void *)strdup(name));
}

static void set_var_value(const char *var_name, const char *ssa_name) {
    if (current_build && current_build->var_map && var_name && ssa_name)
        dict_put(current_build->var_map, (void *)var_name, (void *)strdup(ssa_name));
}

static const char *get_var_value(const char *var_name) {
    if (current_build && current_build->var_map && var_name)
        return (const char *)dict_get(current_build->var_map, (void *)var_name);
    return NULL;
}

static SSABuild *ssa_new(void) {
    SSABuild *s = malloc(sizeof(SSABuild));
    s->unit = malloc(sizeof(SSAUnit));
    s->unit->funcs = make_list();
    s->unit->globals = make_list();
    s->cur_func = NULL;
    s->cur_block = NULL;
    s->instr_buf = make_list();
    s->name_buf = make_list();
    s->var_map = &EMPTY_DICT;
    current_build = s;
    return s;
}

static Global *create_global(const char *name, Ctype *type, bool is_extern) {
    Global *global = malloc(sizeof(Global));
    global->name = strdup(name);
    global->type = type;
    global->is_extern = is_extern;
    global->init.i = 0;
    return global;
}

static const char *process_literal(Ast *ast) {
    if (!ast || ast->type != AST_LITERAL) return NULL;
    const char *name = make_ssa_name();
    IrOp op;
    switch (ast->ctype->type) {
    case CTYPE_INT: case CTYPE_LONG: case CTYPE_CHAR: case CTYPE_BOOL: op = IROP_CONST; break;
    case CTYPE_FLOAT: case CTYPE_DOUBLE: op = IROP_LCONST; break;
    default: error("Unsupported literal type in SSA conversion");
    }
    Instr *instr = create_instr(op, name, ast->ctype);
    if (is_inttype(ast->ctype)) instr->ival = ast->ival;
    else if (is_flotype(ast->ctype)) instr->fval = ast->fval;
    add_instr_to_current_block(instr);
    add_name_to_build(name);
    return name;
}

static const char *process_variable(Ast *ast) {
    if (!ast || (ast->type != AST_LVAR && ast->type != AST_GVAR)) return NULL;
    const char *var_name = ast->varname;
    const char *ssa_name = get_var_value(var_name);
    if (!ssa_name) ssa_name = var_name;
    add_name_to_build(ssa_name);
    return ssa_name;
}

static const char *process_binary_op(Ast *ast) {
    if (!ast) return NULL;
    switch (ast->type) {
    case '+': case '-': case '*': case '/':
    case '<': case '>': 
    case '&': case '|':
    case PUNCT_EQ: case PUNCT_NE:
    case PUNCT_LE: case PUNCT_GE:
    case PUNCT_LOGAND: case PUNCT_LOGOR: break;
    default: return NULL;
    }
    const char *left_name = ast_to_ssa_expr(current_build, ast->left);
    const char *right_name = ast_to_ssa_expr(current_build, ast->right);
    if (!left_name || !right_name) return NULL;
    const char *result_name = make_ssa_name();
    IrOp op;
    switch (ast->type) {
    case '+': op = is_flotype(ast->ctype) ? IROP_FADD : IROP_ADD; break;
    case '-': op = is_flotype(ast->ctype) ? IROP_FSUB : IROP_SUB; break;
    case '*': op = is_flotype(ast->ctype) ? IROP_FMUL : IROP_MUL; break;
    case '/': op = is_flotype(ast->ctype) ? IROP_FDIV : IROP_DIV; break;
    case PUNCT_EQ: op = is_flotype(ast->ctype) ? IROP_FEQ : IROP_EQ; break;
    case '<': op = is_flotype(ast->ctype) ? IROP_FLT : IROP_LT; break;
    case '>': op = is_flotype(ast->ctype) ? IROP_FGT : IROP_GT; break;
    case PUNCT_LE: op = is_flotype(ast->ctype) ? IROP_FLE : IROP_LE; break;
    case PUNCT_GE: op = is_flotype(ast->ctype) ? IROP_FGE : IROP_GE; break;
    case PUNCT_LOGAND: op = IROP_AND; break;
    case PUNCT_LOGOR: op = IROP_OR; break;
    case '&': op = IROP_AND; break;
    case '|': op = IROP_OR; break;
    default: error("Unsupported binary operator in SSA: %d", ast->type);
    }
    Instr *instr = create_instr(op, result_name, ast->ctype);
    add_arg_to_instr(instr, left_name);
    add_arg_to_instr(instr, right_name);
    add_instr_to_current_block(instr);
    add_name_to_build(result_name);
    return result_name;
}

static const char *process_unary_op(Ast *ast) {
    if (!ast) return NULL;
    const char *operand_name = ast_to_ssa_expr(current_build, ast->operand);
    if (!operand_name) return NULL;
    const char *result_name = make_ssa_name();
    IrOp op;
    switch (ast->type) {
    case '!': op = IROP_NOT; break;
    case '~': op = IROP_NOT; break;
    case AST_ADDR: op = IROP_ALLOC; break;
    case AST_DEREF: op = IROP_LOAD; break;
    case PUNCT_INC: case PUNCT_DEC: error("++/-- not yet implemented in SSA");
    default: error("Unsupported unary operator in SSA: %d", ast->type);
    }
    Instr *instr = create_instr(op, result_name, ast->ctype);
    add_arg_to_instr(instr, operand_name);
    add_instr_to_current_block(instr);
    add_name_to_build(result_name);
    return result_name;
}

static const char *process_func_call(Ast *ast) {
    if (!ast || ast->type != AST_FUNCALL) return NULL;
    const char *result_name = NULL;
    if (ast->ctype->type != CTYPE_VOID) result_name = make_ssa_name();
    Instr *instr = create_instr(IROP_CALL, result_name, ast->ctype);
    add_arg_to_instr(instr, ast->fname);
    for (Iter i = list_iter(ast->args); !iter_end(i);) {
        Ast *arg = iter_next(&i);
        const char *arg_name = ast_to_ssa_expr(current_build, arg);
        add_arg_to_instr(instr, arg_name);
    }
    add_instr_to_current_block(instr);
    if (result_name) add_name_to_build(result_name);
    return result_name;
}

static void process_return(Ast *ast) {    
    Instr *instr = create_instr(IROP_RET, NULL, NULL);
    if (ast->retval) {
        const char *retval_name = ast_to_ssa_expr(current_build, ast->retval);
        if (retval_name) add_arg_to_instr(instr, retval_name);
    }
    add_instr_to_current_block(instr);
}

static void process_if_stmt(Ast *ast) {
    if (!ast || ast->type != AST_IF) return;
    const char *cond_name = ast_to_ssa_expr(current_build, ast->cond);
    Block *then_block = create_block(current_build->cur_func->blocks->len);
    list_push(current_build->cur_func->blocks, then_block);
    Block *else_block = NULL;
    if (ast->els) {
        else_block = create_block(current_build->cur_func->blocks->len);
        list_push(current_build->cur_func->blocks, else_block);
    }
    Block *merge_block = create_block(current_build->cur_func->blocks->len);
    list_push(current_build->cur_func->blocks, merge_block);
    Instr *br_instr = create_instr(IROP_BR, NULL, NULL);
    add_arg_to_instr(br_instr, cond_name);
    char then_label[32], else_label[32], merge_label[32];
    snprintf(then_label, sizeof(then_label), "block%u", then_block->id);
    snprintf(else_label, sizeof(else_label), "block%u", else_block ? else_block->id : merge_block->id);
    add_label_to_instr(br_instr, then_label);
    add_label_to_instr(br_instr, else_label);
    add_instr_to_current_block(br_instr);
    current_build->cur_block = then_block;
    ast_to_ssa_stmt(current_build, ast->then);
    Instr *jmp_then = create_instr(IROP_JMP, NULL, NULL);
    snprintf(merge_label, sizeof(merge_label), "block%u", merge_block->id);
    add_label_to_instr(jmp_then, merge_label);
    add_instr_to_current_block(jmp_then);
    if (ast->els) {
        current_build->cur_block = else_block;
        ast_to_ssa_stmt(current_build, ast->els);
        Instr *jmp_else = create_instr(IROP_JMP, NULL, NULL);
        add_label_to_instr(jmp_else, merge_label);
        add_instr_to_current_block(jmp_else);
    }
    current_build->cur_block = merge_block;
}

static void process_while_stmt(Ast *ast) {
    if (!ast || ast->type != AST_WHILE) return;
    Block *cond_block = create_block(current_build->cur_func->blocks->len);
    Block *body_block = create_block(current_build->cur_func->blocks->len + 1);
    Block *merge_block = create_block(current_build->cur_func->blocks->len + 2);
    list_push(current_build->cur_func->blocks, cond_block);
    list_push(current_build->cur_func->blocks, body_block);
    list_push(current_build->cur_func->blocks, merge_block);
    Instr *jmp_to_cond = create_instr(IROP_JMP, NULL, NULL);
    char cond_label[32];
    snprintf(cond_label, sizeof(cond_label), "block%u", cond_block->id);
    add_label_to_instr(jmp_to_cond, cond_label);
    add_instr_to_current_block(jmp_to_cond);
    current_build->cur_block = cond_block;
    const char *cond_name = ast_to_ssa_expr(current_build, ast->while_cond);
    Instr *br_instr = create_instr(IROP_BR, NULL, NULL);
    add_arg_to_instr(br_instr, cond_name);
    char body_label[32], merge_label[32];
    snprintf(body_label, sizeof(body_label), "block%u", body_block->id);
    snprintf(merge_label, sizeof(merge_label), "block%u", merge_block->id);
    add_label_to_instr(br_instr, body_label);
    add_label_to_instr(br_instr, merge_label);
    add_instr_to_current_block(br_instr);
    current_build->cur_block = body_block;
    ast_to_ssa_stmt(current_build, ast->while_body);
    Instr *jmp_back = create_instr(IROP_JMP, NULL, NULL);
    add_label_to_instr(jmp_back, cond_label);
    add_instr_to_current_block(jmp_back);
    current_build->cur_block = merge_block;
}

static const char *ast_to_ssa_expr(SSABuild *b, Ast *ast) {
    if (!ast) return NULL;
    switch (ast->type) {
    case AST_LITERAL: return process_literal(ast);
    case AST_LVAR: case AST_GVAR: return process_variable(ast);
    case AST_FUNCALL: return process_func_call(ast);
    case AST_ADDR: case AST_DEREF: case '!': case '~': case PUNCT_INC: case PUNCT_DEC: return process_unary_op(ast);
    default:
        if (ast->type == '+' || ast->type == '-' || ast->type == '*' || ast->type == '/' ||
            ast->type == '<' || ast->type == '>' ||
            ast->type == '&' || ast->type == '|' ||
            ast->type == PUNCT_EQ || ast->type == PUNCT_NE ||
            ast->type == PUNCT_LE || ast->type == PUNCT_GE ||
            ast->type == PUNCT_LOGAND || ast->type == PUNCT_LOGOR) return process_binary_op(ast);
        printf("ERROR: Unsupported expression type in SSA: %d\n", ast->type);
        error("Unsupported expression type in SSA: %d", ast->type);
    }
    return NULL;
}

static void ast_to_ssa_stmt(SSABuild *b, Ast *ast) {
    if (!ast) return;
    switch (ast->type) {
    case AST_COMPOUND_STMT:
        for (Iter i = list_iter(ast->stmts); !iter_end(i);) {
            Ast *stmt = iter_next(&i);
            ast_to_ssa_stmt(b, stmt);
        }
        break;
    case AST_RETURN: process_return(ast); break;
    case AST_IF: process_if_stmt(ast); break;
    case AST_WHILE: process_while_stmt(ast); break;
    case AST_FOR: error("For loop not yet implemented in SSA"); break;
    case AST_DO_WHILE: error("Do-while loop not yet implemented in SSA"); break;
    case AST_BREAK: case AST_CONTINUE: error("Break/continue not yet implemented in SSA"); break;
    case AST_GOTO: case AST_LABEL: error("Goto/label not yet implemented in SSA"); break;
    case AST_DECL:
        if (ast->declinit && ast->declvar) {
            const char *init_val = ast_to_ssa_expr(b, ast->declinit);
            if (init_val) {
                set_var_value(ast->declvar->varname, init_val);
                add_name_to_build(init_val);
            }
        }
        break;
    default: ast_to_ssa_expr(b, ast); break;
    }
}

static void ast_to_ssa_func_def(SSABuild *b, Ast *ast) {
    if (!ast || ast->type != AST_FUNC_DEF) return;
    Func *func = create_func(ast->fname, ast->ctype);
    current_build->cur_func = func;
    if (current_build->var_map) current_build->var_map = &EMPTY_DICT;
    Block *entry_block = create_block(0);
    func->entry_id = 0;
    list_push(func->blocks, entry_block);
    current_build->cur_block = entry_block;
    for (Iter i = list_iter(ast->params); !iter_end(i);) {
        Ast *param = iter_next(&i);
        const char *param_name = param->varname;
        const char *param_ssa_name = make_ssa_name();
        list_push(func->param_names, (void *)strdup(param_name));
        set_var_value(param_name, param_ssa_name);
        add_name_to_build(param_ssa_name);
    }
    ast_to_ssa_stmt(b, ast->body);
    if (current_build->cur_block && current_build->cur_block->instrs && current_build->cur_block->instrs->len > 0) {
        Instr *last_instr = NULL;
        if (current_build->cur_block->instrs->len > 0)
            last_instr = list_get(current_build->cur_block->instrs, current_build->cur_block->instrs->len - 1);
        if (!last_instr || last_instr->op != IROP_RET) {
            if (ast->ctype->type == CTYPE_VOID) {
                Instr *ret_instr = create_instr(IROP_RET, NULL, NULL);
                add_instr_to_current_block(ret_instr);
            } else error("Function must return a value");
        }
    } else {
        if (ast->ctype->type == CTYPE_VOID) {
            Instr *ret_instr = create_instr(IROP_RET, NULL, NULL);
            add_instr_to_current_block(ret_instr);
        } else error("Function must return a value");
    }
    list_push(b->unit->funcs, func);
    current_build->cur_func = NULL;
    current_build->cur_block = NULL;
}

static void ast_to_ssa_global_var(SSABuild *b, Ast *ast) {
    if (!ast || ast->type != AST_DECL) return;
    Global *global = create_global(ast->declvar->varname, ast->declvar->ctype, (ast->declvar->ctype->attr & (1 << 4)) != 0);
    if (ast->declinit && ast->declinit->type == AST_LITERAL) {
        if (is_inttype(ast->declinit->ctype)) global->init.i = ast->declinit->ival;
        else if (is_flotype(ast->declinit->ctype)) global->init.f = ast->declinit->fval;
    }
    list_push(b->unit->globals, global);
}

void ast_to_ssa(SSABuild *b, Ast *ast) {
    if (!b || !ast) return;
    switch (ast->type) {
    case AST_FUNC_DEF: ast_to_ssa_func_def(b, ast); break;
    case AST_DECL:
        if (!current_build->cur_func) ast_to_ssa_global_var(b, ast);
        else ast_to_ssa_stmt(b, ast);
        break;
    case AST_FUNC_DECL: break;
    default: error("Unsupported top-level AST node in SSA: %d", ast->type);
    }
}

#ifdef MINITEST_IMPLEMENTATION
#include "minitest.h"

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

void ssa_print_bril_exact(SSABuild *b, FILE *out) {
    if (!b || !b->unit) return;
    for (int i = 0; i < b->unit->globals->len; i++) {
        Global *g = list_get(b->unit->globals, i);
        fprintf(out, "@%s", g->name);
        if (g->type) { fprintf(out, ": "); print_bril_type(g->type, out); }
        if (!g->is_extern && (is_inttype(g->type) || is_flotype(g->type))) {
            if (is_inttype(g->type)) fprintf(out, " = %ld", g->init.i);
            else fprintf(out, " = %f", g->init.f);
        }
        fprintf(out, ";\n");
    }
    if (b->unit->globals->len > 0) fprintf(out, "\n");
    for (int i = 0; i < b->unit->funcs->len; i++) {
        Func *f = list_get(b->unit->funcs, i);
        fprintf(out, "@%s", f->name);
        fprintf(out, "(");
        for (int j = 0; j < f->param_names->len; j++) {
            const char *param = list_get(f->param_names, j);
            if (j > 0) fprintf(out, ", ");
            fprintf(out, "%s: int", param);
        }
        fprintf(out, ")");
        fprintf(out, " {\n");
        for (int j = 0; j < f->blocks->len; j++) {
            Block *blk = list_get(f->blocks, j);
            if (blk->id != 0) fprintf(out, "  .L%u:\n", blk->id);
            for (int k = 0; k < blk->instrs->len; k++) {
                Instr *in = list_get(blk->instrs, k);
                if (in->op == IROP_JMP || in->op == IROP_BR) continue;
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
                    for (int m = 0; m < in->labels->len; m++) fprintf(out, " .%s", (char*)list_get(in->labels, m));
                    fprintf(out, ";\n");
                    continue;
                }
                if (in->op == IROP_BR) {
                    fprintf(out, "br");
                    if (in->args->len > 0) fprintf(out, " %s", (char*)list_get(in->args, 0));
                    for (int m = 0; m < in->labels->len; m++) fprintf(out, " .%s", (char*)list_get(in->labels, m));
                    fprintf(out, ";\n");
                    continue;
                }
                if (in->op == IROP_RET) {
                    fprintf(out, "ret");
                    if (in->args->len > 0) fprintf(out, " %s", (char*)list_get(in->args, 0));
                    fprintf(out, ";\n");
                    continue;
                }
                if (in->op == IROP_CALL) {
                    fprintf(out, "call");
                    if (in->args->len > 0) fprintf(out, " %s", (char*)list_get(in->args, 0));
                    for (int m = 1; m < in->args->len; m++) fprintf(out, " %s", (char*)list_get(in->args, m));
                    fprintf(out, ";\n");
                    continue;
                }
                fprintf(out, "%s", opname);
                for (int m = 0; m < in->args->len; m++) fprintf(out, " %s", (char*)list_get(in->args, m));
                if (in->op == IROP_CONST) fprintf(out, " %ld", in->ival);
                else if (in->op == IROP_LCONST) fprintf(out, " %f", in->fval);
                fprintf(out, ";\n");
            }
        }
        fprintf(out, "}\n\n");
    }
}

void ssa_print(SSABuild *b, FILE *out) { ssa_print_bril_exact(b, out); }

TEST(test, ssa) {
    char infile[256] = "./test/test_ssa.c";
    if (!freopen(strtok(infile, "\n"), "r", stdin)) puts("open fail"), exit(1);
    set_current_filename(infile);
    SSABuild *b = ssa_new();
    List *toplevels = read_toplevels();
    for (Iter i = list_iter(toplevels); !iter_end(i);) {
        Ast *ast = (Ast *)iter_next(&i);
        ast_to_ssa(b, ast);
    }
    ssa_print(b, stdout);
    if (strings) list_free(strings);
    if (flonums) list_free(flonums);
    if (ctypes) list_free(ctypes);
}
#endif /* MINITEST_IMPLEMENTATION */