#include "ssa.h"
#include "cc.h"
#include <stdint.h>
#include <string.h>
#include <stdarg.h>

static uint32_t g_vid = 1;
static SSABuild *current_build = NULL;

/* 论文中的数据结构 */
static Dict *current_defs = NULL;          // currentDef[variable][block] -> value
static Dict *incomplete_phis = NULL;       // incompletePhis[block][variable] -> phi
static List *sealed_blocks = NULL;         // List<Block *>

/* 辅助函数声明 */
static const char *ast_to_ssa_expr(SSABuild *b, Ast *ast);
static void ast_to_ssa_stmt(SSABuild *b, Ast *ast);
static void process_if_stmt(Ast *ast);
static void process_while_stmt(Ast *ast);
static void process_return(Ast *ast);
static const char *process_assign(Ast *ast);
static const char *process_func_call(Ast *ast);
static const char *process_unary_op(Ast *ast);
static const char *process_binary_op(Ast *ast);
static const char *process_variable(Ast *ast);
static const char *process_literal(Ast *ast);
static void ast_to_ssa_func_def(SSABuild *b, Ast *ast);
static SSABuild *ssa_new(void);
static Block *create_block(uint32_t id);
static Func *create_func(const char *name, Ctype *ret_type);
static Instr *create_instr(IrOp op, const char *dest, Ctype *ctype);
static void add_instr_to_current_block(Instr *instr);
static void add_arg_to_instr(Instr *instr, const char *arg);
static void add_label_to_instr(Instr *instr, const char *label);
static void seal_block(Block *block);
static void write_variable(const char *var_name, Block *block, const char *value);
static const char *read_variable(const char *var_name, Block *block);
static const char *read_variable_recursive(const char *var_name, Block *block);
static Instr *add_phi_operands(const char *var_name, Instr *phi);
static Instr *try_remove_trivial_phi(Instr *phi);
static const char *make_ssa_name(void);  
static bool ast_returns(Ast *ast);
static bool last_is_terminator(void);
static const char *block_label(Block *b);

/* 论文算法1: writeVariable */
static void write_variable(const char *var_name, Block *block, const char *value) {
    if (!current_defs) { return; }

    Dict *var_map = (Dict *)dict_get(current_defs, (char *)var_name);

    if (!var_map) {
        var_map = (Dict *)make_dict(NULL);
        dict_put(current_defs, (char *)strdup(var_name), var_map);
    }

    char block_key[64];
    snprintf(block_key, sizeof(block_key), "%p", (void *)block);
    dict_put(var_map, (char *)strdup(block_key), (void *)value);
}

/* 论文算法1: readVariable */
static const char *read_variable(const char *var_name, Block *block) {
    if (!current_defs) return NULL;

    Dict *var_map = (Dict *)dict_get(current_defs, (char *)var_name);

    if (!var_map) return NULL;

    char block_key[64];
    snprintf(block_key, sizeof(block_key), "%p", (void *)block);
    const char *val = (const char *)dict_get(var_map, (char *)block_key);

    if (val) return val;
    return read_variable_recursive(var_name, block);
}

/* 论文算法2: readVariableRecursive */
static const char *read_variable_recursive(const char *var_name, Block *block) {
    if (!block) return NULL;
    
    // 检查是否已密封
    bool sealed = false;
    for (int i = 0; i < sealed_blocks->len; i++) {
        if (list_get(sealed_blocks, i) == block) {
            sealed = true;
            break;
        }
    }

    if (!sealed) {
        // 不完全的CFG：创建无操作数的 phi
        Instr *phi = create_instr(IROP_PHI, make_ssa_name(), NULL);
        add_instr_to_current_block(phi);
        write_variable(var_name, block, phi->dest);

        // 记录到 incomplete_phis 中
        char block_key[64];
        snprintf(block_key, sizeof(block_key), "%p", (void *)block);
        Dict *block_phis = (Dict *)dict_get(incomplete_phis, (char *)block_key);
        if (!block_phis) {
            block_phis = (Dict *)make_dict(NULL);
            dict_put(incomplete_phis, (char *)strdup(block_key), block_phis);
        }
        dict_put(block_phis, (char *)strdup(var_name), phi);

        return phi->dest;
    } else if (block->pred_ids->len == 1) {
        // 优化：只有一个前驱
        uint32_t pred_id = (uintptr_t)list_get(block->pred_ids, 0);
        Block *pred = NULL;
        for (int i = 0; i < current_build->cur_func->blocks->len; i++) {
            Block *b = list_get(current_build->cur_func->blocks, i);
            if (b->id == pred_id) {
                pred = b;
                break;
            }
        }
        return read_variable(var_name, pred);
    } else {
        // 多个前驱，需要 phi 函数
        Instr *phi = create_instr(IROP_PHI, make_ssa_name(), NULL);
        write_variable(var_name, block, phi->dest);
        add_instr_to_current_block(phi);
        
        // 添加操作数
        phi = add_phi_operands(var_name, phi);
        write_variable(var_name, block, phi->dest);
        return phi->dest;
    }
}

/* 论文算法2: addPhiOperands */
static Instr *add_phi_operands(const char *var_name, Instr *phi) {
    Block *block = current_build->cur_block;
    if (!block || !phi) return phi;
    
    // 为每个前驱添加参数
    for (int i = 0; i < block->pred_ids->len; i++) {
        uint32_t pred_id = (uintptr_t)list_get(block->pred_ids, i);
        Block *pred = NULL;
        
        // 查找前驱块
        for (int j = 0; j < current_build->cur_func->blocks->len; j++) {
            Block *b = list_get(current_build->cur_func->blocks, j);
            if (b->id == pred_id) {
                pred = b;
                break;
            }
        }
        
        if (!pred) continue;
        
        // 读取前驱块中的变量值
        const char *val = read_variable(var_name, pred);
        if (!val) {
            val = make_ssa_name();
            Instr *def = create_instr(IROP_CONST, val, NULL);
            def->ival = 0;
            add_instr_to_current_block(def);
        }
        add_arg_to_instr(phi, val);
    }
    
    return try_remove_trivial_phi(phi);
}

/* 论文算法3: tryRemoveTrivialPhi */
static Instr *try_remove_trivial_phi(Instr *phi) {
    if (phi->op != IROP_PHI) return phi;

    const char *same = NULL;
    for (int i = 0; i < phi->args->len; i++) {
        const char *op = (const char *)list_get(phi->args, i);
        if (op == same || (op && phi->dest && strcmp(op, phi->dest) == 0)) continue;
        if (same != NULL) return phi; // 至少两个不同值，不是平凡的
        same = op;
    }

    if (same == NULL) {
        same = make_ssa_name();
        Instr *undef = create_instr(IROP_CONST, same, NULL);
        undef->ival = 0;
        add_instr_to_current_block(undef);
    }

    // 简化处理：直接替换 dest
    phi->dest = same;
    return phi;
}

/* 论文算法4: sealBlock */
static void seal_block(Block *block) {
    if (!block) return;
    
    char block_key[64];
    snprintf(block_key, sizeof(block_key), "%p", (void *)block);
    
    // 处理该块中所有未完成的 phi
    Dict *block_phis = (Dict *)dict_get(incomplete_phis, (char *)block_key);
    if (block_phis) {
        List *keys = dict_keys(block_phis);
        for (int i = 0; i < keys->len; i++) {
            const char *var_name = (const char *)list_get(keys, i);
            Instr *phi = (Instr *)dict_get(block_phis, (char *)var_name);
            if (phi) add_phi_operands(var_name, phi);
        }
        list_free(keys);
    }
    
    // 标记为已密封
    list_push(sealed_blocks, block);
    block->sealed = true;
}

/* ========== 基础数据结构创建函数 ========== */
static const char *make_ssa_name(void) {
    static char buf[32];
    snprintf(buf, sizeof(buf), "v%u", g_vid++);
    return strdup(buf);
}

static Instr *create_instr(IrOp op, const char *dest, Ctype *ctype) {
    Instr *instr = malloc(sizeof(Instr));
    memset(instr, 0, sizeof(Instr));
    instr->op = op;
    instr->dest = dest ? strdup(dest) : NULL;
    instr->type = ctype;
    instr->args = make_list();
    instr->labels = make_list();
    instr->ival = 0;
    instr->fval = 0.0;
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
    memset(block, 0, sizeof(Block));
    block->id = id;
    block->sealed = false;
    block->instrs = make_list();
    block->pred_ids = make_list();
    block->succ_ids = make_list();
    return block;
}

static Func *create_func(const char *name, Ctype *ret_type) {
    Func *func = malloc(sizeof(Func));
    memset(func, 0, sizeof(Func));
    func->name = strdup(name);
    func->ret_type = ret_type;
    func->param_names = make_list();
    func->blocks = make_list();
    func->entry_id = 0;
    return func;
}

static void add_instr_to_current_block(Instr *instr) {
    if (!current_build || !current_build->cur_block) {
        list_free(instr->args);
        list_free(instr->labels);
        free(instr);
        return;
    }
    list_push(current_build->cur_block->instrs, instr);
}

static SSABuild *ssa_new(void) {
    SSABuild *s = malloc(sizeof(SSABuild));
    memset(s, 0, sizeof(SSABuild));
    s->unit = malloc(sizeof(SSAUnit));
    memset(s->unit, 0, sizeof(SSAUnit));
    s->unit->funcs = make_list();
    s->unit->globals = make_list();
    s->cur_func = NULL;
    s->cur_block = NULL;
    s->instr_buf = make_list();
    s->name_buf = make_list();
    s->var_map = (Dict *)&EMPTY_DICT;
    current_build = s;
    current_defs = (Dict *)make_dict(NULL);
    incomplete_phis = (Dict *)make_dict(NULL);
    sealed_blocks = make_list();
    return s;
}

/* ========== 表达式处理 ========== */
static const char *process_literal(Ast *ast) {
    if (!ast || ast->type != AST_LITERAL) return NULL;
    const char *name = make_ssa_name();
    Instr *instr = create_instr(IROP_CONST, name, ast->ctype);
    instr->ival = ast->ival;
    add_instr_to_current_block(instr);
    return name;
}

static const char *process_variable(Ast *ast) {
    if (!ast || (ast->type != AST_LVAR && ast->type != AST_GVAR)) return NULL;

    const char *var_name = ast->varname;
    
    // 先尝试读取变量
    const char *ssa_name = read_variable(var_name, current_build->cur_block);
    
    if (!ssa_name) {
        ssa_name = make_ssa_name();
        Instr *load = create_instr(IROP_LOAD, ssa_name, ast->ctype);
        add_arg_to_instr(load, var_name);
        add_instr_to_current_block(load);
        write_variable(var_name, current_build->cur_block, ssa_name);
    }
    
    return ssa_name;
}

static const char *process_assign(Ast *ast) {
    if (!ast || ast->type != '=') return NULL;
    
    const char *rhs_name = ast_to_ssa_expr(current_build, ast->right);
    if (!rhs_name) return NULL;
    
    Ast *lhs = ast->left;
    if (lhs->type == AST_LVAR || lhs->type == AST_GVAR) {
        const char *var_name = lhs->varname;
        write_variable(var_name, current_build->cur_block, rhs_name);
        return rhs_name;
    }
    return NULL;
}

static const char *process_binary_op(Ast *ast) {
    if (!ast) return NULL;
    const char *left_name = ast_to_ssa_expr(current_build, ast->left);
    const char *right_name = ast_to_ssa_expr(current_build, ast->right);
    if (!left_name || !right_name) return NULL;
    const char *result_name = make_ssa_name();
    
    IrOp op = IROP_ADD; 
    switch (ast->type) {
        case '+': op = IROP_ADD; break;
        case '-': op = IROP_SUB; break;
        case '*': op = IROP_MUL; break;
        case '/': op = IROP_DIV; break;
        case '<': op = IROP_LT; break;
        case '>': op = IROP_GT; break;
    }
    
    Instr *instr = create_instr(op, result_name, ast->ctype);
    add_arg_to_instr(instr, left_name);
    add_arg_to_instr(instr, right_name);
    add_instr_to_current_block(instr);
    return result_name;
}

static const char *process_func_call(Ast *ast) {
    if (!ast || ast->type != AST_FUNCALL) return NULL;
    
    const char *result_name = make_ssa_name();
    Instr *instr = create_instr(IROP_CALL, result_name, ast->ctype);
    
    add_arg_to_instr(instr, ast->fname);
    
    if (ast->args) {
    for (Iter i = list_iter(ast->args); !iter_end(i);) {
        Ast *arg = iter_next(&i);
        const char *arg_name = ast_to_ssa_expr(current_build, arg);
        if (arg_name) { add_arg_to_instr(instr, arg_name); }
    }
    }
    
    add_instr_to_current_block(instr);
    return result_name;
}

static const char *ast_to_ssa_expr(SSABuild *b, Ast *ast) {
    if (!ast) return NULL;
    switch (ast->type) {
    case AST_LITERAL: return process_literal(ast);
    case AST_LVAR: case AST_GVAR: return process_variable(ast);
    case AST_FUNCALL: return process_func_call(ast);
    case '=': return process_assign(ast); 
    default:
        if (ast->left && ast->right) return process_binary_op(ast);
        return NULL;
    }
}

static void process_return(Ast *ast) {    
    Instr *instr = create_instr(IROP_RET, NULL, NULL);
    if (ast->retval) {
        const char *retval_name = ast_to_ssa_expr(current_build, ast->retval);
        if (retval_name) add_arg_to_instr(instr, retval_name);
    }
    add_instr_to_current_block(instr);
}

static const char *block_label(Block *b) {
    static char buf[32];
    snprintf(buf, sizeof(buf), "block%u", b->id);
    return buf;
}

/* 简化的 if 语句处理 */
static void process_if_stmt(Ast *ast) {
    if (!ast || ast->type != AST_IF) return;

    const char *cond = ast_to_ssa_expr(current_build, ast->cond);
    if (!cond) return;
    
    // 创建三个基本块
    Block *then_block = create_block(current_build->cur_func->blocks->len);
    Block *else_block = create_block(current_build->cur_func->blocks->len + 1);
    Block *merge_block = create_block(current_build->cur_func->blocks->len + 2);
    
    list_push(current_build->cur_func->blocks, then_block);
    list_push(current_build->cur_func->blocks, else_block);
    list_push(current_build->cur_func->blocks, merge_block);
    
    // 添加前驱关系
    list_push(then_block->pred_ids, (void *)(uintptr_t)current_build->cur_block->id);
    list_push(else_block->pred_ids, (void *)(uintptr_t)current_build->cur_block->id);
    list_push(merge_block->pred_ids, (void *)(uintptr_t)then_block->id);
    list_push(merge_block->pred_ids, (void *)(uintptr_t)else_block->id);
    
    // 条件跳转
    Instr *br = create_instr(IROP_BR, NULL, NULL);
    add_arg_to_instr(br, cond);
    add_label_to_instr(br, block_label(then_block));
    add_label_to_instr(br, block_label(else_block));
    add_instr_to_current_block(br);
    
    // 密封当前块
    seal_block(current_build->cur_block);
    
    // 处理 then 分支
    current_build->cur_block = then_block;
    ast_to_ssa_stmt(current_build, ast->then);
    Instr *jmp_then = create_instr(IROP_JMP, NULL, NULL);
    add_label_to_instr(jmp_then, block_label(merge_block));
    add_instr_to_current_block(jmp_then);
    seal_block(then_block);
    
    // 处理 else 分支
    current_build->cur_block = else_block;
    if (ast->els) ast_to_ssa_stmt(current_build, ast->els);
    Instr *jmp_else = create_instr(IROP_JMP, NULL, NULL);
    add_label_to_instr(jmp_else, block_label(merge_block));
    add_instr_to_current_block(jmp_else);
    seal_block(else_block);
    
    // 继续到合并块
    current_build->cur_block = merge_block;
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
    case AST_IF:
        process_if_stmt(ast);
        break;
    case AST_DECL: {                 
        Ast *init = ast->declinit; 
        const char *val;
        if (init) {
            val = ast_to_ssa_expr(b, init);
        } else {
            val = make_ssa_name();
            Instr *zero = create_instr(IROP_CONST, val, ast->ctype);
            zero->ival = 0;
            add_instr_to_current_block(zero);
        }
        write_variable(ast->declvar->varname, b->cur_block, val);
        break;
    }
    default: ast_to_ssa_expr(b, ast); break;
    }
}

static bool ast_returns(Ast *ast) {
    if (!ast) return false;
    if (ast->type == AST_RETURN) return true;
    if (ast->type == AST_COMPOUND_STMT && ast->stmts->len > 0) {
        Ast *last = list_get(ast->stmts, ast->stmts->len - 1);
        return ast_returns(last);
    }
    return false;
}

static bool last_is_terminator(void) {
    if (!current_build || !current_build->cur_block) return false;
    List *instrs = current_build->cur_block->instrs;
    if (instrs->len == 0) return false;
    Instr *last = list_get(instrs, instrs->len - 1);
    return last->op == IROP_RET || last->op == IROP_JMP || last->op == IROP_BR;
}

/* ========== 函数处理 ========== */
static void ast_to_ssa_func_def(SSABuild *b, Ast *ast) {
    if (!ast || ast->type != AST_FUNC_DEF) return;
    
    Func *func = create_func(ast->fname, ast->ctype);
    current_build->cur_func = func;
    
    current_defs = (Dict *)make_dict(NULL);
    incomplete_phis = (Dict *)make_dict(NULL);
    sealed_blocks = make_list();

    Block *entry_block = create_block(0);
    func->entry_id = 0;
    list_push(func->blocks, entry_block);
    current_build->cur_block = entry_block;

    for (Iter i = list_iter(ast->params); !iter_end(i);) {
        Ast *param = iter_next(&i);
        
        const char *param_name = param->varname;
        const char *param_ssa_name = make_ssa_name();
        
        Instr *load_param = create_instr(IROP_LOAD, param_ssa_name, param->ctype);
        add_arg_to_instr(load_param, param_name);
        
        add_instr_to_current_block(load_param);
        write_variable(param_name, entry_block, param_ssa_name);
    }

    ast_to_ssa_stmt(b, ast->body);

    if (current_build->cur_block != NULL && !last_is_terminator()) {
        if (ast->ctype->type == CTYPE_VOID) {
            Instr *ret = create_instr(IROP_RET, NULL, NULL);
            add_instr_to_current_block(ret);
        }
    }

    list_push(b->unit->funcs, func);
    current_build->cur_func = NULL;
    current_build->cur_block = NULL;
}

/* ========== 公开接口 ========== */
void ast_to_ssa(SSABuild *b, Ast *ast) {
    if (!b || !ast) return;
    if (ast->type == AST_FUNC_DEF) {
        ast_to_ssa_func_def(b, ast);
    }
}

/* ========== 打印函数（保留） ========== */
#ifdef MINITEST_IMPLEMENTATION
#include "minitest.h"
#include "ssa_util.c"

TEST(test, ssa) {
    char infile[256] = "/mnt/d/ws/test/MazuCC/src/test/test_ssa.c";
    if (!freopen(strtok(infile, "\n"), "r", stdin)) 
        puts("open fail"), exit(1);
    
    set_current_filename(infile);
    SSABuild *b = ssa_new();
    List *toplevels = read_toplevels();
    for (Iter i = list_iter(toplevels); !iter_end(i);) {
        ast_to_ssa(b, (Ast *)iter_next(&i));
    }
    
    ssa_print(b, stdout);
}

#endif /* MINITEST_IMPLEMENTATION */
