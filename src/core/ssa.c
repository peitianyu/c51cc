#include "ssa.h"
#include "ssa_util.c"
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

    printf("%s sealed: %d block->preds->len: %d for var %s\n", __FUNCTION__, sealed, block->preds->len, var_name);
    
    // 获取变量类型 - 这里需要从符号表获取，简化处理假设是int
    Ctype *var_type = NULL;
    // 创建int类型作为默认
    var_type = &(Ctype){0, CTYPE_INT, 2, NULL};
    
    // 如果已密封且有多个前驱，需要phi函数
    if (sealed && block->preds->len > 1) {
        printf("  Creating phi for sealed block with %d predecessors\n", block->preds->len);
        
        // 创建phi函数
        const char *phi_name = make_ssa_name();
        
        // 使用变量类型
        Instr *phi = create_instr(IROP_PHI, phi_name, var_type);
        
        // 先添加到当前块
        add_instr_to_current_block(phi);
        // 记录定义
        write_variable(var_name, block, phi_name);
        
        // 为每个前驱添加操作数
        for (int i = 0; i < block->preds->len; i++) {
            uint32_t pred_id = (uintptr_t)list_get(block->preds, i);
            Block *pred = NULL;
            
            // 查找前驱块
            for (int j = 0; j < current_build->cur_func->blocks->len; j++) {
                Block *b = list_get(current_build->cur_func->blocks, j);
                if (b->id == pred_id) {
                    pred = b;
                    break;
                }
            }
            
            if (!pred) {
                printf("  Warning: pred not found for id %u\n", pred_id);
                add_arg_to_instr(phi, "undef");
                continue;
            }
            
            // 读取前驱块中的变量值
            const char *val = read_variable(var_name, pred);
            printf("  Read value from pred %u: %s\n", pred->id, val ? val : "NULL");
            
            if (!val) {
                // 在前驱中未定义，使用未定义值
                add_arg_to_instr(phi, "undef");
            } else {
                add_arg_to_instr(phi, val);
            }
        }
        
        // 尝试简化平凡phi
        Instr *simplified = try_remove_trivial_phi(phi);
        if (simplified != phi) {
            // phi被简化了，更新定义
            write_variable(var_name, block, simplified->dest);
            printf("  Phi simplified to: %s\n", simplified->dest);
            return simplified->dest;
        }
        
        printf("  Created phi: %s\n", phi_name);
        return phi_name;
    }
    else if (!sealed) {
        printf("  Creating placeholder phi for unsealed block\n");
        // 未密封的块：创建占位phi
        const char *phi_name = make_ssa_name();
        Instr *phi = create_instr(IROP_PHI, phi_name, var_type);
        
        // 重要：不立即添加到当前块，等待密封时处理
        // 只记录到incomplete_phis中
        
        // 记录到incomplete_phis中，等待密封时填充操作数
        char block_key[64];
        snprintf(block_key, sizeof(block_key), "%p", (void *)block);
        Dict *block_phis = (Dict *)dict_get(incomplete_phis, (char *)block_key);
        if (!block_phis) {
            block_phis = (Dict *)make_dict(NULL);
            dict_put(incomplete_phis, (char *)strdup(block_key), block_phis);
        }
        dict_put(block_phis, (char *)strdup(var_name), phi);
        
        printf("  Created placeholder phi: %s\n", phi_name);
        return phi_name;
    }
    else if (block->preds->len == 1) {
        printf("  Single predecessor, reading from pred\n");
        // 已密封且只有一个前驱：直接读取前驱的值
        uint32_t pred_id = (uintptr_t)list_get(block->preds, 0);
        Block *pred = NULL;
        for (int i = 0; i < current_build->cur_func->blocks->len; i++) {
            Block *b = list_get(current_build->cur_func->blocks, i);
            if (b->id == pred_id) {
                pred = b;
                break;
            }
        }
        if (pred) {
            const char *val = read_variable(var_name, pred);
            printf("  Value from pred %u: %s\n", pred->id, val ? val : "NULL");
            return val;
        }
    }
    else {
        printf("  No definition found\n");
        // 没有前驱（entry块）且未定义变量
        return NULL;
    }
    
    return NULL;
}

/* 论文算法2: addPhiOperands */
static Instr *add_phi_operands(const char *var_name, Instr *phi) {
    Block *block = current_build->cur_block;
    if (!block || !phi) return phi;
    
    printf("add_phi_operands for var %s in block %u\n", var_name, block->id);
    
    // 清空现有参数
    while (phi->args->len > 0) {
        free((char *)list_pop(phi->args));
    }
    
    // 为每个前驱添加操作数
    for (int i = 0; i < block->preds->len; i++) {
        uint32_t pred_id = (uintptr_t)list_get(block->preds, i);
        Block *pred = NULL;
        
        printf("  Processing pred %u\n", pred_id);
        
        // 查找前驱块
        for (int j = 0; j < current_build->cur_func->blocks->len; j++) {
            Block *b = list_get(current_build->cur_func->blocks, j);
            if (b->id == pred_id) {
                pred = b;
                break;
            }
        }
        
        if (!pred) {
            printf("  Pred not found\n");
            add_arg_to_instr(phi, "undef");
            continue;
        }
        
        // 读取前驱块中的变量值
        const char *val = read_variable(var_name, pred);
        printf("  Value from pred %u: %s\n", pred->id, val ? val : "NULL");
        
        if (!val) {
            add_arg_to_instr(phi, "undef");
        } else {
            add_arg_to_instr(phi, val);
        }
    }
    
    // 尝试简化平凡phi
    Instr *result = try_remove_trivial_phi(phi);
    
    if (result->ival == 1) { // 这是平凡phi
        printf("  Trivial phi detected, replacing with: %s\n", 
               result->args->len > 0 ? (const char *)list_get(result->args, 0) : "NULL");
        
        const char *same_value = result->args->len > 0 ? 
            (const char *)list_get(result->args, 0) : "undef";
        
        // 重要：直接返回NULL，表示phi应该被移除
        // 并且更新定义
        write_variable(var_name, block, same_value);
        
        // 标记phi为已删除
        phi->op = IROP_NOP;
        phi->dest = NULL;
        
        // 释放result
        // free(result->dest);
        list_free(result->args);
        free(result);
        
        return NULL; // 表示phi已被简化移除
    }
    
    printf("  Non-trivial phi: %s with %d args\n", 
           result->dest ? result->dest : "NULL", result->args->len);
    
    return result;
}

/* 论文算法3: tryRemoveTrivialPhi */
/* 论文算法3: tryRemoveTrivialPhi - 修复版本 */
static Instr *try_remove_trivial_phi(Instr *phi) {
    if (!phi || phi->op != IROP_PHI) return phi;

    const char *same = NULL;
    int undef_count = 0;
    bool all_same = true;
    
    // 检查所有操作数是否相同
    for (int i = 0; i < phi->args->len; i++) {
        const char *op = (const char *)list_get(phi->args, i);
        if (!op || strcmp(op, "undef") == 0) {
            undef_count++;
            continue;
        }
        if (same == NULL) {
            same = op;
        } else if (strcmp(same, op) != 0) {
            // 发现不同的操作数，不是平凡phi
            all_same = false;
            break;
        }
    }

    // 如果不是所有操作数都相同，返回原phi
    if (!all_same) {
        return phi;
    }
    
    // 如果所有操作数都是undef，则返回undef
    if (same == NULL && undef_count > 0) {
        // 标记为平凡phi，值为undef
        phi->ival = 1; // 使用ival字段标记这是平凡phi
        return phi;
    }
    
    // 如果same为NULL，说明没有有效操作数
    if (same == NULL) {
        return phi;
    }

    // 平凡phi：标记并返回
    phi->ival = 1; // 使用ival字段标记这是平凡phi
    
    // 创建一个简化的副本（如果需要）
    Instr *result = malloc(sizeof(Instr));
    if (!result) return phi;
    
    memset(result, 0, sizeof(Instr));
    result->op = IROP_PHI;
    result->dest = phi->dest ? strdup(phi->dest) : NULL;
    result->type = phi->type;
    result->args = make_list();
    if (same) {
        add_arg_to_instr(result, same); // 存储相同的值
    }
    result->ival = 1; // 标记为平凡phi
    
    return result;
}

/* 论文算法4: sealBlock */
static void seal_block(Block *block) {
    if (!block) return;
    
    printf("Sealing block %u\n", block->id);
    
    char block_key[64];
    snprintf(block_key, sizeof(block_key), "%p", (void *)block);
    Dict *block_phis = (Dict *)dict_get(incomplete_phis, (char *)block_key);
    
    if (block_phis) {
        printf("Found %d incomplete phis\n", block_phis->list->len);
        
        List *keys = dict_keys(block_phis);
        for (int i = 0; i < keys->len; i++) {
            const char *var_name = (const char *)list_get(keys, i);
            Instr *phi = (Instr *)dict_get(block_phis, (char *)var_name);
            
            if (phi) {
                printf("Processing phi for var %s\n", var_name);
                
                // 填充phi操作数
                Instr *new_phi = add_phi_operands(var_name, phi);
                
                if (new_phi == NULL) {
                    // phi被简化移除了
                    printf("  Phi simplified away\n");
                    // 不需要添加到指令列表
                } else {
                    // 将phi添加到块的指令列表开头
                    if (new_phi != phi) {
                        // free(phi->dest);
                        list_free(phi->args);
                        free(phi);
                    }
                    
                    // 添加到块的指令列表开头
                    list_set(block->instrs, 0, new_phi);
                    
                    // 更新定义
                    if (new_phi->dest) {
                        write_variable(var_name, block, new_phi->dest);
                    }
                }
            }
        }
        list_free(keys);
        
        // 清理incomplete_phis
        dict_remove(incomplete_phis, block_key);
    }
    
    list_push(sealed_blocks, block);
    block->sealed = true;
    printf("Block %u sealed\n", block->id);
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
    block->preds = make_list();
    block->succes = make_list();
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
    Ctype *ctype = ast->ctype;
    
    printf("process_variable: %s (type: %s) in block %u\n", 
           var_name, ctype_to_string(ctype), current_build->cur_block->id);
    
    // 先尝试读取变量
    const char *ssa_name = read_variable(var_name, current_build->cur_block);
    printf("  read_variable returned: %s\n", ssa_name);
    
    if (!ssa_name) {
        // 变量未定义，创建load指令
        ssa_name = make_ssa_name();
        Instr *load = create_instr(IROP_LOAD, ssa_name, ctype);
        add_arg_to_instr(load, var_name);
        add_instr_to_current_block(load);
        // 将load的结果作为该变量的定义
        write_variable(var_name, current_build->cur_block, ssa_name);
        printf("  created load: %s = load %s\n", ssa_name, var_name);
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
        default:
            error("未知操作数");
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

static bool last_is_terminator(void) {
    if (!current_build || !current_build->cur_block) return false;
    List *instrs = current_build->cur_block->instrs;
    if (instrs->len == 0) return false;
    Instr *last = list_get(instrs, instrs->len - 1);
    return last->op == IROP_RET || last->op == IROP_JMP || last->op == IROP_BR;
}

static void process_if_stmt(Ast *ast) {
    if (!ast || ast->type != AST_IF) return;

    const char *cond = ast_to_ssa_expr(current_build, ast->cond);
    if (!cond) return;
    
    // 创建新的基本块
    Block *then_block = create_block(current_build->cur_func->blocks->len);
    Block *else_block = create_block(current_build->cur_func->blocks->len + 1);
    Block *merge_block = create_block(current_build->cur_func->blocks->len + 2);
    
    // 设置前驱后继关系
    list_push(then_block->preds, (void *)(uintptr_t)current_build->cur_block->id);
    list_push(else_block->preds, (void *)(uintptr_t)current_build->cur_block->id);
    list_push(current_build->cur_block->succes, (void *)(uintptr_t)then_block->id);
    list_push(current_build->cur_block->succes, (void *)(uintptr_t)else_block->id);
    
    // 添加条件跳转
    Instr *br = create_instr(IROP_BR, NULL, NULL);
    add_arg_to_instr(br, cond);
    add_label_to_instr(br, block_label(then_block));
    add_label_to_instr(br, block_label(else_block));
    add_instr_to_current_block(br);
    
    // 密封当前块
    seal_block(current_build->cur_block);
    
    // 添加块到函数
    list_push(current_build->cur_func->blocks, then_block);
    list_push(current_build->cur_func->blocks, else_block);
    list_push(current_build->cur_func->blocks, merge_block);
    
    // 处理then分支
    current_build->cur_block = then_block;
    ast_to_ssa_stmt(current_build, ast->then);
    if(!last_is_terminator()) {
        // 添加跳转到合并块
        Instr *jmp_then = create_instr(IROP_JMP, NULL, NULL);
        add_label_to_instr(jmp_then, block_label(merge_block));
        add_instr_to_current_block(jmp_then);
        list_push(then_block->succes, (void *)(uintptr_t)merge_block->id);
    }
    
    // 密封then块
    seal_block(then_block);
    
    // 处理else分支
    current_build->cur_block = else_block;
    if (ast->els) {
        ast_to_ssa_stmt(current_build, ast->els);
    }
    if((!ast->els || !last_is_terminator())) {
        // 添加跳转到合并块
        Instr *jmp_else = create_instr(IROP_JMP, NULL, NULL);
        add_label_to_instr(jmp_else, block_label(merge_block));
        add_instr_to_current_block(jmp_else);
        list_push(else_block->succes, (void *)(uintptr_t)merge_block->id);
    }
    
    // 密封else块
    seal_block(else_block);
    
    // 设置合并块的前驱
    list_push(merge_block->preds, (void *)(uintptr_t)then_block->id);
    list_push(merge_block->preds, (void *)(uintptr_t)else_block->id);
    
    // 继续处理合并块
    current_build->cur_block = merge_block;
}

static void ast_to_ssa_stmt(SSABuild *b, Ast *ast) {
    if (!ast) return;

    printf("ast: %s\n", ast_to_string(ast));
    switch (ast->type) {
    case AST_COMPOUND_STMT:
        for (Iter i = list_iter(ast->stmts); !iter_end(i);) {
            Ast *stmt = iter_next(&i);
            ast_to_ssa_stmt(b, stmt);
        }
        break;
    case AST_RETURN: 
        process_return(ast); 
        break;
    case AST_IF:
        process_if_stmt(ast);
        printf("process_if_stmt preds: %d\n", current_build->cur_block->preds->len);
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

/* ========== 函数处理 ========== */
static void ast_to_ssa_func_def(SSABuild *b, Ast *ast) {
    if (!ast || ast->type != AST_FUNC_DEF) return;

    Func *func = create_func(ast->fname, ast->ctype);
    b->cur_func = func;

    current_defs        = make_dict(NULL);
    incomplete_phis     = make_dict(NULL);
    sealed_blocks       = make_list();

    Block *entry = create_block(0);
    func->entry_id = 0;
    list_push(func->blocks, entry);
    b->cur_block = entry;

    for (Iter i = list_iter(ast->params); !iter_end(i);) {
        Ast *param_ast = iter_next(&i);

        const char *src_name = param_ast->varname;  
        const char *ssa_name = make_ssa_name();

        // NOTE: 函数参数以load形式加载
        Instr *load = create_instr(IROP_LOAD, ssa_name, param_ast->ctype);
        add_arg_to_instr(load, src_name);
        add_instr_to_current_block(load);

        write_variable(src_name, entry, ssa_name);
        list_push(func->param_names, strdup(src_name));
    }

    ast_to_ssa_stmt(b, ast->body);

    // 密封最后一个块
    if (b->cur_block) {
        seal_block(b->cur_block);
    }

    if (b->cur_block && !last_is_terminator()) {
        if (ast->ctype->type == CTYPE_VOID) {
            Instr *ret = create_instr(IROP_RET, NULL, NULL);
            add_instr_to_current_block(ret);
        }
    }

    list_push(b->unit->funcs, func);
    b->cur_func = NULL;
    b->cur_block = NULL;
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


TEST(test, ssa) {
    char infile[256] = "/mnt/d/ws/test/MazuCC/src/test/test_ssa.c";
    if (!freopen(strtok(infile, "\n"), "r", stdin)) 
        puts("open fail"), exit(1);
    
    set_current_filename(infile);
    SSABuild *b = ssa_new();
    List *toplevels = read_toplevels();
    for (Iter i = list_iter(toplevels); !iter_end(i);) {
        Ast *ast = iter_next(&i);
        printf("ast: %s\n", ast_to_string(ast));
        ast_to_ssa(b, ast);
    }
    
    ssa_print(b, stdout);
}

#endif /* MINITEST_IMPLEMENTATION */
