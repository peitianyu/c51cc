#include "ssa.h"
#include "cc.h"
#include <stdint.h>

// static uint32_t g_vid = 1;

// // // 将 cc.h 的 Ctype 递归转换成 ssa.h 的 Type
// // Type *ctype_to_type(Ctype *ct)
// // {
// //     if (!ct) return NULL;

// //     Type *t = calloc(1, sizeof(*t));

// //     switch (ct->type) {
// //     case CTYPE_VOID:  free(t); return NULL;

// //     case CTYPE_BOOL:
// //     case CTYPE_CHAR:
// //     case CTYPE_INT:
// //     case CTYPE_LONG:
// //         t->kind = TYPE_INT;
// //         t->i.bits = ct->size * 8;
// //         t->i.unsign = get_attr(ct->attr).ctype_unsigned;
// //         return t;

// //     case CTYPE_FLOAT:
// //     case CTYPE_DOUBLE:
// //         t->kind = TYPE_FLOAT;
// //         t->i.bits = ct->size * 8;
// //         return t;

// //     case CTYPE_PTR:
// //         t->kind = TYPE_PTR;
// //         t->base = ctype_to_type(ct->ptr);
// //         return t;

// //     case CTYPE_ARRAY:
// //         t->kind = TYPE_ARRAY;
// //         t->a.elem = ctype_to_type(ct->ptr);
// //         t->a.len  = ct->len;
// //         return t;

// //     case CTYPE_STRUCT:  
// //         t->kind = (ct->offset==ct->size) ? TYPE_UNION : TYPE_STRUCT;
// //         // TODO: 这里判断是否需要位域
// //         // FIXME: 这里是否也应该只输出我要的具体值而不需要去关注struct还是union, 只操作内存就好


// //         return t;
// //     case CTYPE_ENUM:  
// //         t->kind = TYPE_INT;
// //         t->i.bits = 16;
// //         t->i.unsign = false;
// //         return t;

// //     default:
// //         assert(0 && "unknown CTYPE");
// //     }
// // }

// static SSABuild *ssa_new()
// {
//     SSABuild *s = malloc(sizeof(SSABuild));
//     s->unit = malloc(sizeof(SSAUnit));
//     s->unit->funcs = make_list();
//     s->unit->globals = make_list();
//     s->cur_func = NULL;
//     s->cur_block = NULL;

//     s->instr_buf = make_list();
//     s->name_buf = make_list();
//     return s;
// }

// static Instr *instr_new(const char *op, const char *dest, Type *ty) 
// {
//     Instr *i = malloc(sizeof(Instr));
//     i->op   = strdup(op);
//     i->dest = dest ? strdup(dest) : NULL;
//     i->type = ty;
//     i->args = make_list();
//     i->labels = make_list();
//     i->ival = 0;
//     i->attr.restrict_ = 0;
//     i->attr.volatile_ = 0;
//     i->attr.reg = 0;
//     i->attr.mem = 0;
//     return i;
// }

// static Block *block_new()
// {
//     Block *b = malloc(sizeof(Block));
//     b->id = 0;
//     b->sealed = false;
//     b->instrs = make_list();
//     b->pred_ids = make_list();
//     b->succ_ids = make_list();
//     return b;
// }

// static Func *func_new(const char* name, Type* ret_type, uint32_t entry_id)
// {
//     Func *f = malloc(sizeof(Func));
//     f->name = strup(name);
//     f->ret_type = ret_type;
//     f->param_names = make_list();
//     f->blocks = make_list();
//     f->entry_id = entry_id;
//     return f;
// }

// void ast_to_ssa(SSABuild *b, Ast *ast)
// {
//     if (!ast) return;

//     switch (ast->type) {
//     case AST_LITERAL:
//         switch (ast->ctype->type) {
//         case CTYPE_BOOL:
//         case CTYPE_CHAR:
//         case CTYPE_INT: 
//         case CTYPE_LONG:    break;
//         case CTYPE_FLOAT:
//         case CTYPE_DOUBLE:  break;
//         case CTYPE_ENUM:    break;
//         default:            error("internal error");
//         }
//         break;
//     case AST_STRING:
//         break;
//     case AST_LVAR:
//     case AST_GVAR:
//         break;
//     case AST_FUNCALL: 
//         break;
//     case AST_FUNC_DECL:
//         break;
//     case AST_FUNC_DEF: 
//         break;
//     case AST_DECL:
//         break;
//     case AST_ARRAY_INIT:
//         break;
//     case AST_STRUCT_INIT:
//         break;
//     case AST_IF:
//         break;
//     case AST_TERNARY:
//         break;
//     case AST_SWITCH: 
//         break;
//     case AST_FOR:
//         break;
//     case AST_WHILE:
//         break;
//     case AST_DO_WHILE:
//         break;
//     case AST_GOTO:
//         break;
//     case AST_CONTINUE:
//         break;
//     case AST_BREAK:
//         break;
//     case AST_LABEL:
//         break;
//     case AST_RETURN:
//         break;
//     case AST_COMPOUND_STMT: 
//         break;
//     case AST_STRUCT_REF:
//         break;
//     case AST_STRUCT_DEF:
//         break;
//     case AST_ENUM_DEF:
//         break;
//     case AST_TYPE_DEF:
//         break;
//     case AST_CAST: 
//         break;
//     case AST_ADDR:
//         break;
//     case AST_DEREF:
//         break;
//     case PUNCT_INC:
//         break;
//     case PUNCT_DEC:
//         break;
//     case PUNCT_LOGAND:
//         break;
//     case PUNCT_LOGOR:
//         break;
//     case '!':
//         break;
//     case '~':
//         break;
//     case '&':
//         break;
//     case '|':
//         break;
//     default: {
//     }
//     }

// }

// static uint32_t ssa_add_global(SSABuild *b, const char *name, Type *ty, int64_t i, bool is_extern) {
//     Type *type = bump_alloc(sizeof(Type));
// }

#ifdef MINITEST_IMPLEMENTATION
#include "minitest.h"

TEST(test, ssa) {
    char infile[256];
    printf("file path: ");
    if (!fgets(infile, sizeof infile, stdin) || !freopen(strtok(infile, "\n"), "r", stdin))
        puts("open fail"), exit(1);

    set_current_filename(infile);

    // SSABuild *b = ssa_new();
        
    List *toplevels = read_toplevels();
    for (Iter i = list_iter(toplevels); !iter_end(i);) {}
        // ast_to_ssa(b, (Ast *)iter_next(&i));
    
    list_free(cstrings);
    list_free(ctypes);

    printf("\n");
}
#endif /* MINITEST_IMPLEMENTATION */