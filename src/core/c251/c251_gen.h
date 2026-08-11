#ifndef C251_GEN_H
#define C251_GEN_H

#include "../obj.h"
#include "../ssa.h"
#include "../dict.h"
#include "../list.h"

/* C251 代码生成上下文（M1 精简版） */
typedef struct C251GenContext {
    ObjFile* obj;
    SSAUnit* unit;
    Func* current_func;
    Block* current_block;

    Dict* value_to_reg;     /* ValueName -> int* (WR 索引 0/2/4/6) */
    Dict* value_type;       /* ValueName -> Ctype* */
    Dict* value_to_const;   /* value -> int64_t* (记录常量值) */
    int label_counter;
    List* temp_values;
} C251GenContext;

/* 主入口 */
ObjFile *c251_gen(SSAUnit *unit);
ObjFile *c251_link_startup(const char *source_path, ObjFile *main_obj);

/* 上下文管理 */
C251GenContext* c251_ctx_new(void);
void c251_ctx_free(C251GenContext* ctx);

/* 汇编/HEX 输出 */
int c251_write_asm(FILE *fp, const ObjFile *obj);
int c251_write_hex(FILE *fp, const ObjFile *obj);

#endif
