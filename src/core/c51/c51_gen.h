#ifndef C51_GEN_H
#define C51_GEN_H

#include "../obj.h"
#include "../ssa.h"
#include "../dict.h"
#include "../list.h"

/* C51代码生成上下文 */
typedef struct C51GenContext {
    ObjFile* obj;
    SSAUnit* unit;
    Func* current_func;
    Block* current_block;

    Dict* value_to_reg;     /* ValueName -> int* (寄存器索引) */
    Dict* value_to_addr;    /* ValueName -> char* (变量名) */
    Dict* value_type;       /* ValueName -> Ctype* */
    Dict* value_to_const;   /* value -> int64_t* (记录常量值) */

    Dict* v16_regs;
    int next_v16_offset;

    /* spill 管理：ValueName -> spill 符号名 */
    Dict* value_to_spill;
    int next_spill_id;

    /* spill 目标配置：选择默认的节 (SEC_DATA / SEC_IDATA / SEC_XDATA)
     * 如果 spill_use_xdata_for_large 为 true，则对于 size>1 的值使用 SEC_XDATA。 */
    SectionKind spill_section;
    int spill_use_xdata_for_large;

    Dict* mmio_map;
    int label_counter;

    List* temp_values;
    
    int value_in_acc;       /* 当前在累加器A中的值，-1表示没有 */
} C51GenContext;

/* 主入口 */
ObjFile *c51_gen(SSAUnit *unit);
ObjFile *c51_link_startup(const char *source_path, ObjFile *main_obj);

/* 上下文管理 */
C51GenContext* c51_ctx_new(void);
void c51_ctx_free(C51GenContext* ctx);

/* 汇编输出 */
int c51_write_asm(FILE *fp, const ObjFile *obj);
int c51_write_hex(FILE *fp, const ObjFile *obj);

#endif
