#ifndef C251_GEN_H
#define C251_GEN_H

#include "../obj.h"
#include "../ssa.h"
#include "../dict.h"
#include "../list.h"

/* EDATA 布局基址：首 0x80 字节避开 IRAM 0x00-0x7F（寄存器文件 R0-R7/位区/数据区），
 * 变量与溢出槽从 0x80 起布局（与 hex 输出 type-04 0x0000 + off 一致） */
#define C251_EDATA_BASE 0x80

/* C251 代码生成上下文（M2：加 value_to_spill 溢出槽管理） */
typedef struct C251GenContext {
    ObjFile* obj;
    SSAUnit* unit;
    Func* current_func;
    Block* current_block;

    Dict* value_to_reg;     /* ValueName -> int* (WR 索引 0/2/4/6) */
    Dict* value_type;       /* ValueName -> Ctype* */
    Dict* value_to_const;   /* value -> int64_t* (记录常量值) */
    Dict* value_to_addr;    /* ValueName -> char* (ADDR 产物指向的全局符号名) */
    Dict* value_to_spill;   /* ValueName -> char* (__spill_N 符号名) */
    Dict* sym_size;         /* 全局符号名 -> int* (字节数, 供 STORE 宽度判定) */
    Dict* sfr_addr;         /* M3: sfr/sbit 符号名 -> int* (SFR 直接地址) */
    Dict* value_to_off;     /* ValueName -> OffInfo* {char* sym; int off} (OFFSET 折叠: 符号基址+常量偏移) */
    int next_spill_id;      /* 溢出槽编号 */
    int label_counter;
    List* temp_values;
} C251GenContext;

/* 值名 → dict key（公共，跨文件共享；返回 strdup，dict_free/remove 负责释放） */
char* c251_key(int n);

/* 溢出槽管理：为值分配/查询 EDATA 临时槽（每槽 2 字节，符号 __spill_N）。
 * 返回符号名（strdup，ctx 持有）；已分配过则复用 */
char* c251_alloc_spill(C251GenContext* ctx, ValueName val);
char* c251_value_spill(C251GenContext* ctx, ValueName val);

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
