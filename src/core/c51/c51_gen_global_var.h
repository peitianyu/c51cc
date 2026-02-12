#ifndef C51_GEN_GLOBAL_VAR_H
#define C51_GEN_GLOBAL_VAR_H

#include "c51_gen.h"

/* 存储区类型 */
enum {
    CTYPE_DATA_NONE = 0,
    CTYPE_DATA_DATA = 1,
    CTYPE_DATA_IDATA = 2,
    CTYPE_DATA_PDATA = 3,
    CTYPE_DATA_XDATA = 4,
    CTYPE_DATA_EDATA = 5,
    CTYPE_DATA_CODE = 6,
};

/* 全局变量处理函数 */
bool handle_const_global_var(C51GenContext* ctx, GlobalVar* g);
bool handle_mmio_global_var(C51GenContext* ctx, GlobalVar* g);
bool handle_extern_global_var(C51GenContext* ctx, GlobalVar* g);
void handle_normal_global_var(C51GenContext* ctx, GlobalVar* g);

/* 辅助函数 */
void append_init_bytes_safe(Section* sec, GlobalVar* g);
void add_data_symbol(C51GenContext* ctx, const char* name,
                     int sec_idx, unsigned int addr_or_offset,
                     int size, int flags);
void select_section_kind_and_prefix(CtypeAttr attr, GlobalVar* g,
                                    SectionKind* out_kind, const char** out_prefix);

#endif
