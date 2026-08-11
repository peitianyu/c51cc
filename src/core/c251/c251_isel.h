#ifndef C251_ISEL_H
#define C251_ISEL_H

#include "c251_gen.h"

/* 指令选择主入口（ISelContext 与其余接口由 M1 任务 6 补充完整） */
void isel_function(C251GenContext* ctx, Func* func);

#endif
