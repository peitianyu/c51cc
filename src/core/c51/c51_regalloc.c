#include "c51_gen_internal.h"

/*
## 寄存器约定
### 传参
- **char**: R7→R5→R3（跳开 R6/R4/R2 预留扩展位）
- **int**: R6R7→R4R5→R2R3（大端）
- **long/float**: R4R7（仅第1个；第2个转栈）
- **指针**: R1(L)R2(H)R3(类型)，避 R0（专留 `@R0/@R1` 寻址）
- **bit**: 内存（`?func?BIT`）
- **结构体/≥4参**: 栈（`?func?BYTE`）

### 返回
- **bit**: C
- **char**: R7
- **int**: R6R7
- **long/float**: R4R7（大端）
- **指针**: R1R2R3
- **结构体**: R1R2R3 传隐式缓冲区地址（写入后返回）

### 关键陷阱
- **R0 禁忌**: R0/R1 是 8051 唯二间接寻址寄存器，指针传参避开 R0 留作索引器
- **非连续分配**: R7→R5→R3 跳开 R6/R4/R2，为多字节参数预留扩展位防重叠
- **存储模式传染**: SMALL 默认 `data*`（2字节），LARGE 默认 `generic*`（3字节）；跨空间访问需显式 `xdata*` 转换
- **重入前缀**: `?func` 表示栈传参，与标准 R3-R7 ABI 不兼容
- **ISR Bank**: `using N` 硬件切 Bank（0x08/0x10/0x18）零开销保存 R0-R7；调用普通函数须同步 PSW.3-4
- **结构体隐式第0参**: 返回结构体时栈预分配空间，R1R2R3 指向缓冲区直接写入
- **double 实为 float**: 默认 32 位（R4R7），仅 `FLOAT64` 选项启用时为 64 位（内存传递）
- **R3 编码**: 0x00=data，0x01=xdata，0xFE=pdata，0xFF=code；通用指针运行时依此选 MOV/MOVX/MOVC
- **保存责任**: A/B/PSW/DPTR 调用者保存；R4-R7 若用于返回，被调者修改前须自保存
*/

// NOTE: 采用线性扫描寄存器分配
void c51_regalloc(C51GenContext* ctx, Section* sec)
{
    
}