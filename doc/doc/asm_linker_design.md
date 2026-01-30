# ASM 生成模块与链接器接口设计

日期：2026-01-30

## 1. 设计目标
- 输出可链接目标文件：段、符号、重定位（ASM 可选）
- ASM 生成从后端 IR/SSA 开始，前端语法解耦
- 链接器只做布局与重定位
- 对齐 Keil51：地址空间语义一致

## 2. 处理流程
1) SSA/后端 IR
2) 指令选择
3) 寄存器分配（线性扫描）
4) 指令降级/展开
5) 窥孔优化
6) ASM 打印
7) 汇编器：ASM → ObjFile（段/符号/重定位）
8) 链接器：布局与重定位
9) 输出 ASM/HEX

## 3. 目标约束
- 内存模型：单一模型（统一指针宽度与默认空间）
- 地址空间：CODE/DATA/IDATA/XDATA/BIT/BDATA/PDATA
- 段按空间分组，可细分到 module/function
- reentrant/interrupt 语义必须体现在调用约定与序言/尾声

### 3.1 段分组与细分
- 空间分组：同一地址空间放入对应段（CODE/DATA/XDATA/IDATA/BIT/BDATA）。
- module 细分：每个源文件形成子段（.text.$module、.data.$module）。
- function 细分：每个函数形成子段（.text.$func），便于裁剪与排序。

### 3.2 static/extern 规则
- static func：CODE 段子段（.text.$func），符号 local，不导出。
- extern func：本文件仅保留未定义符号，调用点生成重定位。
- static var：放入对应数据段（.data/.bss/.xdata/.idata），符号 local。
- extern var：本文件仅保留未定义符号，读写处生成重定位。

## 4. 后端模块职责
### 4.1 指令选择
- 输入：IR（类型/地址空间/属性）
- 输出：抽象目标指令（虚拟寄存器）
- 关键规则：
  - 地址空间决定 MOV/MOVX/MOVC
  - volatile 禁止合并/重排
  - register 表示 sfr/sbit/sfr16（映射到专用寄存器/位操作）
  - bit/sbit 走位操作指令

### 4.2 寄存器分配
- 线性扫描
- 输出：实体寄存器分配 + spill 伪指令
- 固定用途：A/B/DPTR/R0-R7

线性扫描流程（概要）：
1) 计算每个虚拟寄存器的 live interval（起止位置）。
2) 按起点排序，维护一个按结束位置排序的 active 集合。
3) 新区间进入时：
  - 先释放已结束区间。
  - 若有空闲寄存器则分配；否则选择一个 active 区间进行 spill。
4) spill 生成：在定义/使用处插入 load/store，产生新的临时区间。

8051 约束建议：
- 保留 SP/PSW，不参与分配。
- A/DPTR 受指令约束较多，可优先分配给需要累加器/DPTR 的操作。
- R0/R1 常用作间接寻址，可设置更高权重避免频繁 spill。

### 4.3 指令降级
- 参数传递与调用约定
- 大常量装载
- 条件跳转组合
- reentrant/interrupt 的 prologue/epilogue

### 4.4 窥孔优化
- 局部指令级优化
- 典型规则：
  - 消除冗余 MOV
  - 合并等效 load/store
  - 选择短跳转
  - 清理无副作用栈操作

### 4.5 ASM 打印
- 输出汇编文本（可选产物）
- 真实链接输入为 ObjFile

## 5. ObjFile 与链接器
### 5.1 ObjFile（最小字段）
- Section：kind/size/align/bytes 或 asm_lines
- Symbol：name/kind/section/value/size/flags
- Reloc：section/offset/kind/symbol/addend

段命名建议：
- CODE: .text .const
- DATA: .data .bss .idata
- XDATA: .xdata .xdata_bss
- BIT/BDATA: .bit .bdata
- 支持 .text.$func / .data.$module

ObjFile 示例（JSON）：
{
  "sections": [
    {"name":".text", "kind":"CODE", "size":128, "align":1, "bytes":"..."},
    {"name":".data", "kind":"DATA", "size":16, "align":1, "bytes":"..."},
    {"name":".bss",  "kind":"DATA", "size":32, "align":1, "bytes":null}
  ],
  "symbols": [
    {"name":"main", "kind":"FUNC", "section":0, "value":0, "size":24, "flags":["global"]},
    {"name":"g_val", "kind":"DATA", "section":1, "value":0, "size":2, "flags":["global"]},
    {"name":"ext_fn", "kind":"FUNC", "section":-1, "value":0, "size":0, "flags":["extern"]}
  ],
  "relocs": [
    {"section":0, "offset":6, "kind":"REL16", "symbol":"ext_fn", "addend":0},
    {"section":0, "offset":12, "kind":"ABS16", "symbol":"g_val", "addend":0}
  ]
}

### 5.2 链接器接口
- 输入：ObjFile 列表（必须含段/符号/重定位）
- 输出：
  - 段布局结果
  - 符号最终地址
  - 重定位回填
  - 可选：生成最终 ASM/HEX

## 6. 调用约定（参考 Keil）
- 统一指针宽度与默认空间。
- 参数传递：优先使用寄存器，超过部分入 DATA 栈。
  - 8bit/16bit 标量：优先 A、DPTR 或 R2–R7（按需要与指令约束选择）。
  - 结构体或大对象：通过指针传递，指针放寄存器或栈。
- 返回值：
  - 8bit：A
  - 16bit：DPTR
  - 更大：通过隐藏指针参数（caller 分配）。
- 被调保存：R0–R7/DPTR 按约定保存（默认 caller-save，必要时 callee-save）。
- push/pop 习惯：
  - 普通函数仅在确实会破坏寄存器时才生成保存/恢复指令。
  - caller-save 寄存器由调用方在需要时保存，返回后恢复。
  - callee-save 约定的寄存器由被调函数在入口 push，退出 pop。
  - 中断服务例程需保存 A/PSW/DPTR/所用寄存器组。
- reentrant：只使用栈传参/局部变量，避免固定地址。
- interrupt：固定入口序言/尾声，保存 A/PSW/DPTR/寄存器组。

### 6.1 寄存器破坏与保存策略（整理）
- 破坏条件：函数内生成的指令写入该寄存器即视为破坏。
- 普通函数：仅在确实写入寄存器时生成保存/恢复。
- Keil 习惯：caller-save 为主，callee-save 仅在需要时启用。
- SDCC 习惯：同样以 caller-save 为主，按使用情况生成 push/pop。
- 中断/可重入：保存更严格，覆盖 A/PSW/DPTR/使用到的寄存器组。

## 7. 汇编器与伪指令
### 7.1 伪指令（最小集合）
- 段/空间：CSEG/DSEG/ISEG/XSEG/BSEG（或等价 .section/.space）
- 符号可见性：PUBLIC/EXTRN（或 .global/.extern）
- 数据定义：DB/DW/DS
- 定位：ORG
- 结束：END

### 7.2 本项目伪指令映射
- .section / .global / .extern / .label
- .space code|data|idata|xdata|bit|bdata|pdata
- .interrupt n / .using bank / .reentrant

### 7.3 汇编器职责（最小）
- 解析伪指令并生成段/符号/重定位
- 输出 ObjFile，供链接器使用

## 8. IR 对接字段
- 类型宽度/无符号
- 地址空间属性
- volatile/register/static/extern
- reentrant/interrupt

## 9. 实现流程（步骤化）
1) 定义 ObjFile 结构与序列化（JSON）。
2) 建立 section/symbol/reloc 收集接口（供 ASM/汇编器使用）。
3) 实现最小汇编器：解析 .section/.global/.extern/.label/.db/.dw/.ds/.org/.end。
4) 完成 ASM 打印器：输出可被汇编器解析的伪指令与指令序列。
5) 指令选择：先覆盖基本算术、load/store、分支。
6) 寄存器分配：线性扫描 + spill 插入。
7) 指令降级：常量装载、分支组合、调用序言/尾声。
8) 窥孔优化：MOV 冗余、短跳转、无效栈操作。
9) 链接器：段布局 + 重定位回填 + 输出 ASM/HEX。
10) 扩展地址空间与更多重定位类型。

## 10. 文件组织建议
- c51_gen.c：指令选择/寄存器分配/降级/ASM 输出/ObjFile 构建
- c51_link.c：段布局/符号解析/重定位/HEX 输出
- c51_obj.h：ObjFile/Section/Symbol/Reloc 结构与公共接口
