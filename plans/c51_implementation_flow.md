# C51后端实现流程详解

## 当前代码状态分析

### 已完成部分
- ✅ [`c51_gen.c`](src/core/c51/c51_gen.c:1) - 主框架流程清晰
- ✅ [`c51_context.c`](src/core/c51/c51_context.c:1) - 上下文管理已实现
- ✅ [`ssa.h`](src/core/ssa.h:1) - SSA定义完整（含IrOp、Instr、Block、Func、GlobalVar）
- ✅ [`obj.h`](src/core/obj.h:1) - 目标文件格式定义

### 待实现部分
- ⚠️ [`c51_gen_global_var.h`](src/core/c51/c51_gen_global_var.h:1) - 函数声明为空
- ⚠️ [`c51_gen_function.h`](src/core/c51/c51_gen_function.h:1) - 函数声明为空
- ⚠️ [`c51_instr.c`](src/core/c51/c51_instr.c:1) - 指令选择空
- ⚠️ [`c51_regalloc.c`](src/core/c51/c51_regalloc.c:1) - 寄存器分配空
- ⚠️ [`c51_optimize.c`](src/core/c51/c51_optimize.c:1) - 优化空
- ⚠️ [`c51_encode.c`](src/core/c51/c51_encode.c:1) - 编码空
- ⚠️ [`c51_output.c`](src/core/c51/c51_output.c:1) - 输出空

---

## 实现阶段详细计划

### 第一阶段：基础框架打通

#### 1.1 实现最简单的全局变量处理

**目标**: 处理 `int x = 10;` 这类简单全局常量

**修改文件**: [`c51_gen_global_var.h`](src/core/c51/c51_gen_global_var.h:16)

```c
static inline void handle_normal_global_var(C51GenContext *ctx, GlobalVar *g)
{
    // 1. 创建DATA段（如果不存在）
    // 2. 添加符号定义
    // 3. 追加初始值字节到段
}
```

**关键点**:
- 使用 [`obj_add_section()`](src/core/obj.h:58) 创建DATA段
- 使用 [`obj_add_symbol()`](src/core/obj.h:65) 添加符号
- 使用 [`section_append_bytes()`](src/core/obj.h:62) 写入初始值

#### 1.2 实现空函数框架

**目标**: 生成 `void foo() {}` 的汇编

**修改文件**: [`c51_gen_function.h`](src/core/c51/c51_gen_function.h:1)

```c
static inline void handle_function_init(C51GenContext *ctx, Func *f) 
{
    // 1. 创建CODE段
    // 2. 添加函数符号
    // 3. 初始化函数级映射表
}

static inline void handle_function_emit(C51GenContext *ctx, Func *f) 
{
    // 遍历所有Block
    // 遍历Block内所有Instr
    // 调用 c51_instr() 生成汇编指令
}

static inline void handle_function_cleanup(C51GenContext *ctx, Func *f) 
{
    // 清理函数级映射表
}
```

#### 1.3 实现基本ASM输出

**目标**: 输出可读的汇编文件

**修改文件**: [`c51_output.c`](src/core/c51/c51_output.c:1)

```c
int c51_write_asm(FILE *fp, const ObjFile *obj)
{
    // 1. 遍历所有Section
    // 2. 输出段名和类型
    // 3. 遍历AsmInstr列表，输出指令
    // 4. 输出符号表（可选）
}
```

**验证测试**:
```c
int x = 10;
void foo() {}
```
期望输出:
```asm
        AREA    ?DT?DATA, DATA
_x:     DS      2
        DB      10, 0

        AREA    ?PR?foo, CODE
_foo:   RET
```

---

### 第二阶段：指令选择基础

#### 2.1 常量加载指令

**目标**: 处理 `IROP_CONST` → `MOV A, #imm`

**修改文件**: [`c51_instr.c`](src/core/c51/c51_instr.c:8)

```c
void c51_instr(C51GenContext* ctx, Section* sec, Instr* ins)
{
    switch (ins->op) {
        case IROP_CONST:
            // 生成 MOV A, #imm
            // 或 MOV R7, #imm (如果目标是寄存器)
            break;
        // ... 其他指令
    }
}
```

**支持类型**:
- char: `MOV R7, #imm8`
- int: `MOV R6, #imm8` + `MOV R7, #imm8` (大端)

#### 2.2 简单算术指令

**目标**: 处理 `IROP_ADD`, `IROP_SUB`

**C51指令映射**:
| SSA指令 | C51指令 | 说明 |
|---------|---------|------|
| `v3 = add v1, v2` | `MOV A, R7`<br>`ADD A, R5` | 假设v1在R7, v2在R5 |
| `v3 = sub v1, v2` | `MOV A, R7`<br>`CLR C`<br>`SUBB A, R5` | 带借位减法 |

**实现步骤**:
1. 确定操作数所在的寄存器（查询 `ctx->value_to_reg`）
2. 生成对应的C51指令序列
3. 将结果寄存器记录到 `ctx->value_to_reg`

#### 2.3 寄存器传送

**目标**: 处理值传递和拷贝

```c
// 将值从src_reg复制到dst_reg
void emit_mov_reg_reg(Section* sec, int dst_reg, int src_reg)
{
    // MOV A, R{src_reg}
    // MOV R{dst_reg}, A
}
```

---

### 第三阶段：寄存器分配

#### 3.1 寄存器池管理

**修改文件**: [`c51_gen_internal.h`](src/core/c51/c51_gen_internal.h:1)

**新增结构**:
```c
#define C51_REG_R0  0
#define C51_REG_R1  1
// ... R2-R7

typedef struct {
    bool used[8];      // R0-R7使用状态
    int allocated_to[8]; // R{n}分配给哪个ValueName
} RegPool;
```

#### 3.2 线性扫描实现

**修改文件**: [`c51_regalloc.c`](src/core/c51/c51_regalloc.c:34)

**算法流程**:
```c
void c51_regalloc(C51GenContext* ctx, Section* sec)
{
    // 1. 收集所有虚拟寄存器（值）
    // 2. 按程序顺序遍历指令
    // 3. 为每个新值分配物理寄存器
    // 4. 当寄存器耗尽时，溢出到栈
}
```

**Keil C51寄存器约定**:
- char返回值: R7
- int返回值: R6:R7 (大端)
- 参数传递: R7→R5→R3→R2→R4→R6 (跳开模式)
- 指针: R1(L):R2(H):R3(类型)

#### 3.3 栈溢出处理

**目标**: 当8个寄存器不够用时，溢出到栈

```c
typedef struct {
    int stack_offset;  // 栈帧偏移
    bool in_memory;    // 是否在内存
} ValueLocation;

// 溢出策略：将最不常用的值存入栈
void spill_value(C51GenContext* ctx, ValueName v)
{
    // 1. 分配栈偏移
    // 2. 生成 PUSH/MOV 指令保存值
    // 3. 标记该值为"在内存中"
    // 4. 释放占用的寄存器
}
```

---

### 第四阶段：函数支持

#### 4.1 函数参数传递

**目标**: 实现Keil C51参数约定

```c
// 处理 IROP_PARAM
void emit_param(C51GenContext* ctx, Section* sec, Instr* ins, int param_index)
{
    // param_index 0: char→R7, int→R6:R7
    // param_index 1: char→R5, int→R4:R5
    // ...
}
```

#### 4.2 函数返回值

**目标**: 处理 `IROP_RET`

```c
void emit_ret(C51GenContext* ctx, Section* sec, Instr* ins)
{
    // 1. 将返回值放入约定寄存器
    //    char: MOV R7, A
    //    int:  MOV R6, src+0; MOV R7, src+1
    // 2. 生成 RET 指令
}
```

#### 4.3 函数调用

**目标**: 处理 `IROP_CALL`

```c
void emit_call(C51GenContext* ctx, Section* sec, Instr* ins)
{
    // 1. 设置参数（根据约定放入R2-R7）
    // 2. 生成 LCALL 或 ACALL
    // 3. 从R6:R7获取返回值
}
```

---

### 第五阶段：内存访问

#### 5.1 DATA段直接寻址

**目标**: 访问data/idata变量

```c
// 处理 IROP_LOAD (读)
// MOV A, direct
// MOV R7, A

// 处理 IROP_STORE (写)  
// MOV A, R7
// MOV direct, A
```

#### 5.2 IDATA间接寻址

**目标**: 使用@R0/@R1访问

```c
// MOV R0, #offset
// MOV A, @R0
```

#### 5.3 XDATA访问

**目标**: MOVX @DPTR

```c
// MOV DPTR, #addr16
// MOVX A, @DPTR
```

---

### 第六阶段：控制流

#### 6.1 条件跳转

**目标**: 实现 `IROP_BR` (条件分支)

```c
// 比较指令生成状态位
// CJNE A, #imm, label
// 或
// CJNE A, direct, label
// JZ/JNZ label
```

#### 6.2 无条件跳转

**目标**: 实现 `IROP_JMP`

```c
// SJMP label (短跳转，-128~+127)
// AJMP addr11 (2KB范围内)
// LJMP addr16 (64KB全范围)
```

#### 6.3 PHI节点处理

**目标**: 处理SSA的PHI节点（合并点）

**策略**: 在基本块开头插入MOV指令，从前驱块复制值

---

### 第七阶段：优化与完善

#### 7.1 窥孔优化

**修改文件**: [`c51_optimize.c`](src/core/c51/c51_optimize.c:3)

```c
// 模式1: MOV A, Rn / MOV Rn, A → 删除
// 模式2: MOV A, #0 / CLR A → 替换
// 模式3: ADD A, #0 → 删除
```

#### 7.2 死代码消除

**目标**: 删除未使用的指令

```c
// 1. 标记所有返回值和副作用指令为"有用"
// 2. 向后传播，标记依赖的指令
// 3. 删除未标记的指令
```

#### 7.3 HEX输出

**修改文件**: [`c51_output.c`](src/core/c51/c51_output.c:8)

**Intel HEX格式**:
```
:BBAAAATTDDDD...DDCC
BB=字节数, AAAA=地址, TT=记录类型, DD=数据, CC=校验和
```

---

## 总结
