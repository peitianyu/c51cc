# C51 汇编层优化（参考 Keil C51）

## 1. 寄存器优化

### 1.1 寄存器变量分配
```c
// C代码
void test() {
    int a;  // 尽量分配到寄存器
    a = 10;
}

// 优化前
    MOV 0x20, #10    ; 内存访问

// 优化后  
    MOV R0, #10      ; 寄存器访问，更快
```

### 1.2 工作寄存器组切换
```asm
; 使用 USING 指令切换寄存器组
    USING 1          ; 切换到寄存器组1
    ...              ; 使用 R0-R7（实际是08H-0FH）
    USING 0          ; 恢复寄存器组0
```

## 2. 窥孔优化 (Peephole Optimization)

### 2.1 冗余 MOV 消除
```asm
; 优化前
    MOV A, R0
    MOV R1, A
    MOV A, R1    ; 冗余，A 已经是 R0 的值

; 优化后
    MOV A, R0
    MOV R1, A
```

### 2.2 连续 PUSH/POP 优化
```asm
; 优化前
    PUSH ACC
    PUSH B
    PUSH ACC     ; 重复保存
    POP ACC
    POP B
    POP ACC

; 优化后
    PUSH ACC
    PUSH B
    POP B
    POP ACC
```

### 2.3 跳转优化
```asm
; 优化前
    LJMP label   ; 长跳转 (3字节)
    
; 优化后（如果在2KB范围内）
    AJMP label   ; 绝对跳转 (2字节)
    ; 或
    SJMP label   ; 短跳转 (2字节, -128~+127)
```

### 2.4 条件跳转优化
```asm
; 优化前
    CJNE A, #0, L1
    MOV A, #1
    SJMP L2
L1: MOV A, #0
L2:

; 优化后
    MOV C, ACC.0   ; 或直接使用布尔累加器
```

## 3. 指令选择优化

### 3.1 立即数操作
```asm
; 优化前
    MOV A, R0
    ADD A, #1

; 优化后（如果支持）
    INC R0         ; 直接递增
```

### 3.2 间接寻址优化
```asm
; 优化前 - 数组访问
    MOV A, index
    ADD A, #array
    MOV R0, A
    MOV A, @R0

; 优化后 - 使用 DPTR
    MOV DPTR, #array
    MOV A, index
    MOVC A, @A+DPTR
```

## 4. 常量优化

### 4.1 立即数加载优化
```asm
; 优化前
    MOV A, #0

; 优化后
    CLR A          ; 单字节指令
```

### 4.2 字节清零优化
```asm
; 优化前
    MOV 0x20, #0
    MOV 0x21, #0

; 优化后（成对清零）
    CLR A
    MOV 0x20, A
    MOV 0x21, A
```

## 5. 循环优化

### 5.1 循环展开
```c
// C代码
for (i = 0; i < 4; i++) {
    sum += arr[i];
}

// 优化后 - 完全展开
    MOV A, arr+0
    ADD A, arr+1
    ADD A, arr+2
    ADD A, arr+3
    MOV sum, A
```

### 5.2 递减循环（避免比较）
```asm
; 优化前 - 递增循环
    MOV R0, #0
loop:
    INC R0
    CJNE R0, #10, loop

; 优化后 - 递减循环
    MOV R0, #10
loop:
    DJNZ R0, loop    ; 自动减1并跳转
```

## 6. 函数调用优化

### 6.1 寄存器参数传递
```asm
; 优化前 - 栈传递
    PUSH param1
    PUSH param2
    LCALL func
    POP param2
    POP param1

; 优化后 - 寄存器传递
    MOV R0, param1
    MOV R1, param2
    LCALL func       ; 函数内直接使用 R0, R1
```

### 6.2 叶子函数优化
```asm
; 叶子函数（不调用其他函数）可以省略部分保存
    ; 不需要 PUSH/POP 所有寄存器
    ; 只保存实际使用的寄存器
```

## 7. 位操作优化

### 7.1 布尔变量优化
```asm
; C: if (flag) ...

; 优化前
    MOV A, flag
    JNZ label

; 优化后（flag 分配在位寻址区）
    JB flag_bit, label
```

### 7.2 位测试优化
```asm
; 优化前
    MOV A, var
    ANL A, #0x01
    JNZ bit_set

; 优化后
    JB var.0, bit_set
```

## 8. 存储优化

### 8.1 内存布局优化
- 频繁访问的变量放在直接寻址区（00H-7FH）
- 不频繁访问的变量放在间接寻址区

### 8.2 变量合并
```c
// 如果 a 和 b 生命周期不重叠
int a;  // 使用 0x20
...     // a 不再使用
int b;  // 也可以复用 0x20
```

## 9. 实现框架

```c
// c51_opt.c - C51 汇编优化器

// 窥孔优化模式
typedef struct PeepholePattern {
    const char *pattern[4];    // 输入指令模式（支持通配符）
    const char *replacement[4]; // 替换指令
    bool (*condition)(...);     // 额外条件检查
} PeepholePattern;

// 优化 Pass
void c51_opt_peephole(List *instrs);
void c51_opt_registers(Func *f);
void c51_opt_jumps(Func *f);
void c51_opt_loops(Func *f);

// 示例：窥孔优化
static PeepholePattern patterns[] = {
    // 模式：MOV A, Rx; MOV Ry, A -> MOV Ry, Rx (如果 Ry != Rx)
    {
        .pattern = {"MOV A, R%d", "MOV R%d, A", NULL},
        .replacement = {"MOV R%d, R%d", NULL},
        .condition = check_reg_not_equal
    },
    // 模式：PUSH ACC; POP ACC -> 删除
    {
        .pattern = {"PUSH ACC", "POP ACC", NULL},
        .replacement = {NULL},  // 空表示删除
    },
    // 更多模式...
};
```

## 10. Keil C51 特定优化

### 10.1 OPTIMIZE 级别
- **SIZE**: 优先代码大小
- **SPEED**: 优先执行速度

### 10.2 关键字支持
```c
// 指定存储类型
idata int a;   // 内部 RAM 间接寻址
xdata int b;   // 外部 RAM
code char c;   // 代码区

// 指定寄存器
register int d; // 建议分配到寄存器

// 位变量
bit flag;      // 位寻址区
```

### 10.3 中断函数
```c
void timer_isr(void) interrupt 1 using 1 {
    // 自动保存/恢复寄存器组
    // 自动使用 RETI 返回
}
```

## 参考文档
- Keil Cx51 Compiler User's Guide
- 8051 指令集手册
- "The 8051 Microcontroller" by Kenneth Ayala

---

# 优化实现日志

## 2024-01-27 已实现优化

### 1. 立即数加载优化 ✅
**文件**: [`c51gen.c`](src/core/c51gen.c:209)

```c
// MOV A, #0 -> CLR A
static bool try_optimize_load_imm(char *buf, size_t size, int val) {
    if (val == 0) {
        snprintf(buf, size, "    CLR A");
        return true;
    }
    ...
}
```

**效果**:
```asm
; 优化前
MOV A, #0       ; 2字节

; 优化后
CLR A           ; 1字节，节省1字节
```

**测试验证**: `test_sum_n` 函数中 `CLR A` 正确生成

---

### 2. 函数入口/出口优化 ✅
**文件**: [`c51gen.c`](src/core/c51gen.c:536)

**变更**: 普通函数不再自动保存 ACC, B, R0-R3
- 仅中断服务程序(ISR)需要保存寄存器
- 符合 C51 编程惯例，由程序员自行管理寄存器

**效果**:
```asm
; 优化前
PUSH ACC
PUSH B
PUSH R0
PUSH R1
...
POP R1
POP R0
POP B
POP ACC
RET

; 优化后
RET             ; 直接返回
```

---

### 3. 常量扫描框架 ✅
**文件**: [`c51gen.c`](src/core/c51gen.c:257)

```c
static int64_t *vreg_const_values = NULL;

static void scan_const_values(Func *f) {
    // 扫描函数中的所有 CONST 指令
    // 建立 vreg -> 常量值 映射
}

static bool is_imm_value(C51Gen *gen, ValueName vreg, int64_t val) {
    // 检查虚拟寄存器是否为特定立即数
}
```

为后续优化（INC/DEC 代替 ADD/SUB #1）提供基础设施。

---

### 4. 冗余 MOV 消除框架 ✅
**文件**: [`c51gen.c`](src/core/c51gen.c:295)

```c
static ValueName last_stored_vreg = -1;

static void emit_store_vreg(C51Gen *gen, ValueName vreg) {
    ...
    last_stored_vreg = vreg;  // 跟踪最后存储
}

static void emit_binary_op(...) {
    // 如果左操作数刚被存储，避免重复加载
    if (last_stored_vreg == lhs) {
        // A 中已包含值
    } else {
        emit_load_vreg(gen, lhs);
    }
}
```

---

## 待实现优化

### 1. 立即数运算优化 🔧
```asm
; 当前
MOV A, #1
MOV 0x42, A
MOV A, 0x3A
ADD A, 0x42

; 优化为
MOV A, 0x3A
ADD A, #1       ; ADD A, #data 是合法指令
```

### 2. INC/DEC 优化 🔧
```asm
; x + 1 -> INC A
; x - 1 -> DEC A
; 比 ADD/SUB 更快（1周期 vs 2周期）
```

### 3. 比较跳转链优化 🔧
```asm
; 消除中间布尔值转换
; 当前：比较 -> 生成0/1 -> 再测试
; 优化：比较后直接跳转
```

### 4. 跳转范围优化 🔧
```asm
LJMP label  ->  SJMP label  (如果距离 < 128字节)
```

### 5. 窥孔优化 🔧
```asm
; 模式匹配替换
MOV A, R0
MOV R0, A       ; 刚存储又加载，删除

MOV A, A        ; 无意义，删除
```

---

## 性能对比

| 优化项 | 优化前大小 | 优化后大小 | 节省 |
|--------|-----------|-----------|------|
| CLR A 代替 MOV A,#0 | 2字节 | 1字节 | 50% |
| 移除寄存器保存 | 8+ 指令 | 0 指令 | 100% |
| 函数出口简化 | 5+ 指令 | 1 指令 | 80% |

测试文件: [`test/test_c51.c`](src/test/test_c51.c) - 13个测试函数全部通过
