# C51Gen 汇编缓冲区设计

## 目标
将汇编指令从直接打印改为存储在内存中，支持最后统一转换（输出汇编或带链接器信息的hex）。

## 核心设计

### 1. 指令表示

```c
// 操作数类型
typedef enum {
    OP_NONE,
    OP_REG,      // 寄存器: A, B, R0-R7, DPTR, SP, C
    OP_IMM,      // 立即数: #value
    OP_DIRECT,   // 直接地址: 0x20, var
    OP_INDIRECT, // 间接寻址: @R0, @R1, @DPTR
    OP_LABEL,    // 标签引用
} AsmOperandType;

// 操作数
typedef struct {
    AsmOperandType type;
    union {
        int reg;        // 寄存器编号
        int imm;        // 立即数值
        int addr;       // 直接地址
        char *label;    // 标签名 (动态分配)
    };
} AsmOperand;

// 汇编指令类型
typedef enum {
    A_MOV, A_ADD, A_SUB, A_MUL, A_DIV,
    A_INC, A_DEC, A_ANL, A_ORL, A_XRL,
    A_CLR, A_CPL, A_RL, A_RR, A_RLC, A_RRC,
    A_SETB, A_JZ, A_JNZ, A_JC, A_JNC,
    A_JB, A_JNB, A_SJMP, A_AJMP, A_LJMP,
    A_LCALL, A_RET, A_RETI,
    A_PUSH, A_POP, A_NOP,
    // 伪指令
    A_LABEL,      // 标签定义
    A_COMMENT,    // 纯注释行
    A_DIRECTIVE,  // 汇编伪指令
    A_RAW,        // 原始文本（备用）
} AsmOp;

// 单条汇编指令
typedef struct AsmLine {
    AsmOp op;
    AsmOperand dst;
    AsmOperand src1;
    AsmOperand src2;
    
    char *comment;    // 可选注释
    char *raw_text;   // 对于DIRECTIVE/RAW，原始文本
    
    int addr;         // 生成的地址（用于链接/优化）
    int size;         // 指令字节大小
    
    struct AsmLine *next;
} AsmLine;
```

### 2. 汇编缓冲区

```c
typedef struct AsmBuffer {
    AsmLine *head;
    AsmLine *tail;
    int count;
    int cur_addr;     // 当前地址计数器
    
    // 符号表（标签 -> 地址）
    struct {
        char *name;
        int addr;
        AsmLine *line;
    } *symbols;
    int sym_count;
    int sym_cap;
} AsmBuffer;
```

### 3. API 设计

```c
// 缓冲区管理
AsmBuffer* asm_buffer_create(void);
void asm_buffer_free(AsmBuffer *buf);
void asm_buffer_clear(AsmBuffer *buf);

// 指令添加（类型化接口）
void asm_emit(AsmBuffer *buf, AsmOp op, ...);  // 变参接口
void asm_emit_mov(AsmBuffer *buf, AsmOperand dst, AsmOperand src);
void asm_emit_alu(AsmBuffer *buf, AsmOp op, AsmOperand dst, AsmOperand src);
void asm_emit_jump(AsmBuffer *buf, AsmOp op, const char *label);
void asm_emit_label(AsmBuffer *buf, const char *name);
void asm_emit_comment(AsmBuffer *buf, const char *fmt, ...);
void asm_emit_directive(AsmBuffer *buf, const char *text);

// 操作数构造
AsmOperand op_reg(int reg);
AsmOperand op_imm(int val);
AsmOperand op_direct(int addr);
AsmOperand op_label(const char *name);
AsmOperand op_none(void);

// 输出格式
void asm_print(AsmBuffer *buf, FILE *fp);           // 输出汇编
void asm_print_hex(AsmBuffer *buf, FILE *fp);       // 输出Intel HEX
void asm_print_obj(AsmBuffer *buf, FILE *fp);       // 输出目标文件格式
```

### 4. 寄存器编号定义

```c
#define REG_A     0
#define REG_B     1
#define REG_R0    2
#define REG_R1    3
#define REG_R2    4
#define REG_R3    5
#define REG_R4    6
#define REG_R5    7
#define REG_R6    8
#define REG_R7    9
#define REG_DPTR  10
#define REG_SP    11
#define REG_C     12  // 进位标志
```

### 5. 使用示例

```c
// 替换前（直接输出）:
emit(gen, "    MOV A, #0x%02X", val);
emit(gen, "    ADD A, %s", rhs_loc);
emit(gen, "    MOV %s, A", dst_loc);

// 替换后（存储到缓冲区）:
asm_emit_mov(buf, op_reg(REG_A), op_imm(val));
asm_emit_alu(buf, A_ADD, op_reg(REG_A), op_reg(rhs_reg));
asm_emit_mov(buf, op_direct(dst_addr), op_reg(REG_A));

// 最后统一输出:
asm_print(buf, fp);  // 或者 asm_print_hex(buf, fp);
```

### 6. 输出格式

#### 汇编格式 (asm_print)
```asm
; C51 Assembly Generated from SSA IR
    ORG 0000H
    LJMP main

; Function: main
    PUBLIC main
main PROC
    MOV A, #0x05
    ADD A, R0
    MOV 0x20, A
    RET
main ENDP
    END
```

#### Intel HEX 格式 (asm_print_hex)
```
:03000000020006F4
:03000600758205F2
:03000900752800E5
:03000C00A32800C4
:03000F00120015C6
:03001200852800AC
:0300150022D8
:00000001FF
```

#### 目标文件格式 (asm_print_obj) - 带链接信息
```
MAZUOBJ1                    ; 文件头
SYMBOLS                     ; 符号表
  main  0x0006  GLOBAL
  _add  0x0015  GLOBAL
RELOCS                      ; 重定位表
  0x0001  main  16bit      ; LJMP main
  0x0010  _add  16bit      ; LCALL _add
CODE                        ; 代码段
  [binary data]
END
```

### 7. 地址计算

```c
// 为每条指令计算地址和大小（用于跳转优化）
void asm_calc_addresses(AsmBuffer *buf) {
    int addr = 0;
    for (AsmLine *line = buf->head; line; line = line->next) {
        line->addr = addr;
        line->size = calc_insn_size(line);  // 根据指令类型计算
        addr += line->size;
    }
}

// 8051指令大小表
static int insn_size_table[] = {
    [A_MOV] = 2,    // MOV A, #imm (2字节) 或 MOV direct, A (2字节)
    [A_ADD] = 1,    // ADD A, Rn (1字节)
    [A_LJMP] = 3,   // LJMP addr16 (3字节)
    [A_SJMP] = 2,   // SJMP rel (2字节)
    // ...
};
```

### 8. 跳转优化

```c
// 在输出前优化跳转指令
void asm_optimize_jumps(AsmBuffer *buf) {
    asm_calc_addresses(buf);
    
    for (AsmLine *line = buf->head; line; line = line->next) {
        if (line->op == A_LJMP && line->src1.type == OP_LABEL) {
            int target = find_symbol_addr(buf, line->src1.label);
            int offset = target - (line->addr + 2);  // SJMP是2字节
            
            if (offset >= -128 && offset <= 127) {
                line->op = A_SJMP;  // 优化为短跳转
                line->size = 2;
            }
        }
    }
}
```

### 9. 集成到 c51gen.c

```c
// C51Gen 结构修改
typedef struct {
    AsmBuffer *buf;     // 替代 FILE *fp
    Func *cur_func;
    StackFrame frame;
    int *vreg_map;
    int vreg_map_size;
    int temp_count;
    int label_count;
} C51Gen;

// 修改 emit 系列函数
static void emit(C51Gen *gen, AsmOp op, ...) {
    va_list args;
    va_start(args, op);
    
    AsmOperand dst = op_none();
    AsmOperand src1 = op_none();
    AsmOperand src2 = op_none();
    
    switch (op) {
    case A_MOV:
        dst = va_arg(args, AsmOperand);
        src1 = va_arg(args, AsmOperand);
        asm_emit_mov(gen->buf, dst, src1);
        break;
    case A_ADD: case A_SUB: case A_ANL: case A_ORL: case A_XRL:
        dst = va_arg(args, AsmOperand);
        src1 = va_arg(args, AsmOperand);
        asm_emit_alu(gen->buf, op, dst, src1);
        break;
    // ... 其他指令
    }
    
    va_end(args);
}
```

## 优势

1. **延迟输出**: 指令生成和输出格式完全分离
2. **优化机会**: 可以在输出前进行窥孔优化、跳转优化
3. **多格式支持**: 同一缓冲区可输出为 ASM、HEX、OBJ 等多种格式
4. **链接支持**: 符号表和重定位信息支持模块化编译和链接
5. **调试友好**: 保留源文件行号、注释等调试信息

## 实现优先级

1. **P0**: 基础 AsmBuffer 结构和指令添加
2. **P1**: 汇编格式输出 (asm_print)
3. **P2**: Intel HEX 格式输出
4. **P3**: 跳转优化 (LJMP -> SJMP)
5. **P4**: 目标文件格式和链接器支持
