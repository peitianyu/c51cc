# c251 32 位 (long) 全链路支持设计

> 2026-08-18. 目标: 消除 "long 是 16 位假象" — 让 32 位运算/比较/传参/存储真正按 32 位执行。

## 现状根因

- `c251_isel.c value_size_of`: `t->size > 1 ? 2 : 1` 把所有值钳到 16 位 → 32 位运算全按低 16 位做
- `abi_param_reg`: u32 返回 -2 (注释 "M3 支持" 是死代码, sz 永不超过 2)
- lexer `read_number`: `long ival` 32 位溢出 → `0x80000000` 变 "-2147483648" → "Malformed number"
- parser 字面量定型: `val >= 32768 → unsigned int (16 位)` 对 0x10000-0x7FFFFFFF 截断 (应为 long)
- sim251 `mcs251_addw/subw/shiftw/logicw_flags`: N/CY/OV/Z 按 16 位算 (bit15/bit16/low16), dword 运算需 32 位语义
- 编码器无 DRk dword ALU 形态

## 方案: DRk dword 寄存器路径 (Keil 同款)

### 寄存器模型
- DRk = WRk:WR(k+2) 对 (DR0=WR0+WR2, DR4=WR4+WR6, DR8=WR8+WR10, DR12=WR12+WR14)
- 大端: DRk 高字 = WRk, 低字 = WR(k+2) (与内存布局一致: sym[0]=MSB)
- 32 位值占用 reg_val[k/2] 和 reg_val[(k+2)/2] 两个槽, value_to_reg 存 k (DR 基 WR 索引)
- 16 位分配避让: 目标槽的 partner 若被 32 位值占用则不可用 (reg_val[w^2]==reg_val[w] 且值宽 4)

### 指令 (编码器新增, sim251 已支持)
| 指令 | 编码 | 用途 |
|------|------|------|
| ADD DRk,DRk | 2F (k1/4)4\|(k2/4) | 32 位加 |
| SUB DRk,DRk | 9F | 32 位减 |
| ANL/ORL/XRL DRk,DRk | 5F/4F/6F | 32 位逻辑 |
| CMP DRk,DRk | BF | 32 位比较 |
| SLL/SRL/SRA DRk | 3E/1E/0E (k/4)C | 32 位移位 (1 位) |
| INC DRk | 0B (k/4)C | 32 位 INC (NEG 用) |

### 数据移动 (复用现有 16 位形态, 不新增编码)
- MOV DRk,DRk → 2× MOV WRj,WRk (7D)
- MOV DRk,#imm32 → 2× MOV WRj,#imm16 (7E 4)
- MOV DRk,SYM → 2× MOV WRj,dir16 (7E 7, sym / (sym+2))
- 间接 32 位读写 → 2× 16 位 @WRj 与 @WRj+dis16 (09/19/49/59)
- spill 32 位 → 4 字节槽 (槽权威模型下跨块值落槽)

### 运算降级
- MUL (32×32→低32): t = aL*bL + ((aL*bH + aH*bL) << 16) — 3× 16 位 MUL + 32 位 ADD
- DIV/MOD (32): 内联移位-减法循环 (硬件 DIV 仅 16 位); 有符号按 C99 截断向零
- NEG: XRL 两字 #FFFF + INC DRk
- NOT: XRL 两字 #FFFF

### 比较标志 (sim251 修复)
- dword CMP/ADD/SUB: CY=bit31 借位/进位, OV=32 位符号溢出, N=bit31, Z=全 32 位零
- shift/logic dword: N=bit31, Z=全 32 位

### ABI
- 参数: u32 → {DR4, DR0} (与 u16 WR6/WR4 有重叠, 按声明序消费)
- 返回: u32 → DR4 (低字在 WR6, 与 u16 返回一致)

### 前端修复
- lexer: ival 用 long long 累积, %lld 输出
- parser 字面量定型: 0x8000-0xFFFF → unsigned int; 0x10000-0x7FFFFFFF → long;
  0x80000000-0xFFFFFFFF → unsigned long; >32 位 → long 截断 (long long=long 既定决策)

## 测试计划 (test/suite)
- 103_long_basic: long 全局/局部/常量/加减
- 104_long_mul: 32 位乘法
- 105_long_div: 32 位除/模 (有符号/无符号)
- 106_long_cmp: 32 位比较 (EQ/NE/LT/GT/LE/GE, 有符号/无符号)
- 107_long_shift: 32 位移位
- 108_long_conv: int→long / long→int / 32 位常量
- 109_long_param: long 参数与返回
- 110_long_array: long 数组/指针
- 111_ulong_ops: unsigned long (0x80000000 类字面量)

## 验收
- 新测试全绿 + 既有 Suite 102 + Execute 106 全绿
