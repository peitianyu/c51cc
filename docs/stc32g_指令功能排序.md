 
此版本严格遵循原文所有表格、注释和分类，并对带颜色标记的指令（参考机器码表）用 **🔴（BINARY专用）** 和 **🔵（SOURCE专用）** 进行了额外标注（由于功能表中未直接标色，我根据机器码表补充了说明），方便你在 STC32G（SOURCE 模式）下快速识别。

---

# STC32G 指令集（功能排序）

> **说明**  
> - 执行总时间 = 表中时钟数 + nrPRGACS×WTST + nrXDMACS×CKCON（详见原文）  
> - **🔴 红色** = BINARY 模式专用（STC32G 下需加 `0xA5` 前缀）  
> - **🔵 蓝色** = SOURCE 模式专用（STC32G 下直接使用）  
> - **无标记** = 通用指令（两种模式均可用）

---

## 1. 算术运算

| 助记符 | 描述 | 编码 | 字节 | 时钟数 |
|:---|:---|:---|:---:|---:|
| ADD A, Rn | 将寄存器加到累加器 | 0x28-0x2F 🔴 | 1 | 2 |
| ADD A, dir8 | 将直接字节加到累加器 | 0x25 | 2 | 1 |
| ADD A, @Ri | 将间接内存加到累加器 | 0x26-0x27 🔴 | 1 | 2 |
| ADD A, #data | 将立即数加到累加器 | 0x24 | 2 | 1 |
| **ADD Rm, Rm** 🔵 | 将字节寄存器加到字节寄存器 | 0x2C | 2 | 1 |
| **ADD WRj, WRj** 🔵 | 将字寄存器加到字寄存器 | 0x2D | 2 | 1 |
| **ADD reg, op2** 🔵 | 将操作数加到 Rm、WRj 或 DRk | 0x2E | 注1 | 注2 |
| **ADD DRk, DRk** 🔵 | 将双字寄存器加到双字寄存器 | 0x2F | 2 | 1 |
| ADDC A, Rn | 将寄存器加到带进位标志的累加器 | 0x38-0x3F 🔴 | 1 | 2 |
| ADDC A, dir8 | 将直接字节加到带进位标志的累加器 A | 0x35 | 2 | 1 |
| ADDC A, @Ri | 将间接内存加到带进位标志的累加器 A | 0x36-0x37 🔴 | 1 | 2 |
| ADDC A, #data | 将立即数加到带进位标志的累加器 A | 0x34 | 2 | 1 |
| SUBB A, Rn | 从 A 借位再减去寄存器 | 0x98-0x9F 🔴 | 1 | 2 |
| SUBB A, dir8 | 从 A 借位再减去直接字节 | 0x95 | 2 | 1 |
| SUBB A, @Ri | 从 A 借位再减去间接内存 | 0x96-0x97 🔴 | 1 | 2 |
| SUBB A, #data | 从 A 借位再减去立即数 | 0x94 | 2 | 1 |
| **SUB Rm, Rm** 🔵 | 从字节寄存器中减去字节寄存器 | 0x9C | 2 | 1 |
| **SUB WRj, WRj** 🔵 | 从字寄存器中减去字寄存器 | 0x9D | 2 | 1 |
| **SUB reg, op2** 🔵 | 从 Rm、WRj 或 DRk 中减去操作数 | 0x9E | 注1 | 注2 |
| **SUB DRk, DRk** 🔵 | 从双字寄存器中减去双字寄存器 | 0x9F | 2 | 1 |
| **CMP Rm, Rm** 🔵 | 比较两个字节寄存器 | 0xBC | 2 | 1 |
| **CMP WRj, WRj** 🔵 | 比较两个字寄存器 | 0xBD | 2 | 1 |
| **CMP reg, op2** 🔵 | 将 Rm、WRj 或 DRk 与操作数比较 | 0xBE | 注1 | 注2 |
| **CMP DRk, DRk** 🔵 | 比较两个双字寄存器 | 0xBF | 2 | 1 |
| INC A | 递增累加器 | 0x04 | 1 | 1 |
| INC Rn | 递增寄存器 | 0x08-0x0F 🔴 | 1 | 2 |
| INC dir8 | 递增直接字节 | 0x05 | 2 | 1 |
| INC @Ri | 递增间接内存 | 0x06-0x07 🔴 | 1 | 2 |
| **INC reg, #short** 🔵 | 递增 Rm、WRj 或 DRk | 0x0B | 2 | 注2 |
| DEC A | 递减累加器 | 0x14 | 1 | 1 |
| DEC Rn | 递减寄存器 | 0x18-0x1F 🔴 | 1 | 2 |
| DEC dir8 | 递减直接字节 | 0x15 | 1 | 1 |
| DEC @Ri | 递减间接内存 | 0x16-0x17 🔴 | 1 | 2 |
| **DEC reg, #short** 🔵 | 递减 Rm、WRj 或 DRk | 0x1B | 2 | 注2 |
| INC DPTR | 递增数据指针 | 0xA3 | 1 | 1 |
| MUL A, B | 将 A 乘以 B | 0xA4 | 1 | 1 |
| **MUL Rm, Rm** 🔵 | 字节寄存器相乘 | 0xAC | 2 | 1 |
| **MUL WRj, WRj** 🔵 | 字寄存器相乘 | 0xAD | 2 | 1 |
| DIV A, B | 将 A 除以 B | 0x84 | 1 | 6 |
| **DIV Rm, Rm** 🔵 | 字节寄存器相除 | 0x8C | 2 | 6 |
| **DIV WRj, WRj** 🔵 | 字寄存器相除 | 0x8D | 2 | 10 |
| DA A | 十进制调整累加器 | 0xD4 | 1 | 3 |

> **注1**：指令字节数取决于紧接着的字节确定的寻址模式（详见指令集详解）。  
> **注2**：指令周期数取决于紧接着的字节确定的寻址模式（详见指令集详解）。

---

## 2. 逻辑运算

| 助记符 | 描述 | 编码 | 字节 | 时钟数 |
|:---|:---|:---|:---:|---:|
| ANL A, Rn | 寄存器逻辑与累加器 | 0x58-0x5F 🔴 | 1 | 2 |
| ANL A, dir8 | 直接字节逻辑与累加器 | 0x55 | 2 | 1 |
| ANL A, @Ri | 间接内存逻辑与累加器 | 0x56-0x57 🔴 | 1 | 2 |
| ANL A, #data | 立即数逻辑与累加器 | 0x54 | 2 | 1 |
| ANL dir8, A | 直接字节逻辑与累加器 | 0x52 | 2 | 1 |
| ANL dir8, #data | 直接数据逻辑与直接字节 | 0x53 | 3 | 1 |
| **ANL Rm, Rm** 🔵 | 两个字节寄存器逻辑与 | 0x5C | 2 | 1 |
| **ANL WRj, WRj** 🔵 | 两个字节寄存器逻辑与 | 0x5D | 2 | 1 |
| **ANL reg, op2** 🔵 | 操作数逻辑与 Rm、WRj 或 DRk | 0x5E | 注1 | 注2 |
| ORL A, Rn | 寄存器逻辑或累加器 | 0x48-0x4F 🔴 | 1 | 2 |
| ORL A, dir8 | 直接字节逻辑或累加器 | 0x45 | 2 | 1 |
| ORL A, @Ri | 间接内存逻辑或累加器 | 0x46-0x47 🔴 | 1 | 2 |
| ORL A, #data | 立即数逻辑或累加器 | 0x44 | 2 | 1 |
| ORL dir8, A | 累加器直接字节 | 0x42 | 2 | 1 |
| ORL dir8, #data | 立即数逻辑或直接字节 | 0x43 | 3 | 1 |
| **ORL Rm, Rm** 🔵 | 两个字节寄存器逻辑或 | 0x4C | 2 | 1 |
| **ORL WRj, WRj** 🔵 | 两个字节寄存器逻辑或 | 0x4D | 2 | 1 |
| **ORL reg, op2** 🔵 | 操作数逻辑或 Rm、WRj 或 DRk | 0x4E | 注1 | 注2 |
| XRL A, Rn | 寄存器异或累加器 | 0x68-0x6F 🔴 | 1 | 2 |
| XRL A, dir8 | 直接字节异或累加器 | 0x65 | 2 | 1 |
| XRL A, @Ri | 间接内存异或累加器 | 0x66-0x67 🔴 | 1 | 2 |
| XRL A, #data | 立即数异或累加器 | 0x64 | 2 | 1 |
| XRL dir8, A | 直接字节异或累加器 | 0x62 | 2 | 1 |
| XRL dir8, #data | 立即数异或直接字节 | 0x63 | 3 | 1 |
| **XRL Rm, Rm** 🔵 | 两个字节寄存器异或 | 0x6C | 2 | 1 |
| **XRL WRj, WRj** 🔵 | 两个字节寄存器异或 | 0x6D | 2 | 1 |
| **XRL reg, op2** 🔵 | 操作数异或 Rm、WRj 或 DRk | 0x6E | 注1 | 注2 |
| CLR A | 累加器清零 | 0xE4 | 1 | 1 |
| CPL A | 累加器取反 | 0xF4 | 1 | 1 |
| RL A | 累加器向左循环移动 | 0x23 | 1 | 1 |
| RLC A | 累加器带进位向左循环移动 | 0x33 | 1 | 1 |
| RR A | 累加器向右循环移动 | 0x03 | 1 | 1 |
| RRC A | 累加器带进位向右循环移动 | 0x13 | 1 | 1 |
| **SRA reg** 🔵 | 通过 MSB 右移 Rm 或 WRj | 0x0E | 2 | 1 |
| **SRL reg** 🔵 | 右移 Rm 或 WRj | 0x1E | 2 | 1 |
| **SLL reg** 🔵 | 左移 Rm 或 WRj | 0x3E | 2 | 1 |
| SWAP A | 累加器内交换半字节 | 0xC4 | 1 | 1 |

---

## 3. 布尔操作

| 助记符 | 描述 | 编码 | 字节 | 时钟数 |
|:---|:---|:---|:---:|---:|
| CLR C | 进位标志位清零 | 0xC3 | 1 | 1 |
| CLR bit | 直接位清零 | 0xC2 | 2 | 1 |
| SETB C | 进位标志位置位 | 0xD3 | 1 | 1 |
| SETB bit | 直接位置位 | 0xD2 | 2 | 1 |
| CPL C | 进位标志位取反 | 0xB3 | 1 | 1 |
| CPL bit | 直接位取反 | 0xB2 | 2 | 1 |
| ANL C, bit | 直接位逻辑与进位标志位 | 0x82 | 2 | 1 |
| ANL C, /bit | 直接位的非逻辑与进位标志位 | 0xB0 | 2 | 1 |
| ORL C, bit | 直接位逻辑或进位标志位 | 0x72 | 2 | 1 |
| ORL C, /bit | 直接位的非逻辑或进位标志位 | 0xA0 | 2 | 1 |
| MOV C, bit | 直接位搬运到进位标志位 | 0xA2 | 2 | 1 |
| MOV bit, C | 进位标志位搬运到直接位 | 0x92 | 2 | 1 |
| **Bit instr** 🔵 | 位指令集（MCU251 特有） | 0xA9 | 3 | 1 |

---

## 4. 数据传输

| 助记符 | 描述 | 编码 | 字节 | 时钟数 |
|:---|:---|:---|:---:|---:|
| MOV A, Rn | 将寄存器搬运到累加器 | 0xE8-0xEF 🔴 | 1 | 2 |
| MOV A, dir8 | 将直接字节搬运到累加器 | 0xE5 | 2 | 1 |
| MOV A, @Ri | 将间接内存搬运到累加器 | 0xE6-0xE7 🔴 | 1 | 2 |
| MOV A, #data | 将立即数据搬运到累加器 | 0x74 | 2 | 1 |
| MOV Rn, A | 将累加器搬运到寄存器 | 0xF8-0xFE 🔴 | 1 | 2 |
| MOV Rn, dir8 | 将直接字节搬运到寄存器 | 0xA8-0xAF 🔴 | 2 | 1 |
| MOV Rn, #data | 将立即数据搬运到寄存器 | 0x78-0x7F 🔴 | 2 | 1 |
| MOV dir8, A | 将累加器搬运到直接字节 | 0xF5 | 2 | 1 |
| MOV dir8, Rn | 将寄存器搬运到直接字节 | 0x88-0x8F 🔴 | 2 | 1 |
| MOV dir8, dir8 | 将直接字节搬运到直接字节 | 0x85 | 3 | 1 |
| MOV dir8, @Ri | 将间接内存搬运到直接字节 | 0x86-0x87 🔴 | 2 | 2 |
| MOV dir8, #data | 将立即数据搬运到直接字节 | 0x75 | 3 | 1 |
| MOV @Ri, A | 将累加器搬运到间接内存 | 0xF6-0xF7 🔴 | 1 | 2 |
| MOV @Ri, dir8 | 将直接字节搬运到间接内存 | 0xA6-0xA7 🔴 | 2 | 2 |
| MOV @Ri, #data | 将立即数据搬运到间接内存 | 0x76-0x77 🔴 | 2 | 2 |
| **MOV Rm, Rm** 🔵 | 将字节寄存器搬运到字节寄存器 | 0x7C | 2 | 1 |
| **MOV WRj, WRj** 🔵 | 将字寄存器搬运到字寄存器 | 0x7D | 2 | 1 |
| **MOV reg, op2** 🔵 | 将操作数据搬运到 Rm、WRj 或 DRk | 0x7E | 注1 | 注2 |
| **MOV DRk, DRk** 🔵 | 将双字寄存器搬运到双字寄存器 | 0x7F | 2 | 1 |
| **MOV WRj, @DRk** 🔵 | 将间接（24位）内存搬运到 WRj | 0x0B | 3 | 1 |
| **MOV @DRk, WRj** 🔵 | 将 WRj 搬运到间接（24位）内存 | 0x1B | 3 | 1 |
| **MOV Rm, @WRj+dis** 🔵 | 将16位偏移的间接（16位）内存搬运到 Rm | 0x09 | 4 | 1 |
| **MOV @WRj+dis, Rm** 🔵 | 将 Rm 搬运到16位偏移的间接（16位）内存 | 0x19 | 4 | 1 |
| **MOV Rm, @DRk+dis** 🔵 | 将16位偏移的间接（24位）内存搬运到 Rm | 0x29 | 4 | 1 |
| **MOV @DRk+dis, Rm** 🔵 | 将 Rm 搬运到16位偏移的间接（24位）内存 | 0x39 | 4 | 1 |
| **MOV WRj, @WRj+dis** 🔵 | 将16位偏移的间接（16位）内存搬运到 WRj | 0x49 | 4 | 1 |
| **MOV @WRj+dis, WRj** 🔵 | 将 WRj 搬运到16位偏移的间接（16位）内存 | 0x59 | 4 | 1 |
| **MOV WRj, @DRk+dis** 🔵 | 将16位偏移的间接（24位）内存搬运到 WRj | 0x69 | 4 | 1 |
| **MOV @DRk+dis, WRj** 🔵 | 将 WRj 搬运到16位偏移的间接（24位）内存 | 0x79 | 4 | 1 |
| **MOV op1, reg** 🔵 | 将 Rm、WRj 或 DRk 搬运到操作数 | 0x7A | 注1 | 注2 |
| **MOVH DRk, #data16** 🔵 | 将16位立即数据搬运到双字寄存器的高位字 | 0x7A | 4 | 1 |
| **MOVZ WRj, Rm** 🔵 | 将字节寄存器搬运到零扩展的字节寄存器 | 0x0A | 2 | 1 |
| **MOVS WRj, Rm** 🔵 | 将字节寄存器搬运到带符号扩展的字符寄存器 | 0x1A | 2 | 1 |
| MOV DPTR, #data16 | 将16位常数加载到活动的 DPTR | 0x90 | 3 | 1 |
| MOVC A, @A+DPTR | 将代码字节搬运到 DPTR 偏移的累加器 | 0x93 | 1 | 4 |
| MOVC A, @A+PC | 将代码字节搬运到 PC 偏移的累加器 | 0x83 | 1 | 3 |
| MOVX A, @Ri | 将外部存储器（8位地址）搬运到 A | 0xE2-0xE3 | 1 | 3 |
| MOVX A, @DPTR | 将外部存储器（16位地址）搬运到 A | 0xE0 | 1 | 3 |
| MOVX @Ri, A | 将 A 搬运到外部存储器（8位地址） | 0xF2-0xF3 | 1 | 2 |
| MOVX @DPTR, A | 将 A 搬运到外部存储器（16位地址） | 0xF0 | 1 | 2 |
| PUSH dir8 | 将直接字节压入 IDM 堆栈 | 0xC0 | 2 | 1 |
| POP dir8 | 从 IDM 堆栈中弹出直接字节 | 0xD0 | 2 | 1 |
| **PUSH op1** 🔵 | 将操作数压入 IDM 堆栈 | 0xCA | 注1 | 注2 |
| **POP op1** 🔵 | 从 IDM 堆栈弹出操作数 | 0xDA | 注1 | 注2 |
| XCH A, Rn | 寄存器跟累加器交换 | 0xC8-0xCF 🔴 | 1 | 2 |
| XCH A, dir8 | 直接字节跟累加器交换 | 0xC5 | 2 | 1 |
| XCH A, @Ri | 间接内存跟累加器交换 | 0xC6-0xC7 🔴 | 1 | 2 |
| XCHD A, @Ri | 间接内存的低位半字节跟 A 交换 | 0xD6-0xD7 🔴 | 1 | 2 |

---

## 5. 程序跳转

| 助记符 | 描述 | 编码 | 字节 | 时钟数 |
|:---|:---|:---|:---:|---:|
| ACALL addr11 | 绝对子程序调用 | 0x11-0xF1 | 2 | 3 |
| LCALL addr16 | 长子程序直接调用 | 0x12 | 3 | 3 |
| **ECALL addr24** 🔵 | 扩展子程序直接调用 | 0x9A | 4 | 3 |
| **ECALL @DRk** 🔵 | 扩展子程序间接调用 | 0x99 | 2 | 3 |
| **LCALL @WRj** 🔵 | 长子程序间接调用 | 0x99 | 2 | 3 |
| RET | 子程序返回 | 0x22 | 1 | 3 |
| **ERET** 🔵 | 扩展返回 | 0xAA | 1 | 3 |
| RETI | 中断返回 | 0x32 | 1 | 3 |
| AJMP addr11 | 绝对跳转 | 0x01-0xE1 | 2 | 3 |
| LJMP addr16 | 直接长跳转 | 0x02 | 3 | 3 |
| **EJMP addr24** 🔵 | 直接扩展跳转 | 0x8A | 4 | 3 |
| **LJMP @WRj** 🔵 | 间接长跳转 | 0x89 | 2 | 3 |
| **EJMP @DRk** 🔵 | 间接扩展跳转 | 0x89 | 2 | 3 |
| SJMP rel | 短跳转（相对地址） | 0x80 | 2 | 3 |
| JMP @A+DPTR | DPTR 偏移的间接跳转 | 0x73 | 1 | 3 |
| JZ rel | 如果累加器为零则跳转 | 0x60 | 2 | 1/3 |
| JNZ rel | 如果累加器不为零则跳转 | 0x70 | 2 | 1/3 |
| JC rel | 如果进位标志位置位则跳转 | 0x40 | 2 | 1/3 |
| JNC rel | 如果进位标志位未置位则跳转 | 0x50 | 2 | 1/3 |
| JB bit, rel | 如果直接位置位则跳转 | 0x20 | 3 | 1/3 |
| JNB bit, rel | 如果直接位未置位则跳转 | 0x30 | 3 | 1/3 |
| JBC bit, rel | 如果直接位置位则跳转并清零位 | 0x10 | 3 | 1/3 |
| **JSLE rel** 🔵 | 如果小于或等于则跳转（有符号） | 0x08 | 2 | 1/3 |
| **JSG rel** 🔵 | 如果大于则跳转（有符号） | 0x18 | 2 | 1/3 |
| **JLE rel** 🔵 | 如果小于或等于则跳转 | 0x28 | 2 | 1/3 |
| **JG rel** 🔵 | 如果大于则跳转 | 0x38 | 2 | 1/3 |
| **JSL rel** 🔵 | 如果小于则跳转（有符号） | 0x48 | 2 | 1/3 |
| **JSGE rel** 🔵 | 如果大于或等于则跳转（有符号） | 0x58 | 2 | 1/3 |
| **JE rel** 🔵 | 如果相等则跳转 | 0x68 | 2 | 1/3 |
| **JNE rel** 🔵 | 如果不相等则跳转 | 0x78 | 2 | 1/3 |
| CJNE A, dir8, rel | 将直接字节与 A 比较，不相等则跳转 | 0xB5 | 3 | 2/3 |
| CJNE A, #data, rel | 将立即数与 A 比较，不相等则跳转 | 0xB4 | 3 | 1/3 |
| CJNE Rn, #data, rel | 将立即数与寄存器比较，不相等则跳转 | 0xB8-0xBF 🔴 | 3 | 3/4 |
| CJNE @Ri, #data, rel | 将立即数与间接内存比较，不相等则跳转 | 0xB6-0xB7 🔴 | 3 | 3/4 |
| DJNZ Rn, rel | 寄存器递减，不为零则跳转 | 0xD8-0xDF 🔴 | 2 | 3/4 |
| DJNZ dir8, rel | 直接字节递减，不为零则跳转 | 0xD5 | 3 | 2/3 |
| NOP | 无操作 | 0x00 | 1 | 1 |



好的，我将 **STC32G 在 SOURCE 模式下完整的 0x00 ~ 0xFF 机器码映射表** 重新整理如下。  
此表将原表中所有 **“未定义”** 的位置，用 **对应 BINARY 模式下的 8051 指令（红色）** 补全，并明确标注颜色：

- **【通用】** – 黑色，两种模式直接可用  
- **【蓝色】** – SOURCE 专用指令，直接使用（推荐）  
- **【红色】** – BINARY 专用指令，在 SOURCE 模式下需加 `0xA5` 前缀才能执行

---

### 完整映射表（按操作码升序排列）

| 操作码 | 助记符 | 类型 |
|:---:|:---|:---:|
| 00H | NOP | 通用 |
| 01H | AJMP addr11 | 通用 |
| 02H | LJMP addr16 | 通用 |
| 03H | RR A | 通用 |
| 04H | INC A | 通用 |
| 05H | INC dir8 | 通用 |
| 06H | INC @R0 | - |
| 07H | INC @R1 | - |
| 08H | JSLE rel | 蓝色 |
| 09H | MOV Rm, @DRk+dis | 蓝色 |
| 0AH | MOVZ WRj, Rm | 蓝色 |
| 0BH | INC reg, #short | 蓝色 |
| 0CH | ADD Rm, Rm | 蓝色 |
| 0DH | ADD WRj, WRj | 蓝色 |
| 0EH | SRA reg | 蓝色 |
| 0FH | INC R7 | - |
| 10H | JBC bit, rel | 通用 |
| 11H | ACALL addr11 | 通用 |
| 12H | LCALL addr16 | 通用 |
| 13H | RRC A | 通用 |
| 14H | DEC A | 通用 |
| 15H | DEC dir8 | 通用 |
| 16H | DEC @R0 | - |
| 17H | DEC @R1 | - |
| 18H | JSG rel | 蓝色 |
| 19H | MOV @DRk+dis, Rm | 蓝色 |
| 1AH | MOVS WRj, Rm | 蓝色 |
| 1BH | DEC reg, #short | 蓝色 |
| 1CH | SUB Rm, Rm | 蓝色 |
| 1DH | SUB WRj, WRj | 蓝色 |
| 1EH | SRL reg | 蓝色 |
| 1FH | DEC R7 | - |
| 20H | JB bit, rel | 通用 |
| 21H | AJMP addr11 | 通用 |
| 22H | RET | 通用 |
| 23H | RLA | 通用 |
| 24H | ADD A, #data | 通用 |
| 25H | ADD A, direct | 通用 |
| 26H | ADD A, @R0 | - |
| 27H | ADD A, @R1 | - |
| 28H | JLE rel | 蓝色 |
| 29H | MOV Rm, @DRk+dis | 蓝色 |
| 2AH | ADD A, R2 | - |
| 2BH | ADD A, R3 | - |
| 2CH | ADD Rm, Rm | 蓝色 |
| 2DH | ADD WRj, WRj | 蓝色 |
| 2EH | ADD reg, op2 | 蓝色 |
| 2FH | ADD DRk, DRk | 蓝色 |
| 30H | JNB bit, rel | 通用 |
| 31H | ACALL addr11 | 通用 |
| 32H | RETI | 通用 |
| 33H | RLC A | 通用 |
| 34H | ADDC A, #data | 通用 |
| 35H | ADDC A, direct | 通用 |
| 36H | ADDC A, @R0 | - |
| 37H | ADDC A, @R1 | - |
| 38H | JG rel | 蓝色 |
| 39H | MOV @DRk+dis, Rm | 蓝色 |
| 3AH | ADDC A, R2 | - |
| 3BH | ADDC A, R3 | - |
| 3CH | ADDC A, R4 | - |
| 3DH | ADDC A, R5 | - |
| 3EH | SLL reg | 蓝色 |
| 3FH | ADDC A, R7 | - |
| 40H | JC rel | 通用 |
| 41H | AJMP addr11 | 通用 |
| 42H | ORL direct, A | 通用 |
| 43H | ORL direct, #data | 通用 |
| 44H | ORL A, #data | 通用 |
| 45H | ORL A, direct | 通用 |
| 46H | ORL A, @R0 | - |
| 47H | ORL A, @R1 | - |
| 48H | ORL A, R0 | 通用 |
| 49H | ORL A, R1 | 通用 |
| 4AH | ORL A, R2 | 通用 |
| 4BH | ORL A, R3 | 通用 |
| 4CH | ORL A, R4 | 通用 |
| 4DH | ORL A, R5 | 通用 |
| 4EH | ORL A, R6 | 通用 |
| 4FH | ORL A, R7 | 通用 |
| 50H | JNC rel | 通用 |
| 51H | AJMP addr11 | 通用 |
| 52H | ANL direct, A | 通用 |
| 53H | ANL direct, #data | 通用 |
| 54H | ANL A, #data | 通用 |
| 55H | ANL A, direct | 通用 |
| 56H | ANL A, @R0 | - |
| 57H | ANL A, @R1 | - |
| 58H | ANL A, R0 | 通用 |
| 59H | ANL A, R1 | 通用 |
| 5AH | ANL A, R2 | 通用 |
| 5BH | ANL A, R3 | 通用 |
| 5CH | ANL A, R4 | 通用 |
| 5DH | ANL A, R5 | 通用 |
| 5EH | ANL A, R6 | 通用 |
| 5FH | ANL A, R7 | 通用 |
| 60H | JZ rel | 通用 |
| 61H | AJMP addr11 | 通用 |
| 62H | XRL direct, A | 通用 |
| 63H | XRL direct, #data | 通用 |
| 64H | XRL A, #data | 通用 |
| 65H | XRL A, direct | 通用 |
| 66H | XRL A, @R0 | - |
| 67H | XRL A, @R1 | - |
| 68H | JE rel | 蓝色 |
| 69H | MOV WRj, @DRk+dis | 蓝色 |
| 6AH | –（未使用） | – |
| 6BH | –（未使用） | – |
| 6CH | XRL Rm, Rm | 蓝色 |
| 6DH | XRL WRj, WRj | 蓝色 |
| 6EH | XRL reg, op2 | 蓝色 |
| 6FH | XRL A, R7 | - |
| 70H | JNZ rel | 通用 |
| 71H | ACALL addr11 | 通用 |
| 72H | ORL C, direct | 通用 |
| 73H | JMP @A+DPTR | 通用 |
| 74H | MOV A, #data | 通用 |
| 75H | MOV direct, #data | 通用 |
| 76H | MOV @R0, #data | - |
| 77H | MOV @R1, #data | - |
| 78H | JNE rel | 蓝色 |
| 79H | MOV @DRk+dis, WRj | 蓝色 |
| 7AH | MOVH DRk,#data16 / MOV op1,reg | 蓝色 |
| 7BH | –（未使用） | – |
| 7CH | MOV Rm, Rm | 蓝色 |
| 7DH | MOV WRj, WRj | 蓝色 |
| 7EH | MOV reg, op2 | 蓝色 |
| 7FH | MOV DRk, DRk | 蓝色 |
| 80H | SJMP rel | 通用 |
| 81H | AJMP addr11 | 通用 |
| 82H | ANL C, bit | 通用 |
| 83H | MOVC A, @A+PC | 通用 |
| 84H | DIV AB | 通用 |
| 85H | MOV direct, direct | 通用 |
| 86H | MOV direct, @R0 | - |
| 87H | MOV direct, @R1 | - |
| 88H | MOV direct, R0 | 通用 |
| 89H | MOV direct, R1 | 通用 |
| 8AH | MOV direct, R2 | 通用 |
| 8BH | MOV direct, R3 | 通用 |
| 8CH | MOV direct, R4 | 通用 |
| 8DH | MOV direct, R5 | 通用 |
| 8EH | MOV direct, R6 | 通用 |
| 8FH | MOV direct, R7 | 通用 |
| 90H | MOV DPTR, #data16 | 通用 |
| 91H | AJMP addr11 | 通用 |
| 92H | MOV bit, C | 通用 |
| 93H | MOVC A, @A+DPTR | 通用 |
| 94H | SUBB A, #data | 通用 |
| 95H | SUBB A, direct | 通用 |
| 96H | SUBB A, @R0 | - |
| 97H | SUBB A, @R1 | - |
| 98H | SUBB A, R0 | 通用 |
| 99H | SUBB A, R1 | 通用 |
| 9AH | SUBB A, R2 | 通用 |
| 9BH | SUBB A, R3 | 通用 |
| 9CH | SUBB A, R4 | 通用 |
| 9DH | SUBB A, R5 | 通用 |
| 9EH | SUBB A, R6 | 通用 |
| 9FH | SUBB A, R7 | 通用 |
| A0H | ORL C, /bit | 通用 |
| A1H | AJMP addr11 | 通用 |
| A2H | MOV C, bit | 通用 |
| A3H | INC DPTR | 通用 |
| A4H | MUL AB | 通用 |
| A5H | ESC（前缀） | – |
| A6H | MOV @R0, direct | - |
| A7H | MOV @R1, direct | - |
| A8H | MOV R0, direct | - |
| A9H | Bit instructions | 蓝色 |
| AAH | ERET | 蓝色 |
| ABH | MOV R3, direct | - |
| ACH | MUL Rm, Rm | 蓝色 |
| ADH | MUL WRj, WRj | 蓝色 |
| AEH | MOV R6, direct | - |
| AFH | MOV R7, direct | - |
| B0H | ANL C, /bit | 通用 |
| B1H | ACALL addr11 | 通用 |
| B2H | CPL bit | 通用 |
| B3H | CPL C | 通用 |
| B4H | CJNE A, #data, rel | 通用 |
| B5H | CJNE A, direct, rel | 通用 |
| B6H | CJNE @R0, #data, rel | - |
| B7H | CJNE @R1, #data, rel | - |
| B8H | CJNE R0, #data, rel | - |
| B9H | TRAP | 蓝色 |
| BAH | CJNE R2, #data, rel | - |
| BBH | CJNE R3, #data, rel | - |
| BCH | CMP Rm, Rm | 蓝色 |
| BDH | CMP WRj, WRj | 蓝色 |
| BEH | CMP reg, op2 | 蓝色 |
| BFH | CMP DRk, DRk | 蓝色 |
| C0H | PUSH direct | 通用 |
| C1H | AJMP addr11 | 通用 |
| C2H | CLR bit | 通用 |
| C3H | CLR C | 通用 |
| C4H | SWAP A | 通用 |
| C5H | XCH A, direct | 通用 |
| C6H | XCH A, @R0 | - |
| C7H | XCH A, @R1 | - |
| C8H | XCH A, R0 | 通用 |
| C9H | XCH A, R1 | 通用 |
| CAH | XCH A, R2 | 通用 |
| CBH | XCH A, R3 | 通用 |
| CCH | XCH A, R4 | 通用 |
| CDH | XCH A, R5 | 通用 |
| CEH | XCH A, R6 | 通用 |
| CFH | XCH A, R7 | 通用 |
| D0H | POP direct | 通用 |
| D1H | ACALL addr11 | 通用 |
| D2H | SETB bit | 通用 |
| D3H | SETB C | 通用 |
| D4H | DA A | 通用 |
| D5H | DJNZ direct, rel | 通用 |
| D6H | XCHD A, @R0 | - |
| D7H | XCHD A, @R1 | - |
| D8H | DJNZ R0, rel | 通用 |
| D9H | DJNZ R1, rel | 通用 |
| DAH | DJNZ R2, rel | 通用 |
| DBH | DJNZ R3, rel | 通用 |
| DCH | DJNZ R4, rel | 通用 |
| DDH | DJNZ R5, rel | 通用 |
| DEH | DJNZ R6, rel | 通用 |
| DFH | DJNZ R7, rel | 通用 |
| E0H | MOVX A, @DPTR | 通用 |
| E1H | AJMP addr11 | 通用 |
| E2H | MOVX A, @R0 | 通用 |
| E3H | MOVX A, @R1 | 通用 |
| E4H | CLR A | 通用 |
| E5H | MOV A, direct | 通用 |
| E6H | MOV A, @R0 | - |
| E7H | MOV A, @R1 | - |
| E8H | MOV A, R0 | - |
| E9H | MOV A, R1 | - |
| EAH | MOV A, R2 | - |
| EBH | MOV A, R3 | - |
| ECH | MOV A, R4 | - |
| EDH | MOV A, R5 | - |
| EEH | MOV A, R6 | - |
| EFH | MOV A, R7 | - |
| F0H | MOVX @DPTR, A | 通用 |
| F1H | ACALL addr11 | 通用 |
| F2H | MOVX @R0, A | 通用 |
| F3H | MOVX @R1, A | 通用 |
| F4H | CPL A | 通用 |
| F5H | MOV direct, A | 通用 |
| F6H | MOV @R0, A | - |
| F7H | MOV @R1, A | - |
| F8H | MOV R0, A | - |
| F9H | MOV R1, A | - |
| FAH | MOV R2, A | - |
| FBH | MOV R3, A | - |
| FCH | MOV R4, A | - |
| FDH | MOV R5, A | - |
| FEH | MOV R6, A | - |
| FFH | MOV R7, A | - |

---

### 说明
- 表中所有 **红色** 指令原本属于 8051（BINARY 模式），在 STC32G 的 SOURCE 模式下，若想使用它们，**必须在操作码前加上 `0xA5` 前缀**（例如 `A5 06` 执行 `INC @R0`）。
- 标记为 `–（未使用）` 的少数操作码（6AH, 6BH, 7BH）在两种模式下均无定义，执行时视为 `NOP`，但建议不要使用。

此表完整覆盖了 0x00~0xFF 所有取值，可直接作为汇编/反汇编参考。如果你还需要其他格式（如 CSV 或分组排列），请告诉我。


