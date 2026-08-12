# C251 寄存器分配参考 — Keil C251 XSMALL + Source 模式分析

> 2026-08-12 实测: Keil C251 V5.60 (MODSRC XSMALL OPTIMIZE(9,SIZE)), 反汇编 5 个代表性函数。
> 目的: 为 c251cc 后端寄存器分配提供参考纪律。当前 c251cc isel 的跨块值 bug 根因即违反本纪律。

## 1. Keil 的实际代码 (5 样例)

样例源码 `kstudy.c` (5 函数 + main), 完整汇编见附录 A。

| 函数 | 模式 | Keil 分配 |
|------|------|----------|
| f_join | if-else 汇合 | x→WR6(参数), y→WR4; 两分支都写 WR4, 汇合直接读 WR4 |
| f_loop | 循环累加 | sum→WR6, i→WR4 全程占用; 迭代临时只用 WR2 |
| f_tern | 循环+三元+数组写 (c251cc bug 场景) | len→WR6, n→WR4 全程; 临时 WR8(基数)/WR2(d)/WR0(值)/WR10(地址) |
| helper | 双参乘法 | a→WR6, b→WR4 (ABI), MUL WR6,WR4 直接乘 |
| f_call | 调用后恢复 | x,y 常量折叠; r 在 WR6 返回值; 后续直接加常量 |
| f_many | 多变量 | 全常量折叠 → 单条 MOV WR6,#0E7FH |
| main | 跨调用累加 | 用 WR14 保存 f_join 结果 (被调函数不用 WR14 故安全) |

## 2. Keil 寄存器分配纪律 (5 条)

1. **8 个字寄存器可用**: WR0/WR2/WR4/WR6/WR8/WR10/WR12/WR14 (R0-R15, 251 Source 模式)。
   当前 c251cc 只用 WR0-WR6 (4 个) — 寄存器压力直接差一倍。

2. **变量级分配, 非 SSA 值级**: 变量→寄存器映射全程有效 (`Variable 'n' assigned to Register 'WR4'`)。
   循环承载变量 (len/n/sum/i) 钉在专用寄存器, 整个循环不被抢占。

3. **分支汇合用"同目标寄存器"约定**: f_join 的 y、f_tern 的 '0'+d/'A'+d-10 在两分支写同一寄存器,
   汇合点直接读。**无 spill、无槽、无跨块信任问题** — 编译器保证两分支值落在同一寄存器,
   且该寄存器在两分支路径上不被破坏。

4. **临时寄存器按需新鲜分配, 用后即弃**: 每迭代 MOV WR8,#10 / WR2(d) / WR10(地址) / WR0(值)。
   临时值生命周期短, 不跨块。跨块值要么钉寄存器 (规则 2), 要么不存活。

5. **调用纪律**: 参数 ABI 表 (u16: WR6,WR4,WR2,WR0 按序), 返回值 WR6, u8 用 A(R11)。
   caller 用被调函数不使用的寄存器 (如 WR14) 跨调用保存。

## 3. c251cc 现状与根因

当前 c251cc isel (`src/core/c251/c251_isel.c`):
- SSA 值级分配, 4 个字寄存器 (WR0-WR6)
- **跨块值信任寄存器绑定**: `value_to_reg` 映射在块间保留, 物理寄存器被其他块覆写后
  绑定未清除 → 强制溢出路径从物理寄存器读旧绑定值
- 无 def 落槽 / 无块边界纪律

**已确认的 bug 链** (t82b.c: do-while + 三元 + 数组写, 调试输出实证):

```
[forced-spill] WR0 holds v13 (block 2) → MOV __spill_5 WR0  ← b2(循环后)从物理 WR0 溢出 v13
   但 b5 已把 WR0 覆写为 store 地址 → __spill_5 = 垃圾
[forced-spill] WR0 holds v18 (block 4) → MOV __spill_7 WR0  ← b4(else 分支)溢出 v18
   但 v18 只在 b3(then 分支)计算进 WR0 → b4 路径 WR0 = cond 值 → __spill_7 = 垃圾
b5 SELECT 读 __spill_5/__spill_7 → 垃圾 → buf[0] 写错 → ret=1
```

## 4. 修复方案 (对齐 Keil 纪律, 2 个改动)

**方案: 块本地寄存器模型 + def 时落槽**

1. **def 时落槽 (槽权威)**: isel_instr 中每个 global-live dest 物化后立即
   `MOV __spill_N, WRx`。跨块值从槽读取, 物理寄存器只是缓存。

2. **块入口清空绑定 (块本地化)**: isel_block 开头清空 value_to_reg/reg_val。
   绑定只在当前块内有效 — 与 Keil "临时按块新鲜分配" 一致。
   - 强制溢出路径只会碰到本块内创建的绑定 (物理=值) → 物理写永远正确
   - 跨块值在新块从槽加载 (规则 1 保证槽权威)
   - 块内效率保留: 块内值仍寄存器直连

**为什么能修根因**: b4 的 forced-spill 不再能碰到 b3 的 v18 绑定 (b4 入口已清);
v13/v18 的槽在 def 时写入正确值, b5 SELECT 从槽读到正确值。

**与 Keil 的对应**:
- 规则 1 ↔ Keil "跨块值要么钉寄存器要么落槽" (c251cc 无变量钉寄存器机制, 落槽是保守选择)
- 规则 2 ↔ Keil "临时按块新鲜分配"

**后续优化方向 (对照 Keil, 不阻塞正确性)**:
- 扩展 WR8-WR14 (8 寄存器) — 减少 spill 压力
- 循环承载变量钉寄存器 (需要循环级 liveness)
- SELECT/汇合点"同目标寄存器" — 消除 select 的槽往返
- @WRj+imm16 偏移寻址 (`MOV @WR10+buf,R1`) — 免地址预计算

## 附录 A: kstudy.c 关键汇编

```
; f_tern (c251cc bug 场景) — len→WR6, n→WR4, 临时 WR8/WR2/WR0/WR10
000006 7E440010  MOV WR8,#010H        ; base → WR8 (每迭代重载)
00000A 7D12      MOV WR2,WR4          ; d = n
00000C 8D14      DIV WR2,WR8          ; d = n % base (商 WR2/余 WR0)
00000E 7D10      MOV WR2,WR0          ; d = 余数
000010 BE14000A  CMP WR2,#0AH         ; d < 10
000014 5808      JSGE ?C0014
000016 7D01      MOV WR0,WR2          ; 两分支同 WR0
000018 2E040030  ADD WR0,#030H        ; '0'+d
00001C 800A      SJMP ?C0015
00001E 7D01      MOV WR0,WR2
000020 2E040041  ADD WR0,#041H        ; 'A'+d
000024 9E04000A  SUB WR0,#0AH
000028 7D53      MOV WR10,WR6         ; WR10 = len
00002A 0B34      INC WR6,#01H         ; len++
00002C 19150000 MOV @WR10+buf,R1      ; buf[len] = R1 (WR0 低字节) ← 偏移寻址
000030 7D52      MOV WR10,WR4         ; n
000032 8D54      DIV WR10,WR8         ; n /= base
000034 7D25      MOV WR4,WR10         ; n = 商
000036 4D25      ORL WR4,WR10         ; n|商 ≠ 0 测试
000038 78CC      JNE ?C0010

; f_join — 两分支写同寄存器 WR4, 汇合直接读
000000 BE340005  CMP WR6,#05H
000004 0808      JSLE ?C0001
000006 7D23      MOV WR4,WR6
000008 2E24000A  ADD WR4,#0AH
00000C 8006      SJMP ?C0002
00000E 7D23      MOV WR4,WR6
000010 9E24000A  SUB WR4,#0AH
000014 7D32      MOV WR6,WR4          ; y*2 (SLL WR6)
000016 3E34      SLL WR6
```

## 附录 B: far 指针 (Keil XSMALL+Source 通用指针, 2026-08-12 实测)

### Keil 布局 (k77.LST, 77_far_mem.c)
```
; XFR 扩展 SFR 0x7efe10: DR = 0x007EFE10 (空间字节 0x7E 在高 8 位)
000002 7E34FE10  MOV WR6,#0FE10H      ; 低 16 位地址
000006 7E24007E  MOV WR4,#07EH        ; 空间字节 (WR4 = 0x007E → R5 = 0x7E)
00000A 7A1BB0    MOV @DR4,R11         ; far 写 (A=R11)
00000D 7E1BB0    MOV R11,@DR4         ; far 读
; xram 0x000100: 空间 0x00
00006A 7E080100  MOV DR0,#0100H       ; MOV DRj,#imm16 (高字 0)
00006E 7A0BB0    MOV @DR0,R11
```

### 编码 (sim251 decode_impl.inc 交叉验证)
| 指令 | 编码 | 解码路径 |
|------|------|---------|
| MOV Rm,@DRk  | 7E (k/4)B (m)0      | regop2_generic case 0xB |
| MOV @DRk,Rm  | 7A (k/4)B (m)0      | mov_op1_reg case 0xB |
| MOV WRj,@DRk | 7E (k/4)0A (j/2)0   | inc_dec_short sel2 (b1&2) |
| MOV @DRk,WRj | 7E (k/4)1A (j/2)0   | inc_dec_short dec1 sel2 |

### sim251 路由 (mem.c ld_far8/st_far8)
- @DRk 取低 24 位 → 高字节 0xFF → code; 低 16 位 < 0x10000 → IRAM (edata);
  其余 → XRAM/XFR (0xFA00-0xFFFF 窗口由 xram8 内部处理)
- 验证: Keil 编译 77_far_mem 跑 sim251 ret=0 ✓

### c251cc 实现要点
- far 常量 `(u8 volatile far *)0x7efe10`: INTTOPTR 常量透传 (24 位不截断) →
  MOV WR(k+2),#lo16; MOV WRk,#space → DRk
- DRk 选择: DR0 (WR0:WR2) / DR4 (WR4:WR6) 对, 避开活值绑定
- 属性下推 (parser): `unsigned char *` 的 unsigned/volatile/far 修饰被指向类型
