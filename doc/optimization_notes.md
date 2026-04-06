# C51CC 代码生成优化记录

## 当前状态（2026-04-06）

### 测试套件（test/ 目录）
- **总指令数**: c51cc=7468 / keil=6791
- **比率**: **110.0%**（目标 100%）
- **差距**: +677 指令
- **回归**: 77/77 测试通过

### STC51 示例对比（35项，多文件编译，2026-04-06）

c51cc 现已支持多文件编译（`main.c` + `delay.c` 同时输入），以下为完整对比：

| 项目 | Keil hex(B) | c51cc hex(B) | hex比率 | Keil asm | c51cc asm | asm比率 | 状态 |
|------|-------------|--------------|---------|----------|-----------|---------|------|
| 2-1_led_on | 20 | 5 | 0.25x | 2 | 2 | 1.00x | ✓ |
| 2-2_led_blink | 42 | 61 | 1.45x | 12 | 30 | 2.50x | ⚠ DJNZ缺失 |
| 2-3_led_flow | 118 | 82 | 0.69x | 33 | 33 | 1.00x | ✓ |
| 2-4_led_flow_plus | 118 | 70 | 0.59x | 33 | 27 | 0.82x | ✓ |
| 3-1_key_led | 29 | 16 | 0.55x | 6 | 7 | 1.17x | ✓ |
| 3-2_key_led_toggle | 60 | 38 | 0.63x | 10 | 17 | 1.70x | ⚠ |
| 3-3_key_led_binary | 73 | 48 | 0.66x | 19 | 23 | 1.21x | ✓ |
| 3-4_key_led_shift | 152 | 125 | 0.82x | 64 | 67 | 1.05x | ✓ |
| 4-1_nixie_static | 272 | 69 | 0.25x | 57 | 35 | 0.61x | ⚠ sbit功能缺失(代码不正确) |
| 4-2_nixie_dynamic | 317 | 96 | 0.30x | 68 | 47 | 0.69x | ⚠ sbit功能缺失(代码不正确) |
| 5-1_nixie_module | 338 | 117 | 0.35x | 77 | 56 | 0.73x | ⚠ sbit功能缺失(代码不正确) |
| 5-2_lcd1602_debug | 878 | 678 | 0.77x | 339 | 380 | 1.12x | ✓ |
| 6-1_matrix_key | 486 | 179 | 0.37x | 107 | 96 | 0.90x | ⚠ sbit功能缺失(代码不正确) |
| 6-2_matrix_key_lock | 868 | 736 | 0.85x | 393 | 371 | 0.94x | ✓ |
| 7-1_timer_led_mode | 329 | 253 | 0.77x | 155 | 124 | 0.80x | ✓ |
| 7-2_timer_clock | 587 | 396 | 0.67x | 191 | 199 | 1.04x | ✓ |
| 8-1_uart_send | 92 | 63 | 0.68x | 27 | 30 | 1.11x | ✓ |
| 8-2_uart_recv | 91 | 101 | 1.11x | 34 | 49 | 1.44x | ✓ |
| 9-1_matrix_led_static | 312 | 131 | 0.42x | 82 | 82 | 1.00x | ✓ |
| 9-2_matrix_led_anim | 378 | 186 | 0.49x | 116 | 116 | 1.00x | ✓ |
| 10-1_ds1302_clock | 1457 | 1408 | 0.97x | 583 | 873 | 1.50x | ⚠ |
| 10-2_ds1302_adjustable | 2425 | 1628 | 0.67x | 1075 | 1271 | 1.18x | ✓ |
| 11-1_buzzer_beep | 481 | 287 | 0.60x | 152 | 138 | 0.91x | ✓ |
| 11-2_buzzer_music | 577 | 333 | 0.58x | 122 | 194 | 1.59x | ⚠ |
| 12-1_at24c02_storage | 1239 | N/A | - | 442 | N/A | - | ✗ 32-bit DIV |
| 12-2_stopwatch | 1150 | 827 | 0.72x | 528 | 416 | 0.79x | ✓ |
| 13-1_ds18b20_temp | 1141 | N/A | - | 411 | N/A | - | ✗ 32-bit DIV |
| 13-2_ds18b20_alarm | 2366 | N/A | - | 1011 | N/A | - | ✗ 32-bit DIV |
| 14-1_lcd1602 | 1178 | N/A | - | 393 | N/A | - | ✗ 32-bit DIV |
| 15-1_led_breathing | N/A | N/A | - | N/A | N/A | - | ✗ sbit声明（双端均失败） |
| 15-2_dc_motor | 585 | 341 | 0.58x | 203 | 160 | 0.79x | ✓ |
| 16-1_adc | 960 | N/A | - | 316 | N/A | - | ✗ 32-bit DIV |
| 16-2_dac | 214 | 147 | 0.69x | 95 | 77 | 0.81x | ✓ |
| 17-1_ir_remote | 1561 | N/A | - | 608 | N/A | - | ✗ 32-bit DIV |
| 17-2_ir_motor | 982 | 995 | 1.01x | 447 | 547 | 1.22x | ✓ |
| **TOTAL(28项)** | **13431B** | **9416B** | **0.70x** | **5030** | **5467** | **1.09x** | |

> 构建命令：`scripts/build_stc51_examples.bat` → 对比：`python scripts/compare_stc51.py`

---

## 已完成优化（历史）

| 优化 | 文件 | 节省指令 | 比率变化 |
|------|------|----------|----------|
| emit_bitwise IDATA 直接寻址 | c51_isel_logic.c | ~30 | - |
| emit_select ORL A,A bug 修复 | c51_isel_logic.c | ~10 | - |
| emit_cmp_zero_branch 16-bit fix | c51_isel_logic.c | ~20 | - |
| emit_bitwise imm 特殊值(#0/#FF) | c51_isel_logic.c | ~15 | - |
| peephole_idata_store_load_forward (16-bit) | c51_optimize.c | 217 | 117.9→114.7% |
| peephole_redundant_load 扩展(lookahead=3) | c51_optimize.c | ~10 | - |
| peephole_mov_chain 扩展到 IDATA direct | c51_optimize.c | 307 | 114.7→110.1% |
| peephole_idata_load_from_reg (质量改进) | c51_optimize.c | 0 | 110.1% |
| peephole_propagate_reg_imm | c51_optimize.c | ~8 | 110.1→110.0% |
| **EQ(sbit,0)→JB 优化** | **c51_isel_ctrl.c** | ~3/sbit比较 | STC51 3-1_key_led: 49B→47B |
| **rotate8 idiom 优化**（`(v<<n)\|(v>>(8-n))` → `RL`/`RR`） | **c51_isel_logic.c, c51_isel_arith.c** | STC51 7-1: 474B→265B | 7-1: 1.26x→0.81x |
| **16-bit `>>8`/`<<8` 特殊优化**（字节交换替代8次RRC）| **c51_isel_arith.c** | 11-2: asm 301→194, hex 438→333B | TOTAL asm 1.13x→1.09x, hex 0.72x→0.70x |



## 差距最大的测试（当前）

| 测试 | c51cc | keil | 差距 |
|------|-------|------|------|
| test_isel_branch | 680 | 471 | +209 |
| test_regalloc_combo | 561 | 364 | +197 |
| test_regalloc_logic | 432 | 306 | +126 |
| test_regalloc_select | 328 | 214 | +114 |
| test_isel_arith | 342 | 243 | +99 |
| test_ssa | 565 | 471 | +94 |
| test_regalloc_mix | 369 | 281 | +88 |

---

## 全局指令频率差距

| 指令 | c51cc | keil | delta | 说明 |
|------|-------|------|-------|------|
| MOV | 4899 | 3140 | +1759 | 最大差距，大量 spill/reload |
| SJMP | 192 | 95 | +97 | 过多无条件跳转 |
| JZ | 118 | 28 | +90 | 比较后零值判断多余 |
| ANL | 115 | 50 | +65 | AND 操作 |
| INC | 126 | 58 | +68 | 自增指令 |
| CJNE | 84 | 27 | +57 | 条件比较跳转 |
| CPL | 43 | 6 | +37 | 按位取反 |
| XCH | 0 | 89 | -89 | keil 用 XCH，c51cc 未实现 |
| DJNZ | 0 | 27 | -27 | keil 用 DJNZ，c51cc 未实现 |
| CLR | 146 | 248 | -102 | keil 多用 CLR A |

---

## 可继续优化的点（按优先级排序）

### [P1] 死 IDATA spill store 消除（预估 -80~120 指令）

**问题**: 经过 `peephole_idata_store_load_forward` 处理后，许多 spill store 的
reload 被消除，但 store 本身仍然保留，变成了"死 store"。

**模式**: 
```asm
MOV __spill_N, A        ; ← 如果 __spill_N 之后从未被 load，这是死 store
MOV A, #0
MOV (__spill_N + 1), A  ; ← 同理
```

**统计**: 当前全局有 `spill_store=379, spill_load=255`，差 124 次（潜在死 store）

**实现思路**: 
- 扫描每个 section，收集所有 `__spill_N` 的 load 地址集合
- 删除 store 到不在集合里的 `__spill_N` 的指令对
- 参考现有 `XDATA dead-store elimination pass`

---

### [P2] `MOV A, #0; MOV (__spill+1), A` → `CLR A; MOV (__spill+1), A`（指令等价，质量改进）

实际上已经通过 `peephole_propagate_reg_imm` 将 `MOV A, R_zero` 替换为 `MOV A, #0`。
统计有 **78 对** `MOV A,#0 -> MOV (__spill+1), A`。

如果进一步：`MOV (__spill+1), A` 后面 A=#0，可能被后续 `idata_store_load_forward` 消除。

---

### [P3] 16-bit or-then-branch 简化（预估 -40~60 指令）

**问题**: 生成了大量
```asm
MOV R0, #0
MOV A, #0         ← A = 0（来自 R0=#0 传播）
ORL A, R1         ← A = R1
JNZ label
```
Keil 直接：`MOV A, R1; JNZ label`（或更好地 `MOV A, R1; JNZ`）

**根因**: `emit_cmp_zero_branch` 对 16-bit 零值判断生成 `ORL A, Rhi; JNZ`，
但 `Rhi=0`（来自截断/掩码操作的零扩展）时未能省略。

**实现思路（peephole）**:  
模式：`MOV A, #0; ORL A, Rx; JNZ/JZ label`  
→ `MOV A, Rx; JNZ/JZ label`（3→2 条，节省 1 条）

全局 `MOV A,#0` 有 155 次，其中很多后跟 ORL。

---

### [P4] 16-bit IDATA 存储后 hi byte 为 #0 可省略（预估 -30~50 指令）

**模式**:
```asm
ANL A, #3        ; result 在 0..3，hi byte 必为 0
MOV __spill_1, A
MOV A, #0        ; hi = 0
MOV (__spill_1+1), A
```

如果后续 `MOV R, (__spill_1+1)` 能知道 hi 始终为 0，可用 `MOV R, #0` 替代
（避免 load），甚至整个 hi store+load 可以消除。

这要结合 P1（死 store 消除）一起实现更彻底。

---

### [P5] `MOV A, #0; ORL A, Rx` → `MOV A, Rx`（预估 -40 指令）

这是 P3 的简化形式（不带分支），直接删除：
- `MOV A, #0` 后紧跟 `ORL A, Rx` → 删 `MOV A,#0`，`ORL A,Rx` 改为 `MOV A, Rx`
- 原因：A=0 时 `ORL A, Rx = Rx`

**统计**: 全局 `MOV A,#0` 155次，`ORL A` 57次，有相当重叠。

**实现**: 在 `peephole_logical_nop` 附近增加一个规则即可。

---

### [P6] `SJMP` 过多（+97）

Keil 的 SJMP=95，c51cc 的 SJMP=192。c51cc 多出 97 条 SJMP。

原因：`emit_select`（三目运算符）和 16-bit 比较结束后的无条件跳转。

Keil 会将 `if/else` 的落穿边不生成 SJMP，而 c51cc 强制生成。  
`peephole_sjmp_to_next_label` 已有，但需要检查是否仍有漏洞。

---

### [P7] 冗余 16-bit ADDC A, #0 累积（+24）

c51cc 比 keil 多 24 条 ADDC。这是必要的进位传播，无法消除。
但对于 `src1_size==1` 的值做 16-bit add，`MOV A, #0; ADDC A, #0` = `CLR A; ADDC A, #0` = `MOV A, C`（进位），
如果进位为 0 则可用 `CLR A` 替代（但运行时不能确定 C=0）。
**跳过**。

---

### [P8] 寄存器分配改进（isel 层面，复杂度高）

**问题**: 
- 13个 spill 槽（test_regalloc_logic）vs keil 0个
- test_isel_branch 的 `for_sum` 函数 spill 了循环变量 `s`

这是线性扫描分配器的根本限制。改进方案：
1. 提高溢出决策质量（选择使用频率最低的值溢出）
2. 增加溢出后直接在内存操作（ADD A, sym 等）——已部分完成
3. 改用图着色分配器——复杂度极高

**优先级**: 低（需大量改动 c51_isel_regalloc.c）

---

### [P9] isel 层面的 v17 lo byte 丢失 bug（功能 bug）

**发现**: `test_regalloc_logic::reg_logic` 中，`v17 = a+3` 的 lo byte 计算结果
被后续指令覆盖，导致 `v20 = v17 XOR v19` 实际计算了 `v19 XOR v19 = 0`。

测试功能上通过（因为 `main()` 不检查 `reg_logic` 的返回值），但这是功能 bug。

**根因**: `emit_add(v17, size=2)` 时 `dst_lo` 与后续 `emit_add(v19)` 分配了同一寄存器，
v17 的结果被 v19 覆盖，线性扫描分配器没有检测到这个 lifetime 冲突。

**修复**: 需要在 regalloc 中确保 v17 的 live range 不与 v19 的 dst 冲突。
**优先级**: 中（会同时修复功能和减少指令数）

---

### [P10] XCH 指令支持（keil=89，c51cc=0，-89 差距）

Keil 在 16-bit add/sub 中大量使用 `XCH A, Rx` 来临时交换 A 和寄存器，
避免需要额外的 MOV。

例如：
```asm
; keil 的 16-bit a+b-c
MOV A, R7; ADD A, R5; MOV R7, A
MOV A, R6; ADDC A, R4; XCH A, R7  ; ← XCH 保存 hi，同时拿到 lo
CLR C; SUBB A, R3; XCH A, R7; SUBB A, R2; MOV R6, A
```

c51cc 同样操作需要额外 MOV。在 `emit_add/sub` 中引入 XCH 可减少约 40-50 条 MOV。
**优先级**: 中（需改 isel，但对 MOV delta 贡献大）

---

### [P11] DJNZ 循环模式（keil=27，c51cc=0，-27 差距）

Keil 识别 `for(i=n; i>0; i--)` 模式，生成 `DJNZ Rx, label`（1条）。
c51cc 用 `DEC Rx; MOV A, Rx; JNZ label`（3条）。

在 `emit_cmp_zero_branch` 或循环优化层识别此模式。
**优先级**: 低（需 SSA 层识别循环模式）

---

## 立即可实施的优化（今日）

### [今日-1] P5: `MOV A, #0; ORL A, Rx` → `MOV A, Rx`

只需在 `peephole_logical_nop` 或新建规则中：
- 检测 `MOV A, #0` 后紧跟 `ORL A, Rx`（Rx = R0-R7 或其他）
- 删除 `MOV A, #0`，将 `ORL A, Rx` 改为 `MOV A, Rx`

### [今日-2] P1: IDATA 死 spill store 消除

扫描 section，找所有 `__spill_N` 只写不读的情况，删除对应 store 指令对。
参考已有的 XDATA dead-store elimination 逻辑。

### [今日-3] P3: `MOV A, #0; ORL A, Rx; JNZ/JZ` → `MOV A, Rx; JNZ/JZ`

是 P5 的进一步延伸。

### [新-P12] `>>8` 展开为 8 次 RRC 优化（来自 11-2_buzzer_music）

**问题**: `unsigned int val >> 8` 展开成了 **8次 RRC 对**（每次 2条 = 16条），asm 比率 2.47x。  
Keil 直接使用 `MOV A, Rhi`（高字节即移位结果，0条 RRC）。

**模式**:
```asm
; c51cc 生成（16条）：
CLR C; RRC A; MOV A, R1; RRC A; MOV R1, A  × 8
; 应优化为：
MOV A, Rhi   ; 直接取高字节
MOV Rlo, #0  ; 低字节清零（若需要）
```

**实现位置**: `c51_isel_arith.c` 的 `emit_shr`，识别 `shift_amount == 8`（16-bit）时：
- `result_lo = src_hi`
- `result_hi = 0`
- 无需 RRC

**预估收益**: 11-2_buzzer_music asm 从 301→~200，比率 2.47x→~1.6x

### [新-P13] sbit switch/case 跳转表为空（来自 4-1/4-2/5-1/6-1 nixie/matrix）

**问题**: `switch(loc)` 对 sbit 赋值（`P2_4=1; P2_3=1; P2_2=1`）生成的 case 体**完全为空**，
Nixie_SetPos/Nixie 函数退化为空函数。这是**功能正确性 bug**，不是优化问题。

**根因**: c51cc 未支持 `sbit` 类型变量的赋值（只读不写）。

**影响**: 4-1/4-2/5-1/6-1 的 hex 小于 Keil 是**因为代码不完整**，非真正优化。

**修复优先级**: 高（功能 bug）

---

## 技术约束

- 8051 寄存器：R0-R7（工作寄存器），A（累加器），B（辅助），C（进位），DPTR（16-bit）
- 函数传参：R6/R7（第1参数 lo/hi），R4/R5（第2参数），R2/R3（第3参数）
- 函数返回：R6/R7（16-bit）或 R7（8-bit）
- `__spill_N`：IDATA 直接地址，可用 `MOV sym, A` 和 `MOV Rx, sym` 直接访问
- `(__spill_N + 1)`：16-bit spill 的 hi byte
- ADDC A, #0：必要进位传播，**不可删除**
