# 外设验证测试框架 (sim251/tests/periph/)

针对 TCC→C251/STC32G 编译器 + sim251 模拟器项目的外设行为验证。
对应 `docs/hex-verification-plan.md` (v3 方案) **Part C 三层框架的 Tier A (模型级)**:

> Tier A 模型级: 编译测试 C 源码 (TCC C251 后端) → hex → sim251 运行 →
> 断言串口输出 / SFR 标志 / 定时器周期 / ADC 转换结果。
> (不依赖 Keil ref hex, 直接验证"TCC 编译的程序在 sim251 上外设行为是否正确")

当前覆盖: **10 个测试, 7 外设模块 (UART/Timer/ADC/SPI/CMP/INT/IAP/WDT)**。\n\nXFR 级模块 (RTC/PWM/DMA/I2C) 待 TCC 支持 `far` 指针后补充。

---

## 目录结构

```
sim251/tests/periph/
├── README.md              本文档
├── run_periph.py          驱动脚本 (编译 → 运行 → 校验 → 报告)
├── report.txt             最近一次运行报告 (自动生成)
├── uart/
│   ├── uart_smoke.c       UART1 冒烟: TI 轮询逐字节输出已知字符串
│   └── uart_isr.c         UART1 中断驱动发送 (已知 bug 复现/记录)
├── timer/
│   ├── timer_smoke.c      Timer0 1T 快速溢出 → TF0 + 自动重装
│   └── timer_isr.c        Timer0 中断触发 → ISR 计数 + 写 P1
└── adc/
    └── adc_smoke.c        ADC 上电 + 启动 → 完成标志 + 结果寄存器
```

每个外设一个子目录, 每个测试一个自包含 `.c` (含 `sfr`/`sbit` 声明, 无外部依赖)。

---

## 运行方法 (Windows)

```bat
REM 0. 前置: 已构建 sim251 与 TCC (若未构建见下方)
REM 1. 编译 + 运行全部测试 (默认行为)
C:\Users\12165\AppData\Local\Programs\Python\Python38\python.exe sim251\tests\periph\run_periph.py

REM 2. 只跑某组/某测试 (按 name 或 group 过滤)
C:\Users\12165\AppData\Local\Programs\Python\Python38\python.exe sim251\tests\periph\run_periph.py uart
C:\Users\12165\AppData\Local\Programs\Python\Python38\python.exe sim251\tests\periph\run_periph.py timer
C:\Users\12165\AppData\Local\Programs\Python\Python38\python.exe sim251\tests\periph\run_periph.py adc_smoke

REM 3. 其他模式
... run_periph.py --compile      # 只编译 (输出 hex 到 tmp\periph\)
... run_periph.py --run          # 只运行 (不重新编译, 用上次 hex)
... run_periph.py --list         # 列出测试
... run_periph.py --report       # 打印上次报告
```

工具链路径 (脚本自动定位, 不存在时报错):
- sim251: `sim251/mcs251.exe` (编译: `cd sim251 && gcc -O2 -Wall -Wextra -std=c99 -o mcs251.exe src/*.c`)
- TCC: `build/tcc_c251.exe` (构建: `tmp/build_ascii.bat`)

产物 (构建/运行中间文件, 不纳入版本控制):
- hex / 串口 / dump: `tmp/periph/<test>.hex|.ser|.dmp`
- 报告: `sim251/tests/periph/report.txt`

---

## 测试规格与判定 (run_periph.py)

每个测试规格: 源文件 + `cycles` (运行周期) + `checks` (断言列表)。断言类型:

| 断言 | 含义 |
|------|------|
| `serial_exact` | `--serial` 捕获的串口字节流 == 期望 (最强信号) |
| `serial_contains` | 串口字节流包含期望子串 |
| `sfr_eq`   | `--dump-ram` 的 SFR 终值 == 期望 |
| `sfr_bits` | SFR 终值含全部指定位掩码 |
| `sfr_ne`   | SFR 终值 != 期望 (缺失按 0 处理, 不会虚假通过) |
| `no_escape`| 程序无逃逸/栈违规, 安全跑满周期 |

判定: 全部断言通过 → `PASS`; 有失败 → `FAIL` (或 `KNOWN-BUG` 若该测试标记为已知缺口); 编译失败 → `COMPILE-FAIL`。

---

## 测试说明

### UART1
- **`uart_smoke`** (PASS): `SCON=0x40` 后经 `SBUF` + `TI` 轮询逐字节发送
  `"UART_SMOKE_OK\r\n"`, 断言串口字节流完全一致。验证 sim251 UART1 TX 模型
  (写 SBUF → 立即输出 1 字节 + 置 TI)。
- **`uart_isr`** (KNOWN-BUG): 走完整 UART 中断路径 (写 SBUF → TI → VEC 0x23 ISR)。
  当前 sim251 的中断驱动 TX 路径**损坏**: 期望逐字节发送 `"ABCDEFGHIJKLM"`,
  实际只输出首字节后反复重复同一字节 (中断反复触发且 ISR 状态不推进,
  IRAM 出现重复的 `00 48 42` 模式)。这是 **sim251 已知 UART 中断 bug**
  (文档: "只输出 1 字节"), 主线程修复中; **框架不依赖该 bug 修复**,
  修复后本测试会自动转为 PASS。

### Timer0
- **`timer_smoke`** (PASS): `TMOD=0` + `AUXR.T0x12=1` (1T) + 重装 `0xFFE0`,
  32 周期溢出 → 断言 `TCON.TF0` 置位、`TH0` 自动重装回 `0xFF`、`AUXR=0x80`。
- **`timer_isr`** (PASS): 同上配置 + `ET0/EA`, Timer0 中断 (VEC 0x0B) 内
  `t0_irq_cnt++` 并写 `P1`。断言 `P1 != 0` (ISR 执行过) 且 TR0 仍在运行。

### ADC
- **`adc_smoke`** (PASS): `ADC_CONTR=0x80` (POWER) → `0xC0` (+START),
  ~16 周期转换完成。断言 `ADC_CONTR=0xA0` (POWER+FLAG, START 清)、
  `ADC_RES=0xC0` (`0x300>>2`, 10 位通道 0 固定电压)、`ADC_RESL=0x00`。

---

## 重要发现 / 已知缺口 (2026-08-07)

### 1. TCC C251 启动清内存循环需要 ~3200 周期 (非 bug, 测试需调大 cycles)
TCC 为每个带 `main` 的程序生成 `?C_C51STARTUP` 组: 18B 前缀含一个
`MOV WR4,#0x041F; 清内存循环 (MOV @WR4,R11; DEC WR4,#1; JNE)` — 清空
`0x041F..0x0000` 约 1056 字节 IRAM, 约 3200 周期后才 `JMP main`。
**后果**: 若 `--cycles` 设太小 (<~3500), main 尚未执行, SFR 全部是复位值,
测试误判失败。**对策**: 本框架所有测试 cycles ≥ 5000。

### 2. TCC C251 对"初始化字符串/数组"的 INITEDATA 拷贝生成缺口 (TCC bug)
`const char msg[] = "..."` / `const char *msg = "..."` / `char msg[] = "..."` 的
测试程序, 生成的 hex 里 **startup 组只有 18B 前缀 + JMP main, 没有 41B 的
`?C_C51STARTUP?2` INITEDATA 拷贝模板, 也没有初始化表**。运行结果: 字符串字面量
留在代码空间 (如 0x0065), 但生成代码用**数据空间间接读** (如 `MOV R11,@WR6`
= 读 IRAM/XRAM 0x0065), 读到 0 → 程序认为字符串为空, 串口无输出。
**后果**: 字符串/初始化数组无法在 sim251 动态验证。
**对策**: 测试改用**字面量逐字节** (如 `SBUF='U'`) 或**运行时填充数组** /
**算术生成序列**, 完全规避字符串初始化。 (此缺口影响 `cross_validate.py`
中串口类 demo 的"强验证", 建议主线程修 TCC 的 INITEDATA 生成。)

### 3. sim251 UART 中断驱动 TX 路径损坏 (sim251 已知 bug, 主线程修复中)
`uart_isr` 测试验证: 中断驱动的多字节发送无法工作 — 只输出首字节,
随后中断反复触发但 ISR 内共享计数 (tx_phase) 不推进, 反复发送同一字节,
且 ISR 反复入栈在 IRAM 留下重复的 `00 48 42` 模式。
与文档 `hex-verification-plan.md` 记载的 "sim251 串口模型捕获不完整
(Keil ref 03 只出 1B)" 一致。**框架将其判为 KNOWN-BUG 而非 FAIL**,
不阻塞其余外设验证; 修复后自动转 PASS。

---

## 扩展指南

新增外设/测试的步骤:
1. `mkdir sim251/tests/periph/<name>/`, 写自包含 `<name>_smoke.c`
   (用 `sfr`/`sbit`, C89 风格, 避开已知缺口 — 见上节)。
2. 在 `run_periph.py` 的 `TESTS` 表加一项: `src`、`cycles`、`checks`。
3. 运行 `run_periph.py <name>` 验证。

参考: `sim251/tests/functional.py` (D 组外设测试的 SFR 地址与期望值)、
`tests/c251/golden/golden_uart.c` (TCC 可编译的 C 语法风格)。
