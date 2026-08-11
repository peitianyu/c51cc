# MCS-251 独立解释器 (c251_standalone)

一个**零依赖、纯 C99** 的 MCS-251 (Intel 251, Source Mode) 指令级解释器,
直接读取 Keil C251 / SDCC 生成的固件并逐条执行,不依赖 QEMU 或任何第三方库。

## 为什么存在

最初为 QEMU 移植 MCS-251 支持,但 QEMU 源码庞大(编译千余文件、exe 34MB)。
本目录是把 QEMU 的 `target/mcs251` 语义逐条移植成 ~1500 行纯 C 解释器,
只保留核心:**CPU 状态、内存模型、指令解码、定时器/中断/UART/端口**。
最终 `mcs251.exe` 仅 **~300KB**。

## 构建

```bash
make            # 编译出 ./mcs251 (需要 cc; 也支持 make CC=gcc)
make debug      # 可选: 编译出 ./mcs251_o0 (-O0 -g, 仅供调试)
```

无任何外部依赖,只用到标准 C 库。

> **调试构建注意**: `make debug` 产出的 `mcs251_o0` 是**未优化**构建
> (-O0 -g), 速度约慢 **9 倍** (~7.7 Mcy/s vs 优化构建 ~68.6 Mcy/s),
> 仅供带调试器单步分析解释器内部使用。所有测试脚本
> (functional.py / cross_validate.py / sim_keil_validate.py / run_periph.py)
> 一律使用优化构建 `./mcs251`;**禁止用 `mcs251_o0` 跑长回归或性能测试**。

## 用法

```
mcs251 [-machine mcs251] [-bios FIRMWARE] [-d cpu] [-D LOGFILE]
       [-display none] [--cycles N] [--dump-every N]
```

- `-bios FIRMWARE`:加载固件。**自动识别两种格式**:
  - 原始二进制 `.bin`
  - Intel HEX `.hex`(Keil 输出格式;支持记录类型 00/01/02/04,含校验和校验)
- `-d cpu`:输出寄存器 dump(与 QEMU 格式兼容,供测试脚本解析)
- `-d in_asm`:逐条打印指令 PC + 操作码(调试用)
- `-D FILE`:把 dump 写入文件(默认 stdout)
- `--cycles N`:最多执行 N 个机器周期(默认 200 万)
- `--dump-every N`:每 N 周期打印一次状态

示例:

```bash
./mcs251 -bios app.hex -d cpu -D trace.log
./mcs251 -bios ../c251/tests/firmware/stc32g_led.bin -D stc32g.log --cycles 120000000
```

## 测试

```bash
make test      # 25 项指令级回归测试(复用 c251/tests/run_tests.py + 固件)
make stc32g    # STC32G LED 流水灯验收(检查 P7 8 值循环 fe→fd→fb→f7→ef→df→bf→7f)
```

回归测试结果:**25/25 通过**;STC32G 流水灯:**P7 完整循环通过**。
性能:约 3000 万周期/秒(MinGW64, -O2)。

## 源码结构

| 文件 | 职责 |
|------|------|
| `src/mcs251.h`   | CPU 状态结构、常量、全部原型 |
| `src/mem.c`      | 寄存器文件(bank 感知)、WRj/DRk 大小端、IRAM/SFR/XRAM、@Ri 间接、双 DPTR、reset |
| `src/alu.c`      | 8/16/32 位算术/逻辑/移位标志位(从 QEMU helper.c 逐条移植) |
| `src/cpu.c`      | 取指/位解码、栈、8051 指令族、`mcs251_execute_one()` 主分发 |
| `src/decode_impl.inc` | 251 Source 模式解码:decode_8051 / decode_a5 / decode_bit(A9) / decode_251 / regop2 |
| `src/soc.c`      | 定时器 T0/T1、UART、中断(INT0/T0/INT1/T1/SIO)、SFR 端口 |
| `src/main.c`     | CLI、run loop、dump_state(与 QEMU 格式字节兼容)、固件加载(bin+hex) |

### 关键设计约定

- **Source Mode 指令集**;WRj 字寄存器**大端**(Rj=高字节),DRk 双字**小端**(Rk=低字节)。
- 内存空间:CODE / IRAM / SFR / XRAM,通过 `mcs251_ld/st_*` 访问;`@Ri` 按 R0/R1
  的值间接访问内部 RAM。
- 中断向量:INT0=0x0003, T0=0x000B, INT1=0x0013, T1=0x001B, SIO=0x0023。
- dump_state 中 `R[00]..R[07]` 为当前 bank 的寄存器,`R[08]..R[15]` 为物理寄存器
  (与 QEMU `target/mcs251/cpu.c` 的 dump 一致)。

## 与 QEMU 版对比

| | QEMU `qemu-system-mcs251.exe` | 本解释器 `mcs251.exe` |
|---|---|---|
| 代码量 | 数百个文件 | 7 个源文件 |
| 二进制体积 | ~34MB | ~300KB |
| 依赖 | meson/ninja + 大量 QEMU 基础设施 | 无,仅 libc |
| 执行速度 | 慢(TCG 翻译) | 快(原生直译,约 3000 万指令/秒) |
| 外设 | 完整 QEMU 设备模型 | 精简:定时器/中断/UART/端口 |
| 用途 | 完整系统仿真 | 指令级验证 / CI 回归 |
