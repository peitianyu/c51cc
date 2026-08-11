# C251 平台后端设计（c251cc）

> 日期：2026-08-11
> 状态：已批准（用户确认，待书面审查）
> 目标平台：MCS-251 / STC32G，Keil C251 XSMALL 内存模型，Source Mode 指令集

## 1. 背景与目标

c51cc 是自研 C 编译器（SSA 中端：`pp.c → parser.c → ssa.c → ssa_pass.c`），目前只有 C51 后端（`src/core/c51/`，指令选择 + 线性扫描寄存器分配 + 窥孔优化 + 编码 + 输出，完整可用）。`src/core/c251/` 目前为空目录。

本项目为 c51cc 添加 **C251 平台后端（c251cc）**：

- 编译 STC32G 官方示例（`test/stc32g/` 下 32 个示例工程）
- 生成 MCS-251 **Source Mode** 指令，经 **sim251**（`sim251/mcs251.exe`，Source Mode 指令级模拟器）验证行为
- 与 **Keil C251 编译器**持续对齐：行为对齐（sim251 跑 Keil golden hex 对比）+ 大小对齐（逐函数/整体代码大小对比）
- 最终成为一个独立项目（自包含：编译 → hex，不依赖 Keil 工具链运行）

## 2. 已确认决策

| # | 决策 | 内容 |
|---|------|------|
| D1 | 范围 | **B 完整 Keil 对标**：XSMALL 内存模型完整实现（near 变量 + code 常量 + 4 字节 far 指针 + sfr/sbit + 中断），能编译 STC32G 官方示例 |
| D2 | ABI | **Keil C251 ABI 完全兼容**（便于混合链接 STC 官方 STARTUP.A51 / 库），最终为独立项目 |
| D3 | 代码归属 | **A 同仓库双后端**：`src/core/c251/` 独立后端目录，c251cc 独立可执行，共享 `src/core/` 前端 + SSA；稳定后可拆独立仓库 |
| D4 | 实现方案 | **C 混合**：复用 obj/输出/流水线/运行时库模式等与指令集无关部分；指令选择、分层寄存器分配、Source Mode 编码全新实现 |
| D5 | 验证 | 复制 `D:\work\tinycc_c251\tests\c251\` 验证脚本到 `scripts/c251/`，测试 `test/` 下所有文件（suite 73 + execute 216 + ssa 81 + stc32g 32） |
| D6 | 对齐节奏 | **与 Keil 不断对齐**是持续机制：每实现一个功能模块 → 跑 sim_keil_validate + keil_size_compare → 有偏差立即修正 |
| D7 | 构建 | 使用 **tcc.exe** 构建（唯一构建方式，同 c51cc 现有 `build_compiler.bat` 模式），产出 `c251cc.exe` |
| D8 | 仓库精简 | **保持代码仓库精简**：复用优先、只提取最小必要资产，禁止整文件复制膨胀（c51 后端不复制、tinycc_c251 资产只摘取编码表/ABI/例程序段） |

## 3. 架构设计

### 3.1 平台选择机制

单一 `main.c`，后端调用点抽象为函数指针（`backend_gen(SSAUnit*)`、`backend_write_asm/hex`、`backend_link_startup`）：

- 通过 **argv[0] 文件名** 自动选择后端（`c51cc.exe` / `c251cc.exe`），同时支持 `-target c51|c251` 显式覆盖
- 现有 `-asm/-hex/-ssa/-reg/-O0/-O1/-O2/-o/-I` 选项全部复用
- 新增 `-model xsmall`（默认，C251）等内存模型选项

### 3.2 构建脚本

`build_compiler.bat c251cc`：**tcc.exe** 编译 `src/main.c + src/core/*.c + src/core/c251/*.c` → `c251cc.exe`。

- tcc.exe 是唯一构建方式（不做 clang/gcc 多工具链支持）
- c251cc 构建**不包含** c51 后端文件（反之亦然），避免符号冲突
- 注意：现有 `build_compiler.bat` 硬编码路径 `D:\ws\test\C51CC\src`，需改为相对路径 `..\src`

### 3.3 复用 / 新写边界（遵循 D8 仓库精简原则）

**复用（引用或最小裁剪，不整文件复制）**：

- `obj.c` 链接框架（`obj_link`、符号/section/reloc 管理）——**直接共享，不复制**
- `c51_output.c` 的 asm/hex 输出骨架——提取公共输出逻辑到共享模块（如 `src/core/backend_out.c`）或按需裁剪最小文件
- `c51_gen.c` 的流水线结构——仅借鉴流程，不复制代码
- linscan 活跃区间计算算法——如可行，提取为共享算法模块（`src/core/linscan.c`），c51/c251 共用；否则按需移植最小实现

**全新**：

- 指令选择（16 位优先，C251 价值核心）
- 分层寄存器分配（R0-R7 / WR0-WR7 / DR0-DR4）
- Source Mode 编码器（AsmInstr → 机器码）
- C251 窥孔优化

**提取（只摘取必要片段，不整文件搬运）**：

- 编码表：从 tinycc_c251 `src/c251-ops.inc / c251-load.inc / c251-call.inc` 注释**摘取需要的指令编码条目**（转为 c251_encode.c 的紧凑表）+ sim251 `src/decode_impl.inc` + `sim251/tests/functional.py` 编码辅助函数（交叉验证）
- Keil ABI 规则：从 tinycc_c251 `c251-call.inc` 注释摘取传参/返回表（写入 ABI 注释或文档，不搬运代码）
- 运行时库：从 tinycc_c251 `c251-lib.inc` 摘取**实际用到的 `?C?` 例程**（先只含 32 位除法/移位等必需项，用到再补）

**指令选择参考（新增，用户指定）**：

- 实现思路直接参考 tinycc_c251 的指令选择：`c251-gen.c`（生成入口）+ `c251-ops.inc`（算术/位运算/移位/比较）+ `c251-load.inc`（加载/寻址/常量）+ `c251-call.inc`（调用/ABI/函数序言）
- 参考其**指令模式选择规则**（何时用 WRj 单指令、何时 8 位兼容、常量加载策略、间接寻址决策、save_regs 时机），按 SSA 架构重写，不照搬 VT 栈式代码

## 4. C251 后端模块（src/core/c251/）

| 文件 | 职责 | 来源 |
|------|------|------|
| `c251_gen.h/.c` | 后端上下文（值→寄存器/地址/常量映射、spill 管理、linscan 快照、mmio 映射） | 按需最小实现 |
| `c251_isel.c` | isel 入口：`isel_function/block/instr` 分发 + 值位置管理 | 新写（模式仿 c51） |
| `c251_isel_arith.c` | 16 位优先算术/位运算/移位/比较（WRj 单指令） | 参考 c251-ops.inc |
| `c251_isel_mem.c` | 加载/存储/地址计算（@WRj/@DRk 间接、dir16、far 指针、MOVC） | 参考 c251-load.inc |
| `c251_isel_ctrl.c` | 跳转/分支/调用/返回/switch/phi 拷贝 | 参考 c251-call.inc |
| `c251_regalloc.c` | 分层线性扫描寄存器分配 | 新写（算法仿 c51 linscan） |
| `c251_optimize.c` | 汇编级窥孔优化 | 参考 c251-opt.inc |
| `c251_encode.c` | Source Mode 编码（AsmInstr → bytes） | 提取编码表（精简表）+ sim251 验证 |
| `c251_lib.inc` | 运行时库（`?C?` 例程汇编源码，只含必需例程） | 从 c251-lib.inc 摘取 |
| `c251_output.c` | asm/hex 写出 | 共享输出模块 / 最小裁剪 |
| `c251_link.c` | 多文件链接 + STARTUP251 启动代码注入 | 最小实现 |

## 5. 指令选择策略（16 位优先）

### 5.1 寄存器模型（分层，大小端规约）

- 字节：R0-R7（bank 0）
- 16 位：WR0/WR2/WR4/WR6（= R0:R1 等，**大端：Rj=高字节**）
- 32 位：DR0/DR2/DR4（= WR0:WR2 等拼接，小端布局，**DR4 = WR6:WR4**）
- 值宽度映射：`char → 1 字节寄存器`，`int/short → WRj`，`long/指针 → DRk`
- 16 位值优先整个 WRj 分配（避免 C51 高/低字节分离式分配）
- linscan 扩展：活跃区间按**值宽度分层着色**；分配 WR4 隐式占用 R4+R5，冲突检测按占用字节区间计算

### 5.2 算术模式（对照 c251-ops.inc 编码）

| SSA 指令 | 生成模式 | 编码示例 |
|----------|---------|---------|
| ADD (16位) | `ADD WRj,WRk` / `ADD WRj,#imm16` | 2D (j/2)4\|(k/2) |
| MUL (16位) | `MUL WRj,WRk` → 32 位结果 | AD (j/2)4\|(k/2) |
| DIV/MOD (16位) | 硬件 `DIV WRj` | 8D |
| DIV/MOD (32位) | 调 `?C?` 例程 | — |
| CMP (16位) | `CMP WRj,#imm` → `JNC/JC` 等条件跳转族（CMP_JE/JNE/JG/JLE 全套） | BD |
| SHL/SHR (16位) | `SLL/SRL/SRA WRj` | 3E/1E/0E |
| ZEXT/SEXT | `MOVZ WRj,Rm` / `MOVS WRj,Rm`（16 位加载即扩展） | 0A/1A |
| 8 位值 | Rm/dir8 指令（与 251 兼容的 8051 子集） | 7C/7E |

### 5.3 寻址模式

- near 变量（EDATA）：`MOV Rm,dir16` / `@WRj` 间接（16 位地址）
- far / xdata 指针：`@DRk` 间接（24 位地址，空间选择由高字节路由；sim251 `regop2_ind` 已支持 XFR 窗口）
- code 常量：`MOVC A,@DPTR` 族 / DPX 扩展寻址
- sfr（0x80-0xFF）：直接寻址 `MOV dir8`；sbit：A9 位指令族（SETB/CLR/CPL/JB/JNB）

## 6. XSMALL 内存模型

| 项 | Keil XSMALL 语义 | c251cc 实现 |
|----|-----------------|-------------|
| 默认变量 | near（EDATA，16 位地址） | 新增 `SEC_EDATA` SectionKind，`@WRj`/dir16 寻址 |
| 默认常量 | code | SEC_CODE，`MOVC @DPTR` 访问 |
| 显式空间 | data/idata/xdata/code/edata | 复用前端 `ctype_data` 属性 |
| 默认指针 | 4 字节 far*（1 空间字节 + 3 地址字节） | 指针类型带空间标记；near* 优化为 2 字节 |
| 栈/局部 | near 栈（EDATA） | EDATA 栈帧，SP/SPH |
| 链接 | — | `obj.h` 增加 `RELOC_ABS24`（far 指针 reloc） |

C51 的 SEC_DATA/SEC_IDATA/SEC_XDATA 保留（显式空间声明在 251 上仍可用）。

## 7. Keil C251 ABI（以 c251-call.inc 记录为准，逐项对照 Keil 输出验证）

- **参数传递**（REGPARMS，寄存器不足走栈）：u8 依次 R7→R5→R3→R1；u16 依次 WR6→WR4→WR2→WR0；u32/far 指针 DR4→DR0；混合类型按声明序填充
- **返回值**：u8→R7；u16→WR6（R6:R7 大端）；u32→DR4
- **调用约定**：caller-saves——调用点保存跨调用活跃值；普通函数 prolog/epilog 不保存寄存器
- **中断函数**：prolog/epilog 保存 PSW + 用到的寄存器；`interrupt_id` 映射 STC32G 向量表（sim251 `mcs251.h` VEC_*：INT0=0x03, T0=0x0B, …）
- **位返回**：Carry 标志

## 8. 运行时库（c251_lib.inc）

- 从 tinycc_c251 `c251-lib.inc` 摘取**实际用到的** `?C?` 例程：先只含 32 位除法/移位等必需项，用到再补（遵循 D8 精简原则，不整文件搬运）
- 例程名与 Keil 一致（`?C?` 前缀），**逐例程用 Keil 输出反汇编交叉验证语义**
- 32 位运算策略：`u32 + - * & | ^ << >>` 用硬件 DRk 指令；`u32 / %` 调 `?C?` 例程（Keil 同款策略）
- 启动代码：仿 c51_link_startup 模式注入（初始化 EDATA/SPX/DPX、调用 main、中断向量表跳转）

## 9. 验证闭环（与 Keil 持续对齐）

### 9.1 脚本迁移

从 `D:\work\tinycc_c251\tests\c251\` 复制到 `scripts/c251/`，适配 c251cc 路径/输出格式：

| 脚本 | 作用 |
|------|------|
| `c251_sim.py` | c251cc hex → sim251 执行，解析返回值/寄存器 dump |
| `sim_keil_validate.py` | 同一源码 Keil 编译 → golden hex → sim251 跑 → 与 c251cc 行为对比（行为对齐） |
| `keil_size_compare.py` | 逐函数/整体代码大小对比（大小对齐） |
| `stc32g_build.py` + `stc32g_compare.py` | STC32G 官方示例编译 + 与 Keil 构建结果对比 |
| `cross_validate.py` | Keil golden 指令序列 vs c251cc 序列的反汇编级 diff |
| `run_suite.py` | test/ 全量回归 |

### 9.2 测试范围（test/ 下所有文件）

- `test/suite/`（73 个行为测试）→ c251cc 编译 → sim251 跑，行为断言
- `test/execute/`（216 个）→ 同上
- `test/ssa/`（81 个）→ 后端正确性（汇编输出检查）
- `test/stc32g/`（32 个官方示例）→ 分阶段编译跑通，与 Keil 输出持续对比
- golden 参考记录在 `scripts/c251/golden/`（Keil .LST/.hex）

### 9.3 对齐节奏

每实现一个功能模块 → 跑一轮 sim_keil_validate + keil_size_compare → 有偏差立即定位修正。对齐是持续机制而非一次性验收。

## 10. 里程碑

每阶段门禁：suite 全过 + Keil 对齐。

| 里程碑 | 内容 | 验收 |
|--------|------|------|
| M1 骨架 | c251cc.exe 平台选择 + obj/输出/链接裁剪 + 编码器骨架（mov/arith 基础表）+ 分层 linscan 雏形 | test/suite 基础算术测试过 sim251 |
| M2 核心指令 | 16 位算术/比较/控制流/函数调用完整 isel | test/execute 全部跑通 sim251；keil_size_compare 启动 |
| M3 XSMALL 完整 | near 变量/栈帧/far 指针/@DRk 间接/SEC_EDATA/REGPARMS 传参 | sim_keil_validate 行为对齐通过 |
| M4 外设与中断 | sfr/sbit 全量、中断函数、STC32G 定时器/串口/GPIO 示例 | stc32g 前 8 个示例跑通 + Keil 对比 |
| M5 全量对齐 | 32 位运算例程、peephole 打磨、STC32G 全部示例、测试脚本全绿 | 32 个示例 + suite/execute/ssa 全绿，Keil 大小差距记录在案 |

## 11. 风险与开放问题

1. **Keil C251 传参细节**：REGPARMS 寄存器表需在 M3 用 Keil 输出实证确认（u8 顺序 R7→R5→R3→R1 等），如有出入以 Keil 实测为准
2. **far 指针空间模型**：1 空间字节 + 3 地址字节的布局与空间路由（code/data/xdata/edata）需与 sim251 内存映射对齐（CODE 64K / EDATA 64K / XRAM 64K）
3. **编码表提取工作量**：ops/load/call inc 注释中的编码需逐个用 sim251 `decode_impl.inc` + `functional.py` 交叉验证，M1 先覆盖 mov/arith 基础表
4. **STC32G 示例复杂度**：部分示例（DMA/CAN/LIN/Flash）依赖复杂外设，sim251 外设模型可能未覆盖，M5 的"全部示例"按 sim251 实际覆盖能力界定
5. **tcc.exe 构建**：需确认 tcc 支持当前 src/core 代码（现有 c51cc 已用 tcc 构建成功，风险低）
