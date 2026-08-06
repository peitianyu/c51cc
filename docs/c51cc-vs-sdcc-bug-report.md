# c51cc vs SDCC 对比测试报告（hex 处理 bug 专项）

日期: 2026-08-06
环境: Android / Termux (aarch64), clang 20, SDCC 4.5.0 (源码构建)
方法: 同一 C 源码分别用 c51cc 与 SDCC 编译出 Intel HEX, 送入同一 8051 仿真器
      (sim8051.py) 执行, 对比返回值; 同时对 hex 文件做结构校验(校验和/记录格式/地址)。

## 0. 测试规模与总体结论

- 共对比 78 (test/) + 72 (test/suite/) 个用例
- hex **文件格式**(Intel HEX 规范) 100% 正确: 校验和、记录类型、行长、EOF、地址范围全部通过
- hex **内容**(字节) 与 c51cc 自己的汇编输出一致, 说明编码器(c51_encode)本身正确
- 真正的 bug 分布在: hex 段输出选择、SSA 后端指令选择、寄存器分配、控制流生成

## 1. 【P0】hex 输出模块丢失数据段 —— 全局变量初始化全部失效

**位置**: `src/core/c51/c51_output.c` `c51_write_hex()`

```c
for (Iter it = list_iter(obj->sections); ...) {
    Section *sec = iter_next(&it);
    if (!sec || sec->kind != SEC_CODE || sec->bytes_len <= 0) continue;  // ← BUG
    ...
}
```

全局/静态变量分配在 `SEC_DATA` 段 (`c51_gen_global_var.c:49`), 但 hex 输出**只遍历
SEC_CODE 段**, `SEC_DATA` / `SEC_IDATA` 段的初始化数据被静默丢弃。
启动代码只清 IDATA, 于是所有带初值的全局变量运行时全为 0。

| 用例 | c51cc | SDCC(正确) | 说明 |
|---|---|---|---|
| 71_ifdef_cond   | 0   | 2    | feat_a=1, val_check=1 全变 0 |
| 53_global_init_expr | 0 | 108 | 全局表达式初值丢失 |
| 42_global_array_init | 43 | 231 | g_arr={10,20,30,40} 丢失 |
| 68_static_local | 1542 | 6   | static 局部初值丢失 |
| 33_logical_ops  | 0   | 22  | 依赖全局 g 变量 |
| 34_short_circuit| 28270 | 111 | 全局 g_count 错乱 |
| 51_void_func    | 2570 | 65  | 全局 g_x/g_y 错乱 |

验证: 汇编里 `feat_a: DB 001H, 000H` 定义正确, 但 hex 里没有任何对应字节。

## 2. 【P0】循环/递归死循环 —— 变量版本寄存器分配错乱

**位置**: SSA 值版本(phi)到寄存器的分配 (`c51_isel_regalloc.c` / `c51_isel_arith.c`)

同一变量的不同 SSA 版本被分配/使用到不一致的寄存器:
- 循环条件比较用 R2:R3, 循环体算术却用 R6:R7
- `sum = sum + i` 被编码成 `MOV A,R5; ADD A,R7` (i 在 R2:R3, 却加 R7)
- `i = i + 1` 的源用 R6:R7, 结果又覆盖 R2:R3 与 sum

典型产出(16_for_loop):
```
L2:  MOV A, R5 ; sum低
     ADD A, R7 ; ← 应为 R3 (i低)
L3:  MOV A, R7 ; ← 应为 R3
     ADD A, #1
     MOV R3, A
     MOV A, R6 ; ← 应为 R2 (i高)
     ADDC A, #0
     MOV R2, A
     MOV R5, R7 ; sum被覆盖成 i+1 临时值
     MOV R4, R6
     SJMP L1
```

| 用例 | c51cc | SDCC(正确) | 现象 |
|---|---|---|---|
| 15_while_loop   | 死循环 | 45  | 仿真超时 |
| 16_for_loop     | 死循环 | 55  | 仿真超时 |
| 18_nested_loop  | 死循环 | 15  | 仿真超时 |
| 19_break_continue | 死循环 | 25 | 仿真超时 |
| 23_func_recursive | 死循环 | 133 | 递归+局部变量互踩 |
| 62_power        | 死循环 | 60* | 递归+乘法 |
| test_for        | 7710 | 45  | sum=0+1+..+9 应为45 |
| 54_loop_counter | -32638 | 20 | s+n 用了参数副本(未递减的 n) |
| 63_switch_fallthrough | 105 | 17 | 16位加高位被 `MOV A,#0` 覆盖 |

*(62 的 SDCC 值因 main 尾调用优化需剔除, 见 §7)*

## 3. 【P1】局部 struct / union / 数组 寻址错误

局部复合变量既不分配 IDATA 存储, 又使用错误寻址模式:
- 内容被直接当指针 MOVX 读 (41: `u.i=0x1234` → `MOV DPTR,#0x1234; MOVX A,@DPTR`)
- IDATA 存储的变量用 MOVX (XDATA) 访问 (38)
- 递归函数局部变量静态分配互踩 (23)

| 用例 | c51cc | SDCC(正确) | 说明 |
|---|---|---|---|
| 38_struct_basic     | 0   | 25  | p.x=3,p.y=4 存 IDATA, MOVX 读 XDATA → 0 |
| 40_struct_nested    | 512 | 10  | 结构体内容被当指针 |
| 41_union_basic      | 0   | 70  | union 完全未分配存储 |
| 66_ptr_to_struct    | 140 | 100 | |
| 67_array_of_struct  | 0   | 60  | |
| 25_ptr_basic        | 25642 | 142 | |
| 26_ptr_param        | 514 | 30  | |
| 27_array_basic      | 45  | 156 | |
| 28_array_ptr        | 0   | 50  | |
| 48_ptr_arith        | 0   | 90  | |
| 60_bubble_sort      | 0   | 7   | |
| 61_gcd_lcm          | 0   | 10  | |

## 4. 【P1】全局数组下标寻址断链

42_global_array_init: `g_arr[i]` 的地址计算:
```
MOV DPTR, #g_arr      ; ← 数组地址
... 偏移计算 i*2 → R3:R2
MOV DPTR, #__spill_0  ; ← BUG: DPTR 被覆盖, g_arr 地址丢失
...
MOV A, @R0            ; 又从 IDATA 间接读 (g_arr 是 SEC_DATA)
```

## 5. 【P1】if 分支块错位

11_cmp_lt_gt / 12_cmp_signed: `if(a<b) r+=1; if(b>a) r+=2; ...` 期望 63,
c51cc=48 (=32+16, 只执行了最后两个条件)。CFG 真/假分支的块标号映射错误,
前 4 个条件的结果丢失。

## 6. 【P2】其他

- **switch 分派**: 20_switch_case (105 vs 99), 63
- **多 return 路径**: 52_multi_return (-246 vs 10) —— 纯 int 分支, 疑似分支块/返回路径寄存器污染
- **语言特性缺失** (编译失败, 非崩溃):
  - 整数常量后缀 `1U`/`2U`: `test_isel_arith_int.c:42 Unexpected token: 'U'`
  - C99 复合字面量 `(int[]){...}`: `test_ssa.c:133 ')' expected, but got [`

## 6b. 设计差异(双方都正确, 非 bug)

- **char 默认符号性**: SDCC 的 char 默认 **unsigned**, c51cc(Keil 风格) 默认 **signed**。
  30_type_cast (c51cc=239 vs sdcc=495) 与 47_mixed_types (1246 vs 1502) 都在各自
  char 语义下计算正确, 属于设计差异。对比时需注意。
- **指针大小**: 58_sizeof c51cc=10 vs sdcc=11 —— SDCC 默认 generic 指针 3 字节,
  c51cc 用 2 字节。

## 7. 对比方法学(非 c51cc bug, 但影响结果解读)

1. **返回值约定**: SDCC 的 16 位返回值在 **DPTR**, Keil/c51cc 在 R6:R7
2. **尾调用优化陷阱**: SDCC 对 `main(){ return f(x); }` 生成 `ljmp _f`
   (不压返回地址), RET 后回到启动段 → 仿真死循环重启。62_power 的 SDCC 值
   因此不可信, 需在对比时检查 timed_out 标志。
3. **指针大小设计差异**: 58_sizeof c51cc=10 vs sdcc=11 —— SDCC 默认 generic
   指针 3 字节, c51cc 用 2 字节, 属设计差异非 bug。
4. **char 默认符号性差异**: 30_type_cast / 47_mixed_types 的差异来自 SDCC
   char 默认 unsigned、c51cc 默认 signed, 双方各自正确, 非 bug。
5. **49_func_ptr**: SDCC 编译失败 (Keil 风格 sbit/函数指针语法不兼容), 无法对比。

## 8. 构建问题: 官方 build.sh 在 64 位 Linux 上不可用

官方构建 `scripts/build.sh` 用 tcc 编译, 在 Linux/Android aarch64 上:
- `minitest.h` 的 TCC 分支 `__asm__` 定义符号后 `&__start_testsec` 报
  "lvalue expected" (TCC 不把汇编符号当可取地址的 lvalue)
- 即便绕过 (不带 MINITEST_IMPLEMENTATION 构建产品编译器), tcc 产物运行即
  SIGSEGV (PC 跳到栈地址, 疑似指针截断/未定义行为)

**clang / gcc 构建完全正常**:
```
clang -O0 src/main.c src/core/*.c src/core/c51/*.c -o scripts/c51cc_clang
```
作者在 Windows/TCC-PE 下开发, Linux 用户需换编译器。

## 9. 优化建议(按优先级)

| 优先级 | 建议 | 影响 |
|---|---|---|
| P0 | hex 输出含 SEC_DATA/IDATA 段, 或生成启动复制代码 (XINIT 模式) | 全局初始化全恢复 |
| P0 | 修 SSA 版本→寄存器分配一致性 (循环 phi 点) | 消除死循环/累加错误 |
| P1 | 局部复合变量: 分配 IDATA 存储 + 正确寻址 (data 直接寻址/IDATA 间接, 禁 MOVX) | struct/union/数组/递归 |
| P1 | 16 位算术: 低字节结果先落寄存器再算高字节 | 大量算术类 |
| P1 | CFG 真假块映射与 switch 跳转表验证 | 分支/switch |
| P2 | lexer 支持 U/L 整数后缀、C99 复合字面量 | 标准 C 兼容 |
| P2 | 构建脚本改用 gcc/clang, 修 minitest.h TCC 分支 | 跨平台可构建 |

## 附: 复现命令

```bash
# 构建 c51cc (clang)
clang -O0 src/main.c src/core/*.c src/core/c51/*.c -o scripts/c51cc_clang

# 全量对比 (需要 SDCC 4.5.0, SDCC_HOME 指向构建目录)
python3 scripts/compare_sdcc.py                # test/
python3 scripts/compare_sdcc.py --src-dir suite
python3 scripts/compare_sdcc.py --filter struct
```

## 10. 修复记录（2026-08-06 第二轮，按用户要求"都修复掉"）

### 已修复（13 项，含 2 轮）
| # | Bug | 文件 | 效果 |
|---|---|---|---|
| 1 | **hex 输出丢数据段**：只写 SEC_CODE，全局初始化数据不进 hex | c51_output.c | 全局/static 初始化恢复（71/53/51/03/34 等） |
| 2 | **SEC_DATA 从 0x00 排**踩寄存器组 | c51_gen_global_var.c | reserve 16 字节 |
| 3 | **循环死循环**：回边 phi 源 interval 未扩展 + coalescing 拒绝合并 | c51_isel_regalloc.c | 16/15/19/20 等死循环消除（测试值精确命中） |
| 4 | **临时寄存器覆盖活跃值**：alloc_temp_reg 未避开 linscan 分配 | c51_isel_util.c + interval 快照 | test_for/54 修复 |
| 5 | **多文件 -I 路径丢失**：pp_global_free 中途释放 | pp.c / main.c | 多文件 include 可用 |
| 6 | **整数后缀 U/L** 不支持 | lexer.c | `1U/2U/…UL` 可解析 |
| 7 | **C99 复合字面量** `(int[]){..}` 不支持 | parser.c/ssa.c/cc.h | test_ssa 可编译 |
| 8 | **指针变量初始化** `char *p = q;` eval_intexpr 误报 | parser.c | 指针赋变量可用 |
| 9 | **多变量声明指针嵌套** `const char *x, *y` 双层指针 | parser.c | 类型正确 + const 保留 |
| 10 | **extern 引用被当定义** → 多文件链接 duplicate | c51_isel_mem.c | extern 符号正确 |
| 11 | **#if 行尾 `//` 注释**致表达式解析失败 | pp.c | 10+ 用例恢复 |
| 12 | **多文件 main 去重**固定保留首文件 | main.c | 保留第一个含 main 的文件 |
| 13 | **无 STARTUP.A51 时无启动代码** | c51_gen.c | 内置默认启动注入 |

### 效果
- 自带套件: PASS 56 → 76（无回归）
- SDCC 4.5.0 回归测试集（350 个可选）: **125 PASS** / 9 真差异 / 159 编译失败（多为语言特性缺失）
- 对比工具: `scripts/compare_sdcc.py`（自带套件）+ `scripts/run_sdcc_tests.py`（SDCC 回归集，自动 stub testfwk + wrapper main + DPTR/R6R7 双约定）

### 剩余问题（未修，工程量大的特性缺失/边缘 bug）
- **9 个行为差异**（c51cc 断言失败，SDCC 全过）：bug-1292721/1408066/2175/2228/227710/2385/2458/2473/2582 —— 零散后端 bug（多重 !、volatile、struct 参数、位运算寄存器压力等）
- **~159 编译失败**：long long、float 运算、位域、`__addressmod` 等 SDCC 特有语法/类型缺失
- **2 个崩溃**：全局数组元素地址初始化 `&(arr[1].i)`（bug-1898/2123）

## 11. 修复记录（2026-08-06 第三轮，继续修复）

### 新增修复
| # | Bug | 文件 |
|---|---|---|
| 14 | **volatile 局部变量被常量折叠/寄存器化**（volatile 语义丢失）：SSA 读走 var_map 值而非内存 load | ssa.c（AST_LVAR 读、AST_DECL/ASSIGN 写强制 load/store） |

### 定位的深层根因（未完全修复，架构级）
- **SEC_DATA 与 SEC_IDATA 物理地址重叠**：两段都从 IRAM 0x00 起（各自 reserve 16/40），
  SEC_DATA 变量（0x10-0x7F 直接寻址）与 SEC_IDATA 变量（spill/参数槽）物理地址冲突 →
  变量互相覆盖（bug-2448：badfunc 写参数槽覆盖 __fail_map 等）。修复需 SEC_IDATA 符号
  移到 0x80+ 且后端支持 @R0 间接访问（当前 SEC_IDATA 用直接寻址，>0x7F 失效）——
  涉及 load/store 生成全面改造，未完成。

### 最终状态（SDCC 回归集 350 可选用例）
- **121 PASS** / 9 行为差异（bug-1292721/1408066/2175/2228/227710/2385/2448/2458/2473）
- 162 c51cc 编译失败（long long/float/位域/__addressmod 等特性缺失）
- 自带套件 PASS 76 无回归

### 调试教训
- **测试脚本返回值语义**：ASSERT 失败计数/行号返回方式会影响生成的代码布局
  （三元表达式 vs 简单返回触发不同变量分配 → 地址冲突假象），对比脚本需用简单确定的形式
- **expire 条件 `<=` vs `<`**：净效果≈0（interval end 语义两可），保持原始
- **调试打印（fprintf）会改变堆布局**，可能掩盖/暴露寄存器分配 bug，结论需在干净构建复验

## 12. 修复记录（2026-08-06 第四轮）

### 尝试与结论
- **SEC_DATA/SEC_IDATA 地址重叠**（bug-2448 根因）：尝试 SEC_IDATA 移 0x80+ + @R0 间接访问改造
  （emit_mov/load_symbol_byte/store_symbol_byte 三处改为 `MOV R0,#addr; MOV @R0`），
  **回归 14 个 + 2 hang**（@R0 改造覆盖不全，spill 等路径仍用直接寻址）→ 回退。
  **结论**：需全面审计 SEC_IDATA 访问路径（含 spill store/load、emit_store 主路径等）才能安全改造，属架构级。
- **SSA phi 悬空**（bug-2458 根因）：pass_const_branch 折叠 br 后死块 phi arm 未清理 → 块合并后
  phi 两 arm 同块且值不同 → 无法简化 → 悬空。尝试在 pass_const_branch 清理死 arm，无效
  （实际是 br 未折叠、块合并路径的深层多 pass 交互）→ 回退。
- **测试脚本确认**：位图版本（`__fail_map |= 1<<(line%32)`）最可靠；__fail_line 三元返回触发
  布局污染假象（已弃用）。

### 最终状态（稳定基线）
- SDCC 回归集：**153 PASS** / 5 行为差异（bug-1292721/2175/2448/2458/2582）/
  162 编译失败（特性缺失）
- 自带套件：PASS 76 无回归

### 剩余 5 个 diff 根因分类
1. **bug-2448**：SEC_DATA/SEC_IDATA 物理重叠（架构级，需 @R0 全面改造）
2. **bug-2458**：SSA 优化 phi 悬空（多 pass 交互，深层）
3. **bug-1292721/2175/2582**：待进一步分析（static/volatile/struct 参数相关）

## 13. 修复记录（2026-08-06 第五轮：static局部变量 / SSA phi 残留标签 / struct 成员访问）

### 新增修复（5 个 commit：892799b/99c4873/32dce94/206b844）
| # | Bug | 文件 | 根因与修复 |
|---|---|---|---|
| 15 | **函数内 static 局部变量撞寄存器组+初值丢失**（bug-1292721 根因之一） | ssa.c | 静态局部（AST_GVAR）此前不注册进 unit->globals，isel fallback 建符号时既无 16 字节寄存器组/栈保留区（`__sloc_0` 落到 IRAM 0x00=R0，bar() 的 `MOV R0,#0` 把 ret 写回 0），初值也丢成全 0（`static char ret=7` 编出 DB 000H）。gen_stmt AST_DECL 加 AST_GVAR 分支 → ssa_add_global（含 init_instr），由 handle_normal_global_var 统一 reserve+写初值 |
| 16 | **SSA phi 置 NOP 残留块标签 → 幻影 CFG 边**（bug-1292721 死循环根因） | ssa.c/ssa_pass.c | ssa_try_remove_trivial_phi 把 trivial phi 置 NOP 时保留前驱块标签；尾部 NOP 被 rebuild_preds/pass_block_merge 当终止指令读取 → 幻影 preds，块合并把 preheader 的 `aa=bar()` 拉进循环体（每轮重执行→死循环）。修复：置 NOP 时清 args/labels；rebuild_preds/block_has_other_preds/pass_block_merge/block_has_terminator 改用最后非 NOP 指令作终止指令 |
| 17 | **pass_block_merge 误删尾部 PHI → 自环 jmp**（bug-1408066 链接错误） | ssa_pass.c | 块结构可为 `[JMP, PHI]`，list_remove_last 删的是 PHI 而非 JMP，残留 JMP 经 replace_label_all 变 `jmp b0` 自环 → 悬空 L0 重定位。改为按 effective terminator（最后非 NOP/PHI 指令）指针移除 |
| 18 | **全局 struct 成员访问错（struct 参数类）**（bug-2582 根因） | ssa.c | AST_STRUCT_REF/AST_ASSIGN 对 AST_GVAR 走 gen_expr（LOAD 整个 struct 当作指针）+offset，而非取地址（AST_BIT_REF 已正确处理 GVAR）。修复：GVAR 与 LVAR 一样 ssa_build_addr；嵌套 struct/数组字段的 STRUCT_REF 返回地址不 load |
| 19 | **嵌套 OFFSET 链无法折叠 → 寄存器残留**（bug-2582 读写错） | c51_isel_mem.c | emit_offset/emit_store/emit_load 折叠检查只解析一层 OFFSET(ADDR/LOAD)；嵌套 offset(offset(offset(addr,0),0),0)（嵌套 struct 成员产生）无法解析 → 外层按 linscan 寄存器复制内层值，而内层因折叠未物化 → 拿到 mpStyle 写后残留的 R2:R3。新增 resolve_offset_chain 递归解析 (符号,总偏移) 三处统一使用；不解析 LOAD(ADDR(sym)) 链（指针字段加载，折叠会把指针值错当基地址） |

### 调试工具
- `C51CC_SKIP_PASS`（ssa_pass.c）/ `C51CC_SKIP_PEEP`（c51_optimize.c）：环境变量跳过指定优化 pass/窥孔，用于二分定位。
- `scripts/run3.py` / `scripts/suite_check.py`：单独跑 SDCC 3 个 bug 用例 / 自带套件（Android 可跑，替代 Windows run_suite.py）。

### 最终状态
- SDCC 回归集：**150 PASS** / 3 行为差异（bug-2448/2458/2632）/ 162 编译失败（特性缺失）
- 自带套件：66/6（6 个为历史遗留：14_if_chain/23_func_recursive/49_func_ptr/52_multi_return/62_power/69_enum，与基线一致）

### 剩余 3 个 diff 根因
1. **bug-2448**：SEC_DATA/SEC_IDATA 物理重叠（架构级，需 @R0 全面改造 + IDATA 移 0x80+）
2. **bug-2458**：SSA phi 悬空（多 pass 交互，深层）
3. **bug-2632**：大数组下标寻址（testArr255[255] 超出 SEC_DATA 直接寻址域，i*24+j 索引地址计算断链；全优化级别均挂）
