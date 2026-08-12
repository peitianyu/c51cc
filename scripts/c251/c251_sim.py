#!/usr/bin/env python3
"""c251cc hex → sim251 执行 → 断言返回值 (R6:R7 大端)。

用法:
  python scripts/c251/c251_sim.py                    # 跑 test/suite/ 全部
  python scripts/c251/c251_sim.py test/suite/01_const_expr.c  # 单个
  python scripts/c251/c251_sim.py --filter "0[1-5]"  # 过滤
  python scripts/c251/c251_sim.py --ret-reg A       # u8 返回断言 R[11] (A)

期望值约定: 源码中 `return EXPR;  /* VALUE */` 注释, 或 `/* EXPECT VALUE */`。
返回寄存器: 默认 WR6 (R6:R7 大端, Keil u16 返回); `/* RETREG A */` 或
`--ret-reg A` 断言 A 寄存器 (R[11], Keil u8 返回)。文件注释优先于命令行。
"""
import argparse
import glob
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
MCS251 = os.environ.get("MCS251", os.path.join(ROOT, "sim251", "mcs251.exe"))
C251CC = os.environ.get("C251CC", os.path.join(ROOT, "scripts", "c251cc.exe"))
MAX_CYCLES = int(os.environ.get("C251_MAX_CYCLES", "2000000"))


def parse_expected(src_text):
    """期望值解析, 优先级从高到低:
    1. `/* EXPECT N */`
    2. `return EXPR; /* ... = N ... */` (紧跟 return 的注释, 取注释内最后一个 `= N`)
    3. 无检查点模式时 (`? 0 : N` 硬件测试风格), 独立注释行 `/* ... = N */` 取最后一个
    4. 返回 None → 调用方走 M3 约定 (编号 >=72 或检查点风格, 期望 0)
    """
    def nums_in_comment(comment):
        # 注释内所有 `= N` (排除十六进制 0x.., 取最后一个)
        nums = re.findall(r"=\s*(?!0[xX])(-?\d+)", comment)
        return int(nums[-1]) if nums else None

    m = re.search(r"/\*\s*EXPECT\s+(-?\d+)\s*\*/", src_text)
    if m:
        return int(m.group(1))
    # return 行后紧跟的纯数字注释
    m = re.search(r"return\s+[^;]*;\s*/\*\s*(-?\d+)\s*\*/", src_text)
    if m:
        return int(m.group(1))
    # return 行后紧跟的 `... = N` 注释
    for cm in re.finditer(r"return\s+[^;]*;\s*/\*(.*?)\*/", src_text, re.S):
        v = nums_in_comment(cm.group(1))
        if v is not None:
            return v
    # 检查点风格 → 硬件测试, 期望 0:
    #   a) `return expr ? 0 : N`
    #   b) `if (...) return N;` 多个检查点 + 末尾 `return 0;`
    if re.search(r"return\s+[^;]*\?\s*0\s*:", src_text):
        return 0
    rets = re.findall(r"return\s+(-?\d+)\s*;", src_text)
    if len(rets) >= 2 and rets[-1] == "0":
        return 0
    # 独立注释行 `/* ... = N ... */` (取最后一个, 通常离 return 最近)
    main_body = src_text[src_text.find("main"):]
    best = None
    for cm in re.finditer(r"/\*(.*?)\*/", main_body, re.S):
        v = nums_in_comment(cm.group(1))
        if v is not None:
            best = v
    if best is not None:
        return best
    return None


def parse_retreg(src_text):
    """返回寄存器注释: `/* RETREG A */` → 'A', `/* RETREG WR6 */` → 'WR6', 无则 None。"""
    m = re.search(r"/\*\s*RETREG\s+(A|WR6)\s*\*/", src_text)
    if m:
        return m.group(1)
    return None


def run_hex(hex_path, max_cycles=MAX_CYCLES, ret_reg="WR6"):
    with tempfile.TemporaryDirectory() as d:
        dump = os.path.join(d, "dump.txt")
        r = subprocess.run(
            [MCS251, "-bios", hex_path, "-d", "cpu", "-D", dump,
             "--cycles", str(max_cycles)],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=120)
        if r.returncode != 0:
            return None, r.stderr.strip()
        regs = {}
        if os.path.exists(dump):
            for line in open(dump):
                # sim251 每行打印 8 个寄存器 (R[00]..R[07] 同行) → 用 finditer 捕获全部
                for m in re.finditer(r"R\[(\d+)\]\s*:\s*([0-9a-fA-F]{2})", line):
                    regs[int(m.group(1))] = int(m.group(2), 16)
        if ret_reg == "A":
            # Keil u8 返回: A 寄存器 = R[11] (RF_ACC), 无符号 0-255
            return regs.get(11, 0), ""
        r6 = regs.get(6, 0)
        r7 = regs.get(7, 0)
        ret = (r6 << 8) | r7
        if ret > 0x7FFF:
            ret -= 0x10000
        return ret, ""


def compile_c(source, outdir):
    # hex 写入统一临时目录，避免污染源目录（test/ 下 86 个未提交改动须保持原样）
    hex_path = os.path.join(outdir, os.path.splitext(os.path.basename(source))[0] + ".hex")
    r = subprocess.run([C251CC, "-hex", "-o", hex_path, source],
                       capture_output=True, text=True, encoding="utf-8", errors="replace",
                       timeout=120)
    if r.returncode != 0:
        return None, r.stderr
    return hex_path, ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("tests", nargs="*")
    ap.add_argument("--filter", default=None)
    ap.add_argument("--ret-reg", choices=["A", "WR6"], default="WR6",
                    help="返回寄存器: WR6 (默认, R6:R7 大端 u16) 或 A (R[11], u8)")
    args = ap.parse_args()

    if args.tests:
        files = args.tests
    else:
        files = sorted(glob.glob(os.path.join(ROOT, "test", "suite", "*.c")))
    if args.filter:
        files = [f for f in files if re.search(args.filter, os.path.basename(f))]

    ok = fail = skip = 0
    workdir = tempfile.TemporaryDirectory(prefix="c251sim_")
    for src in files:
        src_text = open(src, encoding="utf-8", errors="replace").read()
        exp = parse_expected(src_text)
        if exp is None:
            # M3 硬件测试 (编号 >=72) 约定: 返回 0 = 通过 (无 EXPECT 注释)
            bn = os.path.basename(src)
            is_m3 = len(bn) >= 2 and bn[:2].isdigit() and int(bn[:2]) >= 72
            if is_m3:
                exp = 0
            else:
                print(f"SKIP {bn:<40} (无期望值注释)")
                skip += 1
                continue
        hexp, cerr = compile_c(src, workdir.name)
        if hexp is None:
            print(f"FAIL {os.path.basename(src):<40} 编译错误: {cerr.splitlines()[-1] if cerr else ''}")
            fail += 1
            continue
        # 文件 `/* RETREG A */` 注释优先于命令行默认
        ret_reg = parse_retreg(src_text) or args.ret_reg
        ret, rerr = run_hex(hexp, ret_reg=ret_reg)
        if ret is None:
            print(f"FAIL {os.path.basename(src):<40} sim251 错误: {rerr}")
            fail += 1
            continue
        if ret == exp:
            print(f"OK   {os.path.basename(src):<40} ret={ret} ({ret_reg})")
            ok += 1
        else:
            print(f"FAIL {os.path.basename(src):<40} ret={ret} 期望={exp} ({ret_reg})")
            fail += 1
    workdir.cleanup()

    print(f"\n结果: {ok} OK / {fail} FAIL / {skip} SKIP")
    return 0 if fail == 0 and ok > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
