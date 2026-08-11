#!/usr/bin/env python3
"""c251cc hex → sim251 执行 → 断言返回值 (R6:R7 大端)。

用法:
  python scripts/c251/c251_sim.py                    # 跑 test/suite/ 全部
  python scripts/c251/c251_sim.py test/suite/01_const_expr.c  # 单个
  python scripts/c251/c251_sim.py --filter "0[1-5]"  # 过滤

期望值约定: 源码中 `return EXPR;  /* VALUE */` 注释, 或 `/* EXPECT VALUE */`。
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
    m = re.search(r"/\*\s*EXPECT\s+(-?\d+)\s*\*/", src_text)
    if m:
        return int(m.group(1))
    m = re.search(r"return\s+[^;]*;\s*/\*\s*(-?\d+)\s*\*/", src_text)
    if m:
        return int(m.group(1))
    return None


def run_hex(hex_path, max_cycles=MAX_CYCLES):
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
                for m in re.finditer(r"R\[(\d+)\]:\s*([0-9a-fA-F]{2})", line):
                    regs[int(m.group(1))] = int(m.group(2), 16)
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
        exp = parse_expected(open(src, encoding="utf-8", errors="replace").read())
        if exp is None:
            print(f"SKIP {os.path.basename(src):<40} (无期望值注释)")
            skip += 1
            continue
        hexp, cerr = compile_c(src, workdir.name)
        if hexp is None:
            print(f"FAIL {os.path.basename(src):<40} 编译错误: {cerr.splitlines()[-1] if cerr else ''}")
            fail += 1
            continue
        ret, rerr = run_hex(hexp)
        if ret is None:
            print(f"FAIL {os.path.basename(src):<40} sim251 错误: {rerr}")
            fail += 1
            continue
        if ret == exp:
            print(f"OK   {os.path.basename(src):<40} ret={ret}")
            ok += 1
        else:
            print(f"FAIL {os.path.basename(src):<40} ret={ret} 期望={exp}")
            fail += 1
    workdir.cleanup()

    print(f"\n结果: {ok} OK / {fail} FAIL / {skip} SKIP")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
