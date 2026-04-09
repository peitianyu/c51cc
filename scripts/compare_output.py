#!/usr/bin/env python3
"""
C51CC vs Keil ASM / HEX 对比工具
=================================

用法:
  python compare_output.py <test_name>                      # 对比 ASM + 仿真
  python compare_output.py <test_name> --mode asm           # 只对比 ASM
  python compare_output.py <test_name> --mode trace         # 逐步仿真 trace
  python compare_output.py <test_name> --mode trace --max-steps 500
  python compare_output.py <test_name> --source-dir suite   # 指定源目录标签
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sim8051 import run_hex, CPU8051, load_hex


def find_files(output_root, source_tag, test_name):
    """查找 keil 和 c51cc 的输出文件"""
    keil_dir = os.path.join(output_root, "keil", source_tag, test_name)
    c51cc_dir = os.path.join(output_root, "c51cc", source_tag, test_name)

    files = {
        "keil_hex": None,
        "c51cc_hex": None,
        "keil_asm": None,
        "c51cc_asm": None,
    }

    for d, prefix in [(keil_dir, "keil"), (c51cc_dir, "c51cc")]:
        if not os.path.isdir(d):
            continue
        for f in os.listdir(d):
            path = os.path.join(d, f)
            if f.endswith(".hex"):
                files[f"{prefix}_hex"] = path
            elif f.endswith(".asm"):
                files[f"{prefix}_asm"] = path

    return files


def show_asm_diff(keil_asm, c51cc_asm):
    """并排显示 ASM"""

    def read_lines(path):
        if not path or not os.path.exists(path):
            return []
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return [l.rstrip() for l in f.readlines()]

    kl = read_lines(keil_asm)
    cl = read_lines(c51cc_asm)

    print(f"\n{'='*110}")
    print(f"{'KEIL ASM':<52} | {'C51CC ASM':<52}")
    print(f"{'='*110}")

    max_len = max(len(kl), len(cl))
    for i in range(max_len):
        k = kl[i][:50] if i < len(kl) else ""
        c = cl[i][:50] if i < len(cl) else ""
        marker = "│" if k.strip() == c.strip() else "╳"
        print(f"  {k:<50} {marker} {c:<50}")


def show_trace(hex_path, label, max_steps=500):
    """输出仿真 trace"""
    code = load_hex(hex_path)
    cpu = CPU8051(code)

    print(f"\n{'='*80}")
    print(f"  {label} trace ({hex_path})")
    print(f"{'='*80}")

    for i in range(max_steps):
        if cpu.halted:
            print(
                f"  [{i:05d}] === HALTED === ret={cpu.get_return_signed()} "
                f"(R6:R7 = {cpu.iram[6]:02X}:{cpu.iram[7]:02X})"
            )
            break
        pc = cpu.pc
        op = code[pc]
        # 解码操作码名称 (简要)
        print(
            f"  [{i:05d}] PC={pc:04X} OP={op:02X} "
            f"A={cpu.acc:02X} B={cpu.b_reg:02X} "
            f"R0-R7=[{cpu.iram[0]:02X} {cpu.iram[1]:02X} {cpu.iram[2]:02X} {cpu.iram[3]:02X} "
            f"{cpu.iram[4]:02X} {cpu.iram[5]:02X} {cpu.iram[6]:02X} {cpu.iram[7]:02X}] "
            f"SP={cpu.sp:02X} CY={cpu._get_cy()}"
        )
        cpu.step()
    else:
        print(f"  [TIMEOUT after {max_steps} steps] ret={cpu.get_return_signed()}")


def show_sim_result(hex_path, label, max_steps=2_000_000):
    """显示仿真结果"""
    try:
        ret, insns, timeout = run_hex(hex_path, max_steps)
        status = "TIMEOUT" if timeout else "OK"
        print(f"  {label:<10} ret={ret:<10} insns={insns:<8} status={status}")
        return ret, timeout
    except Exception as e:
        print(f"  {label:<10} ERROR: {e}")
        return None, True


def main():
    parser = argparse.ArgumentParser(description="C51CC vs Keil 输出对比")
    parser.add_argument("test_name", help="测试名称 (不含.c)")
    parser.add_argument("--repo-root", default=r"d:\ws\test\C51CC")
    parser.add_argument("--source-dir", default="test", help="源目录标签 (test/suite)")
    parser.add_argument(
        "--mode", default="all", choices=["all", "asm", "trace", "sim"], help="对比模式"
    )
    parser.add_argument("--max-steps", type=int, default=2000, help="trace 最大步数")
    args = parser.parse_args()

    output_root = os.path.join(args.repo_root, "output")

    # 尝试多个 source_dir
    source_tags = [args.source_dir]
    if args.source_dir == "test":
        source_tags.append("suite")

    files = None
    for tag in source_tags:
        files = find_files(output_root, tag, args.test_name)
        if files["keil_hex"] or files["c51cc_hex"]:
            print(f"[INFO] 使用 source_tag: {tag}")
            break

    if not files or (not files["keil_hex"] and not files["c51cc_hex"]):
        print(f"[ERROR] 没有找到 {args.test_name} 的输出文件")
        print(
            f"  搜索路径: {[os.path.join(output_root, 'keil', t, args.test_name) for t in source_tags]}"
        )
        return 1

    # 仿真比较
    if args.mode in ("all", "sim"):
        print(f"\n[SIM] 仿真比较: {args.test_name}")
        print("-" * 60)
        kret = cret = None
        if files["keil_hex"]:
            kret, _ = show_sim_result(files["keil_hex"], "Keil")
        if files["c51cc_hex"]:
            cret, _ = show_sim_result(files["c51cc_hex"], "C51CC")
        if kret is not None and cret is not None:
            if kret == cret:
                print(f"  结果: ✓ 匹配 (ret={kret})")
            else:
                print(f"  结果: ✗ 不匹配! keil={kret} c51cc={cret}")

    # ASM 对比
    if args.mode in ("all", "asm"):
        show_asm_diff(files["keil_asm"], files["c51cc_asm"])

    # Trace 对比
    if args.mode in ("trace",):
        if files["keil_hex"]:
            show_trace(files["keil_hex"], "Keil", args.max_steps)
        if files["c51cc_hex"]:
            show_trace(files["c51cc_hex"], "C51CC", args.max_steps)

    return 0


if __name__ == "__main__":
    sys.exit(main())
