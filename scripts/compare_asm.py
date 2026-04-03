#!/usr/bin/env python3
"""
compare_asm.py - 对比 c51cc 与 keil 生成的汇编代码
逐个测试用例对比指令数、指令序列差异，汇总优化方向
"""

import os
import re
import sys
import argparse
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent

C51CC_DIR = REPO_ROOT / "output" / "c51cc" / "single-exec"
KEIL_DIR = REPO_ROOT / "output" / "keil" / "single-exec"

# 跳过注释和空行，只保留有效汇编指令
COMMENT_RE = re.compile(r";.*$")
LABEL_RE = re.compile(r"^\s*[A-Za-z_?][A-Za-z0-9_?]*:\s*$")


def strip_comment(line: str) -> str:
    return COMMENT_RE.sub("", line).strip()


def is_directive(line: str) -> bool:
    """跳过汇编器伪指令 (DB, DS, ORG, SEGMENT, RSEG, USING, EXTRN, PUBLIC, NAME, END)"""
    m = strip_comment(line).upper()
    for d in (
        "DB ",
        "DS ",
        "ORG ",
        "SEGMENT ",
        "RSEG ",
        "USING ",
        "EXTRN ",
        "PUBLIC ",
        "NAME ",
        "END",
        "ORG\t",
    ):
        if m.startswith(d) or m == d.strip():
            return True
    return False


def extract_instructions(path: Path):
    """从 .asm 文件提取有效指令（非注释、非标签、非伪指令）"""
    instrs = []
    if not path.exists():
        return instrs
    with open(path, encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = strip_comment(raw)
            if not line:
                continue
            if LABEL_RE.match(raw):
                continue
            if is_directive(line):
                continue
            # keil 生成带缩进 + 内部注释行（SOURCE LINE）
            if line.startswith(";"):
                continue
            # 跳过 c51cc 的 Symbol Table / Relocations 注释块标题
            if line.startswith("=") or line.startswith("-"):
                continue
            instrs.append(line)
    return instrs


def count_real_instrs(path: Path) -> int:
    return len(extract_instructions(path))


def analyze_pair(test_id: str, c51cc_asm: Path, keil_asm: Path):
    c_instrs = extract_instructions(c51cc_asm)
    k_instrs = extract_instructions(keil_asm)
    c_cnt = len(c_instrs)
    k_cnt = len(k_instrs)
    diff = c_cnt - k_cnt
    return {
        "id": test_id,
        "c51cc": c_cnt,
        "keil": k_cnt,
        "diff": diff,
        "c_instrs": c_instrs,
        "k_instrs": k_instrs,
    }


def classify_instructions(instrs):
    """统计各类指令出现次数"""
    freq = {}
    for line in instrs:
        op = line.split()[0].upper() if line.split() else ""
        freq[op] = freq.get(op, 0) + 1
    return freq


def _split_instr(line):
    """将已去注释的指令行拆分为 (op, [arg0, arg1, ...])，arg 已去尾部逗号"""
    parts = line.split()
    if not parts:
        return "", []
    return parts[0].upper(), [a.rstrip(",") for a in parts[1:]]


def find_common_patterns(instrs):
    """查找常见冗余模式（每条指令已去除注释和首尾空白）"""
    patterns = {
        "mov_self": 0,  # MOV Rx, Rx
        "mov_via_acc": 0,  # MOV A, Rx; MOV Ry, A  →  MOV Ry, Rx
        "add_zero": 0,  # ADD A, #0 / ADDC A, #0
        "clr_then_mov": 0,  # CLR A; MOV Rx, A
    }
    for i, line in enumerate(instrs):
        op, args = _split_instr(line)
        if not op:
            continue

        # MOV A, Rx 后紧跟 MOV Ry, A
        if op == "MOV" and len(args) >= 2:
            dst, src = args[0], args[1]
            if dst == "A" and src.startswith("R") and i + 1 < len(instrs):
                nop, nargs = _split_instr(instrs[i + 1])
                if (
                    nop == "MOV"
                    and len(nargs) >= 2
                    and nargs[1] == "A"
                    and nargs[0].startswith("R")
                    and nargs[0] != src
                ):
                    patterns["mov_via_acc"] += 1
            # MOV Rx, Rx
            if dst == src:
                patterns["mov_self"] += 1

        # ADD/ADDC A, #0
        if op in ("ADD", "ADDC") and len(args) >= 2 and args[1] == "#0":
            patterns["add_zero"] += 1

        # CLR A 后跟 MOV Rx, A
        if op == "CLR" and args and args[0] == "A" and i + 1 < len(instrs):
            nop, nargs = _split_instr(instrs[i + 1])
            if nop == "MOV" and len(nargs) >= 2 and nargs[1] == "A":
                patterns["clr_then_mov"] += 1

    return patterns


def main():
    parser = argparse.ArgumentParser(description="比较 c51cc 与 keil 生成的汇编代码")
    parser.add_argument(
        "--top", type=int, default=20, help="显示指令数差距最大的前N个测试"
    )
    parser.add_argument(
        "--detail",
        type=str,
        default=None,
        help="打印指定测试用例的完整对比 (如 --detail 00004)",
    )
    parser.add_argument("--c51cc-dir", type=str, default=str(C51CC_DIR))
    parser.add_argument("--keil-dir", type=str, default=str(KEIL_DIR))
    args = parser.parse_args()

    c51cc_root = Path(args.c51cc_dir)
    keil_root = Path(args.keil_dir)

    # 只对比两边都有的测试
    c51cc_ids = {p.name for p in c51cc_root.iterdir() if p.is_dir()}
    keil_ids = {p.name for p in keil_root.iterdir() if p.is_dir()}
    common = sorted(c51cc_ids & keil_ids)

    results = []
    total_c51cc = 0
    total_keil = 0

    for tid in common:
        c_asm = c51cc_root / tid / f"{tid}.asm"
        k_asm = keil_root / tid / f"{tid}.asm"
        r = analyze_pair(tid, c_asm, k_asm)
        results.append(r)
        total_c51cc += r["c51cc"]
        total_keil += r["keil"]

    # --- 汇总 ---
    print("=" * 72)
    print(
        f"  共 {len(common)} 个测试  |  c51cc总指令: {total_c51cc}  |  keil总指令: {total_keil}"
    )
    ratio = total_c51cc / total_keil * 100 if total_keil else 0
    print(f"  c51cc/keil 比率: {ratio:.1f}%  (越接近100%越好)")
    print("=" * 72)

    # 按差值降序排列
    by_diff = sorted(results, key=lambda r: r["diff"], reverse=True)

    # 打印前N个差距最大的
    print(f"\n[ 指令数差距最大的前 {args.top} 个测试 (c51cc - keil) ]\n")
    print(f"  {'ID':>6}  {'c51cc':>6}  {'keil':>6}  {'diff':>6}")
    print(f"  {'-'*6}  {'-'*6}  {'-'*6}  {'-'*6}")
    for r in by_diff[: args.top]:
        sign = "+" if r["diff"] > 0 else ""
        print(f"  {r['id']:>6}  {r['c51cc']:>6}  {r['keil']:>6}  {sign}{r['diff']:>5}")

    # --- 全局模式分析 ---
    print("\n[ 全局冗余模式分析 (c51cc) ]\n")
    all_c_instrs = []
    for r in results:
        all_c_instrs.extend(r["c_instrs"])
    patterns = find_common_patterns(all_c_instrs)
    for pat, cnt in sorted(patterns.items(), key=lambda x: -x[1]):
        if cnt > 0:
            print(f"  {pat:<25}: {cnt} 次")

    # --- 指令频率对比 ---
    print("\n[ 指令频率对比 (c51cc vs keil) ]\n")
    c_freq = classify_instructions(all_c_instrs)
    all_k_instrs = []
    for r in results:
        all_k_instrs.extend(r["k_instrs"])
    k_freq = classify_instructions(all_k_instrs)

    all_ops = sorted(
        set(c_freq) | set(k_freq),
        key=lambda op: -(c_freq.get(op, 0) + k_freq.get(op, 0)),
    )
    print(f"  {'OP':>8}  {'c51cc':>7}  {'keil':>7}  {'delta':>7}")
    print(f"  {'-'*8}  {'-'*7}  {'-'*7}  {'-'*7}")
    for op in all_ops[:30]:
        cv = c_freq.get(op, 0)
        kv = k_freq.get(op, 0)
        delta = cv - kv
        sign = "+" if delta > 0 else ""
        print(f"  {op:>8}  {cv:>7}  {kv:>7}  {sign}{delta:>6}")

    # --- 单个测试详情 ---
    if args.detail:
        tid = args.detail.zfill(5)
        found = [r for r in results if r["id"] == tid]
        if not found:
            print(f"\n[!] 未找到测试 {tid}")
        else:
            r = found[0]
            print(f"\n{'='*72}")
            print(
                f"  测试 {tid}: c51cc={r['c51cc']}条  keil={r['keil']}条  diff={r['diff']:+d}"
            )
            print(f"{'='*72}")
            max_len = max(len(r["c_instrs"]), len(r["k_instrs"]))
            print(f"\n  {'c51cc':<45}  {'keil'}")
            print(f"  {'-'*45}  {'-'*45}")
            for i in range(max_len):
                ci = r["c_instrs"][i] if i < len(r["c_instrs"]) else ""
                ki = r["k_instrs"][i] if i < len(r["k_instrs"]) else ""
                marker = "<<" if ci != ki else "  "
                print(f"  {ci:<45}  {ki}  {marker}")

    print()


if __name__ == "__main__":
    main()
