#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
compare_stc51.py  -- 对比 Keil 与 c51cc 生成的 hex/asm
用法:
    python compare_stc51.py [output/stc51 目录]

输出:
  - 各示例 hex 大小对比
  - asm 指令数对比
  - 优化建议（c51cc 代码膨胀的情况）
"""

import os
import sys
import re


def parse_hex_size(hex_path):
    """返回 Intel HEX 文件中实际代码字节总数"""
    total = 0
    try:
        with open(hex_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line.startswith(":"):
                    continue
                byte_count = int(line[1:3], 16)
                rec_type = int(line[7:9], 16)
                if rec_type == 0x00:  # data record
                    total += byte_count
    except Exception:
        return None
    return total


def count_asm_instructions(asm_path):
    """统计 asm 文件中有效指令行数（过滤注释/标签/空行）"""
    count = 0
    try:
        with open(asm_path, "r", errors="replace") as f:
            for line in f:
                s = line.strip()
                if not s:
                    continue
                # 跳过注释行、段声明、标签行、伪指令
                if s.startswith(";"):
                    continue
                if re.match(r"^[A-Za-z_][A-Za-z0-9_]*:", s):
                    # 标签行（可能带指令在后面）
                    s = re.sub(r"^[A-Za-z_][A-Za-z0-9_]*:\s*", "", s)
                    if not s or s.startswith(";"):
                        continue
                # 过滤 .xxx 伪指令
                if (
                    s.startswith(".")
                    or s.upper().startswith("SEGMENT")
                    or s.upper().startswith("PUBLIC")
                    or s.upper().startswith("EXTRN")
                    or s.upper().startswith("END")
                    or s.upper().startswith("RSEG")
                    or s.upper().startswith("USING")
                    or s.upper().startswith("ORG")
                    or s.upper().startswith("DB")
                    or s.upper().startswith("DS")
                    or s.upper().startswith("DW")
                    or s.upper().startswith("NAME")
                ):
                    continue
                count += 1
    except Exception:
        return None
    return count


def count_keil_lst_instructions(lst_path):
    """从 Keil .lst 文件统计汇编指令数（有实际地址的行）"""
    count = 0
    try:
        with open(lst_path, "r", errors="replace") as f:
            for line in f:
                # Keil lst 格式：行首是十六进制地址，如 "0000 75A0FE ..."
                # 跳过头部注释和标签行
                m = re.match(r"^[0-9A-Fa-f]{4}\s+(?:[0-9A-Fa-f]{2})", line)
                if m:
                    count += 1
    except Exception:
        return None
    return count if count > 0 else None


def compare(output_root):
    keil_root = os.path.join(output_root, "keil")
    c51cc_root = os.path.join(output_root, "c51cc")

    # 收集所有项目名
    projects = set()
    for root, dirs, _ in [
        (keil_root, os.listdir(keil_root) if os.path.isdir(keil_root) else [], None),
        (c51cc_root, os.listdir(c51cc_root) if os.path.isdir(c51cc_root) else [], None),
    ]:
        for d in dirs:
            projects.add(d)

    projects = sorted(projects)

    header = f"{'项目名':<32} {'Keil hex':>10} {'c51cc hex':>10} {'比率':>8}  {'Keil asm':>10} {'c51cc asm':>10} {'比率':>8}"
    sep = "-" * len(header)
    print(header)
    print(sep)

    total_keil_hex = 0
    total_c51cc_hex = 0
    total_keil_asm = 0
    total_c51cc_asm = 0
    warn_list = []

    for proj in projects:
        keil_dir = os.path.join(keil_root, proj)
        c51cc_dir = os.path.join(c51cc_root, proj)

        # --- hex size ---
        keil_hex_size = None
        c51cc_hex_size = None

        for fname in os.listdir(keil_dir) if os.path.isdir(keil_dir) else []:
            if fname.endswith(".hex"):
                keil_hex_size = parse_hex_size(os.path.join(keil_dir, fname))
        for fname in os.listdir(c51cc_dir) if os.path.isdir(c51cc_dir) else []:
            if fname.endswith(".hex"):
                c51cc_hex_size = parse_hex_size(os.path.join(c51cc_dir, fname))

        # --- asm instr count ---
        keil_asm_cnt = None
        c51cc_asm_cnt = None

        for fname in os.listdir(keil_dir) if os.path.isdir(keil_dir) else []:
            if fname.lower().endswith(".asm"):
                keil_asm_cnt = count_asm_instructions(os.path.join(keil_dir, fname))
            elif fname.lower().endswith(".lst") and keil_asm_cnt is None:
                keil_asm_cnt = count_keil_lst_instructions(
                    os.path.join(keil_dir, fname)
                )
        for fname in os.listdir(c51cc_dir) if os.path.isdir(c51cc_dir) else []:
            if fname.endswith(".asm"):
                c51cc_asm_cnt = count_asm_instructions(os.path.join(c51cc_dir, fname))

        def fmt(v):
            return f"{v:>10}" if v is not None else f"{'N/A':>10}"

        def ratio(a, b):
            if a is None or b is None or a == 0:
                return f"{'N/A':>8}"
            r = b / a
            return f"{r:>7.2f}x"

        print(
            f"{proj:<32} {fmt(keil_hex_size)} {fmt(c51cc_hex_size)} {ratio(keil_hex_size, c51cc_hex_size)}"
            f"  {fmt(keil_asm_cnt)} {fmt(c51cc_asm_cnt)} {ratio(keil_asm_cnt, c51cc_asm_cnt)}"
        )

        if keil_hex_size and c51cc_hex_size:
            total_keil_hex += keil_hex_size
            total_c51cc_hex += c51cc_hex_size
            r = c51cc_hex_size / keil_hex_size
            if r > 1.5:
                warn_list.append((proj, r, keil_hex_size, c51cc_hex_size))

        if keil_asm_cnt and c51cc_asm_cnt:
            total_keil_asm += keil_asm_cnt
            total_c51cc_asm += c51cc_asm_cnt

    print(sep)
    ratio_hex = (total_c51cc_hex / total_keil_hex) if total_keil_hex else 0
    ratio_asm = (total_c51cc_asm / total_keil_asm) if total_keil_asm else 0
    print(
        f"{'[TOTAL]':<32} {total_keil_hex:>10} {total_c51cc_hex:>10} {ratio_hex:>7.2f}x"
        f"  {total_keil_asm:>10} {total_c51cc_asm:>10} {ratio_asm:>7.2f}x"
    )

    if warn_list:
        print()
        print("=== 优化建议（c51cc 生成代码 > Keil 1.5x 的项目）===")
        for proj, r, keil_sz, c51cc_sz in warn_list:
            print(f"  {proj}: c51cc={c51cc_sz}B  keil={keil_sz}B  膨胀 {r:.2f}x")
    else:
        print()
        print("所有项目 c51cc/Keil hex 比率均在 1.5x 以内，代码质量良好。")


if __name__ == "__main__":
    root = (
        sys.argv[1]
        if len(sys.argv) > 1
        else os.path.join(os.path.dirname(__file__), "..", "output", "stc51")
    )
    root = os.path.normpath(root)
    if not os.path.isdir(root):
        print(f"[ERROR] output directory not found: {root}")
        sys.exit(1)
    compare(root)
