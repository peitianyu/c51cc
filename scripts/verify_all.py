#!/usr/bin/env python3
"""
verify_all.py -- 对每个 test/ 下的 C 文件，运行 Keil 的 hex 文件在 ucsim_51 中
               获取 main 的返回值（期望值），然后手动跑 C51CC 的 hex（如果可以），
               或者通过编译 + 分析 ASM 来验证。

当前实现：
  1. 运行 Keil 的 hex，获取返回值（ground truth）
  2. 输出结果列表

用法: python verify_all.py
"""

import os
import sys
import subprocess
import struct

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UCSIM = os.path.join(REPO_ROOT, "_tools", "sdcc", "bin", "ucsim_51.exe")
C51CC_EXE = os.path.join(REPO_ROOT, "scripts", "c51cc.exe")
KEIL_OUT = os.path.join(REPO_ROOT, "output", "keil", "test")
C51CC_OUT = os.path.join(REPO_ROOT, "output", "c51cc", "test")


def parse_ihex(path):
    """Parse Intel HEX file, return {addr: byte} dict."""
    mem = {}
    try:
        with open(path, "r", encoding="ascii", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line.startswith(":"):
                    continue
                count = int(line[1:3], 16)
                addr = int(line[3:7], 16)
                rtype = int(line[7:9], 16)
                if rtype == 0:
                    for i in range(count):
                        mem[addr + i] = int(line[9 + i * 2 : 11 + i * 2], 16)
    except Exception as e:
        pass
    return mem


def find_last_ret_before(mem, limit_addr):
    """Find the last RET (0x22) at or before limit_addr."""
    candidates = sorted([a for a, v in mem.items() if v == 0x22 and a <= limit_addr])
    return candidates[-1] if candidates else None


def find_program_entry(mem):
    """Find program entry (address of first LJMP or first non-FF byte at 0)."""
    if 0 not in mem:
        return None
    b0 = mem.get(0, 0xFF)
    if b0 == 0x02:  # LJMP
        hi = mem.get(1, 0)
        lo = mem.get(2, 0)
        return (hi << 8) | lo
    return 0


def run_sim(hex_path, breakpoint_addr, timeout=12):
    """
    Run ucsim_51 with any hex file.
    Set breakpoint at breakpoint_addr, run, dump iram, return (signed_int, info).
    Uses Popen + file redirection to avoid stdin blocking / TimeoutExpired issues.
    """
    cmds_path = os.path.join(REPO_ROOT, "_tmp_sim_cmds.txt")
    out_path = os.path.join(REPO_ROOT, "_tmp_sim_out.txt")
    err_path = os.path.join(REPO_ROOT, "_tmp_sim_err.txt")

    # MUST include "quit\n" so ucsim exits cleanly
    cmds = "reset\nrun\ndump iram 0 7\nquit\n"
    with open(cmds_path, "w", encoding="ascii") as f:
        f.write(cmds)

    args = [UCSIM, "-t", "8051", "-e", f"break 0x{breakpoint_addr:04x}", hex_path]

    proc = None
    try:
        with open(cmds_path, "r") as sin_f, open(out_path, "w") as sout_f, open(
            err_path, "w"
        ) as serr_f:
            proc = subprocess.Popen(
                args, stdin=sin_f, stdout=sout_f, stderr=serr_f, cwd=REPO_ROOT
            )
            proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        if proc:
            proc.kill()
            proc.wait()
        return None, "timeout"
    finally:
        try:
            os.unlink(cmds_path)
        except:
            pass

    try:
        with open(out_path, "r", encoding="ascii", errors="replace") as f:
            output = f.read()
    except:
        output = ""

    lines = output.splitlines()

    # Format A: "R0 R1 R2 R3 R4 R5 R6 R7" header + next value line
    for i, line in enumerate(lines):
        if "R0 R1 R2 R3 R4 R5 R6 R7" in line and i + 1 < len(lines):
            vals = lines[i + 1].strip().split()
            if len(vals) >= 8:
                try:
                    regs = [int(v, 16) for v in vals[:8]]
                    r6, r7 = regs[6], regs[7]
                    return (
                        struct.unpack(">h", bytes([r6, r7]))[0],
                        f"R6={r6:02X} R7={r7:02X}",
                    )
                except:
                    pass

    # Format B: "0x00   v0 v1 v2 v3 v4 v5 v6 v7 ..."
    for line in lines:
        if line.startswith("0x00") and len(line) > 20:
            parts = line.split()
            if len(parts) >= 9:
                try:
                    regs = [int(v, 16) for v in parts[1:9]]
                    r6, r7 = regs[6], regs[7]
                    return (
                        struct.unpack(">h", bytes([r6, r7]))[0],
                        f"R6={r6:02X} R7={r7:02X}",
                    )
                except:
                    pass

    if "Stop at" in output or "Breakpoint" in output:
        return None, "bp_hit_but_parse_fail"

    return None, "no_bp_hit"


# keep old name as alias for compatibility
def run_sim_keil(hex_path, breakpoint_addr, timeout=12):
    return run_sim(hex_path, breakpoint_addr, timeout)


def analyze_keil_hex(project_name):
    """
    Given a project name, load Keil's hex file and find the last cmp_signed/main RET.
    Returns (breakpoint_addr, hex_path) or (None, error_str).
    """
    # Find Keil hex file
    hex_dir = os.path.join(KEIL_OUT, project_name)
    hex_path = os.path.join(hex_dir, f"{project_name}.hex")
    if not os.path.exists(hex_path):
        return None, None, f"not found: {hex_path}"

    mem = parse_ihex(hex_path)
    if not mem:
        return None, None, "empty hex"

    # Find all RET instructions
    rets = sorted([a for a, v in mem.items() if v == 0x22])
    if not rets:
        return None, None, "no RET found"

    # Keil uses LJMP tail-calls from main, so the called function's RET
    # is the effective "main return".  The last meaningful RET is the one
    # before a SJMP/LJMP infinite loop that Keil inserts after main.
    # Reliable heuristic: skip RETs whose preceding byte is 0xFF (ROM fill).
    # Among the remaining, use second-to-last (last is often startup loop-back).
    real_rets = [a for a in rets if mem.get(a - 1, 0xFF) != 0xFF]
    if not real_rets:
        real_rets = rets
    if len(real_rets) >= 2:
        bp = real_rets[-2]
    else:
        bp = real_rets[-1]

    return bp, hex_path, None


def get_keil_return_value(project_name):
    """Get the return value of main() from Keil's hex file."""
    bp, hex_path, err = analyze_keil_hex(project_name)
    if err:
        return None, err

    return run_sim_keil(hex_path, bp)


def get_c51cc_return_value(project_name):
    """Get the return value of main() from C51CC's hex file."""
    hex_path = os.path.join(C51CC_OUT, project_name, f"{project_name}.hex")
    if not os.path.exists(hex_path):
        return None, "no_hex"
    mem = parse_ihex(hex_path)
    if not mem:
        return None, "empty_hex"
    rets = sorted([a for a, v in mem.items() if v == 0x22])
    if not rets:
        return None, "no_ret"
    # C51CC does not insert infinite loop after main; its last RET is main's RET.
    # Use last real RET (preceding byte != 0xFF).
    real_rets = [a for a in rets if mem.get(a - 1, 0xFF) != 0xFF]
    bp = real_rets[-1] if real_rets else rets[-1]
    return run_sim(hex_path, bp)


def main():
    filter_name = sys.argv[1].lower() if len(sys.argv) > 1 else None

    if not os.path.exists(KEIL_OUT):
        print(f"ERROR: Keil output dir not found: {KEIL_OUT}")
        sys.exit(1)

    keil_projects = set(
        d for d in os.listdir(KEIL_OUT) if os.path.isdir(os.path.join(KEIL_OUT, d))
    )
    c51cc_projects = (
        set(
            d
            for d in os.listdir(C51CC_OUT)
            if os.path.isdir(os.path.join(C51CC_OUT, d))
        )
        if os.path.exists(C51CC_OUT)
        else set()
    )

    projects = sorted(keil_projects | c51cc_projects)
    if filter_name:
        projects = [p for p in projects if filter_name in p.lower()]

    has_c51cc = bool(c51cc_projects)
    if has_c51cc:
        print(f"{'Project':<35} {'Keil':>6}  {'C51CC':>6}  Status")
        print("-" * 70)
    else:
        print(f"{'Project':<35} {'KeilRet':>8}  Info")
        print("-" * 60)

    match = mismatch = fail = 0

    for proj in projects:
        kv, ki = get_keil_return_value(proj)

        if has_c51cc and proj in c51cc_projects:
            cv, ci = get_c51cc_return_value(proj)
        else:
            cv, ci = None, "no_hex"

        if kv is None:
            fail += 1
            if has_c51cc:
                print(f"{proj:<35} {'?':>6}  {'?':>6}  KEIL_FAIL({ki})")
            else:
                print(f"{proj:<35} {'?':>8}  FAIL: {ki}")
            continue

        if not has_c51cc or cv is None:
            # Only Keil result
            if has_c51cc:
                fail += 1
                print(f"{proj:<35} {kv:6d}  {'?':>6}  C51CC_FAIL({ci})")
            else:
                print(f"{proj:<35} {kv:8d}  {ki}")
            continue

        if kv == cv:
            match += 1
            print(f"{proj:<35} {kv:6d}  {cv:6d}  OK")
        else:
            mismatch += 1
            print(f"{proj:<35} {kv:6d}  {cv:6d}  MISMATCH")

    print()
    if has_c51cc:
        print(f"MATCH={match}  MISMATCH={mismatch}  FAIL={fail}")
    else:
        print("Done (only Keil hex available).")


if __name__ == "__main__":
    main()
