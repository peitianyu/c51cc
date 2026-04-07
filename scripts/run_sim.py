#!/usr/bin/env python3
"""
run_sim.py  -- Run a C51CC-compiled hex file in ucsim_51 and extract the
               int return value of main() (in R6:R7, hi=R6, lo=R7).

Usage:
    python run_sim.py <hex_file> [ret_addr_hex]

If ret_addr_hex is omitted, we parse the hex file to find the last RET (0x22)
that belongs to main() (the last RET in the file).

Returns:
    Prints the signed 16-bit integer return value.
    Exit code 0 on success, non-zero on error.
"""

import sys
import os
import subprocess
import tempfile
import struct

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UCSIM = os.path.join(REPO_ROOT, "_tools", "sdcc", "bin", "ucsim_51.exe")
C51CC = os.path.join(REPO_ROOT, "scripts", "c51cc.exe")


def parse_ihex(hex_file):
    """Return dict: addr -> byte for all data records."""
    mem = {}
    with open(hex_file, "r", encoding="ascii") as f:
        for line in f:
            line = line.strip()
            if not line.startswith(":"):
                continue
            count = int(line[1:3], 16)
            addr = int(line[3:7], 16)
            rtype = int(line[7:9], 16)
            if rtype == 0:
                for i in range(count):
                    b = int(line[9 + i * 2 : 11 + i * 2], 16)
                    mem[addr + i] = b
    return mem


def find_main_ret_addr(mem):
    """
    Find the RET (0x22) that ends main().
    Strategy: the last RET in the entire ROM image is main's RET,
    because cmp_signed / other functions come before main in our layout.
    """
    last_ret = None
    for addr in sorted(mem):
        if mem[addr] == 0x22:
            last_ret = addr
    return last_ret


def run_and_get_return(hex_file, ret_addr=None):
    """
    Load hex_file into ucsim_51, break at ret_addr (main's RET),
    and read R6:R7.
    Returns signed int16 value.
    """
    mem = parse_ihex(hex_file)
    if ret_addr is None:
        ret_addr = find_main_ret_addr(mem)
    if ret_addr is None:
        raise ValueError("Could not find RET in hex file")

    # ucsim commands to run
    cmds = f'file "{hex_file}"\n' f"break 0x{ret_addr:04x}\n" "run\n" "dump iram 0 7\n"

    result = subprocess.run(
        [UCSIM, "-t", "8051"],
        input=cmds,
        capture_output=True,
        text=True,
        timeout=30,
        cwd=REPO_ROOT,
    )
    output = result.stdout + result.stderr

    # Parse "R0 R1 R2 R3 R4 R5 R6 R7" line then next line with values
    regs = None
    lines = output.splitlines()
    for i, line in enumerate(lines):
        if "R0 R1 R2 R3 R4 R5 R6 R7" in line and i + 1 < len(lines):
            vals = lines[i + 1].strip().split()
            if len(vals) >= 8:
                regs = [int(v, 16) for v in vals[:8]]
                break

    if regs is None:
        # Try to find 'dump iram 0 7' result
        for line in lines:
            if line.startswith("0x00"):
                parts = line.split()
                # format: 0x00  val0 val1 ... val7
                if len(parts) >= 9:
                    regs = [int(v, 16) for v in parts[1:9]]
                    break

    if regs is None:
        print("DEBUG OUTPUT:")
        print(output)
        raise ValueError("Could not parse register values from ucsim output")

    r6, r7 = regs[6], regs[7]
    # int return: hi=R6, lo=R7
    unsigned = (r6 << 8) | r7
    # sign-extend to int16
    signed = struct.unpack(">h", bytes([r6, r7]))[0]
    return signed, unsigned, r6, r7, output


def compile_and_run(c_file, expected=None):
    """Compile c_file with c51cc and run in simulator. Returns (actual, pass)."""
    # Write hex to a temp file
    with tempfile.NamedTemporaryFile(suffix=".hex", delete=False, mode="w") as f:
        tmpname = f.name

    try:
        # Compile
        result = subprocess.run(
            [C51CC, "-hex", c_file, "-o", tmpname],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=REPO_ROOT,
        )
        if result.returncode != 0:
            return None, False, f"compile error: {result.stderr[:200]}"

        # Run
        signed, unsigned, r6, r7, _ = run_and_get_return(tmpname)

        if expected is not None:
            ok = signed == expected
            return signed, ok, f"R6={r6:02X} R7={r7:02X} -> {signed}"
        return signed, True, f"R6={r6:02X} R7={r7:02X} -> {signed}"
    finally:
        try:
            os.unlink(tmpname)
        except:
            pass


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <hex_file> [ret_addr_hex]")
        sys.exit(1)

    hex_file = sys.argv[1]
    ret_addr = int(sys.argv[2], 16) if len(sys.argv) > 2 else None

    signed, unsigned, r6, r7, _ = run_and_get_return(hex_file, ret_addr)
    print(f"Return value: {signed} (0x{unsigned:04X}, R6={r6:02X} R7={r7:02X})")
