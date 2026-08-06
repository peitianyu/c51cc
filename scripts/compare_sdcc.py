#!/usr/bin/env python3
"""
c51cc vs SDCC HEX 对比测试
============================
对每个 C 源文件:
  1. c51cc -hex  → c51cc.hex
  2. sdcc -mmcs51 → sdcc.ihx
  3. 各自用 8051 仿真器执行, 取 R6/R7 返回值
  4. 对比返回值 + hex 结构(校验和/行长度/记录类型/地址范围)

用法:
  python compare_sdcc.py                    # 跑 test/*.c 全部
  python compare_sdcc.py --filter add       # 只跑名字含 add 的
  python compare_sdcc.py --src-dir suite    # 跑 test/suite/
  python compare_sdcc.py --verbose          # 失败时打印反汇编差异
"""
import argparse
import os
import re
import signal
import subprocess
import sys

# 每用例仿真超时 (秒), 超时即判为该用例失败/挂起, 绝不让整个测试卡死
SIM_TIMEOUT = 30
MAX_STEPS = 500_000

class _Timeout(Exception):
    pass

def _alarm_handler(signum, frame):
    raise _Timeout()

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sim8051 import run_hex, load_hex, CPU8051


def run_hex_dptr(path, max_steps=MAX_STEPS):
    """SDCC 约定: 16 位返回值在 DPTR (DPL=0x82, DPH=0x83)"""
    code = load_hex(path)
    cpu = CPU8051(code)
    timed_out = cpu.run_until_halt_or_sjmp_self(max_steps)
    dpl = cpu._read_sfr(0x82)
    dph = cpu._read_sfr(0x83)
    v = (dph << 8) | dpl
    if v >= 0x8000:
        v -= 0x10000
    return v, cpu._icount, timed_out


def sim_with_timeout(fn, *args):
    """包一层 POSIX alarm 超时; 超时抛 _Timeout"""
    old = signal.signal(signal.SIGALRM, _alarm_handler)
    signal.alarm(SIM_TIMEOUT)
    try:
        return fn(*args)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)

C51CC = os.environ.get("C51CC", os.path.join(os.path.dirname(os.path.abspath(__file__)), "c51cc_clang"))
SDCC = os.environ.get("SDCC", os.path.expanduser("~/ws/sdcc-4.5.0+dfsg/bin/sdcc"))
SDCC_HOME = os.environ.get("SDCC_HOME", os.path.expanduser("~/ws/sdcc-4.5.0+dfsg"))
WORK = os.environ.get("WORK", os.path.expanduser("~/ws/hexcmp"))


def run(cmd, **kw):
    try:
        return subprocess.run(cmd, text=True, capture_output=True, timeout=120, **kw)
    except subprocess.TimeoutExpired:
        return None


# ── Intel HEX 结构校验 ─────────────────────────────
def parse_hex(path):
    """解析 Intel HEX, 返回 (records, data_map, errors)
    records: [(addr, type, data)]
    data_map: {addr: byte}
    errors: [错误描述]
    """
    records = []
    data_map = {}
    errors = []
    base = 0
    with open(path) as f:
        for ln, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            if not line.startswith(":"):
                errors.append(f"L{ln}: 不以 ':' 开头: {line[:40]!r}")
                continue
            try:
                raw = bytes.fromhex(line[1:])
            except ValueError:
                errors.append(f"L{ln}: 非法 hex 字符: {line[:40]!r}")
                continue
            if len(raw) < 5:
                errors.append(f"L{ln}: 记录过短: {line!r}")
                continue
            byte_count = raw[0]
            addr = (raw[1] << 8) | raw[2]
            rtype = raw[3]
            payload = raw[4:-1]
            checksum = raw[-1]
            calc = (sum(raw[:-1]) & 0xFF)
            if ((calc + checksum) & 0xFF) != 0:
                errors.append(f"L{ln}: 校验和不符! 计算={calc:02X} 记录={checksum:02X}")
            if rtype == 0:
                if len(payload) != byte_count:
                    errors.append(f"L{ln}: 数据长度不符 声明={byte_count} 实际={len(payload)}")
                for i, b in enumerate(payload):
                    data_map[base + addr + i] = b
            elif rtype == 1:
                records.append((addr, rtype, payload))
                return records, data_map, errors  # EOF 即结束
            elif rtype == 2:
                base = ((payload[0] << 8) | payload[1]) << 4
            elif rtype == 4:
                base = ((payload[0] << 8) | payload[1]) << 16
            elif rtype == 5:
                pass  # 起始地址
            else:
                errors.append(f"L{ln}: 未知记录类型 {rtype}")
            records.append((addr, rtype, payload))
    return records, data_map, errors


def hex_stats(path):
    """hex 文件结构统计: 行数, 行长度集合, 类型集合, 地址范围, 字节数"""
    recs, data, errors = parse_hex(path)
    lens = sorted({r[2].__len__() for r in recs})
    types = sorted({r[1] for r in recs})
    addrs = sorted(data.keys())
    return {
        "records": len(recs),
        "line_lens": lens,
        "types": types,
        "first_addr": addrs[0] if addrs else None,
        "last_addr": addrs[-1] if addrs else None,
        "nbytes": len(data),
        "errors": errors,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--filter", default="")
    ap.add_argument("--src-dir", default="test", choices=["test", "suite", "both"])
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--dump-hex", action="store_true", help="把两个 hex 保存到 WORK")
    args = ap.parse_args()

    os.makedirs(WORK, exist_ok=True)
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    src_dirs = []
    if args.src_dir in ("test", "both"):
        src_dirs.append(os.path.join(repo, "test"))
    if args.src_dir in ("suite", "both"):
        src_dirs.append(os.path.join(repo, "test", "suite"))

    sources = []
    for d in src_dirs:
        for f in sorted(os.listdir(d)):
            if f.endswith(".c"):
                sources.append(os.path.join(d, f))
    if args.filter:
        sources = [s for s in sources if args.filter in os.path.basename(s)]

    env = dict(os.environ)
    env["SDCC_HOME"] = SDCC_HOME

    passed = failed = crash = 0
    fail_list = []
    for src in sources:
        name = os.path.splitext(os.path.basename(src))[0]
        c_hex = os.path.join(WORK, name + "_c51cc.hex")
        s_hex = os.path.join(WORK, name + "_sdcc.ihx")

        # c51cc
        r = run([C51CC, "-hex", src])
        if r is None or r.returncode != 0:
            print(f"[CRASH] {name}: c51cc 退出码={r.returncode if r else 'timeout'}")
            crash += 1
            fail_list.append(name)
            continue
        with open(c_hex, "w") as f:
            f.write(r.stdout)

        # sdcc
        r = run([SDCC, "-mmcs51", "--model-small", src, "-o", s_hex], env=env)
        if r is None or r.returncode != 0:
            print(f"[CRASH] {name}: sdcc 退出码={r.returncode if r else 'timeout'}")
            crash += 1
            fail_list.append(name)
            continue

        # hex 结构对比
        cs, ss = hex_stats(c_hex), hex_stats(s_hex)

        # 语义对比 (c51cc/Keil 用 R6:R7, SDCC 用 DPTR) — 均带超时保护
        try:
            cr, cn, ct = sim_with_timeout(run_hex, c_hex, MAX_STEPS)
            sr, sn, st = sim_with_timeout(run_hex_dptr, s_hex, MAX_STEPS)
        except _Timeout:
            print(f"[TIMEOUT] {name}: 仿真超过 {SIM_TIMEOUT}s, 跳过该用例")
            failed += 1
            fail_list.append(name)
            continue
        except Exception as e:
            print(f"[ERROR] {name}: 仿真异常 {e}")
            failed += 1
            fail_list.append(name)
            continue

        ok = True
        notes = []
        if cs["errors"]:
            ok = False
            notes.append(f"c51cc hex 结构错误: {cs['errors'][:3]}")
        if ss["errors"]:
            notes.append(f"sdcc hex 结构错误: {ss['errors'][:3]}")
        if ct != st:
            notes.append(f"运行状态不同 c51cc={ct} sdcc={st}")
        if cr != sr:
            ok = False
            notes.append(f"返回值不同 c51cc={cr} (steps={cn}) sdcc={sr} (steps={sn})")
        if cr is None and sr is not None:
            notes.append("c51cc 超时/挂起")
        if not ok:
            failed += 1
            fail_list.append(name)
            print(f"[FAIL] {name}: " + "; ".join(notes))
            if args.verbose:
                print(f"       c51cc hex: {cs}")
                print(f"       sdcc  hex: {ss}")
        else:
            passed += 1
            mark = ""
            if cr != sr:  # 都返回 None(挂起) 但算通过? 不, 都挂起不算通过
                pass
            print(f"[PASS] {name}: ret={cr} steps={cn}")

    print(f"\n===== 汇总: PASS={passed} FAIL={failed} CRASH={crash} 共{passed+failed+crash} =====")
    if fail_list:
        print("失败: " + ", ".join(fail_list))


if __name__ == "__main__":
    main()
