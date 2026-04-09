#!/usr/bin/env python3
"""
C51CC 完整回归测试套件运行器
=================================

功能:
  1. 构建 keil 和 c51cc 输出 (asm + hex)
  2. 通过 sim8051 仿真比较 hex 输出的返回值
  3. 支持 c51cc 中间产物输出 (ast / ssa / asm / hex / reg)
  4. 生成详细的对比报告
  5. 支持按类别/编号过滤
  6. 支持逐步迭代模式

用法:
  python run_suite.py                          # 构建+比较全部
  python run_suite.py --suite-only             # 只跑 test/suite/ 目录
  python run_suite.py --filter "00_"           # 只跑匹配的测试
  python run_suite.py --compare-only           # 跳过构建, 只做仿真比较
  python run_suite.py --dump ast               # 同时输出 c51cc 的 AST
  python run_suite.py --dump ssa               # 同时输出 c51cc 的 SSA
  python run_suite.py --dump asm               # 对比 keil/c51cc 的 ASM
  python run_suite.py --diff-asm test_name     # 对比指定测试的 ASM
  python run_suite.py --stop-on-fail           # 遇到失败即停
  python run_suite.py --verbose                # 显示仿真 trace
"""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime

# 确保能导入同目录的 sim8051
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sim8051 import run_hex, CPU8051, load_hex


def resolve(path):
    return os.path.abspath(path)


def run_command(command, cwd=None, env=None, timeout=120):
    try:
        return subprocess.run(
            command, cwd=cwd, env=env, text=True, capture_output=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        return None


# ──────────────────────────────────────────────
# C51CC 中间产物输出
# ──────────────────────────────────────────────
def dump_c51cc_artifact(
    c51cc_exe, source_file, artifact_type, output_dir, include_dirs=None
):
    """调用 c51cc 输出 ast/ssa/asm/hex/reg 等中间产物"""
    flag_map = {
        "ast": ["-ast"],
        "ssa": ["-ssa"],
        "asm": ["-asm"],
        "hex": ["-hex"],
        "reg": ["-reg", "-asm"],
        "all": ["-asm", "-hex"],
    }
    flags = flag_map.get(artifact_type, ["-hex"])

    cmd = [c51cc_exe] + flags
    if include_dirs:
        for d in include_dirs:
            cmd.append(f"-I{d}")
    cmd.append(source_file)

    result = run_command(cmd, cwd=os.path.dirname(source_file))
    if result is None:
        return None, "timeout"

    # 保存输出
    name = os.path.splitext(os.path.basename(source_file))[0]
    ext = {
        "ast": ".ast",
        "ssa": ".ssa",
        "asm": ".asm",
        "hex": ".hex",
        "reg": ".reg",
    }.get(artifact_type, ".out")

    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, name + ext)

    content = result.stdout
    if artifact_type == "reg":
        content = result.stderr  # reg output goes to stderr

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(content)

    return out_path, result.stderr if artifact_type != "reg" else ""


# ──────────────────────────────────────────────
# ASM 对比
# ──────────────────────────────────────────────
def diff_asm_files(keil_asm, c51cc_asm, max_lines=80):
    """生成 keil vs c51cc 的 ASM 并排对比"""

    def read_clean(path):
        if not os.path.exists(path):
            return ["(file not found)"]
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        # 过滤空行和纯注释
        return [l.rstrip() for l in lines]

    keil_lines = read_clean(keil_asm)
    c51cc_lines = read_clean(c51cc_asm)

    output = []
    output.append(f"{'KEIL ASM':<50} | {'C51CC ASM':<50}")
    output.append("-" * 103)

    max_len = max(len(keil_lines), len(c51cc_lines))
    for i in range(min(max_len, max_lines)):
        kl = keil_lines[i] if i < len(keil_lines) else ""
        cl = c51cc_lines[i] if i < len(c51cc_lines) else ""
        marker = " " if kl.strip() == cl.strip() else "*"
        output.append(f"{kl:<50} {marker} {cl:<50}")

    if max_len > max_lines:
        output.append(f"... ({max_len - max_lines} more lines)")

    return "\n".join(output)


# ──────────────────────────────────────────────
# 仿真 trace 输出
# ──────────────────────────────────────────────
def trace_hex(hex_path, max_steps=2000):
    """输出仿真 trace 用于调试"""
    code = load_hex(hex_path)
    cpu = CPU8051(code)
    lines = []
    for i in range(max_steps):
        if cpu.halted:
            lines.append(
                f"[{i:04d}] HALTED R6={cpu.iram[6]:02X} R7={cpu.iram[7]:02X} (ret={cpu.get_return_signed()})"
            )
            break
        pc = cpu.pc
        op = code[pc]
        lines.append(
            f"[{i:04d}] PC={pc:04X} OP={op:02X} A={cpu.acc:02X} "
            f"R0={cpu.iram[0]:02X} R1={cpu.iram[1]:02X} R2={cpu.iram[2]:02X} "
            f"R3={cpu.iram[3]:02X} R4={cpu.iram[4]:02X} R5={cpu.iram[5]:02X} "
            f"R6={cpu.iram[6]:02X} R7={cpu.iram[7]:02X} SP={cpu.sp:02X}"
        )
        cpu.step()
    else:
        lines.append(
            f"[TIMEOUT] after {max_steps} steps, R6={cpu.iram[6]:02X} R7={cpu.iram[7]:02X}"
        )

    return "\n".join(lines)


# ──────────────────────────────────────────────
# 收集和比较
# ──────────────────────────────────────────────
def collect_projects(keil_dir, c51cc_dir, project_filter=None):
    """收集 keil_dir 和 c51cc_dir 下可比较的项目"""
    projects = []
    all_dirs = set()

    for d in [keil_dir, c51cc_dir]:
        if os.path.isdir(d):
            for name in os.listdir(d):
                if os.path.isdir(os.path.join(d, name)):
                    all_dirs.add(name)

    for name in sorted(all_dirs):
        if project_filter and project_filter not in name:
            continue
        keil_hex = os.path.join(keil_dir, name, f"{name}.hex")
        c51cc_hex = os.path.join(c51cc_dir, name, f"{name}.hex")

        keil_asm = None
        c51cc_asm = None
        # 查找 keil asm
        keil_proj_dir = os.path.join(keil_dir, name)
        if os.path.isdir(keil_proj_dir):
            for f in os.listdir(keil_proj_dir):
                if f.endswith(".asm"):
                    keil_asm = os.path.join(keil_proj_dir, f)
                    break
        # 查找 c51cc asm
        c51cc_proj_dir = os.path.join(c51cc_dir, name)
        if os.path.isdir(c51cc_proj_dir):
            for f in os.listdir(c51cc_proj_dir):
                if f.endswith(".asm"):
                    c51cc_asm = os.path.join(c51cc_proj_dir, f)
                    break

        has_keil = os.path.exists(keil_hex)
        has_c51cc = os.path.exists(c51cc_hex)

        projects.append(
            {
                "name": name,
                "keil_hex": keil_hex if has_keil else None,
                "c51cc_hex": c51cc_hex if has_c51cc else None,
                "keil_asm": keil_asm,
                "c51cc_asm": c51cc_asm,
                "has_keil": has_keil,
                "has_c51cc": has_c51cc,
            }
        )

    return projects


def compare_project(proj, max_steps=2_000_000, verbose=False):
    """比较单个项目的 keil 和 c51cc 输出"""
    name = proj["name"]
    result = {
        "project": name,
        "status": "unknown",
        "keil_ret": None,
        "c51cc_ret": None,
        "keil_insns": 0,
        "c51cc_insns": 0,
        "keil_timeout": False,
        "c51cc_timeout": False,
        "message": "",
    }

    if not proj["has_keil"]:
        result["status"] = "skip_keil"
        result["message"] = "no keil hex"
        return result

    if not proj["has_c51cc"]:
        result["status"] = "skip_c51cc"
        result["message"] = "no c51cc hex"
        return result

    try:
        kr, kn, kt = run_hex(proj["keil_hex"], max_steps)
        cr, cn, ct = run_hex(proj["c51cc_hex"], max_steps)
    except Exception as e:
        result["status"] = "exception"
        result["message"] = str(e)
        return result

    result["keil_ret"] = kr
    result["c51cc_ret"] = cr
    result["keil_insns"] = kn
    result["c51cc_insns"] = cn
    result["keil_timeout"] = kt
    result["c51cc_timeout"] = ct

    if kt or ct:
        result["status"] = "timeout"
        if kt and ct:
            result["message"] = "both timed out"
        elif kt:
            result["message"] = "keil timed out"
        else:
            result["message"] = "c51cc timed out"
    elif kr == cr:
        result["status"] = "pass"
    else:
        result["status"] = "fail"
        result["message"] = f"keil={kr} c51cc={cr}"

    return result


# ──────────────────────────────────────────────
# 报告
# ──────────────────────────────────────────────
CATEGORY_DESC = {
    "00-09": "基础: 返回值/常量/变量/算术",
    "10-19": "控制流: 比较/分支/循环",
    "20-29": "函数: 调用/递归/指针参数/数组",
    "30-39": "类型: 有符号/无符号/逻辑/复合赋值/自增减/三元",
    "40-49": "数据结构: 结构体/联合体/全局数组/函数指针/typedef",
    "50-59": "高级: void/多return/全局初始化/寄存器压力/sizeof/转换",
    "60-69": "综合: 排序/GCD/快速幂/switch/枚举/边界值/结构体指针/静态",
    "70+": "预处理: 宏/条件编译",
}


def get_category(name):
    """从测试名提取编号并分类"""
    m = re.match(r"^(\d+)_", name)
    if not m:
        return "other"
    num = int(m.group(1))
    if num < 10:
        return "00-09"
    if num < 20:
        return "10-19"
    if num < 30:
        return "20-29"
    if num < 40:
        return "30-39"
    if num < 50:
        return "40-49"
    if num < 60:
        return "50-59"
    if num < 70:
        return "60-69"
    return "70+"


def print_report(results, show_categories=True):
    """打印详细报告"""
    passed = [r for r in results if r["status"] == "pass"]
    failed = [r for r in results if r["status"] == "fail"]
    timeout = [r for r in results if r["status"] == "timeout"]
    skipped = [r for r in results if r["status"].startswith("skip")]
    errors = [r for r in results if r["status"] == "exception"]

    # 按类别统计
    if show_categories:
        categories = {}
        for r in results:
            cat = get_category(r["project"])
            if cat not in categories:
                categories[cat] = {
                    "pass": 0,
                    "fail": 0,
                    "timeout": 0,
                    "skip": 0,
                    "error": 0,
                }
            s = r["status"]
            if s == "pass":
                categories[cat]["pass"] += 1
            elif s == "fail":
                categories[cat]["fail"] += 1
            elif s == "timeout":
                categories[cat]["timeout"] += 1
            elif s.startswith("skip"):
                categories[cat]["skip"] += 1
            else:
                categories[cat]["error"] += 1

        print("\n+--------------------------------------------------------------+")
        print("|                   Category Summary                           |")
        print("+--------------------------------------------------------------+")
        for cat in sorted(categories.keys()):
            desc = CATEGORY_DESC.get(cat, "")
            c = categories[cat]
            total = sum(c.values()) - c["skip"]
            pass_rate = (c["pass"] / total * 100) if total > 0 else 0
            filled = int(pass_rate / 5)
            bar = "#" * filled + "." * (20 - filled)
            print(f"| {cat:<6} [{bar}] {pass_rate:5.1f}% ({c['pass']}/{total}) {desc}")
        print("+--------------------------------------------------------------+")

    # 详细列表
    print(f"\n=== PASS ({len(passed)}) ===")
    for r in passed:
        print(
            f"  OK   {r['project']:<45} ret={r['keil_ret']:<8} insns: keil={r['keil_insns']:<6} c51cc={r['c51cc_insns']}"
        )

    print(f"\n=== FAIL ({len(failed)}) ===")
    for r in failed:
        print(
            f"  FAIL {r['project']:<45} keil={r['keil_ret']:<8} c51cc={r['c51cc_ret']:<8} "
            f"insns: keil={r['keil_insns']:<6} c51cc={r['c51cc_insns']}"
        )

    print(f"\n=== TIMEOUT ({len(timeout)}) ===")
    for r in timeout:
        print(
            f"  TOUT {r['project']:<45} {r['message']:<30} "
            f"keil_ret={r['keil_ret']} c51cc_ret={r['c51cc_ret']}"
        )

    if skipped:
        print(f"\n=== SKIP ({len(skipped)}) ===")
        for r in skipped:
            print(f"  SKIP {r['project']:<45} {r['message']}")

    if errors:
        print(f"\n=== ERROR ({len(errors)}) ===")
        for r in errors:
            print(f"  ERR  {r['project']:<45} {r['message']}")

    total = len(passed) + len(failed) + len(timeout) + len(errors)
    pass_rate = (len(passed) / total * 100) if total > 0 else 0
    print(f"\n{'='*60}")
    print(
        f"[SUMMARY] total={total} pass={len(passed)} fail={len(failed)} "
        f"timeout={len(timeout)} error={len(errors)} skip={len(skipped)}"
    )
    print(f"[PASS RATE] {pass_rate:.1f}%")
    print(f"{'='*60}")


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="C51CC 回归测试套件")
    parser.add_argument(
        "source",
        nargs="?",
        default=None,
        help="源文件或目录 (默认: test/suite 或 test)",
    )
    parser.add_argument("--repo-root", default=r"d:\ws\test\C51CC")
    parser.add_argument("--output-root", default=None)
    parser.add_argument("--filter", default=None, help="项目名过滤子串")
    parser.add_argument("--max-steps", type=int, default=2_000_000)
    parser.add_argument("--compare-only", action="store_true", help="跳过构建")
    parser.add_argument("--suite-only", action="store_true", help="只跑 test/suite/")
    parser.add_argument("--stop-on-fail", action="store_true")
    parser.add_argument(
        "--dump",
        default=None,
        choices=["ast", "ssa", "asm", "hex", "reg", "all"],
        help="输出 c51cc 中间产物",
    )
    parser.add_argument("--diff-asm", default=None, help="对比指定测试的 ASM")
    parser.add_argument("--verbose", action="store_true", help="显示仿真 trace")
    parser.add_argument("--trace", default=None, help="输出指定测试的仿真 trace")
    parser.add_argument("--reg", action="store_true", help="启用寄存器分配调试")
    parser.add_argument("--json", default=None, help="输出 JSON 报告")
    args = parser.parse_args()

    repo_root = resolve(args.repo_root)
    scripts_dir = os.path.join(repo_root, "scripts")

    # 确定源目录
    if args.source:
        source = resolve(args.source)
    elif args.suite_only:
        source = os.path.join(repo_root, "test", "suite")
    else:
        source = os.path.join(repo_root, "test")

    output_root = (
        resolve(args.output_root)
        if args.output_root
        else os.path.join(repo_root, "output")
    )

    env = os.environ.copy()
    if args.reg:
        env["C51CC_EXTRA_FLAGS"] = (
            env.get("C51CC_EXTRA_FLAGS", "").strip() + " -reg"
        ).strip()

    # 构建
    if not args.compare_only:
        build_cmd = [os.path.join(scripts_dir, "build_all.bat"), source, output_root]
        print(f"[BUILD] {' '.join(build_cmd)}")
        result = run_command(build_cmd, cwd=scripts_dir, env=env, timeout=600)
        if result:
            sys.stdout.write(result.stdout)
            sys.stderr.write(result.stderr)
            if result.returncode != 0:
                print(f"[WARN] build exited with code {result.returncode}")
        else:
            print("[ERROR] build timed out")

    # 收集
    if os.path.isfile(source):
        source_tag = os.path.basename(os.path.dirname(source))
        effective_filter = args.filter or os.path.splitext(os.path.basename(source))[0]
    else:
        source_tag = os.path.basename(source)
        effective_filter = args.filter

    keil_dir = os.path.join(output_root, "keil", source_tag)
    c51cc_dir = os.path.join(output_root, "c51cc", source_tag)

    projects = collect_projects(keil_dir, c51cc_dir, effective_filter)

    if not projects:
        print(f"[ERROR] 没有找到可比较的项目:")
        print(f"  keil_dir:  {keil_dir}")
        print(f"  c51cc_dir: {c51cc_dir}")
        return 2

    # ASM 对比模式
    if args.diff_asm:
        for p in projects:
            if args.diff_asm in p["name"]:
                if p["keil_asm"] and p["c51cc_asm"]:
                    print(diff_asm_files(p["keil_asm"], p["c51cc_asm"]))
                else:
                    print(f"[ERROR] ASM files not found for {p['name']}")
                    if p["keil_asm"]:
                        print(f"  keil: {p['keil_asm']}")
                    if p["c51cc_asm"]:
                        print(f"  c51cc: {p['c51cc_asm']}")
        return 0

    # Trace 模式
    if args.trace:
        for p in projects:
            if args.trace in p["name"]:
                if p["has_c51cc"]:
                    print(f"=== C51CC trace: {p['name']} ===")
                    print(trace_hex(p["c51cc_hex"], args.max_steps))
                if p["has_keil"]:
                    print(f"\n=== Keil trace: {p['name']} ===")
                    print(trace_hex(p["keil_hex"], args.max_steps))
        return 0

    # 比较
    results = []
    for proj in projects:
        r = compare_project(proj, args.max_steps, args.verbose)
        results.append(r)

        if args.verbose and r["status"] == "fail":
            # 输出简短 trace
            if proj["has_c51cc"]:
                print(f"\n  --- c51cc trace (last 20 insns) ---")
                trace_lines = trace_hex(proj["c51cc_hex"], 500).split("\n")
                for line in trace_lines[-20:]:
                    print(f"    {line}")

        if args.stop_on_fail and r["status"] == "fail":
            print(f"\n[STOP] 在 {r['project']} 上失败, 停止运行")
            break

    # 报告
    print_report(results)

    # JSON 输出
    if args.json:
        json_path = resolve(args.json)
        os.makedirs(
            os.path.dirname(json_path) if os.path.dirname(json_path) else ".",
            exist_ok=True,
        )
        summary = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "source": source,
            "results": results,
        }
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        print(f"\n[JSON] 报告已写入 {json_path}")

    # 中间产物 dump
    if args.dump:
        c51cc_exe = os.path.join(scripts_dir, "c51cc.exe")
        dump_dir = os.path.join(output_root, "dump", source_tag)
        print(f"\n[DUMP] 输出 {args.dump} 到 {dump_dir}")
        for proj in projects:
            # 查找源文件
            src_path = None
            for root, dirs, files in os.walk(source):
                for f in files:
                    if f == proj["name"] + ".c":
                        src_path = os.path.join(root, f)
                        break
                if src_path:
                    break
            if src_path:
                out_path, err = dump_c51cc_artifact(
                    c51cc_exe, src_path, args.dump, os.path.join(dump_dir, proj["name"])
                )
                if out_path:
                    print(f"  {proj['name']}: {out_path}")
                else:
                    print(f"  {proj['name']}: FAILED ({err})")

    failed_count = sum(1 for r in results if r["status"] in ("fail", "exception"))
    return 1 if failed_count > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
