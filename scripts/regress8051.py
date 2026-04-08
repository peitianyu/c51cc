import argparse
import json
import os
import subprocess
import sys
from datetime import datetime

from sim8051 import run_hex


def resolve(path):
    return os.path.abspath(path)


def run_command(command, cwd, env=None):
    return subprocess.run(command, cwd=cwd, env=env, text=True, capture_output=True)


def collect_projects(keil_dir, c51cc_dir, project_filter=None):
    projects = []
    if not os.path.isdir(keil_dir):
        return projects

    for name in sorted(os.listdir(keil_dir)):
        if project_filter and project_filter not in name:
            continue
        keil_hex = os.path.join(keil_dir, name, f"{name}.hex")
        c51cc_hex = os.path.join(c51cc_dir, name, f"{name}.hex")
        if os.path.exists(keil_hex) and os.path.exists(c51cc_hex):
            projects.append((name, keil_hex, c51cc_hex))
    return projects


def compare_projects(projects, max_steps):
    passed = []
    failed = []
    timed_out = []

    for name, keil_hex, c51cc_hex in projects:
        try:
            keil_ret, keil_insns, keil_timeout = run_hex(keil_hex, max_steps)
            c51cc_ret, c51cc_insns, c51cc_timeout = run_hex(c51cc_hex, max_steps)
        except Exception as exc:
            failed.append(
                {
                    "project": name,
                    "status": "exception",
                    "message": str(exc),
                }
            )
            continue

        record = {
            "project": name,
            "keil_ret": keil_ret,
            "c51cc_ret": c51cc_ret,
            "keil_insns": keil_insns,
            "c51cc_insns": c51cc_insns,
            "keil_timeout": keil_timeout,
            "c51cc_timeout": c51cc_timeout,
        }

        if keil_timeout or c51cc_timeout:
            timed_out.append(record)
        elif keil_ret == c51cc_ret:
            passed.append(record)
        else:
            failed.append(record)

    return passed, failed, timed_out


def print_summary(passed, failed, timed_out):
    print(f"=== PASS ({len(passed)}) ===")
    for item in passed:
        print(f"  OK   {item['project']:<40} ret={item['keil_ret']}")

    print(f"\n=== FAIL ({len(failed)}) ===")
    for item in failed:
        if item.get("status") == "exception":
            print(f"  FAIL {item['project']:<40} exception={item['message']}")
            continue
        print(
            f"  FAIL {item['project']:<40} keil={item['keil_ret']} c51cc={item['c51cc_ret']}"
            f" (keil_insns={item['keil_insns']} c51cc_insns={item['c51cc_insns']})"
        )

    print(f"\n=== TIMEOUT ({len(timed_out)}) ===")
    for item in timed_out:
        print(
            f"  TOUT {item['project']:<40} keil_ret={item['keil_ret']} c51cc_ret={item['c51cc_ret']}"
            f" keil_timeout={item['keil_timeout']} c51cc_timeout={item['c51cc_timeout']}"
        )


def main():
    parser = argparse.ArgumentParser(
        description="Build and compare Keil/c51cc 8051 HEX outputs"
    )
    parser.add_argument(
        "source",
        nargs="?",
        default=r"d:\ws\test\C51CC\test",
        help="Source file or directory",
    )
    parser.add_argument(
        "--repo-root", default=r"d:\ws\test\C51CC", help="Repository root"
    )
    parser.add_argument("--output-root", default=None, help="Override output root")
    parser.add_argument(
        "--filter",
        default=None,
        help="Only compare project names containing this substring",
    )
    parser.add_argument(
        "--max-steps", type=int, default=2_000_000, help="Max simulator steps"
    )
    parser.add_argument(
        "--compare-only",
        action="store_true",
        help="Skip build step and compare existing outputs",
    )
    parser.add_argument(
        "--stop-on-fail",
        action="store_true",
        help="Return non-zero on build failure or semantic mismatch",
    )
    parser.add_argument(
        "--reg",
        action="store_true",
        help="Enable c51cc register allocation debug output",
    )
    parser.add_argument(
        "--json", default=None, help="Write machine-readable summary to this file"
    )
    args = parser.parse_args()

    repo_root = resolve(args.repo_root)
    source = resolve(args.source)
    output_root = (
        resolve(args.output_root)
        if args.output_root
        else os.path.join(repo_root, "output")
    )
    scripts_dir = os.path.join(repo_root, "scripts")
    env = os.environ.copy()

    if args.reg:
        env["C51CC_EXTRA_FLAGS"] = (
            env.get("C51CC_EXTRA_FLAGS", "").strip() + " -reg"
        ).strip()

    if not args.compare_only:
        command = [os.path.join(scripts_dir, "build_all.bat"), source, output_root]
        result = run_command(command, cwd=scripts_dir, env=env)
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
        if result.returncode != 0:
            if args.stop_on_fail:
                return result.returncode
            print(
                f"[WARN] build_all exited with code {result.returncode}, continuing with available HEX outputs"
            )

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
        print(
            f"[ERROR] no comparable HEX outputs found under {keil_dir} and {c51cc_dir}"
        )
        return 2

    passed, failed, timed_out = compare_projects(projects, args.max_steps)
    print_summary(passed, failed, timed_out)

    summary = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "repo_root": repo_root,
        "source": source,
        "output_root": output_root,
        "filter": effective_filter,
        "passed": passed,
        "failed": failed,
        "timed_out": timed_out,
    }

    if args.json:
        json_path = resolve(args.json)
        os.makedirs(os.path.dirname(json_path), exist_ok=True)
        with open(json_path, "w", encoding="utf-8") as fp:
            json.dump(summary, fp, indent=2, ensure_ascii=False)
        print(f"\n[JSON] wrote summary to {json_path}")

    print(f"\n[SUMMARY] pass={len(passed)} fail={len(failed)} timeout={len(timed_out)}")
    if failed and args.stop_on_fail:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
