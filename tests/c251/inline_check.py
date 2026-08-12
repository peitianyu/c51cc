# -*- coding: utf-8 -*-
"""M4-B 多块函数内联回归测试 (proof-first):
对常量参数调用多块函数 (无 phi) 的测试, 断言:
  1. 优化后 main 中无 call 指令 (内联已生效)
  2. simssa 仿真返回值与 EXPECT 一致 (功能正确)
输出格式: "--- PASS: <name>" / "--- FAIL: <name>" (proof harness 可解析)

运行: python tests/c251/inline_check.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "simssa"))
import simssa  # noqa: E402

# (文件名, 期望值) — 常量参数 + 多块无 phi 函数调用
CASES = [
    ("13_if_else.c", 12),
    ("14_if_chain.c", 2),
    ("52_multi_return.c", 10),
]


def main_calls(src):
    text, err = simssa.compile_ssa([src], "-O1")
    if text is None:
        return None, f"COMPILE-ERR: {err.splitlines()[-1] if err else ''}"
    g, funcs = simssa.parse_ssa_text(text, False)
    main = funcs.get("main")
    if not main:
        return None, "main 缺失"
    calls = []
    for bid in sorted(main.blocks):
        b = main.blocks[bid]
        for i in b.instrs:
            if i.op == "call":
                calls.append(i.labels[0].lstrip("@") if i.labels else "?")
    return calls, ""


def main():
    fails = 0
    for name, expect in CASES:
        src = os.path.join(simssa.SUITE_DIR, name)
        calls, err = main_calls(src)
        ret, verdict, detail = simssa.simulate([src], "-O1")
        ok_val = (verdict == "RUN" and ret == expect)
        ok_inl = (err == "" and calls == [])
        if ok_val and ok_inl:
            print(f"--- PASS: {name}")
        else:
            fails += 1
            print(f"--- FAIL: {name} calls={calls} err={err} ret={ret}(expect {expect}) verdict={verdict} {detail[:80] if detail else ''}")
    print(f"{'ALL PASS' if fails == 0 else f'{fails} FAILED'}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
