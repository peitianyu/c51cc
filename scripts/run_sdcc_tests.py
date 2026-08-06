#!/usr/bin/env python3
"""
SDCC 回归测试集 vs c51cc 综合对比
==================================
从 SDCC 4.5.0 回归测试中挑选纯 C 用例:
  1. stub testfwk.h (ASSERT 计数)
  2. 提取 testXxx() 函数, 生成 wrapper main
  3. c51cc 与 SDCC 各自编译, 8051 仿真执行
  4. 对比失败计数 (0 = 全部断言通过)
"""
import os, re, subprocess, sys, glob

REPO = os.path.expanduser("~/ws/c51cc")
SDCC = os.path.expanduser("~/ws/sdcc-4.5.0+dfsg/bin/sdcc")
SDCC_HOME = os.path.expanduser("~/ws/sdcc-4.5.0+dfsg")
C51CC = os.path.join(REPO, "scripts", "c51cc_clang")
STUB_INC = os.path.expanduser("~/ws/c51test/include")
WORK = os.path.expanduser("~/ws/c51test/out")
TEST_DIR = os.path.join(SDCC_HOME, "support/regression/tests")

sys.path.insert(0, os.path.join(REPO, "scripts"))
from sim8051 import load_hex, CPU8051

# SDCC 特有语法/依赖 → 过滤 (地址空间 __data/__xdata/__code 等 c51cc 支持, 不滤)
SDCC_ONLY = re.compile(
    r"(__sfr|__sbit|__bit|__at\b|__critical|__endasm|\bsfr\b|\bsbit\b|__sdcc|__bit32|"
    r"__xdata_at|#pragma|__reentrant|__naked|__signed__|__unsigned__|__fixed|__accum|__memory_model|"
    r"__SFR|__SFRX|__SFR16|__SFR32|__xdata\s+\w+\s*=|__code\s+\w+\s*=|__near|__far)", re.S)
NO_MAIN_DEPS = re.compile(r"#include\s*<(std|string|stdlib|stdio|limits|math|setjmp|time|assert|ctype|stdbool|stdint|float|errno|signal|locale)")

def has_main_like(fn):
    txt = open(fn, encoding="utf-8", errors="replace").read()
    return bool(re.search(r"\bvoid\s+main\b|\bint\s+main\b", txt)) or not re.search(r"\btest[A-Za-z0-9_]*\s*\(", txt)

def extract_tests(fn):
    txt = open(fn, encoding="utf-8", errors="replace").read()
    # 去掉注释
    txt = re.sub(r"/\*.*?\*/", "", txt, flags=re.S)
    txt = re.sub(r"//[^\n]*", "", txt)
    tests = re.findall(r"\bvoid\s+(test[A-Za-z0-9_]*)\s*\(\s*void\s*\)", txt)
    # 排除 static/条件编译里的
    return tests

def gen_wrapper(tests):
    decls = "\n".join(f"void {t}(void);" for t in tests)
    calls = "\n    ".join(f"{t}();" for t in tests)
    return f"""/* auto-generated wrapper */
#include <testfwk.h>
#include <stdlib.h>
#include <string.h>
int __numTests;
int __test_fails;
int __fail_map;
/* 极简库实现 */
int abs(int x) {{ return x < 0 ? -x : x; }}
long labs(long x) {{ return x < 0 ? -x : x; }}
int rand(void) {{ static unsigned int s = 1; s = s * 251 + 113; return (int)(s & 0x7FFF); }}
void srand(unsigned int seed) {{ (void)seed; }}
int strlen(const char *s) {{ int n = 0; while (s[n]) n++; return n; }}
int strcmp(const char *a, const char *b) {{ while (*a && *a == *b) {{ a++; b++; }} return *a - *b; }}
char *strcpy(char *d, const char *s) {{ char *r = d; while ((*d++ = *s++)); return r; }}
void *memcpy(void *d, const void *s, int n) {{ char *x = d; const char *y = s; while (n--) *x++ = *y++; return d; }}
void *memset(void *d, int c, int n) {{ char *x = d; while (n--) *x++ = (char)c; return d; }}
int memcmp(const void *a, const void *b, int n) {{ const char *x = a, *y = b; while (n--) {{ if (*x != *y) return *x - *y; x++; y++; }} return 0; }}
{decls}
int main(void) {{
    __numTests = 0;
    __test_fails = 0;
    __fail_map = 0;
    {calls}
    return __fail_map;
}}
"""

def run(cmd, env=None, timeout=90):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, errors="replace", env=env, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None

def sim_ret(hexpath, max_steps=800000, use_dptr=False):
    cpu = CPU8051(load_hex(hexpath))
    to = cpu.run_until_halt_or_sjmp_self(max_steps)
    if use_dptr:
        v = (cpu._read_sfr(0x83) << 8) | cpu._read_sfr(0x82)
    else:
        v = (cpu._getr(6) << 8) | cpu._getr(7)
    if v >= 0x8000: v -= 0x10000
    return v, to

def main():
    files = sorted(glob.glob(os.path.join(TEST_DIR, "*.c")))
    os.makedirs(WORK, exist_ok=True)
    env = dict(os.environ); env["SDCC_HOME"] = SDCC_HOME

    stats = {"pass": 0, "fail": 0, "c51cc_err": 0, "sdcc_err": 0, "skip": 0}
    fails = []
    for i, fn in enumerate(files):
        name = os.path.basename(fn)
        txt = open(fn, encoding="utf-8", errors="replace").read()
        # 过滤 SDCC 特有语法
        if SDCC_ONLY.search(txt):
            stats["skip"] += 1; continue
        # 过滤需要库头文件(除 testfwk)的
        if NO_MAIN_DEPS.search(txt):
            stats["skip"] += 1; continue
        tests = extract_tests(fn)
        if not tests:
            stats["skip"] += 1; continue

        wrap = gen_wrapper(tests)
        wf = os.path.join(WORK, f"{name}.wrap.c")
        open(wf, "w").write(wrap)

        # c51cc
        cr = run([C51CC, "-hex", "-I" + STUB_INC, fn, wf])
        if cr is None or cr.returncode != 0:
            stats["c51cc_err"] += 1
            fails.append((name, "c51cc_err", (cr.stderr or "")[:60] if cr else "timeout"))
            continue
        ch = os.path.join(WORK, f"{name}.c51cc.hex")
        open(ch, "w").write(cr.stdout)
        # sdcc: mcs51 只编译单文件, 需分步 -c 编译 + 链接
        test_rel = os.path.join(WORK, f"{name}.test.rel")
        wrap_rel = os.path.join(WORK, f"{name}.wrap.rel")
        sr1 = run([SDCC, "-c", "-mmcs51", "--model-small", "-I" + STUB_INC, fn, "-o", test_rel], env=env)
        sr2 = run([SDCC, "-c", "-mmcs51", "--model-small", "-I" + STUB_INC, wf, "-o", wrap_rel], env=env)
        if sr1 is None or sr1.returncode != 0 or sr2 is None or sr2.returncode != 0:
            stats["sdcc_err"] += 1
            msg = (sr1.stderr or "")[-60:] if sr1 and sr1.returncode != 0 else ((sr2.stderr or "")[-60:] if sr2 else "timeout")
            fails.append((name, "sdcc_err", msg))
            continue
        sr3 = run([SDCC, "-mmcs51", "--model-small", test_rel, wrap_rel,
                   "-o", os.path.join(WORK, f"{name}.ihx")], env=env)
        if sr3 is None or sr3.returncode != 0:
            stats["sdcc_err"] += 1
            fails.append((name, "sdcc_err", (sr3.stderr or "")[-60:] if sr3 else "timeout"))
            continue
        # 仿真 (c51cc 返回值在 R6:R7, SDCC 在 DPTR)
        try:
            cval, cto = sim_ret(ch)
            sval, sto = sim_ret(os.path.join(WORK, f"{name}.ihx"), use_dptr=True)
        except Exception as e:
            stats["fail"] += 1
            fails.append((name, "sim_err", str(e)[:60])); continue
        if cto or sto:
            stats["fail"] += 1
            fails.append((name, "hang", f"c_to={cto} s_to={sto}"))
        elif cval == sval:
            stats["pass"] += 1
        else:
            stats["fail"] += 1
            fails.append((name, "diff", f"c51cc={cval} sdcc={sval}"))

        if (i + 1) % 200 == 0:
            print(f"...{i+1} files: {stats}", flush=True)

    print(f"\n===== 汇总: {stats} =====")
    print(f"跑通 {stats['pass']} 个, 行为差异 {stats['fail']} 个, c51cc编译失败 {stats['c51cc_err']} 个, sdcc失败 {stats['sdcc_err']} 个")
    for f in fails[:40]:
        print(f"  {f[0]:45s} {f[1]:12s} {f[2]}")

if __name__ == "__main__":
    main()
