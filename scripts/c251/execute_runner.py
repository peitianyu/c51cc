#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test/execute 接入 C251 — c251cc 编译 + sim251 跑 + 返回值判定。

tests/execute 是 C 功能测试 (107 个), main 返回 0 = 成功。
判定:
  PASS        : 编译 + 返回 0
  FAIL        : 编译 + 返回非 0 (后端 bug)
  COMPILE-ERR : 编译失败 (分类: 能力缺口/前端不支持)

用法:
  python scripts/c251/execute_runner.py                # 全量
  python scripts/c251/execute_runner.py 0001           # 前缀过滤
  python scripts/c251/execute_runner.py --O0           # 优化级别 (默认 -O1)
  python scripts/c251/execute_runner.py --limit 20     # 只跑前 20 个
  python scripts/c251/execute_runner.py --report       # 结果写入 tmp/c251_execute_report.txt
"""
import os, sys, glob, subprocess, re, tempfile

sys.stdout.reconfigure(encoding='utf-8', errors='replace')
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
C251CC = os.environ.get('C251CC', os.path.join(ROOT, 'scripts', 'c251cc.exe'))
SIM = os.environ.get('MCS251', os.path.join(ROOT, 'sim251', 'mcs251.exe'))
SRC = os.path.join(ROOT, 'test', 'execute')
OPT = os.environ.get('C251_OPT', '-O1')
REPORT = os.path.join(ROOT, '.tmp', 'c251_execute_report.txt')
MAX_CYCLES = int(os.environ.get('C251_MAX_CYCLES', '5000000000'))
TIMEOUT = int(os.environ.get('C251_TIMEOUT', '120'))


def run(t, outdir):
    """编译单个 execute 测试并跑 sim251, 返回 (判定, 分类, 说明)。"""
    src = os.path.join(SRC, t + '.c')
    hexf = os.path.join(outdir, t + '.hex')
    libc = os.path.join(ROOT, 'src', 'core', 'c251', 'c251_libc.c')

    def compile_with(sources):
        return subprocess.run([C251CC, OPT, '-hex', '-o', hexf] + sources,
                              capture_output=True, text=True, encoding='utf-8',
                              errors='replace', timeout=TIMEOUT)

    r = compile_with([src])
    if r.returncode != 0:
        err = (r.stderr or r.stdout or '')
        cat = 'ERR'
        if 'c251_encode: unsupported' in err:
            cat = 'ENCODE-UNSUPPORTED'
        elif 'error:' in err or 'expected' in err or 'failed' in err:
            cat = 'FRONTEND'
        return 'COMPILE-ERR', cat, (err.splitlines()[-1] if err else '')[:100]

    # 未定义函数调用 (strlen/calloc/...) → 附加系统库 c251_libc.c 重编译 (0025/0041)
    err_all = (r.stderr or '') + (r.stdout or '')
    if 'unknown abs target' in err_all or 'unknown symbol' in err_all:
        if os.path.exists(libc):
            r2 = compile_with([src, libc])
            if r2.returncode == 0:
                r = r2

    dump = os.path.join(outdir, t + '.dump')
    p = subprocess.run([SIM, '-bios', hexf, '-d', 'cpu', '-D', dump,
                        '--cycles', str(MAX_CYCLES)],
                       capture_output=True, text=True, encoding='utf-8',
                       errors='replace', timeout=TIMEOUT)
    if p.returncode != 0:
        why = 'TIMEOUT' if p.returncode == 2 else 'SIM-ERROR(%d)' % p.returncode
        return 'FAIL', why, 'sim251 非零退出 (死循环/模拟器故障, 非正常返回)'
    regs = {}
    if os.path.exists(dump):
        for line in open(dump, encoding='utf-8', errors='replace'):
            # sim251 每行 8 个寄存器 → finditer 捕获全部 (R[06]=高字节 R[07]=低字节)
            for m in re.finditer(r'R\[(\d+)\]:\s*([0-9a-fA-F]{2})', line):
                regs[int(m.group(1))] = int(m.group(2), 16)
    r6 = regs.get(6, 0)
    r7 = regs.get(7, 0)
    ret = (r6 << 8) | r7
    if ret > 0x7FFF:
        ret -= 0x10000
    if ret == 0:
        return 'PASS', '', ''
    return 'FAIL', 'ret=%d' % ret, '返回非 0'


def main():
    argv = sys.argv[1:]
    # 先提取 --limit [N] / --limit=N / --limit（默认 20），支持空格形式
    limit = None
    filtered = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a.startswith('--limit='):
            limit = int(a.split('=', 1)[1])
        elif a == '--limit':
            if i + 1 < len(argv) and argv[i + 1].lstrip('-').isdigit():
                limit = int(argv[i + 1])
                i += 1
            else:
                limit = 20
        else:
            filtered.append(a)
        i += 1
    args = [a for a in filtered if not a.startswith('--')]
    flags = [a for a in filtered if a.startswith('--')]
    global OPT
    for f in flags:
        if f == '--O0':
            OPT = '-O0'
        elif f == '--O2':
            OPT = '-O2'
    prefix = ''.join(args)
    want_report = '--report' in flags
    include_slow = '--include-slow' in flags

    # 慢测试 (0041-queen 需 ~3G cycles/30s): 默认跳过, --include-slow 才跑
    SLOW = {'0041-queen'}

    tests = sorted(os.path.basename(f)[:-2]
                   for f in glob.glob(os.path.join(SRC, '*.c')))
    if prefix:
        tests = [t for t in tests if prefix in t]
    if not include_slow:
        tests = [t for t in tests if t not in SLOW]
    if limit:
        tests = tests[:limit]

    rows = []
    with tempfile.TemporaryDirectory(prefix='c251exec_') as outdir:
        for t in tests:
            v, why, note = run(t, outdir)
            rows.append((t, v, why, note))
            print('%-28s %-12s %-20s %s' % (t, v, why, note))

    if want_report:
        os.makedirs(os.path.dirname(REPORT), exist_ok=True)
        with open(REPORT, 'w', encoding='utf-8') as f:
            f.write('# c251 execute report (opt=%s)\n' % OPT)
            for t, v, why, note in rows:
                f.write('%s\t%s\t%s\t%s\n' % (t, v, why, note))

    n = len(rows)
    p = sum(1 for r in rows if r[1] == 'PASS')
    fl = [r for r in rows if r[1] == 'FAIL']
    ce = [r for r in rows if r[1] == 'COMPILE-ERR']
    print('\n===== execute 总结 (opt=%s, %d tests) =====' % (OPT, n))
    print('PASS %d/%d, FAIL %d, COMPILE-ERR %d' % (p, n, len(fl), len(ce)))
    for r in fl:
        print('  FAIL %-28s %s %s' % (r[0], r[2], r[3]))
    if ce:
        cats = {}
        for r in ce:
            cats[r[2]] = cats.get(r[2], 0) + 1
        print('  COMPILE-ERR 分类: %s' % sorted(cats.items()))
    return 1 if fl else 0


if __name__ == '__main__':
    sys.exit(main())
