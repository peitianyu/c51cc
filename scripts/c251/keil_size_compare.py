#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""keil_size_compare.py — suite/execute 测试 c251cc (-O1/-O2) vs Keil C251 O9 SIZE 对比

每个测试:
  Keil:  C251 MODSRC XSMALL OPTIMIZE(9,SIZE) -> L251 -> 解析 "code="
  c251cc: -O1 / -O2 -> HEX 字节数
输出表: 测试名, Keil code, c251cc-O1, c251cc-O2, O1/Keil%, O2/Keil%
跳过:  Keil 编译失败 (c251cc 支持但 Keil 不支持的语法/头差异) 或 c251cc 编译失败

用法:
  python scripts/c251/keil_size_compare.py            # suite + execute 全部
  python scripts/c251/keil_size_compare.py suite      # 只 suite
  python scripts/c251/keil_size_compare.py execute    # 只 execute
  python scripts/c251/keil_size_compare.py --limit 20 # 每组前 20 个

Keil 工具链缺失时优雅降级: 打印检测结果并跳过, 不崩溃。
"""
import os, re, subprocess, sys, glob, tempfile

sys.stdout.reconfigure(encoding='utf-8', errors='replace')
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
C251 = os.environ.get('KEIL_C251', r'C:\Keil_v5\C251\BIN\C251.EXE')
L251 = os.environ.get('KEIL_L251', r'C:\Keil_v5\C251\BIN\L251.EXE')
C251CC = os.environ.get('C251CC', os.path.join(ROOT, 'scripts', 'c251cc.exe'))
SUITE = os.path.join(ROOT, 'test', 'suite')
EXEC = os.path.join(ROOT, 'test', 'execute')

KEIL_AVAILABLE = os.path.isfile(C251) and os.path.isfile(L251)


def keil_code(src, workdir):
    """编译+链接单个 .c, 返回 code 字节数; None=编译/链接失败. 工作目录 workdir."""
    obj = os.path.join(workdir, 'k.obj')
    try:
        os.remove(obj)
    except OSError:
        pass
    lst = os.path.join(workdir, 'k.lst')
    r1 = subprocess.run([C251, src, 'MODSRC', 'XSMALL', 'OPTIMIZE(9, SIZE)',
                         'OBJECT(%s)' % obj, 'PRINT(%s)' % lst],
                        capture_output=True, text=True, encoding='utf-8',
                        errors='replace', timeout=120)
    if r1.returncode != 0 or not os.path.exists(obj):
        return None
    absf = os.path.join(workdir, 'k.abs')
    r2 = subprocess.run([L251, obj, 'TO', absf],
                        capture_output=True, text=True, encoding='utf-8',
                        errors='replace', timeout=120)
    m = re.search(r'code=(\d+)', r2.stdout)
    return int(m.group(1)) if m else None


def cc_hex(src, flag, workdir):
    """c251cc 编译 src → hex 字节数 (CODE section 数据记录之和)."""
    hexf = os.path.join(workdir, 'c.hex')
    r = subprocess.run([C251CC, flag, '-hex', '-o', hexf, src],
                       capture_output=True, text=True, encoding='utf-8',
                       errors='replace', timeout=120)
    if r.returncode != 0 or not os.path.exists(hexf):
        return None
    total = 0
    for ln in open(hexf, encoding='utf-8', errors='replace'):
        ln = ln.strip()
        # :LLAAAATT<data>CC — 数据记录 (type 00) 才计数; 跳过 01(EOF)/02/04(扩展地址)
        if ln.startswith(':') and len(ln) >= 11 and ln[7:9] == '00':
            total += int(ln[1:3], 16)
    return total


def compare_group(name, files, workdir, limit=None):
    print('=== %s (%d tests) ===' % (name, len(files)))
    if limit:
        files = files[:limit]
    if not KEIL_AVAILABLE:
        print('Keil 工具链不可用 (C251=%s 或 L251=%s 不存在) — 跳过大小对比' % (C251, L251))
        print('可用: 设置 KEIL_C251 / KEIL_L251 环境变量指向 Keil 安装')
        return None
    print("%-30s %5s %8s %8s %7s %7s" % ('test', 'Keil', 'cc-O1', 'cc-O2', 'O1/K', 'O2/K'))
    tot = dict(k=0, o1=0, o2=0)
    n = keil_fail = cc_fail = 0
    for f in files:
        t = os.path.basename(f)[:-2]
        k = keil_code(f, workdir)
        if k is None:
            keil_fail += 1
            continue
        o1 = cc_hex(f, '-O1', workdir)
        o2 = cc_hex(f, '-O2', workdir)
        if o1 is None or o2 is None:
            cc_fail += 1
            continue
        n += 1
        tot['k'] += k
        tot['o1'] += o1
        tot['o2'] += o2
        print("%-30s %5d %8d %8d %6.1f%% %6.1f%%" % (t, k, o1, o2, o1 / k * 100, o2 / k * 100))
    if n:
        print("%-30s %5d %8d %8d %6.1f%% %6.1f%%" % ('TOTAL', tot['k'], tot['o1'], tot['o2'],
                                                      tot['o1'] / tot['k'] * 100,
                                                      tot['o2'] / tot['k'] * 100))
    print('(Keil 编译失败跳过: %d, c251cc 编译失败跳过: %d)' % (keil_fail, cc_fail))
    return tot


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
    which = args[0] if args else 'all'

    with tempfile.TemporaryDirectory(prefix='c251ks_') as workdir:
        if which in ('suite', 'all'):
            compare_group('suite', sorted(glob.glob(os.path.join(SUITE, '*.c'))), workdir, limit)
        if which in ('execute', 'all'):
            compare_group('execute', sorted(glob.glob(os.path.join(EXEC, '*.c'))), workdir, limit)
    return 0


if __name__ == '__main__':
    sys.exit(main())
