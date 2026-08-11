# -*- coding: utf-8 -*-
"""外设验证测试框架驱动 (sim251/tests/periph/)。

三层验证框架 (见 docs/hex-verification-plan.md Part C) 的 Tier A 模型级:
  每个外设一个子目录 (uart/ timer/ adc/ ...), 内含独立 C 测试源码,
  run_periph.py 负责:
    1. 用 TCC C251 后端编译 C → Intel HEX
       (build/tcc_c251.exe -O0 -nostdlib <src> -Iinclude -o <hex>)
    2. 用 sim251 (mcs251.exe) 运行:
       mcs251.exe -bios <hex> --cycles N --serial <ser> --dump-ram <dmp>
    3. 解析 --dump-ram 全状态 (SFR/IRAM/XRAM) 与 --serial 串口输出
    4. 按每测试的期望规格断言外设行为 (串口字节 / SFR 标志 / 定时器周期)

用法 (Windows: cmd /c 前缀, Python38):
  python sim251/tests/periph/run_periph.py             # 全部
  python sim251/tests/periph/run_periph.py uart        # 只跑 uart 组
  python sim251/tests/periph/run_periph.py --compile   # 只编译不运行
  python sim251/tests/periph/run_periph.py --list      # 列出测试
  python sim251/tests/periph/run_periph.py --report    # 读上次报告
"""
import os
import sys
import subprocess
import glob

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# ------------------------------------------------------------------ #
# 路径 (Windows 默认; 其他平台自动切换)
# ------------------------------------------------------------------ #
ROOT = (r'd:\work\tinycc_c251' if os.name == 'nt'
        else '/data/data/com.termux/files/home/ws/tcc_c251')
SIM = os.path.join(ROOT, 'sim251', 'mcs251.exe' if os.name == 'nt' else 'mcs251')
TCC = os.path.join(ROOT, 'build', 'tcc_c251.exe' if os.name == 'nt' else 'tcc_c251')
INCLUDE = os.path.join(ROOT, 'include')
PERIPH = os.path.dirname(os.path.abspath(__file__))
TMP = os.path.join(ROOT, 'tmp', 'periph')
REPORT = os.path.join(PERIPH, 'report.txt')

os.makedirs(TMP, exist_ok=True)


# ================================================================== #
# 测试规格表: 每项 = 一个外设验证点
#   src      : C 源文件 (相对 periph/), 单个文件自包含
#   cycles   : sim251 运行周期数
#   checks   : 断言列表, 每项 (kind, arg):
#                ('serial_exact', bytes)    串口输出 == arg
#                ('serial_contains', bytes) 串口输出包含 arg
#                ('sfr_eq',  {0x88: 0x30})  SFR 终值精确等于
#                ('sfr_bits',{0x88: 0x20})  SFR 全部位掩码置位
#                ('sfr_ne',  {0x90: 0x00})  SFR 终值不等于
#                ('iram_bits',{0x20: 0x01}) IRAM 全部位掩码置位
#                ('iram_ne',  {0x20: 0x00}) IRAM 终值不等于
#                ('no_escape', None)        程序无逃逸/栈违规 (跑满周期)
#   expect    : 可选 'known-bug' — 预期失败 (记录 sim251 已知缺口, 不算框架错误)
#   note      : 说明文字
# ================================================================== #
TESTS = [
    # ---------------- UART ---------------- #
    {
        'name': 'uart_smoke',
        'group': 'uart',
        'src': 'uart/uart_smoke.c',
        'cycles': 6000,
        'checks': [
            ('serial_exact', b'UART_SMOKE_OK\r\n'),
            ('no_escape', None),
        ],
        'note': 'TI 轮询逐字节发送已知字符串 (字面量), 校验串口字节流完整',
    },
    {
        'name': 'uart_isr',
        'group': 'uart',
        'src': 'uart/uart_isr.c',
        'cycles': 20000,
        'checks': [
            ('serial_exact', b'ABCDEFGHIJKLM'),
            ('no_escape', None),
        ],
        'note': 'UART1 中断驱动发送 13 字节 (TI 延迟 + ISR 路径)',
    },
    # ---------------- Timer ---------------- #
    {
        'name': 'timer_smoke',
        'group': 'timer',
        'src': 'timer/timer_smoke.c',
        'cycles': 5000,
        'checks': [
            ('sfr_bits', {0x88: 0x20}),      # TCON.TF0 置位
            ('sfr_bits', {0x88: 0x10}),      # TR0 仍在运行
            ('sfr_eq',   {0x8C: 0xFF}),      # TH0 自动重装回 0xFF
            ('sfr_eq',   {0x8E: 0x80}),      # AUXR.T0x12=1
            ('no_escape', None),
        ],
        'note': 'Timer0 1T 快速溢出 → TF0 + 自动重装',
    },
    {
        'name': 'timer_isr',
        'group': 'timer',
        'src': 'timer/timer_isr.c',
        'cycles': 5000,
        'checks': [
            ('sfr_ne', {0x90: 0x00}),        # P1 != 0 → ISR 执行过并写计数
            ('sfr_bits', {0x88: 0x10}),      # TR0 仍在运行
            ('no_escape', None),
        ],
        'note': 'Timer0 中断触发: ISR 递增计数并写 P1',
    },
    # ---------------- ADC ---------------- #
    {
        'name': 'adc_smoke',
        'group': 'adc',
        'src': 'adc/adc_smoke.c',
        'cycles': 5000,
        'checks': [
            ('sfr_eq', {0xBC: 0xA0}),        # ADC_CONTR: POWER+FLAG, START 清
            ('sfr_eq', {0xBD: 0xC0}),        # ADC_RES = 0x300>>2 (10bit)
            ('sfr_eq', {0xBE: 0x00}),        # ADC_RESL 低 2 位 = 0
            ('no_escape', None),
        ],
        'note': 'ADC 上电 + 启动 → 转换完成标志 + 结果寄存器',
    },
    # ---------------- SPI ---------------- #
    {
        'name': 'spi_smoke',
        'group': 'spi',
        'src': 'spi/spi_smoke.c',
        'cycles': 5000,
        'checks': [
            ('sfr_bits', {0xCD: 0x80}),      # SPSTAT.SPIF 置位
            ('no_escape', None),
        ],
        'note': 'SPI 写 SPDAT → SPIF 标志置位',
    },
    # ---------------- CMP (比较器) ---------------- #
    {
        'name': 'cmp_smoke',
        'group': 'cmp',
        'src': 'cmp/cmp_smoke.c',
        'cycles': 5000,
        'checks': [
            ('sfr_bits', {0xE6: 0x08}),      # CMPCR1.CMPRES 置位 (翻转到达)
            ('no_escape', None),
        ],
        'note': '比较器 CMPEN → 模拟输入翻转 → CMPRES 置位',
    },
    # ---------------- INT (外部中断) ---------------- #
    {
        'name': 'int_smoke',
        'group': 'int',
        'src': 'int/int_smoke.c',
        'cycles': 5000,
        'checks': [
            ('sfr_eq', {0x90: 0xAA}),        # P1==0xAA → ISR 执行过
            ('no_escape', None),
        ],
        'extra_args': ['--int0', '4500'],     # INT0 脉冲在 4500cy (TCC 启动 ~3200 后)
        'note': 'INT0 脉冲 (4500cy) → ISR 执行写 P1',
    },
    # ---------------- IAP/EEPROM ---------------- #
    {
        'name': 'iap_smoke',
        'group': 'iap',
        'src': 'iap/iap_smoke.c',
        'cycles': 5000,
        'checks': [
            ('sfr_eq', {0x90: 0x5A}),        # P1==0x5A → 编程+回读一致
            ('no_escape', None),
        ],
        'note': 'IAP 擦除→编程 0x5A→读回校验',
    },
    # ---------------- WDT ---------------- #
    {
        'name': 'wdt_smoke',
        'group': 'wdt',
        'src': 'wdt/wdt_smoke.c',
        'cycles': 300000,
        'checks': [
            ('sfr_eq', {0x90: 0xCC}),        # P1==0xCC → 安全喂狗到达
            ('no_escape', None),
        ],
        'note': 'WDT 使能 + 循环喂狗 → 无复位安全跑满',
    },
    # ---------------- RTC (XFR) ---------------- #
    {
        'name': 'rtc_smoke',
        'group': 'rtc',
        'src': 'rtc/rtc_smoke.c',
        'cycles': 10000,
        'checks': [
            ('sfr_ne', {0x90: 0x00}),        # P1 != 0 → SSEC 已递增
            ('no_escape', None),
        ],
        'note': 'RTC 使能 → SSEC 递增 (far 指针访问 XFR)',
    },
    # ---------------- PWM (XFR) ---------------- #
    {
        'name': 'pwm_smoke',
        'group': 'pwm',
        'src': 'pwm/pwm_smoke.c',
        'cycles': 5000,
        'checks': [
            ('sfr_ne', {0x90: 0x00}),        # P1 != 0 → CNTR 已累加
            ('no_escape', None),
        ],
        'note': 'PWMA 使能 → 计数器递增 (far 指针访问 XFR)',
    },
    # ---------------- DMA M2M (XFR) ---------------- #
    {
        'name': 'dma_smoke',
        'group': 'dma',
        'src': 'dma/dma_smoke.c',
        'cycles': 5000,
        'checks': [
            ('sfr_ne', {0x90: 0xAA}),        # P1 != 0xAA → DONE/STA 非零
            ('no_escape', None),
        ],
        'note': 'DMA M2M 传输完成 (far+xdata 指针访问)',
    },
    # ---------------- I2C (XFR) ---------------- #
    {
        'name': 'i2c_smoke',
        'group': 'i2c',
        'src': 'i2c/i2c_smoke.c',
        'cycles': 10000,
        'checks': [
            ('sfr_ne', {0x90: 0x00}),        # P1 != 0 → I2C 状态非零
            ('no_escape', None),
        ],
        'note': 'I2C 主模式发送 (far 指针访问 XFR)',
    },
]


# ================================================================== #
# 编译 / 运行 / 解析
# ================================================================== #
def compile_test(test):
    """编译单个 C → hex, 返回 (ok, err)"""
    src = os.path.join(PERIPH, test['src'])
    out = os.path.join(TMP, test['name'] + '.hex')
    cmd = [TCC, '-O0', '-nostdlib', src, '-I' + INCLUDE, '-o', out]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode == 0:
        return True, ''
    err = ''
    for line in (r.stderr or r.stdout or '').splitlines():
        if 'error' in line.lower():
            err = line.strip()
            break
    return False, err or (r.stderr or '')[-200:]


def run_sim(test):
    """跑 sim251, 返回 (status, serial, dump, anomalies)"""
    hexp = os.path.join(TMP, test['name'] + '.hex')
    ser = os.path.join(TMP, test['name'] + '.ser')
    dmp = os.path.join(TMP, test['name'] + '.dmp')
    for f in (ser, dmp):
        if os.path.exists(f):
            os.remove(f)
    cmd = [SIM, '-bios', hexp, '--cycles', str(test['cycles']),
           '--serial', ser, '--dump-ram', dmp]
    for a in test.get('extra_args', []):
        cmd.append(a)
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=180)
    except subprocess.TimeoutExpired:
        return 'TIMEOUT', b'', {}, {'escape': True}
    err = p.stderr.decode('utf-8', errors='replace')
    serial = open(ser, 'rb').read() if os.path.exists(ser) else b''
    anomalies = {
        'escape': 'ESCAPED' in err,
        'retv': 'RET-MISMATCH' in err,
    }
    status = {0: 'OK', 1: 'ESCAPE', 2: 'CYCLIMIT', 3: 'RETVIO'}.get(
        p.returncode, 'RC%d' % p.returncode)
    return status, serial, parse_dump(dmp), anomalies


def parse_dump(path):
    """解析 --dump-ram 文本 → {'SFR': {addr:int}, 'IRAM': {...}, 'XRAM': {...}}"""
    out = {'SFR': {}, 'IRAM': {}, 'XRAM': {}}
    try:
        sec = None
        for line in open(path, encoding='utf-8', errors='replace'):
            line = line.strip()
            if line in ('[SFR]', '[IRAM]', '[XRAM]', '[XFR]'):
                sec = line.strip('[]')
                continue
            if line.startswith('['):
                sec = None
                continue
            if sec in out and '=' in line:
                a, v = line.split('=', 1)
                try:
                    out[sec][int(a, 16)] = int(v, 16)
                except ValueError:
                    pass
    except OSError:
        pass
    return out


# ================================================================== #
# 断言
# ================================================================== #
def check_one(kind, arg, status, serial, dump, anomalies):
    """返回 (ok, detail)"""
    if kind == 'serial_exact':
        if not isinstance(arg, bytes):
            arg = arg.encode('utf-8')
        if serial == arg:
            return True, '串口 %dB == 期望' % len(serial)
        n = 0
        while n < min(len(serial), len(arg)) and serial[n] == arg[n]:
            n += 1
        return False, '串口 %dB != 期望 %dB (前 %dB 一致)' % (
            len(serial), len(arg), n)
    if kind == 'serial_contains':
        if not isinstance(arg, bytes):
            arg = arg.encode('utf-8')
        return (arg in serial,
                '串口 %dB 包含期望' % len(serial) if arg in serial
                else '串口 %dB 不含期望 %dB' % (len(serial), len(arg)))
    if kind in ('sfr_eq', 'sfr_bits', 'sfr_ne'):
        sec = dump['SFR']
    elif kind in ('iram_bits', 'iram_ne'):
        sec = dump['IRAM']
    else:
        return False, '未知断言 %s' % kind
    ok = True
    details = []
    for addr, val in arg.items():
        if kind.endswith('_ne'):
            got = sec.get(addr, 0)      # 缺失按 0 处理, 避免虚假通过
        else:
            got = sec.get(addr)
        if kind.endswith('_eq'):
            good = (got == val)
            exp = '==0x%02X' % val
        elif kind.endswith('_bits'):
            good = (got is not None and (got & val) == val)
            exp = 'bits 0x%02X' % val
        else:  # _ne
            good = (got != val)
            exp = '!=0x%02X' % val
        if not good:
            ok = False
            details.append('%02X:%s got=%s' % (addr, exp,
                          'none' if got is None else '0x%02X' % got))
    return ok, (('; '.join(details)) if details else '%d 项通过' % len(arg))


def check_no_escape(status, anomalies):
    bad = anomalies.get('escape') or anomalies.get('retv')
    if bad:
        return False, '程序逃逸/栈违规 (status=%s)' % status
    return True, '安全跑满 %s' % status


# ================================================================== #
# 主流程
# ================================================================== #
def run_test(test, do_compile=True):
    """执行单个测试, 返回 (name, verdict, why)"""
    name = test['name']
    if do_compile:
        ok, err = compile_test(test)
        if not ok:
            return name, 'COMPILE-FAIL', err
    status, serial, dump, anomalies = run_sim(test)
    # 逐断言执行
    passed = []
    failed = []
    for kind, arg in test['checks']:
        if kind == 'no_escape':
            ok, detail = check_no_escape(status, anomalies)
        else:
            ok, detail = check_one(kind, arg, status, serial, dump, anomalies)
        (passed if ok else failed).append((kind, detail))
    if failed:
        why = '; '.join('%s: %s' % (k, d) for k, d in failed)
        if test.get('expect') == 'known-bug':
            return name, 'KNOWN-BUG', why
        return name, 'FAIL', why
    if test.get('expect') == 'known-bug':
        # 预期失败的测试现在全过 → sim251 bug 已修
        return name, 'PASS(修复!)', '已知 bug 已不再复现'
    why = '; '.join(d for k, d in passed)
    return name, 'PASS', why


def main():
    args = [a for a in sys.argv[1:]]
    if '--report' in args:
        print(open(REPORT, encoding='utf-8', errors='replace').read()
              if os.path.exists(REPORT) else '无报告')
        return 0
    if '--list' in args:
        for t in TESTS:
            print('%-14s [%s] %s' % (t['name'], t['group'], t['note']))
        return 0
    do_compile = '--compile' in args
    only_compile = '--compile' in args and '--run' not in args
    only_run = '--run' in args and '--compile' not in args
    group = ''.join(a for a in args if not a.startswith('--'))
    tests = [t for t in TESTS if not group or group in t['name'] or group == t['group']]

    # 编译缺失工具检查
    if not only_run:
        for exe, tag in ((SIM, 'sim251'), (TCC, 'tcc_c251')):
            if not os.path.exists(exe):
                print('缺少 %s: %s (请先构建)' % (tag, exe))
                return 1

    rows = []
    for t in tests:
        if only_compile:
            ok, err = compile_test(t)
            rows.append((t['name'], 'OK' if ok else 'COMPILE-FAIL', err))
            print('%-6s %s %s' % ('OK' if ok else 'FAIL', t['name'], err))
            continue
        name, verdict, why = run_test(t, do_compile=not only_run)
        rows.append((name, verdict, why))
        print('%-14s %-12s %s' % (name, verdict, why))

    if only_compile:
        return 0

    with open(REPORT, 'w', encoding='utf-8') as f:
        for name, v, w in rows:
            f.write('%s\t%s\t%s\n' % (name, v, w))

    n_pass = sum(1 for r in rows if r[1] == 'PASS')
    n_bug = sum(1 for r in rows if r[1] == 'KNOWN-BUG')
    n_fail = sum(1 for r in rows if r[1] == 'FAIL' or r[1] == 'COMPILE-FAIL')
    print('\n===== 外设验证总结 =====')
    print('PASS: %d   KNOWN-BUG(sim251 已知缺口): %d   FAIL: %d   (共 %d)'
          % (n_pass, n_bug, n_fail, len(rows)))
    return 1 if n_fail else 0


if __name__ == '__main__':
    sys.exit(main())
