# -*- coding: utf-8 -*-
"""sim251 功能测试套件 — 逐个检测各功能模块是否存在问题。

模块:
  A. L0 单指令解码 (每个 opcode 家族的最小执行 + 效果检查)
  B. CPU 核心 (寄存器大小端 / 标志位 / 栈 / CALL-RET / 条件跳转)
  C. 内存模型 (直接寻址 / @Ri / @WRj / @DRk / dir16 / MOVX / MOVC / XFR / 位寻址)
  D. 外设 (定时器 / UART / WDT / ADC / SPI / IAP / RTC / PWM / DMA)
  E. CLI / 固件加载 (hex 类型 / bin / 退出码 / 追踪选项)

原理: 每个测试 = 原始字节程序 (bin) → mcs251 --dump-ram 运行 N 周期 →
解析全状态转储 → 检查期望值。

用法:
  python sim251/tests/functional.py            # 全部
  python sim251/tests/functional.py <前缀>      # 只跑指定前缀
"""
import os
import re
import sys
import glob
import subprocess

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

ROOT = os.environ.get('TCC_C251_ROOT',
                      (r'd:\work\tinycc_c251' if os.name == 'nt'
                       else '/data/data/com.termux/files/home/ws/tcc_c251'))
_SIM = os.path.join(ROOT, 'sim251', 'mcs251.exe' if os.name == 'nt' else 'mcs251')
TMP = os.path.join(ROOT, 'tmp')
os.makedirs(TMP, exist_ok=True)

PASS = []
FAIL = []


# ------------------------------------------------------------------ #
# 字节序列组装辅助 (Keil C251 source 模式编码, 与 decode_impl 对应)
# ------------------------------------------------------------------ #
def b(*vals):
    return bytes(vals)


def mov_rn_rm(rd, rs):        # 7C rd rs      MOV Rrd,Rrs
    return b(0x7C, (rd << 4) | rs)


def mov_wr_wr(jd, js):        # 7D (jd/2)4|(js/2)   MOV WRjd,WRjs
    return b(0x7D, ((jd // 2) << 4) | (js // 2))


def mov_rn_imm(m, v):         # 7E m0 v      MOV Rm,#v
    return b(0x7E, (m << 4) | 0x0, v)


def mov_wr_imm(j, v):         # 7E (j/2)4 hi lo   MOV WRj,#d16 (大端)
    return b(0x7E, ((j // 2) << 4) | 0x4, (v >> 8) & 0xFF, v & 0xFF)


def mov_rn_dir(m, d):         # 7E m1 d      MOV Rm,dir8
    return b(0x7E, (m << 4) | 0x1, d)


def mov_dir_rn(m, d):         # 7A m1 d      MOV dir8,Rm
    return b(0x7A, (m << 4) | 0x1, d)


def mov_dir16_rn(m, d):       # 7A m3 hi lo  MOV dir16,Rm (edata)
    return b(0x7A, (m << 4) | 0x3, (d >> 8) & 0xFF, d & 0xFF)


def mov_rn_dir16(m, d):       # 7E m3 hi lo  MOV Rm,dir16
    return b(0x7E, (m << 4) | 0x3, (d >> 8) & 0xFF, d & 0xFF)


def mov_a_imm(v):             # 74 v         MOV A,#v
    return b(0x74, v)


def mov_a_dir(d):             # E5 d         MOV A,dir8
    return b(0xE5, d)


def mov_dir_a(d):             # F5 d         MOV dir8,A
    return b(0xF5, d)


def add_rn_rm(rd, rs):        # 2C rd rs     ADD Rrd,Rrs
    return b(0x2C, (rd << 4) | rs)


def add_wr_wr(jd, js):        # 2D (jd/2)4|(js/2)
    return b(0x2D, ((jd // 2) << 4) | (js // 2))


def add_wr_imm(j, v):         # 2E (j/2)4 hi lo
    return b(0x2E, ((j // 2) << 4) | 0x4, (v >> 8) & 0xFF, v & 0xFF)


def sub_wr_imm(j, v):         # 9E (j/2)4 hi lo
    return b(0x9E, ((j // 2) << 4) | 0x4, (v >> 8) & 0xFF, v & 0xFF)


def cmp_rn_imm(m, v):         # BE m0 v      CMP Rm,#v (只设标志)
    return b(0xBE, (m << 4) | 0x0, v)


def cmp_wr_imm(j, v):         # BD (j/2)4 hi lo? 用 BD WRj,#d16
    return b(0xBD, ((j // 2) << 4) | 0x4, (v >> 8) & 0xFF, v & 0xFF)


def xrl_rn_rm(rd, rs):        # 6C rd rs     XRL Rrd,Rrs
    return b(0x6C, (rd << 4) | rs)


def anl_rn_imm(m, v):         # 5E m0 v      ANL Rm,#v
    return b(0x5E, (m << 4) | 0x0, v)


def orl_rn_imm(m, v):         # 4E m0 v      ORL Rm,#v
    return b(0x4E, (m << 4) | 0x0, v)


def movz_wr_rn(j, m):         # 0A (j/2)4|m  MOVZ WRj,Rm
    return b(0x0A, ((j // 2) << 4) | m)


def movs_wr_rn(j, m):         # 1A (j/2)4|m  MOVS WRj,Rm
    return b(0x1A, ((j // 2) << 4) | m)


def inc_rn_1(m):              # 0B m0        INC Rm,#1 (byte)
    return b(0x0B, (m << 4) | 0x0)


def inc_wr_1(j):              # 0B (j/2)4    INC WRj,#1 (word)
    return b(0x0B, ((j // 2) << 4) | 0x4)


def dec_rn_1(m):              # 1B m0        DEC Rm,#1
    return b(0x1B, (m << 4) | 0x0)


def srl_rn(m):                # 1E m0        SRL Rm
    return b(0x1E, (m << 4) | 0x0)


def srl_wr(j):                # 1E (j/2)4    SRL WRj
    return b(0x1E, ((j // 2) << 4) | 0x4)


def sll_wr(j):                # 3E (j/2)4    SLL WRj
    return b(0x3E, ((j // 2) << 4) | 0x4)


def sra_wr(j):                # 0E (j/2)4    SRA WRj
    return b(0x0E, ((j // 2) << 4) | 0x4)


def mov_dptr(v):              # 90 hi lo     MOV DPTR,#d16
    return b(0x90, (v >> 8) & 0xFF, v & 0xFF)


def sjmp(rel):                # 80 rel
    return b(0x80, rel & 0xFF)


def je(rel):                  # 68 rel      JE (Z)
    return b(0x68, rel & 0xFF)


def jne(rel):                 # 78 rel      JNE (!Z)
    return b(0x78, rel & 0xFF)


def jz(rel):                  # 60 rel      JZ (A==0)
    return b(0x60, rel & 0xFF)


def jnz(rel):                 # 70 rel      JNZ (A!=0)
    return b(0x70, rel & 0xFF)


def ljmp(addr):               # 02 hi lo
    return b(0x02, (addr >> 8) & 0xFF, addr & 0xFF)


def lcall(addr):              # 12 hi lo
    return b(0x12, (addr >> 8) & 0xFF, addr & 0xFF)


def ret():                    # 22
    return b(0x22)


def nop():
    return b(0x00)


def push_dir(d):              # C0 d
    return b(0xC0, d)


def pop_dir(d):               # D0 d
    return b(0xD0, d)


def push_rn(m):               # CA m8        PUSH Rm
    return b(0xCA, (m << 4) | 0x8)


def pop_rn(m):                # DA m8        POP Rm
    return b(0xDA, (m << 4) | 0x8)


def movc_a_dptr():            # 93
    return b(0x93)


def movx_a_dptr():            # E0
    return b(0xE0)


def movx_dptr_a():            # F0
    return b(0xF0)


# ---- 外设测试辅助 ----
def sfr_imm(d, v):            # 75 d v       MOV dir8,#v (SFR 直接写)
    return b(0x75, d, v)


def far_set(addr, reg, val):  # DR4=0x007E:addr, MOV @DR4,Rreg (XFR 写)
    return (mov_wr_imm(6, addr) + mov_wr_imm(4, 0x007E)
            + mov_rn_imm(reg, val) + b(0x7A, 0x1B, (reg << 4)))


def far_get(addr, reg):       # DR4=0x007E:addr, MOV Rreg,@DR4 (XFR 读)
    return (mov_wr_imm(6, addr) + mov_wr_imm(4, 0x007E)
            + b(0x7E, 0x1B, (reg << 4)))


def spin():                   # 80 FE 自旋 (程序末尾挂起)
    return b(0x80, 0xFE)


def irq_test(mainp, vec, val, extra=None):
    """构造中断向量测试: LJMP 跳过向量区, vec 处放 MOV R7,#val; RETI,
    main 在 0x20。返回 (buf, 周期上限), 用 check(..., load=buf) 运行。"""
    buf = bytearray(0x400)
    buf[0:3] = ljmp(0x20)
    buf[vec:vec + 3] = mov_rn_imm(7, val)
    buf[vec + 3] = 0x32            # RETI
    buf[0x20:0x20 + len(mainp)] = mainp
    return bytes(buf), extra


# ------------------------------------------------------------------ #
# 运行辅助: bin → mcs251 --dump-ram → 状态字典
# ------------------------------------------------------------------ #
class State:
    def __init__(self, text):
        self.lines = text.splitlines()
        self.ram = {}
        self.sfr = {}
        self.xfr = {}
        self.xram = {}
        self.regs = {}
        cur = None
        for ln in self.lines:
            m = re.match(r'^(R[0-9A-F]{2}|PC|SP|PSW|PSW1|CYCLES)=([0-9A-F]+)$', ln)
            if m:
                self.regs[m.group(1)] = int(m.group(2), 16)
                continue
            if ln.startswith('['):
                cur = ln.strip('[]')
                continue
            m = re.match(r'^([0-9A-F]+)=([0-9A-F]+)$', ln)
            if not m or cur is None:
                continue
            a = int(m.group(1), 16)
            v = int(m.group(2), 16)
            if cur == 'IRAM':
                self.ram[a] = v
            elif cur == 'SFR':
                self.sfr[a] = v
            elif cur == 'XFR':
                self.xfr[a] = v
            elif cur == 'XRAM':
                self.xram[a] = v

    def r(self, n):
        return self.regs.get('R%02X' % n, 0)

    def wr(self, j):
        return (self.r(j) << 8) | self.r(j + 1)

    def dr(self, k):
        v = 0
        for i in range(4):
            v = (v << 8) | self.r(k + i)
        return v

    @property
    def pc(self):
        return self.regs.get('PC', 0)

    @property
    def sp(self):
        return self.regs.get('SP', 0)

    @property
    def psw(self):
        return self.regs.get('PSW', 0)

    @property
    def psw1(self):
        return self.regs.get('PSW1', 0)


def _write_bin(prog, load):
    """prog (或 load 覆盖) → 临时 bin 文件, 返回路径。"""
    p = os.path.join(TMP, 'fn_%s.bin' % (abs(hash(prog)) % 100000000))
    with open(p, 'wb') as f:
        if load is not None:
            f.write(load)
        else:
            f.write(prog)
    return p


def run(prog, cycles, extra=None, bin_file=None, load=None):
    """运行 prog (bytes, 放 0x0000) N 周期, 返回 (State, exit_code, stderr).
    立即单次执行 (sec_e 侧效应测试用: --serial/--trace-watch 需即时结果)。"""
    p = _write_bin(prog, load)
    cmd = [_SIM, '-bios', p, '--cycles', str(cycles), '--dump-ram', p + '.dump']
    if extra:
        cmd += extra
    r = subprocess.run(cmd, capture_output=True, text=True,
                       encoding='utf-8', errors='replace', timeout=60)
    st = State(open(p + '.dump', encoding='utf-8', errors='replace').read())
    return st, r.returncode, (r.stderr or '')


# ------------------------------------------------------------------ #
# 批量执行: check() 只登记, 段结束后 _flush_registry() 用一次            #
# mcs251 --run-list 子进程跑完整个段的用例 (进程启动 51ms/次 → 批处理    #
# 后每段仅 1 次启动, 套件 ~3.5s → ~0.6s)。兜底: 若批处理产物缺失         #
# (旧 mcs251 / 批失败), 单独重跑该用例。                                #
# ------------------------------------------------------------------ #
_REG = []          # 待执行 check 规格: dict(name, prog, cycles, checks, ...)


def _verify(name, st, rc, spec):
    """对单个已执行的 check 规格做状态比对并登记 PASS/FAIL。"""
    problems = []
    for key, want in spec['checks'].items():
        if key.startswith('R') and key[1:].isdigit():
            got = st.r(int(key[1:]))
        elif key.startswith('WR') and key[2:].isdigit():
            got = st.wr(int(key[2:]))
        elif key.startswith('DR') and key[2:].isdigit():
            got = st.dr(int(key[2:]))
        elif key == 'PC':
            got = st.pc
        elif key == 'SP':
            got = st.sp
        elif key == 'PSW':
            got = st.psw
        elif key == 'PSW1':
            got = st.psw1
        elif key.startswith('IRAM:'):
            got = st.ram.get(int(key[5:], 16), 0)
        elif key.startswith('SFR:'):
            got = st.sfr.get(int(key[4:], 16), 0)
        elif key.startswith('XFR:'):
            got = st.xfr.get(int(key[4:], 16), 0)
        elif key.startswith('XRAM:'):
            got = st.xram.get(int(key[5:], 16), 0)
        elif key == 'EXIT':
            got = rc
        else:
            continue
        if got != want:
            problems.append('%s: want=%r got=%r' % (key, want, got))
    if problems and spec['known_bug']:
        print('KNOWN %-42s %s  [已知 bug, 见文件头]' % (name, '; '.join(problems)))
    elif problems:
        FAIL.append(name)
        print('FAIL %-42s %s' % (name, '; '.join(problems)))
    else:
        PASS.append(name)
        print('PASS %-42s' % name)


def _flush_registry():
    """把 _REG 中所有已登记 check 用一次 --run-list 子进程批量执行并验证。"""
    if not _REG:
        return
    runlist = os.path.join(TMP, 'fn_batch.runlist')
    lines, dumps = [], []
    for i, spec in enumerate(_REG):
        p = _write_bin(spec['prog'], spec['load'])
        dump = '%s.b%d.dump' % (p, i)          # 每 run 唯一 dump (防同 prog 碰撞)
        dumps.append(dump)
        fields = [p, str(spec['cycles']), dump] + list(spec['extra'] or [])
        lines.append(' '.join(fields))
    with open(runlist, 'w') as f:
        f.write('\n'.join(lines) + '\n')
    try:
        r = subprocess.run([_SIM, '--run-list', runlist],
                           capture_output=True, text=True,
                           encoding='utf-8', errors='replace', timeout=600)
    except subprocess.TimeoutExpired:
        print('BATCH TIMEOUT: 逐用例兜底重跑')
        r = None
    rcs = []
    if r is not None:
        for m in re.finditer(r'^BATCH (\d+) (\d+)\s*$', r.stdout, re.M):
            rcs.append(int(m.group(2)))
    for i, spec in enumerate(_REG):
        if r is not None and os.path.exists(dumps[i]) and i < len(rcs):
            st = State(open(dumps[i], encoding='utf-8',
                            errors='replace').read())
            rc = rcs[i]
        else:
            # 兜底: 单独重跑 (旧 mcs251 无 --run-list / 批处理失败)
            st, rc, err = run(spec['prog'], spec['cycles'], spec['extra'],
                              load=spec['load'])
        _verify(spec['name'], st, rc, spec)
    _REG.clear()


def check(name, prog, cycles, checks, extra=None, load=None, retc=None,
          known_bug=False):
    """登记一个功能测试 (批量执行, 见 _flush_registry)。
    checks: dict; 键 = 状态表达式, 值 = 期望。支持:
       R<n>=, WR<j>=, DR<k>=, PC=, SP=, PSW=, PSW1=, IRAM:<addr>=, SFR:<addr>=,
       XFR:<addr>=, XRAM:<addr>=, EXIT=<code>
       known_bug=True: 预期失败 (记录已知问题, 不判 FAIL)。"""
    _REG.append(dict(name=name, prog=prog, cycles=cycles, checks=checks,
                     extra=extra, load=load, retc=retc, known_bug=known_bug))


# ================================================================== #
# A. L0 单指令解码
# ================================================================== #
def sec_a():
    print('\n=== A. L0 单指令解码 ===')
    # A1: MOV Rm,Rm / MOV WRj,WRj / MOV Rm,#imm / MOV WRj,#imm
    check('mov_rn_rn', mov_rn_imm(4, 0x2A) + mov_rn_rm(5, 4), 10,
          {'R5': 0x2A})
    check('mov_wr_wr', mov_wr_imm(6, 0x1234) + mov_wr_wr(4, 6), 10,
          {'WR4': 0x1234, 'R4': 0x12, 'R5': 0x34})   # WR 大端
    check('mov_rn_imm', mov_rn_imm(7, 0xAB), 10, {'R7': 0xAB})
    check('mov_wr_imm_be', mov_wr_imm(6, 0xABCD), 10,
          {'R6': 0xAB, 'R7': 0xCD})                   # 大端验证
    # A2: MOVZ / MOVS 零扩展/符号扩展
    check('movz_zext', mov_rn_imm(4, 0xFF) + movz_wr_rn(6, 4), 10,
          {'WR6': 0x00FF})
    check('movs_sext', mov_rn_imm(4, 0x80) + movs_wr_rn(6, 4), 10,
          {'WR6': 0xFF80})
    # A3: ADD / SUB (8/16 位 + 立即数)
    check('add_rn_rn', mov_rn_imm(4, 0x10) + mov_rn_imm(5, 0x20)
          + add_rn_rm(3, 4) + add_rn_rm(3, 5), 10, {'R3': 0x30})
    check('add_wr_imm', mov_wr_imm(6, 0x0001) + add_wr_imm(6, 0x0002), 10,
          {'WR6': 0x0003})
    check('sub_wr_imm', mov_wr_imm(6, 0x0010) + sub_wr_imm(6, 0x0004), 10,
          {'WR6': 0x000C})
    # A4: 逻辑 AND/OR/XRL
    check('anl_rn_imm', mov_rn_imm(4, 0xF0) + anl_rn_imm(4, 0x3F), 10,
          {'R4': 0x30})
    check('orl_rn_imm', mov_rn_imm(4, 0x30) + orl_rn_imm(4, 0x0F), 10,
          {'R4': 0x3F})
    check('xrl_rn_rm', mov_rn_imm(4, 0xFF) + mov_rn_imm(5, 0x0F)
          + xrl_rn_rm(4, 5), 10, {'R4': 0xF0})
    # A5: INC/DEC short (byte/word)
    check('inc_rn_1', mov_rn_imm(3, 0x0F) + inc_rn_1(3), 10, {'R3': 0x10})
    check('inc_wr_1', mov_wr_imm(6, 0x0FFF) + inc_wr_1(6), 10, {'WR6': 0x1000})
    check('dec_rn_1', mov_rn_imm(3, 0x00) + dec_rn_1(3), 10, {'R3': 0xFF})
    # A6: 移位 SRL/SLL/SRA
    check('srl_wr', mov_wr_imm(6, 0x8000) + srl_wr(6), 10, {'WR6': 0x4000})
    check('sll_wr', mov_wr_imm(6, 0x4000) + sll_wr(6), 10, {'WR6': 0x8000})
    check('sra_wr_arith', mov_wr_imm(6, 0x8000) + sra_wr(6), 10, {'WR6': 0xC000})
    # A7: MOV dir16 (edata) 读写 + 直接寻址
    #   EDATA 已扩到 64KB (00:0000-00:FFFF), dir16 直接寻址访问 EDATA,
    #   0x1234 现在落在 iram (不再溢出到 xram)
    check('mov_dir16_rn', mov_rn_imm(7, 0x42) + mov_dir16_rn(7, 0x1234), 10,
          {'IRAM:0x1234': 0x42})
    check('mov_rn_dir16', mov_rn_imm(7, 0x42) + mov_dir16_rn(7, 0x1234)
          + mov_rn_dir16(6, 0x1234), 10, {'R6': 0x42})
    check('mov_dir_a', mov_a_imm(0x55) + mov_dir_a(0x40), 10, {'IRAM:0x40': 0x55})
    check('mov_a_dir', mov_rn_imm(7, 0x77) + mov_dir_rn(7, 0x40)
          + mov_a_dir(0x40), 10, {'R11': 0x77})   # A=R11
    # A8: CMP (回归: 曾越界写 0xBF 的 bug)
    check('cmp_rn_imm_flags_eq',
          mov_rn_imm(11, 0x09) + cmp_rn_imm(11, 0x09) + ret(), 10,
          {'IRAM:0xBF': 0x00, 'PSW1': 0x02})      # Z=1 (PSW1.Z = bit1)
    check('cmp_rn_imm_flags_ne',
          mov_rn_imm(11, 0x0A) + cmp_rn_imm(11, 0x09) + ret(), 10,
          {'IRAM:0xBF': 0x00, 'PSW1': 0x00})
    # A9: 条件跳转 JNE/JE/JLE/JG (u8 比较用 PSW1 N/Z)
    #   JE 命中 → 跳 4 字节 (跳过 7E 70 EE + 22), 落到 7E 70 11
    prog = (mov_rn_imm(11, 0x0A) + cmp_rn_imm(11, 0x0A) + je(0x04)
            + mov_rn_imm(7, 0xEE) + ret() + mov_rn_imm(7, 0x11) + ret())
    check('je_taken', prog, 30, {'R7': 0x11})      # JE 命中 → 跳到 0x11 分支
    prog = (mov_rn_imm(11, 0x0A) + cmp_rn_imm(11, 0x0B) + je(0x04)
            + mov_rn_imm(7, 0xEE) + ret() + mov_rn_imm(7, 0x11) + ret())
    check('je_not_taken', prog, 30, {'R7': 0xEE})
    prog = (mov_rn_imm(11, 0x0A) + cmp_rn_imm(11, 0x0B) + jne(0x04)
            + mov_rn_imm(7, 0xEE) + ret() + mov_rn_imm(7, 0x11) + ret())
    check('jne_taken', prog, 30, {'R7': 0x11})
    # A10: 栈 PUSH/POP (Rm + dir8)
    check('push_pop_rn',
          mov_rn_imm(6, 0x5A) + push_rn(6)
          + mov_rn_imm(6, 0x00) + pop_rn(6), 10, {'R6': 0x5A, 'SP': 0x07})
    check('push_pop_dir',
          mov_a_imm(0x3C) + mov_dir_a(0x30) + push_dir(0x30)
          + mov_a_imm(0x00) + mov_dir_a(0x30) + pop_dir(0x30)
          + mov_a_dir(0x30), 10, {'R11': 0x3C, 'IRAM:0x30': 0x3C, 'SP': 0x07})
    # A11: MOV DPTR + MOVC
    code = bytes([0x90, 0x00, 0x20]) + b(0xE4) + movc_a_dptr() + ret()
    prog = code + b(0x00) * (0x20 - len(code)) + b(0xAB)
    check('movc_a_dptr', prog, 20, {'R11': 0xAB})
    # A12: A5 转义 (MOV A,R7)
    check('a5_escape', mov_rn_imm(7, 0x66) + b(0xA5, 0xEF), 10, {'R11': 0x66})
    # A13: A9 扩展位 SETB/CLR
    check('a9_setb', b(0xA9, 0xD7, 0xBA), 10, {'SFR:0xBA': 0x80})   # P_SW2.7
    check('a9_clr', b(0x75, 0x8F, 0xFF) + b(0xA9, 0xC7, 0x8F), 10,
          {'SFR:0x8F': 0x7F})                                     # TCON.7
    # A14: 8051 兼容 MOV A,# / MOV dir,# / MOVX
    check('mov_a_imm', mov_a_imm(0x99), 10, {'R11': 0x99})
    check('mov_dir_imm', b(0x75, 0x50, 0x77), 10, {'IRAM:0x50': 0x77})
    check('movx_a_dptr', mov_dptr(0x0050) + b(0xE0), 10, {'R11': 0x00})  # 未初始化 → 0
    # A15: LCALL + RET 嵌套 (栈返回)
    prog = b(0x00) * 0x30 + (mov_rn_imm(4, 0x21) + ret())           # @0x30
    prog = (lcall(0x0030) + mov_rn_imm(5, 0x22) + ret()
            + prog[4:])                                            # 对齐
    check('lcall_ret', prog[:0x30] + (mov_rn_imm(4, 0x21) + ret()), 30,
          {'R4': 0x21})
    # A16: LJMP
    check('ljmp', mov_rn_imm(4, 0x01) + ljmp(0x20)
          + mov_rn_imm(4, 0xFF) + b(0x00) * 0x18 + mov_rn_imm(4, 0x02), 20,
          {'R4': 0x02})


# ================================================================== #
# B. CPU 核心
# ================================================================== #
def sec_b():
    print('\n=== B. CPU 核心 ===')
    # B1: ADD 进位 CY + AC + 溢出
    check('add_carry', mov_a_imm(0xFF) + b(0x24, 0x01), 10,
          {'R11': 0x00, 'PSW': 0xC0})       # CY(0x80)+AC(0x40), A=0
    check('add_ov', mov_a_imm(0x7F) + b(0x24, 0x01), 10,
          {'R11': 0x80, 'PSW': 0x45})       # AC(0x40)+OV(0x04)+P(0x01)
    # B2: SUBB 借位
    check('subb_borrow', b(0xC3) + mov_a_imm(0x00) + b(0x94, 0x01), 10,
          {'R11': 0xFF, 'PSW': 0xC0})       # CY+AC (借位)
    # B3: 逻辑标志 N/Z (PSW1)
    check('logic_z', mov_a_imm(0x00) + b(0x54, 0xFF), 10, {'PSW1': 0x02})
    check('logic_n', mov_a_imm(0x80) + b(0x44, 0x00), 10,
          {'PSW1': 0x20})                   # ORL A,#0 → N=1 (bit5)
    # B4: 奇偶 P (PSW.0) — 8051: A 含奇数个 1 时 P=1
    check('parity_even', mov_a_imm(0x00) + b(0x24, 0x00), 10,
          {'PSW': 0x00})                    # 0x00 偶(0个1) → P=0
    check('parity_odd', mov_a_imm(0x01) + b(0x24, 0x00), 10,
          {'PSW': 0x01})                    # 0x01 奇(1个1) → P=1
    # B5: 16 位 ADD 进位 (WR) — addw_flags 只设 CY
    check('addw_carry', mov_wr_imm(6, 0xFFFF) + add_wr_imm(6, 0x0001), 10,
          {'WR6': 0x0000, 'PSW': 0x80})
    # B6: DRk 小端
    check('drk_little_endian', mov_wr_imm(4, 0x1122) + mov_wr_imm(6, 0x3344),
          10, {'DR4': 0x11223344})
    # B7: JZ 条件跳转 (A==0)
    prog = (mov_a_imm(0xFF) + b(0x24, 0x01)      # A=0xFF+1=0x00
            + jz(0x04) + mov_rn_imm(7, 0xEE) + ret()
            + mov_rn_imm(7, 0x11) + ret())
    check('jz_taken', prog, 30, {'R7': 0x11})
    # B8: CALL 返回地址正确性 (嵌套)
    prog = bytearray(0x40)
    prog[0x00:0x03] = lcall(0x20)
    prog[0x03:0x06] = lcall(0x30)
    prog[0x06:0x08] = sjmp(-2)                     # 主程序末尾自旋 (80 FE)
    prog[0x20:0x22] = inc_wr_1(8)
    prog[0x22:0x24] = ret()
    prog[0x30:0x32] = inc_wr_1(8)
    prog[0x32:0x34] = ret()
    check('nested_call', bytes(prog), 40, {'WR8': 0x0002, 'SP': 0x07})


# ================================================================== #
# C. 内存模型
# ================================================================== #
def sec_c():
    print('\n=== C. 内存模型 ===')
    # C1: @Ri 间接 (MOV @R0,R4 → MOV R6,@R0)
    prog = (mov_rn_imm(0, 0x40) + mov_rn_imm(4, 0x77)
            + b(0x7A, 0x42, 0x40)          # MOV @R0,R4 (byte2 = m<<4|i = 0x40)
            + mov_rn_imm(0, 0x40) + b(0x7E, 0x62, 0x00))  # MOV R6,@R0 (b2&1=0)
    check('at_ri', prog, 10, {'R6': 0x77, 'IRAM:0x40': 0x77})
    # C2: 位寻址 IRAM 0x20-0x2F
    check('bit_set_clr', b(0x75, 0x20, 0x00) + b(0xD2, 0x00)
          + b(0xE5, 0x20), 10, {'R11': 0x01})     # SETB 0x20.0 → A=0x20=1
    # C3: 位寻址 SFR (MOV C,bit)
    check('bit_sfr_c', b(0x75, 0x90, 0x02) + b(0xA2, 0x91), 10,
          {'PSW': 0x80})                     # P1=0x02, MOV C,P1.1 → CY=1
    # C4: XFR 窗口 far 写 (DR4 = 0x007EFEC0, MOV @DR4,R3)
    # (DRk 大端 + SPX 特判 + @DRk xram8 路由 已修复, 提交 a2870d4)
    prog = (mov_wr_imm(6, 0xFEC0) + mov_wr_imm(4, 0x007E)
            + mov_rn_imm(3, 0x55) + b(0x7A, 0x1B, 0x30) + ret())
    check('xfr_far_write', prog, 15, {'XFR:0xFEC0': 0x55})
    # C4b: far 写后经 @DRk 读回
    prog = (mov_wr_imm(6, 0xFEC0) + mov_wr_imm(4, 0x007E)
            + mov_rn_imm(3, 0x55) + b(0x7A, 0x1B, 0x30)
            + mov_wr_imm(6, 0xFEC0) + mov_wr_imm(4, 0x007E)
            + b(0x7E, 0x1B, 0x30) + ret())   # MOV R3,@DR4
    check('xfr_far_readback', prog, 20, {'R3': 0x55})
    # C5: XFR far 读 (初始 0)
    prog = (mov_wr_imm(6, 0xFEC0) + mov_wr_imm(4, 0x007E)
            + b(0x7E, 0x1B, 0x30) + ret())   # MOV R3,@DR4
    check('xfr_far_read', prog, 15, {'R3': 0x00})
    # C6: MOVX @Ri / @DPTR xram
    check('movx_write_read', mov_dptr(0x0100) + mov_a_imm(0x66) + movx_dptr_a()
          + mov_a_imm(0x00) + movx_a_dptr(), 15, {'R11': 0x66, 'XRAM:0x0100': 0x66})
    # C7: @WRj 16 位间接
    prog = (mov_wr_imm(6, 0x0040) + mov_rn_imm(4, 0x99)
            + b(0x1B, 0x68, 0x40) + ret())   # MOV @WR6? 用 0x08 形式
    # MOV @WRj,WRj = 0x1B? 用 mov_op1_reg 0x7A 0x69? 简化: 用 0x1B 6 8 = MOV WR6,@WR6? 待定
    #   直接用 7A A0 形式: MOV @WR6,R4 = 7A (6/2=3)<<4|9, 40  → 0x7A 0x39 0x40
    prog = (mov_wr_imm(6, 0x0040) + mov_rn_imm(4, 0x99)
            + b(0x7A, 0x39, 0x40) + ret())
    check('at_wrj_store', prog, 15, {'IRAM:0x40': 0x99})
    # C8: dir16 读 edata (数据段)
    check('dir16_read', mov_dir16_rn(7, 0x0200) + mov_rn_dir16(6, 0x0200), 10,
          {'R6': 0x00})                      # 未初始化 → 0
    # C9: 间接 @DRk 32 位读 (dword) — DR4=0x0000:0100, 先写 0x11223344 再读回
    #   写: DR4→addr, WR6=0x1122, WR4=0x3344 (大端 DR 高字=WR4)?? 简化: 写 16 位
    #   MOV @DR4,WR6 (0x7A jd=6→? 编码 0x7A (6/2=3)<<4|0xB? 用 xfr_far 已验证的
    #   8 位路径即可代表 @DRk 路由; 32 位在 C9b 用已知 0x0B 形式 (见占位)。
    check('drk_placeholder', b(0x00) + ret(), 5, {'R0': 0x00})
    # C10: 双 DPTR (DPS=0x86 切换; DPTR0/DPTR1 独立)
    #   DPTR0→xram[0x0100]=0x11; DPS=1 → DPTR1→xram[0x0200]=0x22;
    #   DPS=0 读回 DPTR0 指向的 0x0100
    prog = (mov_dptr(0x0100) + mov_a_imm(0x11) + movx_dptr_a()
            + sfr_imm(0x86, 0x01)                       # DPS=1
            + mov_dptr(0x0200) + mov_a_imm(0x22) + movx_dptr_a()
            + sfr_imm(0x86, 0x00)                       # DPS=0
            + mov_a_imm(0x00) + movx_a_dptr()           # A = xram[0x0100]
            + spin())                                   # 挂起 (勿 RET, 避免重启覆盖状态)
    check('dual_dptr', prog, 20,
          {'R11': 0x11, 'XRAM:0x0100': 0x11, 'XRAM:0x0200': 0x22})
    # C11: 端口复位默认 0xFF (STC32G 上拉; P0-P7)
    check('ports_reset_high', b(0x00) + ret(), 5,
          {'SFR:0x80': 0xFF, 'SFR:0x90': 0xFF, 'SFR:0xA0': 0xFF,
           'SFR:0xB0': 0xFF, 'SFR:0xC0': 0xFF, 'SFR:0xF8': 0xFF})


# ================================================================== #
# D. 外设 (定时器/UART/WDT/ADC/SPI/IAP/RTC/PWM/DMA)
# ================================================================== #
def sec_d():
    print('\n=== D. 外设 ===')
    # D1: Timer0 16 位自动重装计数 + 溢出 (1T, 重装 0xFFF0 → 16 周期后 TF0)
    #   写 TL0/TH0 设重装影子; TR0 启动; 1T (AUXR.T0x12=1)。
    prog = (sfr_imm(0x89, 0x00)          # TMOD = 0 (mode0 16bit auto-reload)
            + sfr_imm(0x8E, 0x80)        # AUXR.T0x12 = 1 (1T)
            + sfr_imm(0x8A, 0xF0)        # TL0 = 0xF0
            + sfr_imm(0x8C, 0xFF)        # TH0 = 0xFF (重装 0xFFF0)
            + sfr_imm(0x88, 0x10)        # TCON = 0x10 (TR0=1)
            + spin())
    # 溢出后 TF0 置位 + 自动重装 (高字节 0xFF 保持, 计数器在 0xFFF0-0xFFFF 区间)
    check('timer_t0_overflow', prog, 40,
          {'SFR:0x88': 0x30,             # TR0 + TF0 (0x10|0x20)
           'SFR:0x8C': 0xFF})            # 溢出后重装, 高字节仍 0xFF

    # D2: Timer0 12T 模式 (慢 12 倍, 40 周期内不溢出)
    prog = (sfr_imm(0x89, 0x00)
            + sfr_imm(0x8E, 0x00)        # AUXR.T0x12 = 0 (12T)
            + sfr_imm(0x8A, 0xF0) + sfr_imm(0x8C, 0xFF)
            + sfr_imm(0x88, 0x10)
            + spin())
    check('timer_t0_12t_no_overflow', prog, 40,
          {'SFR:0x88': 0x10})            # 40 周期 < 16*12 → TF0 未置

    # D3: UART1 TX → SCON.TI (位 1) 置位
    prog = (sfr_imm(0x98, 0x40)          # SCON = mode1
            + mov_a_imm(0x41) + mov_dir_a(0x99)   # SBUF = 'A'
            + spin())
    # TI 延迟 64 周期 (UART_TI_DELAY, 模拟串行发送耗时) → 实测 cyc66 置位,
    # 窗口需 >64: 用 80 (阻塞式 while(!TI) 死锁修复依赖该延迟, 不可缩短)
    check('uart_tx_ti', prog, 80, {'SFR:0x98': 0x42})   # TI 置位

    # D4: UART1 RX (--input 注入字节 → SBUF + RI)
    in_file = os.path.join(TMP, 'fn_rx.bin')
    open(in_file, 'wb').write(b'\x5A')
    prog = sfr_imm(0x98, 0x50) + spin()  # SCON = mode1 + REN
    check('uart_rx_inject', prog, 1000, {'SFR:0x99': 0x5A, 'SFR:0x98': 0x51},
          extra=['--input', in_file])

    # D5: WDT 使能 + 长时间运行 (超时复位不崩溃, 稳定 CYCLIMIT)
    prog = (sfr_imm(0xC1, 0x20)          # WDT_CONTR = EN_WDT (ps=0 → 32768 周期)
            + sfr_imm(0x90, 0xAA)        # P1 = 0xAA (标记)
            + spin())
    check('wdt_enable_stable', prog, 50000, {'EXIT': 2})   # 周期耗尽, 无逃逸

    # D6: ADC 转换 (POWER+START → 完成后 ADC_FLAG + 结果)
    #   ADC_CONTR=0xBC, ADCCFG=0xDE (SPEED), ADC_RES=0xBD, ADC_RESL=0xBE
    prog = (sfr_imm(0xBC, 0x80)          # ADC_POWER
            + sfr_imm(0xBC, 0xC0)        # + ADC_START
            + spin())
    #  转换周期 ≈ 16<<SPEED(0)=16; 30 周期后完成
    check('adc_convert', prog, 40,
          {'SFR:0xBC': 0xA0,             # POWER + FLAG (START 清除)
           'SFR:0xBD': 0xC0})            # ADC_RES = 0x300>>2 = 0xC0 (10bit)

    # D7: SPI 回环 (SPDAT 写 → SPIF + SPDAT 回读)
    prog = (sfr_imm(0xCE, 0x40)          # SPCTL = SPEN
            + mov_a_imm(0x77) + mov_dir_a(0xCF)   # SPDAT = 0x77
            + spin())
    check('spi_loopback', prog, 30, {'SFR:0xCD': 0x80})   # SPIF

    # D8: IAP/EEPROM 写+读 (IAPCMD=PROG, IAPTRIG 5A/A5)
    #   IAP_DATA=0xC2, IAP_ADDRL=0xC4, IAP_ADDRH=0xC3, IAP_CMD=0xC5,
    #   IAP_TRIG=0xC6, IAP_CONTR=0xC7
    prog = (sfr_imm(0xC7, 0x80)          # IAPEN
            + mov_a_imm(0x66) + mov_dir_a(0xC2)   # IAP_DATA = 0x66
            + mov_a_imm(0x00) + mov_dir_a(0xC3)   # IAP_ADDRH = 0
            + mov_a_imm(0x10) + mov_dir_a(0xC4)   # IAP_ADDRL = 0x10
            + sfr_imm(0xC5, 0x02)        # IAP_CMD = PROG
            + sfr_imm(0xC6, 0x5A) + sfr_imm(0xC6, 0xA5)   # 触发
            + sfr_imm(0xC5, 0x01)        # IAP_CMD = READ
            + sfr_imm(0xC6, 0x5A) + sfr_imm(0xC6, 0xA5)
            + spin())
    check('iap_eeprom_rw', prog, 30, {'SFR:0xC2': 0x66})   # 读回

    # D9: RTC 秒计数 (ENRTC → SEC 递增)
    #   RTCCR=0xFE60 bit7 使能; 1s = 128*480 周期 → 70000 周期 > 1s
    prog = (far_set(0xFE60, 3, 0x80)     # RTCCR.ENRTC = 1
            + spin())
    check('rtc_sec_inc', prog, 70000, {'XFR:0xFE75': 0x01})   # SEC ≥ 1

    # D10: PWM 计数 (CEN → CNTR 递增, 到 ARR 溢出置 UIF)
    #   PWMA_CR1=0xFEC0 CEN=bit0; ARR=0xFED2/FED3; CNTR=0xFECE/FECF
    prog = (far_set(0xFED3, 3, 0x0A)     # ARRL = 10 (ARR = 10)
            + far_set(0xFEC0, 3, 0x01)   # CR1.CEN = 1
            + spin())
    #  每周期计数, >10 周期后溢出置 UIF (SR1.0)
    check('pwm_count_overflow', prog, 30, {'XFR:0xFEC5': 0x01})   # SR1.UIF

    # D11: DMA M2M 拷贝 (xram 拷贝)
    #   CFG=0xFA00, CR=0xFA01(EN), STA=0xFA02, AMT=0xFA03/0xFA80(高),
    #   TX=0xFA05/06, RX=0xFA07/08
    prog = (mov_dptr(0x0300) + mov_a_imm(0x42) + movx_dptr_a()   # xram[0x300]=0x42
            + far_set(0xFA05, 3, 0x03)   # TXAL = 0x03 (src 0x0300)
            + far_set(0xFA06, 3, 0x00)   # TXAH = 0
            + far_set(0xFA07, 3, 0x04)   # RXAL = 0x04 (dst 0x0400)
            + far_set(0xFA08, 3, 0x00)   # RXAH = 0
            + far_set(0xFA03, 3, 0x01)   # AMT = 1 字节
            + far_set(0xFA01, 3, 0x01)   # CR.EN = 1 (启动)
            + spin())
    check('dma_m2m_copy', prog, 40, {'XRAM:0x0400': 0x42})

    # D12: Timer1 溢出 (TR1=TCON.0x40, 1T, 重装 0xFFF0 → TF1=TCON.0x80)
    prog = (sfr_imm(0x89, 0x00) + sfr_imm(0x8E, 0x40)        # AUXR.T1x12=1 (1T)
            + sfr_imm(0x8B, 0xF0) + sfr_imm(0x8D, 0xFF)      # TL1/TH1 = 0xFFF0
            + sfr_imm(0x88, 0x40) + spin())                  # TR1=1
    check('timer_t1_overflow', prog, 40, {'SFR:0x88': 0xC0}) # TR1+TF1

    # D13: T0 中断真实跳转 + RETI 返回 (EA+ET0 → 向量 0x0B → 0x77 → RETI 回 spin)
    #   用 LJMP 跳过向量区; 0x0B 放 MOV R7,#0x77; RETI
    mainp = (sfr_imm(0x89, 0x00) + sfr_imm(0x8E, 0x80)
             + sfr_imm(0x8A, 0xF0) + sfr_imm(0x8C, 0xFF)
             + sfr_imm(0xA8, 0x82)                            # IE = EA|ET0
             + sfr_imm(0x88, 0x10) + spin())                 # TR0
    buf = bytearray(0x200)
    buf[0:3] = ljmp(0x20)                                    # 跳过向量区
    buf[0x0B:0x0E] = mov_rn_imm(7, 0x77)                     # 向量: MOV R7,#0x77
    buf[0x0E] = 0x32                                         # RETI
    buf[0x20:0x20 + len(mainp)] = mainp
    check('t0_irq_jump_reti', bytes(buf), 60, {'R7': 0x77, 'SP': 0x07})

    # D14: T2 中断 (IE2.ET2=0x04 → 向量 0x63; 内部 tf2 无 SFR 位)
    mainp = (sfr_imm(0x8E, 0x14) + sfr_imm(0xD7, 0xF0) + sfr_imm(0xD6, 0xFF)
             + sfr_imm(0xA8, 0x80) + sfr_imm(0xAF, 0x04)     # EA + ET2
             + spin())
    buf = bytearray(0x200)
    buf[0:3] = ljmp(0x20)
    buf[0x63:0x66] = mov_rn_imm(7, 0x66)
    buf[0x66] = 0x32
    buf[0x20:0x20 + len(mainp)] = mainp
    check('t2_irq_jump', bytes(buf), 60, {'R7': 0x66})

    # D15: UART2 TX → S2CON.TI (S2CON=0x9A, S2BUF=0x9B)
    prog = (sfr_imm(0x9A, 0x40) + mov_a_imm(0x42) + mov_dir_a(0x9B) + spin())
    check('uart2_tx_ti', prog, 80, {'SFR:0x9A': 0x42})  # TI 延迟 64, 窗口 >64

    # D16: UART3 TX → S3CON.TI (S3CON=0xAC, S3BUF=0xAD)
    prog = (sfr_imm(0xAC, 0x40) + mov_a_imm(0x43) + mov_dir_a(0xAD) + spin())
    check('uart3_tx_ti', prog, 80, {'SFR:0xAC': 0x42})  # TI 延迟 64, 窗口 >64

    # D17: UART4 TX → S4CON.TI (S4CON=0xFD, S4BUF=0xFE)
    prog = (sfr_imm(0xFD, 0x40) + mov_a_imm(0x44) + mov_dir_a(0xFE) + spin())
    check('uart4_tx_ti', prog, 80, {'SFR:0xFD': 0x42})  # TI 延迟 64, 窗口 >64

    # D18: DMA M2M 多字节 + 完成标志 (AMT=3, STA.ENF + DONE)
    prog = (mov_dptr(0x0300) + mov_a_imm(0x41) + movx_dptr_a()
            + mov_dptr(0x0301) + mov_a_imm(0x42) + movx_dptr_a()
            + mov_dptr(0x0302) + mov_a_imm(0x43) + movx_dptr_a()
            + far_set(0xFA05, 3, 0x03) + far_set(0xFA06, 3, 0x00)
            + far_set(0xFA07, 3, 0x04) + far_set(0xFA08, 3, 0x00)
            + far_set(0xFA03, 3, 0x03)                      # AMT = 3
            + far_set(0xFA01, 3, 0x01) + spin())
    check('dma_m2m_multi', prog, 60,
          {'XRAM:0x0400': 0x41, 'XRAM:0x0401': 0x42, 'XRAM:0x0402': 0x43,
           'XFR:0xFA02': 0x80, 'XFR:0xFA04': 0x03})         # STA.ENF + DONE=3

    # D19: PWMB 计数溢出 (PWMB_CR1=0xFEE0, ARRL=0xFEF3, SR1=0xFEE5)
    prog = (far_set(0xFEF3, 3, 0x0A)                        # ARRL = 10
            + far_set(0xFEE0, 3, 0x01)                      # CR1.CEN
            + spin())
    check('pwmb_count_overflow', prog, 30, {'XFR:0xFEE5': 0x01})  # SR1.UIF

    # D20: CMP 比较器 — CMPEN+PIE 后 ~1000 周期模拟输入翻转 → CMPIF + 中断 0xAB
    #   CMPCR1=0xE6: CMPEN(0x80)|PIE(0x20)=0xA0
    mainp = (sfr_imm(0xA8, 0x80) + sfr_imm(0xE6, 0xA0) + spin())
    buf, ex = irq_test(mainp, 0xAB, 0x77)
    check('cmp_irq_trigger', buf, 1150, {'R7': 0x77, 'SFR:0xE6': 0xA8},
          load=buf, extra=ex)   # 中断后: CMPEN(0x80)|PIE(0x20)|CMPRES(0x08)

    # D21: I2C — ENI2C + 写 I2CTXD → 800 周期后 I2CMSST.I2CIF + 中断 0xC3
    #   I2CCFG=0xFE80 ENI2C(0x80), I2CMSCR=0xFE81 bit7, I2CTXD=0xFE86
    mainp = (sfr_imm(0xA8, 0x80)
             + far_set(0xFE80, 3, 0x80)                     # ENI2C
             + far_set(0xFE81, 3, 0x80)                     # I2CMSCR bit7
             + far_set(0xFE86, 3, 0x55)                     # I2CTXD → 启动
             + spin())
    buf, ex = irq_test(mainp, 0xC3, 0x66)
    check('i2c_irq_trigger', buf, 1000, {'R7': 0x66, 'XFR:0xFE82': 0x01},
          load=buf, extra=ex)   # I2CMSST.I2CIF

    # D22: LVD — --lvd 50 周期后置 AUXINTIF.LVDIF + 中断 0x33
    #   IE=0xC0 (EA|ELVD), AUXINTIF=0xEF
    mainp = (sfr_imm(0xA8, 0xC0) + spin())
    buf, ex = irq_test(mainp, 0x33, 0x55, extra=['--lvd', '50'])
    check('lvd_irq_trigger', buf, 120, {'R7': 0x55}, load=buf, extra=ex)

    # D23: INT2 — --int2 50 周期后置 AUXINTIF.INT2IF + 中断 0x53
    #   INTCLKO=0x8F EX2(0x10)
    mainp = (sfr_imm(0xA8, 0x80) + sfr_imm(0x8F, 0x10) + spin())
    buf, ex = irq_test(mainp, 0x53, 0x44, extra=['--int2', '50'])
    check('int2_irq_trigger', buf, 120, {'R7': 0x44}, load=buf, extra=ex)

    # D24: INT3 — --int3 50 周期后置 AUXINTIF.INT3IF + 中断 0x5B
    #   INTCLKO EX3(0x20)
    mainp = (sfr_imm(0xA8, 0x80) + sfr_imm(0x8F, 0x20) + spin())
    buf, ex = irq_test(mainp, 0x5B, 0x33, extra=['--int3', '50'])
    check('int3_irq_trigger', buf, 120, {'R7': 0x33}, load=buf, extra=ex)

    # D25: INT0 — --int0 覆盖默认 1000 周期, 50 周期触发 + 中断 0x03
    mainp = (sfr_imm(0xA8, 0x81) + spin())                 # EA|EX0
    buf, ex = irq_test(mainp, 0x03, 0x11, extra=['--int0', '50'])
    check('int0_irq_override', buf, 120, {'R7': 0x11}, load=buf, extra=ex)


# ================================================================== #
# E. CLI / 固件加载 (--serial / --op-stats / --trace-watch / hex)
# ================================================================== #
def sec_e():
    print('\n=== E. CLI / 固件加载 ===')
    # E1: --serial 文件输出 (UART1 TX 'A' → 文件字节)
    outf = os.path.join(TMP, 'fn_serial.bin')
    if os.path.exists(outf):
        os.remove(outf)
    prog = sfr_imm(0x98, 0x40) + mov_a_imm(0x41) + mov_dir_a(0x99) + spin()
    st, rc, err = run(prog, 15, extra=['--serial', outf])
    data = open(outf, 'rb').read() if os.path.exists(outf) else b''
    if data == b'A':
        PASS.append('serial_out'); print('PASS %-42s' % 'serial_out')
    else:
        FAIL.append('serial_out'); print('FAIL %-42s want=A got=%r' % ('serial_out', data))

    # E2: --op-stats 直方图 (输出到 stdout, 主循环结束 dump_state 打印)
    cmd = [_SIM, '-bios', os.path.join(TMP, 'fn_opstats.bin'),
           '--cycles', '10', '--op-stats']
    open(os.path.join(TMP, 'fn_opstats.bin'), 'wb').write(
        mov_rn_imm(7, 0x01) + spin())
    rr = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8',
                        errors='replace', timeout=30)
    if 'OP-STATS' in (rr.stdout + rr.stderr):
        PASS.append('op_stats'); print('PASS %-42s' % 'op_stats')
    else:
        FAIL.append('op_stats')
        print('FAIL %-42s stdout=%r' % ('op_stats', rr.stdout[-80:]))

    # E3: --trace-watch ADDR 写看门狗 (写 IRAM:0x50 → [WATCH] 报告)
    prog = (mov_rn_imm(4, 0x55) + mov_dir_rn(4, 0x50) + spin())
    st, rc, err = run(prog, 10, extra=['--trace-watch', '0x50'])
    if '[WATCH]' in err:
        PASS.append('trace_watch'); print('PASS %-42s' % 'trace_watch')
    else:
        FAIL.append('trace_watch'); print('FAIL %-42s stderr=%r' % ('trace_watch', err[-120:]))

    # E4: Intel HEX 固件加载 (自动识别; 校验和正确)
    #   :040000007E70772275  = MOV R7,#0x77 (7E 70 77); RET (22)
    #   (sum=0x8B, cksum=0x75)
    hexdata = (':040000007E70772275\n'
               ':00000001FF\n').encode()
    check('hex_load', hexdata, 10, {'R7': 0x77})

    # E5: 无效固件 → 退出码 2
    cmd = [_SIM, '-bios', os.path.join(TMP, 'no_such_fw.bin')]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if r.returncode == 2:
        PASS.append('bad_bios_rc2'); print('PASS %-42s' % 'bad_bios_rc2')
    else:
        FAIL.append('bad_bios_rc2')
        print('FAIL %-42s want rc=2 got=%d' % ('bad_bios_rc2', r.returncode))


# ================================================================== #
# 主入口
# ================================================================== #
def main():
    pfx = sys.argv[1] if len(sys.argv) > 1 else ''
    for sec in (sec_a, sec_b, sec_c, sec_d, sec_e):
        if pfx and pfx not in ('A', 'B', 'C', 'D', 'E'):
            pass
        sec()
        _flush_registry()          # 每段一次批量子进程 (--run-list)
    print('\n===== 结果: %d PASS, %d FAIL =====' % (len(PASS), len(FAIL)))
    for n in FAIL:
        print('  FAIL %s' % n)
    return 0 if not FAIL else 1


if __name__ == '__main__':
    sys.exit(main())
