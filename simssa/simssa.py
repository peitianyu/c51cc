#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""simssa — c51cc SSA 输出仿真器 (解析 + 解释执行 + 测试运行)。

黑盒验证: c251cc -O1 -ssa 编译 C 源 → 解析 SSA 文本 → 逐指令解释执行
→ 取 main() 返回值。独立于 C251 后端验证 SSA (前端 + 优化器) 语义正确性。

用法:
  python simssa/simssa.py test/ssa/add_int.c         # 单个文件
  python simssa/simssa.py a.c b.c                    # 多文件 (多编译单元)
  python simssa/simssa.py --suite                    # 跑 test/suite 全部
  python simssa/simssa.py --execute                  # 跑 test/execute 全部
  python simssa/simssa.py --ssa                      # 跑 test/ssa 全部
  python simssa/simssa.py --filter "0[0-5]"          # 过滤
  python simssa/simssa.py --O0|--O1|--O2             # 优化级别 (默认 -O1)
  python simssa/simssa.py --before                   # 仿真优化前 SSA
  python simssa/simssa.py --trace                    # 打印执行 trace
  python simssa/simssa.py --strict                   # 未定义值/未知符号报错

期望值约定:
  suite/ssa: 源码 `/* EXPECT N */`、`return EXPR; /* N */`、`// expect N` 注释;
             无注释 → SKIP
  execute  : main 返回 0 = 成功 (也可用注释覆盖)
"""
import argparse
import os
import re
import subprocess
import sys

sys.setrecursionlimit(100000)
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except AttributeError:
    pass

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
C251CC = os.environ.get("C251CC", os.path.join(ROOT, "scripts", "c251cc.exe"))
SUITE_DIR = os.path.join(ROOT, "test", "suite")
EXECUTE_DIR = os.path.join(ROOT, "test", "execute")
SSA_DIR = os.path.join(ROOT, "test", "ssa")
LIBC = os.path.join(ROOT, "src", "core", "c251", "c251_libc.c")
MAX_INSTS = int(os.environ.get("SIMSSA_MAX_INSTS", "20000000"))
TIMEOUT = int(os.environ.get("SIMSSA_TIMEOUT", "120"))

# ── 内存布局 ──────────────────────────────────────────────────────────────
MEM_SIZE = 1 << 26            # 64MB 扁平内存 (16 位地址空间只用低 64KB)
# 地址必须落在 16 位内: int 型 phi/trunc 会携带指针地址 (机器 data 地址本身
# 是 16 位, 0057-duff 的 int phi 承接 addr @a 即依赖此性质)
DATA_BASE = 0x2000            # 全局变量 (避开 0x00-0x1FFF 特殊区)
MMIO_HOLE = (0x4000, 0x4FFF)  # 保留给 inttoptr 裸地址 (如 0x4000)
LOCAL_BASE = 0x5000           # 局部变量池
LOCAL_CHUNK = 0x200           # 每个局部槽 512B (SSA 无大小信息; 48KB 空间 ≈ 96 槽)
FUNC_BASE = 0xF000            # 函数地址区 (16 位内, 64 函数上限)
FUNC_STRIDE = 64
SBIT_BASE = 0x400             # sbit 虚拟地址区 = (sfr_addr << 3) | bit


# ── 类型模型 ──────────────────────────────────────────────────────────────
class T:
    __slots__ = ("name", "size", "sign")

    def __init__(self, name, size, sign):
        self.name = name
        self.size = size
        self.sign = sign

    def __repr__(self):
        return f"T({self.name})"


T_MAP = {
    "bool": T("bool", 1, False),
    "char": T("char", 1, True),
    "int": T("int", 2, True),
    "long": T("long", 4, True),
    "float": T("float", 4, False),
    "double": T("double", 4, False),
    # ptr 值在仿真器内为全宽地址 (64MB 扁平内存), 不做 16 位截断;
    # 全局变量中指针的存储大小仍为 2 (见 type_size)。
    "ptr": T("ptr", 8, False),
    "void": T("void", 0, False),
}


def parse_type(s):
    """解析 SSA 指令类型字符串: 'int' / 'unsigned char' / 'ptr' / 'void'。"""
    s = s.strip()
    sign = True
    if s.startswith("unsigned "):
        sign = False
        s = s[len("unsigned "):]
    t = T_MAP.get(s)
    if not t:
        return T(s, 2, sign)
    if s == "bool":
        return T("bool", 1, False)
    return T(s, t.size, sign)


# ── SSA 文本解析 ──────────────────────────────────────────────────────────
class Instr:
    __slots__ = ("op", "dest", "type", "args", "labels", "imm")

    def __init__(self, op, dest, ty, args, labels, imm):
        self.op = op          # str
        self.dest = dest      # int (0 = 无)
        self.type = ty        # T
        self.args = args      # list[('v'|'c', int)]
        self.labels = labels  # list[str]
        self.imm = imm        # int

    def __repr__(self):
        return f"Instr({self.op}, d={self.dest})"


class Block:
    __slots__ = ("id", "phis", "instrs")

    def __init__(self, bid):
        self.id = bid
        self.phis = []
        self.instrs = []


class Func:
    __slots__ = ("name", "params", "ret_type", "blocks", "entry_id")

    def __init__(self, name, params, ret_type):
        self.name = name
        self.params = params      # list[str]
        self.ret_type = ret_type  # T
        self.blocks = {}          # id -> Block
        self.entry_id = 0


class Global:
    __slots__ = ("name", "type_str", "addr", "size", "kind", "sfr_addr", "bit")

    def __init__(self, name, type_str, addr, size, kind="data", sfr_addr=0, bit=0):
        self.name = name
        self.type_str = type_str
        self.addr = addr
        self.size = size
        self.kind = kind          # 'data' | 'sfr' | 'sfr16' | 'sbit'
        self.sfr_addr = sfr_addr
        self.bit = bit


# 指令 RHS 解析 -------------------------------------------------------------
BINOPS = {"add", "sub", "mul", "div", "mod", "and", "or", "xor", "land", "lor"}
SHIFTS = {"shl", "shr"}
CMPOPS = {"eq", "ne", "lt", "gt", "le", "ge"}
UNARYS = {"neg", "not", "lnot", "trunc", "zext", "sext", "bitcast",
          "inttoptr", "ptrtoint"}

RE_OPERAND = re.compile(r"^(?:v(\d+)|const\s+(-?\d+))$")
RE_INSTR = re.compile(r"^\s*v(\d+):\s+((?:unsigned\s+)?\w+)\s+=\s+(.*?)\s*$")


def parse_operand(s):
    m = RE_OPERAND.match(s.strip())
    if not m:
        raise ValueError(f"bad operand: {s!r}")
    if m.group(1) is not None:
        return ("v", int(m.group(1)))
    return ("c", int(m.group(2)))


def parse_rhs(op, rhs):
    """解析指令 RHS 文本 → (args, labels, imm)。"""
    if op == "param":
        return ([], [rhs.strip()], 0)
    if op == "const":
        return ([], [], int(rhs.strip()))
    if op in UNARYS:
        return ([parse_operand(rhs)], [], 0)
    if op in BINOPS or op in SHIFTS or op in CMPOPS:
        m = re.match(r"^(\S+),\s*(.+)$", rhs)
        if not m:
            raise ValueError(f"bad binop rhs: {rhs!r}")
        return ([parse_operand(m.group(1)), parse_operand(m.group(2))], [], 0)
    if op == "offset":
        m = re.match(r"^(\S+),\s*(.+?),\s*#(-?\d+)$", rhs)
        if not m:
            raise ValueError(f"bad offset rhs: {rhs!r}")
        return ([parse_operand(m.group(1)), parse_operand(m.group(2))], [], int(m.group(3)))
    if op == "select":
        m = re.match(r"^(.+?):\s*select\s+(.+?),\s*(.+)$", rhs)
        if not m:
            raise ValueError(f"bad select rhs: {rhs!r}")
        return ([parse_operand(m.group(1)), parse_operand(m.group(2)),
                 parse_operand(m.group(3))], [], 0)
    if op == "load":
        return ([parse_operand(rhs.split()[0])], [], 0)
    if op == "store":
        parts = [p.strip() for p in rhs.split(",")]
        if parts[0].startswith("@"):
            # store @sym, const N
            return ([], [parts[0]], parse_operand(parts[1])[1])
        return ([parse_operand(parts[0]), parse_operand(parts[1])], [], 0)
    if op == "addr":
        return ([], [rhs.split()[0]], 0)
    if op == "phi":
        args, labels = [], []
        for m in re.finditer(r"\[(v\d+),\s*b(\d+)\]", rhs):
            args.append(("v", int(m.group(1)[1:])))
            labels.append("block" + m.group(2))
        return (args, labels, 0)
    if op == "jmp":
        m = re.match(r"^b(\d+)$", rhs.strip())
        return ([], [m.group(1)], 0)
    if op == "br":
        m = re.match(r"^(\S+),\s*b(\d+),\s*b(\d+)$", rhs.strip())
        return ([parse_operand(m.group(1))], [m.group(2), m.group(3)], 0)
    if op == "call":
        m = re.match(r"^(.+?)\s*\(([^)]*)\)\s*$", rhs.strip())
        if not m:
            raise ValueError(f"bad call rhs: {rhs!r}")
        callee = m.group(1).strip()
        argtext = m.group(2).strip()
        args = [parse_operand(x) for x in argtext.split(",")] if argtext else []
        if callee.startswith("*"):
            toks = callee[1:].split()
            callee_val = parse_operand(toks[0])
            hint = toks[1] if len(toks) > 1 else ""
            return ([callee_val] + args, [hint, "indirect"], 0)
        return (args, [callee[1:]], 0)  # labels[0] = 函数名
    if op == "ret":
        rhs = rhs.strip()
        if not rhs:
            return ([], [], 0)
        return ([parse_operand(rhs)], [], 0)
    if op == "asm":
        return ([], [], 0)
    raise ValueError(f"unknown op: {op} rhs={rhs!r}")


# 类型大小 (用于全局分配) ------------------------------------------------------
RE_ARRAY = re.compile(r"^\[(\d+)\](.*)$")
RE_PTR = re.compile(r"^\(\*?(.*)\)$")
ATTR_WORDS = {"code", "xdata", "idata", "pdata", "edata", "data", "volatile",
              "register", "near", "far", "const", "static", "extern"}


def strip_attrs(s):
    """去掉类型串前导/内嵌的地址空间等属性词 (code/xdata/...)。"""
    s = s.strip()
    while True:
        m = re.match(r"^(unsigned\s+)?([a-z_]+)(?:\s+(.*))?$", s)
        if not m:
            break
        g1, g2, g3 = m.group(1) or "", m.group(2), m.group(3) or ""
        if g2 in ATTR_WORDS:
            s = (g1 + g3).strip()
        else:
            break
    return s


def type_size(s):
    """从全局类型字符串计算字节大小: '[4]int' / 'int' / '(struct ...)'。"""
    s = s.strip()
    if not s:
        return 2
    m = RE_ARRAY.match(s)
    if m:
        return int(m.group(1)) * type_size(m.group(2))
    m = RE_PTR.match(s)
    if m:
        return 2
    if s.startswith("(struct") or s.startswith("(union"):
        return struct_size(s)
    if s.startswith("(enum"):
        return 2
    s = strip_attrs(s)
    if s.startswith("unsigned "):
        s = s[len("unsigned "):]
    return {"bool": 1, "char": 1, "int": 2, "long": 4,
            "float": 4, "double": 4, "ptr": 2, "void": 0}.get(s, 2)


def struct_size(s):
    """'(struct (int x) (int y))' / '(union ...)' → 大小。"""
    is_union = s.startswith("(union")
    total, max_m = 0, 0
    depth = 0
    start = None
    for k, ch in enumerate(s):
        if ch == "(":
            if depth == 1 and start is None:
                start = k
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 1 and start is not None:
                mem = s[start + 1:k]
                start = None
                mm = re.match(r"^(.*?)\s+(\w+)$", mem.strip())
                tstr = mm.group(1).strip() if mm else mem.strip()
                sz = type_size(tstr)
                total += sz
                max_m = max(max_m, sz)
    return max_m if is_union else total


def unescape_c_string(s):
    """反转义 SSA 字符串字面量内容: \\n \\\" \\\\ → 原始字节。"""
    out = bytearray()
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            n = s[i + 1]
            if n == "n":
                out.append(0x0A)
            elif n == "\\":
                out.append(0x5C)
            elif n == '"':
                out.append(0x22)
            else:
                out.extend(n.encode("latin-1"))
            i += 2
        else:
            out.extend(c.encode("latin-1"))
            i += 1
    return bytes(out)


# 单元解析 --------------------------------------------------------------------
def parse_globals_block(lines, i):
    """解析 '@globals { ... }' 块, 返回 (globals dict, 下一行索引)。"""
    globals_ = {}
    i += 1  # 跳过 '{'
    while i < len(lines):
        line = lines[i].strip()
        i += 1
        if not line:
            continue
        if line == "}":
            break
        m = re.match(r"^@([\w.$]+)\s+sbit\s*=\s*\{0x([0-9A-Fa-f]+)\.(\d)\}\s*(?:;.*)?$", line)
        if m:
            name, base, bit = m.group(1), int(m.group(2), 16), int(m.group(3))
            globals_[name] = Global(name, "sbit", 0, 1, kind="sbit",
                                    sfr_addr=base, bit=bit)
            continue
        m = re.match(r"^@([\w.$]+)\s+sfr16\s*=\s*\{0x([0-9A-Fa-f]+)\}\s*(?:;.*)?$", line)
        if m:
            name, addr = m.group(1), int(m.group(2), 16)
            globals_[name] = Global(name, "sfr16", addr, 2, kind="sfr16", sfr_addr=addr)
            continue
        m = re.match(r"^@([\w.$]+)\s+sfr\s*=\s*\{0x([0-9A-Fa-f]+)\}\s*(?:;.*)?$", line)
        if m:
            name, addr = m.group(1), int(m.group(2), 16)
            globals_[name] = Global(name, "sfr", addr, 1, kind="sfr", sfr_addr=addr)
            continue
        m = re.match(r"^@([\w.$]+):\s*(.*?)\s*$", line)
        if not m:
            raise ValueError(f"bad global line: {line!r}")
        name, rest = m.group(1), m.group(2)
        gtype, init = rest, None
        m2 = re.match(r"^(.*?)\s*=\s*(.+)$", rest)
        if m2:
            gtype, init = m2.group(1).strip(), m2.group(2).strip()
        relocs = {}
        if init and "; relocs:" in init:
            # 指针字段重定位: `{...} ; relocs: +2=@x, +4=@y`
            head, _, tail = init.partition("; relocs:")
            init = head.strip()
            for tok in tail.split(","):
                mm = re.match(r"\s*\+(\d+)=@([\w.$]+)", tok)
                if mm:
                    relocs[int(mm.group(1))] = mm.group(2)
        if init and init.startswith("&@") and len(init) > 2:
            # 标量指针 = &全局符号: `@p: (*int) = &@x` → 整个指针槽重定位到 @x
            relocs[0] = init[2:]
            init = None
        size = type_size(gtype) if gtype else 2
        blob = None
        if init:
            if init.startswith("{") and init.endswith("}"):
                blob = bytes(int(x, 16) for x in re.findall(r"0x([0-9A-Fa-f]+)", init))
                size = max(size, len(blob))
            elif init.startswith('"') and init.endswith('"'):
                raw = unescape_c_string(init[1:-1])
                blob = raw + b"\0" * max(0, size - len(raw))
            else:
                blob = None  # 标量 init_value, 由分配处写入
        globals_[name] = (gtype, size, blob, init, relocs)
    return globals_, i


def parse_func(lines, i):
    """解析函数定义, 返回 (Func, 下一行索引)。"""
    header = lines[i].strip()
    m = re.match(r"^@([\w.$]+)\((.*?)\)\s*:\s*((?:unsigned\s+)?\w+)\s*\{", header)
    if not m:
        raise ValueError(f"bad func header: {header!r}")
    fname, params_text, ret = m.group(1), m.group(2), m.group(3)
    params = []
    if params_text.strip():
        for p in params_text.split(","):
            pm = re.match(r"^\s*([\w.$]+)\s*:\s*(?:unsigned\s+)?\w+\s*$", p)
            if not pm:
                raise ValueError(f"bad param: {p!r}")
            params.append(pm.group(1))
    f = Func(fname, params, parse_type(ret))
    i += 1
    first_block_id = None
    cur = None
    while i < len(lines):
        line = lines[i].strip()
        if not line:
            i += 1
            continue
        if line == "}":
            i += 1
            break
        m = re.match(r"^b(\d+):$", line)
        if m:
            bid = int(m.group(1))
            if first_block_id is None:
                first_block_id = bid
            cur = f.blocks.setdefault(bid, Block(bid))
            i += 1
            continue
        inst, i = parse_inst_line(lines, i)
        if inst is None:
            continue
        if first_block_id is None:
            first_block_id = 0
            cur = f.blocks.setdefault(0, Block(0))
        if inst.op == "phi":
            cur.phis.append(inst)
        else:
            cur.instrs.append(inst)
    if first_block_id is not None:
        f.entry_id = first_block_id
    return f, i


def parse_inst_line(lines, i):
    """解析第 i 行指令 (asm 可跨行消费多行)。返回 (Instr|None, 新 i)。"""
    line = lines[i].strip()
    if line.startswith('asm ') or line == 'asm':
        body = line
        i += 1
        while body.count('"') < 2 and i < len(lines):
            body += "\n" + lines[i].strip()
            i += 1
        mm = re.match(r'^asm\s+"(.*)"\s*$', body, re.DOTALL)
        inst = Instr("asm", 0, T_MAP["void"], [], [], 0)
        inst.imm = mm.group(1) if mm else body
        return inst, i

    m = RE_INSTR.match(line)
    if m:
        dest = int(m.group(1))
        ty = parse_type(m.group(2))
        rhs = m.group(3).strip()
        sm = re.match(r"^.+?:\s*select\s", rhs)
        if sm:
            op = "select"
            rest = rhs
        else:
            op = rhs.split()[0]
            rest = rhs[len(op):].strip()
        args, labels, imm = parse_rhs(op, rest)
        return Instr(op, dest, ty, args, labels, imm), i + 1

    # 无 dest 指令: store / ret / jmp / br / call
    for op in ("store", "ret", "jmp", "br", "call"):
        if line.startswith(op + " ") or line == op:
            rest = line[len(op):].strip()
            args, labels, imm = parse_rhs(op, rest)
            return Instr(op, 0, T_MAP["void"], args, labels, imm), i + 1
    raise ValueError(f"unparsable line: {line!r}")


def parse_ssa_text(text, use_before=False):
    """解析 -ssa 输出 (多文件时合并各段)。返回 (globals, funcs)。"""
    sections = re.split(r"===\s*(SSA Before Optimization|Optimized SSA Output)\s*===",
                        text)
    want = "SSA Before Optimization" if use_before else "Optimized SSA Output"
    units = []
    for k in range(1, len(sections), 2):
        if sections[k].strip() == want:
            units.append(sections[k + 1])
    if not units:
        units = [text]

    globals_ = {}
    funcs = {}
    for unit in units:
        lines = unit.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if not line:
                i += 1
                continue
            if line == "@globals {":
                gs, i = parse_globals_block(lines, i)
                for gname, g in gs.items():
                    globals_.setdefault(gname, g)
            elif line.startswith("@"):
                f, i = parse_func(lines, i)
                funcs.setdefault(f.name, f)  # 测试自身定义优先
            else:
                i += 1
    return globals_, funcs


# ── 解释器 ─────────────────────────────────────────────────────────────────
class Frame:
    __slots__ = ("locals",)

    def __init__(self):
        self.locals = {}  # name -> addr


class Sim:
    def __init__(self, globals_, funcs, trace=False, strict=False):
        self.mem = bytearray(MEM_SIZE)
        self.funcs = funcs
        self.trace = trace
        self.strict = strict
        self.vals = {}     # vN -> int
        self.vtypes = {}   # vN -> T
        self.phi_old = {}  # phi dest -> 旧值 (自引用边)
        self.frames = []
        self.local_counter = 0
        self.inst_count = 0
        self.timed_out = False
        self.error = None
        # 全局分配: 两趟 — 先分配地址 (重定位目标可能后向引用),
        # 再写 blob/标量 init, 最后解析指针重定位 (struct {int a; int *p;} s = {.p = &x})
        self.globals = {}
        self.cur_global_addr = DATA_BASE
        for name, g in globals_.items():
            if isinstance(g, tuple):
                size = g[1]
                self.globals[name] = (self.cur_global_addr, size)
                self.cur_global_addr += size + (size % 2)
            else:  # sfr / sfr16 / sbit
                self.globals[name] = g
        for name, g in globals_.items():
            if not isinstance(g, tuple):
                continue
            gtype, size, blob, init, relocs = g
            addr = self.globals[name][0]
            if blob is not None:
                self.mem[addr:addr + len(blob)] = blob
            elif init is not None:
                v = int(init)
                for b in range(size):
                    self.mem[addr + b] = (v >> (8 * b)) & 0xFF
            # 指针字段地址重定位 (小端写入目标符号地址)
            for off, sym in relocs.items():
                target = self.resolve_symbol_addr(sym)
                if target is not None:
                    tg = self.globals.get(sym)
                    tsz = 2
                    if isinstance(tg, tuple):
                        tsz = min(4, max(2, tg[1]))
                    self.mem[addr + off:addr + off + tsz] =                         target.to_bytes(tsz, "little")[:tsz]
        # 函数地址表
        self.func_addr = {}
        for idx, (fname, f) in enumerate(funcs.items()):
            addr = FUNC_BASE + idx * FUNC_STRIDE
            self.func_addr[addr] = f
            self.func_addr[fname] = addr

    # -- 基础工具 --
    def norm(self, val, t):
        if t.size == 0 or t.size >= 8:
            return val
        bits = t.size * 8
        mask = (1 << bits) - 1
        v = val & mask
        if t.sign and (v >> (bits - 1)):
            v -= (1 << bits)
        return v

    def define(self, v, val, t):
        self.vals[v] = self.norm(val, t)
        self.vtypes[v] = t

    def resolve(self, operand):
        kind, val = operand
        if kind == "c":
            return val
        if val not in self.vals:
            if self.strict:
                raise RuntimeError(f"undefined value v{val}")
            return 0
        return self.vals[val]

    def operand_type(self, operand):
        if operand[0] == "v":
            return self.vtypes.get(operand[1])
        return None

    # -- 内存 --
    @staticmethod
    def sbit_addr(addr):
        return SBIT_BASE <= addr < (SBIT_BASE + 0x400)

    def load(self, addr, t):
        if addr < 0 or addr >= MEM_SIZE:
            if self.strict:
                raise RuntimeError(f"load OOB addr=0x{addr:x}")
            return 0
        if self.sbit_addr(addr):
            byte_addr, bit = (addr - SBIT_BASE) >> 3, (addr - SBIT_BASE) & 7
            if byte_addr >= MEM_SIZE:
                return 0
            return (self.mem[byte_addr] >> bit) & 1
        size = max(1, t.size)
        if addr + size > MEM_SIZE:
            if self.strict:
                raise RuntimeError(f"load OOB addr=0x{addr:x} size={size}")
            return 0
        v = int.from_bytes(self.mem[addr:addr + size], "little")
        return self.norm(v, t)

    def store(self, addr, val, size):
        if addr < 0 or addr >= MEM_SIZE:
            if self.strict:
                raise RuntimeError(f"store OOB addr=0x{addr:x}")
            return
        if self.sbit_addr(addr):
            byte_addr, bit = (addr - SBIT_BASE) >> 3, (addr - SBIT_BASE) & 7
            if byte_addr < MEM_SIZE:
                if val:
                    self.mem[byte_addr] |= (1 << bit)
                else:
                    self.mem[byte_addr] &= ~(1 << bit)
            return
        size = max(1, size)
        if addr + size > MEM_SIZE:
            return
        self.mem[addr:addr + size] = val.to_bytes(size, "little")[-size:]

    def resolve_symbol_addr(self, name):
        """解析符号地址: 全局 / 函数 / 局部 (reloc 目标)。"""
        if name in self.globals:
            return self.global_addr(name)
        if name in self.funcs:
            return self.func_addr[name]
        if self.frames:
            return self.alloc_local(name)
        return None

    def alloc_local(self, name):
        frame = self.frames[-1]
        if name in frame.locals:
            return frame.locals[name]
        addr = LOCAL_BASE + self.local_counter * LOCAL_CHUNK
        self.local_counter += 1
        frame.locals[name] = addr
        return addr

    def global_addr(self, name):
        g = self.globals.get(name)
        if g is None:
            if self.strict:
                raise RuntimeError(f"unknown global @{name}")
            return 0
        if isinstance(g, tuple):
            return g[0]
        if g.kind == "sbit":
            return SBIT_BASE + (g.sfr_addr << 3) + g.bit
        return g.sfr_addr

    def global_size(self, name):
        g = self.globals.get(name)
        if g is None:
            return 1
        return g[1] if isinstance(g, tuple) else g.size

    # -- 执行 --
    def run_main(self):
        if "main" not in self.funcs:
            return None, "NO-MAIN"
        try:
            ret = self.call_func("main", [])
        except RecursionError:
            return None, "RECURSION-ERR"
        except RuntimeError as e:
            return None, str(e)
        if self.timed_out:
            return None, f"TIMEOUT ({self.inst_count} 条指令超限)"
        mt = self.funcs["main"].ret_type
        if mt.size == 1:
            return ret & 0xFF, None  # u8 返回 (Keil RETREG A 约定)
        return ret, None

    def call_func(self, fname, argvals):
        f = self.funcs[fname]
        # SSA 值编号按函数复用: 每次激活独立值命名空间,
        # 否则递归调用会覆盖调用者的 vN (62_power/23_recursive/61_gcd 根因)
        saved = (self.vals, self.vtypes, self.phi_old)
        self.vals, self.vtypes, self.phi_old = {}, {}, {}
        self.frames.append(Frame())
        pi = 0
        for bid in sorted(f.blocks):
            b = f.blocks[bid]
            for inst in b.phis + b.instrs:
                if inst.op == "param":
                    pt = inst.type
                    v = argvals[pi] if pi < len(argvals) else 0
                    self.define(inst.dest, v, pt)
                    pi += 1
        try:
            result = self.exec_body(f, f.entry_id)
        finally:
            self.frames.pop()
            self.vals, self.vtypes, self.phi_old = saved
        return result

    def exec_body(self, f, entry_id):
        cur = entry_id
        incoming = None
        while True:
            r = self.exec_block(f, cur, incoming)
            if r[0] == "ret":
                return r[1]
            cur, incoming = r[1], cur

    def exec_block(self, f, bid, incoming):
        b = f.blocks.get(bid)
        if b is None:
            raise RuntimeError(f"unknown block b{bid}")
        # phi 并行语义: 快照块入口前的操作数值 (61_gcd_lcm: v8 的 phi
        # 操作数引用本块另一 phi v3 — 必须读上一轮的值, 非顺序求值后的新值)
        snap = {}
        for phi in b.phis:
            for opnd in phi.args:
                if opnd[0] == "v" and opnd[1] not in snap:
                    snap[opnd[1]] = self.vals.get(opnd[1], 0)
        for phi in b.phis:
            self.exec_phi(f, phi, incoming, snap)
        result = None
        for inst in b.instrs:
            r = self.exec_inst(f, inst)
            if r is not None and result is None:
                # 首个终止指令决定控制流; 其后的死代码 (打印残留) 仍会执行
                # (真实后端沿 fall-through 路径发射, phi 依赖其副作用)
                result = r
        if result is None:
            raise RuntimeError(f"block b{bid} fell through (no terminator)")
        return result

    def exec_phi(self, f, phi, incoming, snap):
        old = self.phi_old.get(phi.dest, 0)
        val = old
        found = False
        for opnd, lbl in zip(phi.args, phi.labels):
            pred = int(lbl[len("block"):])
            if pred == incoming:
                val = snap.get(opnd[1], 0) if opnd[0] == "v" else opnd[1]
                found = True
                break
        if not found and phi.labels and incoming is not None:
            val = old  # 自引用边 (打印时跳过) → 用 phi 旧值
        self.phi_old[phi.dest] = val
        self.define(phi.dest, val, phi.type)

    def exec_inst(self, f, inst):
        if self.trace:
            print(f"  {inst}")
        self.inst_count += 1
        if self.inst_count > MAX_INSTS:
            self.timed_out = True
            return ("ret", 0)
        op = inst.op
        d = inst.dest

        if op == "param":
            return None  # 已在 call_func 绑定

        if op == "const":
            self.define(d, inst.imm, inst.type)
            return None

        if op in ("neg", "not", "lnot"):
            a = self.resolve(inst.args[0])
            r = -a if op == "neg" else (~a if op == "not" else (0 if a else 1))
            self.define(d, r, inst.type)
            return None

        if op in ("trunc", "zext", "sext", "bitcast", "inttoptr", "ptrtoint"):
            a = self.resolve(inst.args[0])
            at = self.operand_type(inst.args[0])
            if op in ("trunc", "ptrtoint") and at and at.name == "ptr":
                # 指针→整数: 地址是不透明 token, 不做 16 位截断
                # (仿真用 24 位局部地址; 真实机器 data 地址本身在 16 位内)
                self.vals[d] = a
                self.vtypes[d] = inst.type
            else:
                self.define(d, a, inst.type)  # 值已按其定义类型归一化
            return None

        if op in BINOPS or op in SHIFTS or op in CMPOPS:
            a = self.resolve(inst.args[0])
            b = self.resolve(inst.args[1])
            ot = self.operand_type(inst.args[0]) or self.operand_type(inst.args[1])
            uns = bool(ot and not ot.sign)
            if op in ("add", "sub", "mul"):
                r = {"add": a + b, "sub": a - b, "mul": a * b}[op]
            elif op == "div":
                if b == 0:
                    if self.strict:
                        raise RuntimeError("div by zero")
                    r = 0
                elif uns:
                    am, bm = a & 0xFFFFFFFFFFFFFFFF, b & 0xFFFFFFFFFFFFFFFF
                    r = am // bm if bm else 0
                else:
                    q = abs(a) // abs(b)
                    r = -q if (a < 0) != (b < 0) else q
            elif op == "mod":
                if b == 0:
                    r = 0
                elif uns:
                    r = (a & 0xFFFFFFFFFFFFFFFF) % (b & 0xFFFFFFFFFFFFFFFF)
                else:
                    q = abs(a) // abs(b)
                    q = -q if (a < 0) != (b < 0) else q
                    r = a - q * b
            elif op == "and":
                r = a & b
            elif op == "or":
                r = a | b
            elif op == "xor":
                r = a ^ b
            elif op == "land":
                r = 1 if (a and b) else 0
            elif op == "lor":
                r = 1 if (a or b) else 0
            elif op == "shl":
                r = a << b
            elif op == "shr":
                r = a >> b if not uns else (a & 0xFFFFFFFFFFFFFFFF) >> b
            elif op in ("eq", "ne"):
                r = 1 if (a == b) == (op == "eq") else 0
            else:  # lt/gt/le/ge
                if uns:
                    aa, bb = a & 0xFFFFFFFFFFFFFFFF, b & 0xFFFFFFFFFFFFFFFF
                else:
                    aa, bb = a, b
                r = 1 if {"lt": aa < bb, "gt": aa > bb,
                          "le": aa <= bb, "ge": aa >= bb}[op] else 0
            self.define(d, r, inst.type)
            return None

        if op == "offset":
            base = self.resolve(inst.args[0])
            idx = self.resolve(inst.args[1])
            self.define(d, base + idx * inst.imm, inst.type)
            return None

        if op == "select":
            c = self.resolve(inst.args[0])
            r = self.resolve(inst.args[1]) if c else self.resolve(inst.args[2])
            self.define(d, r, inst.type)
            return None

        if op == "load":
            addr = self.resolve(inst.args[0])
            self.define(d, self.load(addr, inst.type), inst.type)
            return None

        if op == "store":
            if inst.labels and inst.labels[0].startswith("@"):
                gname = inst.labels[0][1:]
                if gname in self.globals:
                    addr = self.global_addr(gname)
                    size = self.global_size(gname)
                elif gname in self.funcs:
                    addr = self.func_addr[gname]
                    size = 2
                else:
                    # 取地址局部变量: 优化器将 store v,const 改写为 store @name,const
                    addr = self.alloc_local(gname)
                    size = inst.type.size or 2
                self.store(addr, inst.imm, size)
            else:
                addr = self.resolve(inst.args[0])
                val = self.resolve(inst.args[1])
                vt = None
                if inst.args[1][0] == "v":
                    vt = self.vtypes.get(inst.args[1][1])
                size = vt.size if vt and vt.size else inst.type.size or 2
                self.store(addr, val, size)
            return None

        if op == "addr":
            name = inst.labels[0][1:]  # 去掉 '@'
            if name in self.globals:
                r = self.global_addr(name)
            elif name in self.funcs:
                r = self.func_addr[name]
            else:
                r = self.alloc_local(name)
            self.define(d, r, inst.type)
            return None

        if op == "jmp":
            return ("jump", int(inst.labels[0]))

        if op == "br":
            c = self.resolve(inst.args[0])
            return ("jump", int(inst.labels[0]) if c else int(inst.labels[1]))

        if op == "call":
            if inst.labels and len(inst.labels) > 1 and inst.labels[1] == "indirect":
                callee_addr = self.resolve(inst.args[0])
                callee = self.func_addr.get(callee_addr)
                if callee is None:
                    if self.strict:
                        raise RuntimeError(
                            f"indirect call to unknown addr 0x{callee_addr:x}")
                    return None
                args = [self.resolve(a) for a in inst.args[1:]]
            else:
                fname = inst.labels[0]
                callee = self.funcs.get(fname)
                if callee is None:
                    # 未知直接调用 = 缺失库/链接目标 (如 strlen), 不能静默置 0
                    raise RuntimeError(f"call to unknown function @{fname}")
                args = [self.resolve(a) for a in inst.args]
            ret = self.call_func(callee.name, args)
            if d:
                self.define(d, ret, inst.type)
            return None

        if op == "ret":
            if inst.args:
                v = self.resolve(inst.args[0])
            elif inst.labels and inst.labels[0] == "imm":
                v = inst.imm
            else:
                v = 0
            return ("ret", v)

        if op == "asm":
            return None  # 裸 asm 无法仿真 → 视为无副作用

        raise RuntimeError(f"unhandled op {op}")


# ── 运行器 ─────────────────────────────────────────────────────────────────
def parse_expected(src_text):
    for pat in (r"/\*\s*EXPECT\s+(-?\d+)\s*\*/",
                r"return\s+[^;]*;\s*/\*\s*(-?\d+)\s*\*/",
                r"//\s*[Ee]xpect\s+(-?\d+)",
                r"/\*\s*[Ee]xpect\s+(-?\d+)\s*\*/",
                r"return\s+[^;]*;\s*/\*[^*]*=\s*(-?\d+)\s*\*/"):
        m = re.search(pat, src_text)
        if m:
            try:
                return int(m.group(1))
            except ValueError:
                continue
    return None


def find_undefined_calls(funcs):
    """扫描直接调用但无定义的函数 (系统库缺口)。"""
    missing = set()
    for fn in funcs.values():
        for b in fn.blocks.values():
            for inst in b.instrs:
                if inst.op == "call" and not (
                        len(inst.labels) > 1 and inst.labels[1] == "indirect"):
                    if inst.labels[0] not in funcs:
                        missing.add(inst.labels[0])
    return missing


def compile_ssa(files, opt, timeout=TIMEOUT):
    cmd = [C251CC, opt, "-ssa"] + files
    r = subprocess.run(cmd, capture_output=True, timeout=timeout)
    if r.returncode != 0:
        err = r.stderr.decode("utf-8", "replace") or r.stdout.decode("utf-8", "replace")
        return None, err
    # latin-1: 逐字节 1:1, 保证字符串字面量 blob 字节可恢复
    return r.stdout.decode("latin-1"), ""




def ssa_stats(files, opt="-O1"):
    """编译并统计 Before vs Optimized 的静态指令数 (常量折叠效果量化)。

    返回每部分的 (函数数, 块数, 指令数, op 分布 dict)。
    """
    text, err = compile_ssa(files, opt)
    if text is None:
        return None, "COMPILE-ERR", err.splitlines()[-1] if err else ""

    def count(use_before):
        try:
            g, funcs = parse_ssa_text(text, use_before)
        except (ValueError, IndexError):
            return None
        blocks = 0
        insts = 0
        op_dist = {}
        const_br = 0    # br 条件为 CONST (可折叠但未折叠)
        br_total = 0
        const_phi_arms = 0  # phi 臂全为 const (可折叠)
        for f in funcs.values():
            consts = {}
            # 先收集 const 定义 (单遍)
            for bid in sorted(f.blocks):
                b = f.blocks[bid]
                for p in b.phis:
                    if p.op == "const": consts[p.dest] = p.imm
                for i in b.instrs:
                    if i.op == "const": consts[i.dest] = i.imm
            for bid in sorted(f.blocks):
                b = f.blocks[bid]
                blocks += 1
                for p in b.phis:
                    insts += 1
                    op_dist[p.op] = op_dist.get(p.op, 0) + 1
                    if p.op == "phi":
                        arms = [a for a in p.args if a != 0 and a != p.dest]
                        if arms and all(a in consts for a in arms):
                            const_phi_arms += 1
                for i in b.instrs:
                    insts += 1
                    op_dist[i.op] = op_dist.get(i.op, 0) + 1
                    if i.op == "br":
                        br_total += 1
                        if i.args and i.args[0] in consts:
                            const_br += 1
        return len(funcs), blocks, insts, op_dist, const_br, br_total, const_phi_arms

    before = count(True)
    after = count(False)
    return (before, after), "RUN", ""


def print_stats(files, opt="-O1"):
    """打印 Before/Optimized 指令数对比 + 每指令类型分布。"""
    res, verdict, detail = ssa_stats(files, opt)
    if res is None:
        print(f"{os.path.basename(files[0])}: {verdict} {detail}")
        return
    before, after = res
    print(f"{os.path.basename(files[0])} (opt={opt}):")
    for label, st in (("Before", before), ("Optimized", after)):
        if st is None:
            print(f"  {label:<10} 解析失败")
            continue
        nf, nb, ni, dist = st[0], st[1], st[2], st[3]
        cbr, brt, cphi = st[4], st[5], st[6]
        extra = ""
        if brt:
            extra = f"  br: 条件const未折叠 {cbr}/{brt}  全const臂phi {cphi}"
        print(f"  {label:<10} 函数={nf} 块={nb} 指令={ni}{extra}")
    if before and after:
        bi = before[2]; ai = after[2]
        if bi:
            print(f"  折叠率: {(1 - ai / bi) * 100:.1f}%  ({bi} -> {ai})")
        if after[3]:
            tops = sorted(after[3].items(), key=lambda kv: -kv[1])[:8]
            print("  Optimized op 分布: " + ", ".join(f"{k}={v}" for k, v in tops))

def simulate(files, opt="-O1", use_before=False, trace=False, strict=False):
    """编译 + 仿真, 返回 (ret, verdict, detail)。"""
    text, err = compile_ssa(files, opt)
    if text is None:
        return None, "COMPILE-ERR", err.splitlines()[-1] if err else ""
    try:
        globals_, funcs = parse_ssa_text(text, use_before)
    except (ValueError, IndexError) as e:
        return None, "PARSE-ERR", str(e)
    missing = find_undefined_calls(funcs)
    if missing:
        # 系统库: 与 c251_libc.c 多编译单元合并, 库函数获得真实 SSA 定义
        text2, err2 = compile_ssa(files + [LIBC], opt)
        if text2 is None:
            return None, "RUN-ERR", f"libc 编译失败: {err2.splitlines()[-1] if err2 else ''}"
        try:
            globals_, funcs = parse_ssa_text(text2, use_before)
        except (ValueError, IndexError) as e:
            return None, "PARSE-ERR", str(e)
        still = find_undefined_calls(funcs)
        if still:
            return None, "RUN-ERR",                 f"未定义函数 (libc 未提供): {sorted(still)}"
    sim = Sim(globals_, funcs, trace=trace, strict=strict)
    ret, run_err = sim.run_main()
    if run_err:
        return ret, "RUN-ERR", run_err
    return ret, "RUN", ""


def main():
    ap = argparse.ArgumentParser(description="c51cc SSA 输出仿真器")
    ap.add_argument("tests", nargs="*", help="C 源文件 (多文件=多编译单元)")
    ap.add_argument("--suite", action="store_true", help="跑 test/suite 全部")
    ap.add_argument("--execute", action="store_true", help="跑 test/execute 全部")
    ap.add_argument("--ssa", action="store_true", help="跑 test/ssa 全部")
    ap.add_argument("--filter", default=None, help="按文件名正则过滤")
    ap.add_argument("--O0", "--O1", "--O2", dest="opt", default="-O1",
                    help="优化级别 (默认 -O1)")
    ap.add_argument("--before", action="store_true", help="仿真优化前 SSA")
    ap.add_argument("--trace", action="store_true", help="打印执行 trace")
    ap.add_argument("--strict", action="store_true", help="未定义值/未知符号报错")
    ap.add_argument("--stats", action="store_true", help="统计 Before/Optimized 指令数 (常量折叠量化)")
    args = ap.parse_args()

    files = list(args.tests)
    if args.suite:
        files += sorted(os.path.join(SUITE_DIR, f)
                        for f in os.listdir(SUITE_DIR) if f.endswith(".c"))
    if args.execute:
        files += sorted(os.path.join(EXECUTE_DIR, f)
                        for f in os.listdir(EXECUTE_DIR) if f.endswith(".c"))
    if args.ssa:
        files += sorted(os.path.join(SSA_DIR, f)
                        for f in os.listdir(SSA_DIR) if f.endswith(".c"))
    if not files:
        ap.error("no input files")
    if args.filter:
        files = [f for f in files if re.search(args.filter, os.path.basename(f))]

    if args.stats:
        for src in files:
            print_stats([src], opt=args.opt)
        return

    is_suite = args.suite or (not args.execute and not args.ssa
                              and files and os.path.dirname(files[0]).endswith("suite"))

    ok = fail = skip = cerr = 0
    for src in files:
        name = os.path.basename(src)
        src_text = open(src, encoding="utf-8", errors="replace").read()
        if is_suite or args.ssa:
            exp = parse_expected(src_text)
            if exp is None:
                print(f"SKIP {name:<44} (无期望值注释)")
                skip += 1
                continue
        else:
            exp = parse_expected(src_text)
            if exp is None:
                exp = 0
        ret, verdict, detail = simulate([src], opt=args.opt,
                                        use_before=args.before,
                                        trace=args.trace,
                                        strict=args.strict)
        if verdict == "COMPILE-ERR":
            print(f"COMPILE-ERR {name:<44} {detail[:80]}")
            cerr += 1
            continue
        if verdict == "PARSE-ERR":
            print(f"PARSE-ERR {name:<44} {detail[:80]}")
            fail += 1
            continue
        if verdict == "RUN-ERR":
            print(f"RUN-ERR {name:<44} {detail[:80]}")
            fail += 1
            continue
        if ret == exp:
            print(f"OK   {name:<44} ret={ret}")
            ok += 1
        else:
            print(f"FAIL {name:<44} ret={ret} 期望={exp}")
            fail += 1

    print(f"\n结果: {ok} OK / {fail} FAIL / {cerr} COMPILE-ERR / {skip} SKIP")
    return 0 if fail == 0 and cerr == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
