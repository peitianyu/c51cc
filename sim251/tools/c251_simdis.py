#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""c251_simdis.py — 基于 sim251 decode_impl.inc 权威映射的 C251 source-mode 反汇编器。

用途 (TCC 编译器调试辅助):
  1. 反汇编 TCC/Keil hex → 直接对照两边发射的指令
  2. --check-jumps: 静态检查所有跳转 (SJMP/LJMP/Jcond/LCALL/EJMP/ECALL)
     目标是否在代码范围内 → 定位 rel8 溢出 / 未解析 reloc 链接 bug
  3. --at PC: 反汇编指定地址的指令 (逃逸点归因)
  4. -sym: 函数符号标注

用法:
  python c251_simdis.py <hex> [--check-jumps] [--range lo hi] [-sym file] [--at ADDR]

映射来源: sim251/src/decode_impl.inc (已对照 Keil source+xsmall 验证)。
"""
import sys, re

# ------------------------------------------------------------------
# Intel HEX 加载
# ------------------------------------------------------------------
def load_hex(path):
    data = bytearray(); ext = 0; first = None; last = 0
    for line in open(path, encoding='utf-8', errors='replace'):
        line = line.strip()
        if not line.startswith(':'): continue
        n = int(line[1:3], 16); addr = int(line[3:7], 16); typ = int(line[7:9], 16)
        if typ == 4: ext = int(line[9:13], 16) << 16; continue
        if typ == 0:
            b = bytes(int(line[9 + i*2:11 + i*2], 16) for i in range(n))
            pos = ext + addr
            if (pos & 0xFF0000) == 0xFF0000: pos -= 0xFF0000   # 代码窗口重定位
            if first is None: first = pos
            last = max(last, pos + n)
            if len(data) < pos + n: data.extend(b'\xFF' * (pos + n - len(data)))
            data[pos:pos+n] = b
    return data, (first if first is not None else 0), last

def load_sym(path):
    syms = []
    for line in open(path, encoding='utf-8', errors='replace'):
        m = re.match(r'([0-9A-Fa-f]+)\t(\S+)', line.strip())
        if m: syms.append((int(m.group(1), 16), m.group(2)))
    syms.sort()
    return syms

def func_at(syms, addr):
    best = None
    for a, n in syms:
        if a <= addr: best = (a, n)
        else: break
    return best

# ------------------------------------------------------------------
# 助记符辅助
# ------------------------------------------------------------------
def reg8(i): return 'R%d' % (i & 15)
def wrj(i):  return 'WR%d' % ((i & 7) * 2)
def drk(i):  return 'DR%d' % ((i & 3) * 4)
def rel8_str(pc_after, r): 
    r = r if r < 128 else r - 256
    return 'rel=0x%04X' % ((pc_after + r) & 0xFFFF)
def dir16(v): return '0x%04X' % v
def dir8(v):  return '0x%02X' % v

# 位地址 → 字节/位
def bit_str(ba):
    if ba < 0x80:
        return 'bit 0x%02X' % ba
    return 'byte 0x%02X.%d' % (ba & 0xF8, ba & 7)

# 8051 标准位指令的位地址 (第三字节 = 完整位地址)
def bit8051(ba):
    if ba < 0x80: return '0x%02X(IRAM%d.%d)' % (ba, (ba >> 3) + 0x20, ba & 7)
    return '0x%02X(SFR%02X.%d)' % (ba, ba & 0xF8, ba & 7)

# A9 扩展位: 第三字节 = SFR/IRAM 字节地址, 位 = 第二字节低 3 位
def bit_a9(byte, bitn):
    if byte < 0x80: return '0x%02X.bit%d' % (byte, bitn)
    return 'SFR 0x%02X.%d' % (byte, bitn)

# ------------------------------------------------------------------
# 反汇编单条指令: 返回 (助记符串, 长度, 目标地址 或 None, 跳转类型 或 None)
#   跳转类型: 'rel8' / 'addr16' / 'addr24' / 'call16' / 'call24' / 'ind'
# ------------------------------------------------------------------
def disasm_one(data, pc, code_lo, code_hi):
    op = data[pc]
    def b1(): return data[pc+1] if pc+1 < len(data) else 0
    def b2(): return data[pc+2] if pc+2 < len(data) else 0
    def w16(): return (data[pc+1] << 8) | data[pc+2]
    def rel8_target():
        r = b1(); return (pc + 2 + (r if r < 128 else r-256)) & 0xFFFF

    # ---------- 251 原生 (source mode) ----------
    if op == 0x08: return 'JSLE %s' % rel8_str(pc+2, b1()), 2, rel8_target(), 'rel8'
    if op == 0x18: return 'JSG  %s' % rel8_str(pc+2, b1()), 2, rel8_target(), 'rel8'
    if op == 0x28: return 'JLE  %s' % rel8_str(pc+2, b1()), 2, rel8_target(), 'rel8'
    if op == 0x38: return 'JG   %s' % rel8_str(pc+2, b1()), 2, rel8_target(), 'rel8'
    if op == 0x48: return 'JSL  %s' % rel8_str(pc+2, b1()), 2, rel8_target(), 'rel8'
    if op == 0x58: return 'JSGE %s' % rel8_str(pc+2, b1()), 2, rel8_target(), 'rel8'
    if op == 0x60: return 'JZ   %s' % rel8_str(pc+2, b1()), 2, rel8_target(), 'rel8'
    if op == 0x68: return 'JE   %s' % rel8_str(pc+2, b1()), 2, rel8_target(), 'rel8'
    if op == 0x70: return 'JNZ  %s' % rel8_str(pc+2, b1()), 2, rel8_target(), 'rel8'
    if op == 0x78: return 'JNE  %s' % rel8_str(pc+2, b1()), 2, rel8_target(), 'rel8'
    if op == 0x40: return 'JC   %s' % rel8_str(pc+2, b1()), 2, rel8_target(), 'rel8'
    if op == 0x50: return 'JNC  %s' % rel8_str(pc+2, b1()), 2, rel8_target(), 'rel8'

    # 位移 MOV 家族 (4 字节: op b1 lo hi)
    if op in (0x09, 0x19, 0x29, 0x39, 0x49, 0x59, 0x69, 0x79):
        hi = b1() >> 4; lo = b1() & 0xF; dis = (data[pc+2] << 8) | data[pc+3]
        names = {0x09: 'MOV %s,@%s+0x%04X' % (reg8(hi), wrj(lo), dis),
                 0x19: 'MOV @%s+0x%04X,%s' % (wrj(lo), dis, reg8(hi)),
                 0x69: 'MOV %s,@%s+0x%04X' % (wrj(hi), drk(lo), dis),
                 0x79: 'MOV @%s+0x%04X,%s' % (drk(lo), dis, wrj(hi))}
        for k in (0x29, 0x39, 0x49, 0x59):
            names[k] = 'MOV? 0x%02X (未用)' % k
        return names.get(op, '?'), 4, None, None

    if op == 0x0A: return 'MOVZ %s,%s' % (wrj(b1() >> 4), reg8(b1() & 0xF)), 2, None, None
    if op == 0x1A: return 'MOVS %s,%s' % (wrj(b1() >> 4), reg8(b1() & 0xF)), 2, None, None

    if op in (0x0B, 0x1B):
        b1v = b1(); ss = b1v & 3; sel = (b1v >> 2) & 3; idx = b1v >> 4
        shortv = {0: 1, 1: 2, 2: 4}.get(ss, 1)
        m = 'DEC' if op == 0x1B else 'INC'
        if sel == 0: return '%s %s,#%d' % (m, reg8(idx), shortv), 2, None, None
        if sel == 1: return '%s %s,#%d' % (m, wrj(idx), shortv), 2, None, None
        if sel == 2:
            n = b2() >> 4
            if b1v & 2: return 'MOV %s,@%s' % (wrj(n), drk(idx)), 3, None, None
            return 'MOV %s,@%s' % (wrj(n), wrj(idx)), 3, None, None
        return '%s %s,#%d' % (m, drk(idx), shortv), 2, None, None

    if op in (0x0E, 0x1E, 0x3E):
        b1v = b1(); idx = b1v >> 4; lo = b1v & 0xF
        nm = {0x0E: 'SRA', 0x1E: 'SRL', 0x3E: 'SLL'}[op]
        if lo == 0: return '%s %s' % (nm, reg8(idx)), 2, None, None
        if lo == 4: return '%s %s' % (nm, wrj(idx)), 2, None, None
        if lo == 0xC: return '%s %s' % (nm, drk(idx)), 2, None, None
        return '%s ?' % nm, 2, None, None

    # 双寄存器移位: 0x0C/0x0D/0x0F SRA, 0x1C/0x1D/0x1F SRL, 0x3C/0x3D/0x3F SLL
    if op in (0x0C, 0x0D, 0x0F, 0x1C, 0x1D, 0x1F, 0x3C, 0x3D, 0x3F):
        nm = {0x0C:'SRA',0x0D:'SRA',0x0F:'SRA',0x1C:'SRL',0x1D:'SRL',0x1F:'SRL',
              0x3C:'SLL',0x3D:'SLL',0x3F:'SLL'}[op]
        kind = op & 3
        if kind == 0: return '%s %s,%s' % (nm, reg8(b1()>>4), reg8(b1()&0xF)), 2, None, None
        if kind == 1: return '%s %s,%s' % (nm, wrj((b1()>>4)&7), wrj(b1()&7)), 2, None, None
        return '%s %s,%s' % (nm, drk((b1()>>4)&3), drk(b1()&3)), 2, None, None

    if op == 0x6A:
        return 'CMP %s,#0x%02X' % (reg8(b1() >> 4), b2()), 3, None, None
    if op == 0x6B or op == 0x9B:
        return 'CMP %s,%s' % (reg8(b1() >> 4), reg8(b1() & 0xF)), 2, None, None

    if op == 0x89:
        if (b1() & 0xF) == 0x8: return 'EJMP @%s' % drk(b1() >> 4), 2, None, 'ind'
        return 'LJMP @%s' % wrj(b1() >> 4), 2, None, 'ind'
    if op == 0x8A: return 'EJMP 0x%06X' % ((data[pc+1] << 16) | w16()), 4, ((data[pc+1] << 16) | w16()) & 0xFFFF, 'addr24'
    if op == 0x99:
        if (b1() & 0xF) == 0x8: return 'ECALL @%s' % drk(b1() >> 4), 2, None, 'ind'
        return 'LCALL @%s' % wrj(b1() >> 4), 2, None, 'ind'
    if op == 0x9A:
        return 'ECALL 0x%06X' % ((data[pc+1] << 16) | w16()), 4, ((data[pc+1] << 16) | w16()) & 0xFFFF, 'call24'
    if op == 0xAA: return 'ERET', 1, None, None
    if op == 0xB9: return 'TRAP', 1, None, None

    if op in (0xCA, 0xDA):
        b1v = b1(); kind = b1v & 0xF; idx = b1v >> 4
        m = 'PUSH' if op == 0xCA else 'POP'
        if kind == 2: return '%s #0x%02X' % (m, b2()), 3, None, None
        if kind == 6: return '%s #0x%04X' % (m, (data[pc+2]<<8)|data[pc+3]), 4, None, None
        if kind == 8: return '%s %s' % (m, reg8(idx)), 2, None, None
        if kind == 9: return '%s %s' % (m, wrj(idx)), 2, None, None
        if kind == 0xB: return '%s %s' % (m, drk(idx)), 2, None, None
        return '%s ?' % m, 2, None, None

    if op == 0x8C: return 'DIV %s,%s' % (reg8(b1()>>4), reg8(b1()&0xF)), 2, None, None
    if op == 0x8D: return 'DIV %s,%s' % (wrj((b1()>>4)&7), wrj(b1()&7)), 2, None, None

    # 0x7E MOV reg,op2 — 变长
    if op == 0x7E:
        return disasm_7e(data, pc)
    # 0x7A MOV op1,reg — 变长
    if op == 0x7A:
        return disasm_7a(data, pc)

    # regop2 家族 (C/D/E/F 低半字节): ADD/ORL/ANL/XRL/MOV/SUB/MUL/CMP
    if (op & 0x0F) >= 0xC and op_from_hi(op >> 4) is not None:
        return disasm_regop2(data, pc)

    # ---------- A5 前缀 ----------
    if op == 0xA5:
        return disasm_a5(data, pc)
    # ---------- A9 位前缀 ----------
    if op == 0xA9:
        b1v = b1(); hi = b1v >> 4; bitn = b1v & 7; byte = b2()
        ops = {0x1:'JBC', 0x2:'JB', 0x3:'JNB', 0x7:'ORL C,', 0x8:'ANL C,',
               0x9:'MOV ', 0xA:'MOV C,', 0xB:'CPL ', 0xC:'CLR ', 0xD:'SETB ',
               0xE:'ORL C,/', 0xF:'ANL C,/'}
        nm = ops.get(hi, '?')
        ba = bit_a9(byte, bitn)
        if hi in (0x1, 0x2, 0x3):
            return '%s %s,%s' % (nm, ba, rel8_str(pc+3, data[pc+3] if pc+3 < len(data) else 0)), 4, (pc+3+(data[pc+3] if pc+3<len(data) else 0 if data[pc+3]<128 else data[pc+3]-256))&0xFFFF, 'rel8'
        return '%s%s' % (nm, ba), 3, None, None

    # ---------- 8051 标准指令 ----------
    return disasm_8051(data, pc)

def op_from_hi(hi):
    return {0x2:'ADD', 0x3:'SLL', 0x4:'ORL', 0x5:'ANL', 0x6:'XRL', 0x7:'MOV',
            0x8:'DIV', 0x9:'SUB', 0xA:'MUL', 0xB:'CMP', 0xD:'XRL'}.get(hi)

# 7E: MOV reg,op2 (第二字节低 4 位 = kind, 高 4 位 = idx)
def disasm_7e(data, pc):
    b1v = data[pc+1]; kind = b1v & 0xF; idx = b1v >> 4
    def extra(k):
        return data[pc+k] if pc+k < len(data) else 0
    # kind → 目标寄存器类型 (mode 低 4 位: 0/1/3/7=byte/word/dword 组合)
    # 参考 regop2_generic / mov_reg_op2: kind 映射同 regop2 mode 表
    dst_kind = {0:'Rm', 1:'Rm', 3:'Rm', 4:'WRj', 5:'WRj', 7:'WRj',
                8:'DRk', 9:'Rm', 0xA:'WRj', 0xB:'Rm', 0xC:'DRk', 0xD:'DRk',
                0xE:'DRk', 0xF:'DRk'}.get(kind, 'Rm')
    dst = reg8(idx) if dst_kind == 'Rm' else (wrj(idx) if dst_kind == 'WRj' else drk(idx))
    # kind → 源操作数格式 (与 regop2_generic 一致)
    if kind == 0x0:  return 'MOV %s,#0x%02X' % (dst, extra(2)), 3, None, None
    if kind == 0x1:  return 'MOV %s,%s' % (dst, dir8(extra(2))), 3, None, None
    if kind == 0x2:  return 'MOV %s,@R%d' % (dst, extra(2) & 1), 3, None, None
    if kind == 0x3:  return 'MOV %s,%s' % (dst, dir16((extra(2)<<8)|extra(3))), 4, None, None
    if kind == 0x4:  return 'MOV %s,#0x%04X' % (dst, (extra(2)<<8)|extra(3)), 4, None, None
    if kind == 0x5:  return 'MOV %s,#0x%02X' % (dst, extra(2)), 3, None, None
    if kind == 0x6:  return 'MOV %s,@R%d (word)' % (dst, extra(2) & 1), 3, None, None
    if kind == 0x7:  return 'MOV %s,%s' % (dst, dir16((extra(2)<<8)|extra(3))), 4, None, None
    if kind == 0x8:  return 'MOV %s,%s' % (dst, dir8(extra(2))), 3, None, None
    if kind == 0x9:  return 'MOV %s,@%s' % (dst, wrj(extra(2) >> 4)), 3, None, None
    if kind == 0xA:  return 'MOV %s,@%s (word)' % (dst, wrj(extra(2) >> 4)), 3, None, None
    if kind == 0xB:  return 'MOV %s,@%s' % (dst, drk(idx & 3) if False else drk(extra(2) >> 4)), 3, None, None
    if kind == 0xC:  return 'MOV %s,%s' % (dst, dir8(extra(2))), 3, None, None
    if kind == 0xD:  return 'MOV %s,%s (dword)' % (dst, dir8(extra(2))), 3, None, None
    if kind == 0xE:  return 'MOV %s,@%s (dword)' % (dst, wrj(extra(2) >> 4)), 3, None, None
    if kind == 0xF:  return 'MOV %s,%s' % (dst, dir16((extra(2)<<8)|extra(3))), 4, None, None
    return 'MOV ?', 2, None, None

# 7A: MOV op1,reg (第二字节低 4 位 = kind, 高 4 位 = idx)
def disasm_7a(data, pc):
    b1v = data[pc+1]; kind = b1v & 0xF; idx = b1v >> 4
    def extra(k): return data[pc+k] if pc+k < len(data) else 0
    src = reg8(idx)
    if kind == 0x1:  return 'MOV %s,%s' % (dir8(extra(2)), src), 3, None, None
    if kind == 0x5:  return 'MOV %s,%s (word)' % (dir8(extra(2)), wrj(idx)), 3, None, None
    if kind == 0xD:  return 'MOV %s,%s (dword)' % (dir8(extra(2)), drk(idx)), 3, None, None
    if kind == 0x9:  return 'MOV @%s,%s' % (wrj(idx), reg8(extra(2) >> 4)), 3, None, None
    if kind == 0xA:  return 'MOV @%s,%s (word)' % (wrj(idx), wrj(extra(2) >> 4)), 3, None, None
    if kind == 0xE:  return 'MOV @%s,%s (dword)' % (wrj(idx), drk(extra(2) >> 4)), 3, None, None
    if kind == 0x2:  return 'MOV @R%d,%s' % (extra(2) & 1, reg8(extra(2) >> 4)), 3, None, None
    if kind == 0x6:  return 'MOV @R%d,%s (word)' % (extra(2) & 1, wrj((extra(2) >> 4) & 7)), 3, None, None
    if kind == 0xB:  return 'MOV @%s,%s' % (drk(idx), reg8(extra(2) >> 4)), 3, None, None
    if kind == 0x3:  return 'MOV %s,%s' % (dir16((extra(2)<<8)|extra(3)), src), 4, None, None
    if kind == 0x7:  return 'MOV %s,%s (word)' % (dir16((extra(2)<<8)|extra(3)), wrj(idx)), 4, None, None
    if kind == 0xF:  return 'MOV %s,%s (dword)' % (dir16((extra(2)<<8)|extra(3)), drk(idx)), 4, None, None
    return 'MOV ?', 2, None, None

# regop2: op0 低半字节 C=byte D=word E=变长 F=dword
def disasm_regop2(data, pc):
    op = data[pc]; hi = op >> 4; opn = op_from_hi(hi)
    b1v = data[pc+1] if pc+1 < len(data) else 0
    kind = op & 0xF
    idx = b1v >> 4; k2 = b1v & 0xF
    if kind == 0xC: return '%s %s,%s' % (opn, reg8(idx), reg8(k2)), 2, None, None
    if kind == 0xD: return '%s %s,%s' % (opn, wrj(idx), wrj(k2)), 2, None, None
    if kind == 0xF: return '%s %s,%s' % (opn, drk(idx), drk(k2)), 2, None, None
    if kind == 0xE:
        # 变长: 第二字节低 4 位 = kind (同 regop2_generic)
        rk = k2
        dst = reg8(idx)
        if rk == 0x0: return '%s %s,#0x%02X' % (opn, dst, data[pc+2]), 3, None, None
        if rk == 0x4: return '%s %s,#0x%04X' % (opn, wrj(idx), (data[pc+2]<<8)|data[pc+3]), 4, None, None
        if rk in (0x8, 0xC): return '%s %s,#0x%04X' % (opn, drk(idx), (data[pc+2]<<8)|data[pc+3]), 4, None, None
        if rk == 0x1: return '%s %s,%s' % (opn, dst, dir8(data[pc+2])), 3, None, None
        if rk == 0x2: return '%s %s,@R%d' % (opn, dst, data[pc+2] & 1), 3, None, None
        if rk == 0x3: return '%s %s,%s' % (opn, dst, dir16((data[pc+2]<<8)|data[pc+3])), 4, None, None
        if rk == 0x5: return '%s %s,#0x%02X' % (opn, wrj(idx), data[pc+2]), 3, None, None
        if rk == 0x6: return '%s %s,@R%d (word)' % (opn, wrj(idx), data[pc+2] & 1), 3, None, None
        if rk == 0x7: return '%s %s,%s' % (opn, wrj(idx), dir16((data[pc+2]<<8)|data[pc+3])), 4, None, None
        if rk == 0x9: return '%s %s,@%s' % (opn, dst, wrj(data[pc+2] >> 4)), 3, None, None
        if rk == 0xA: return '%s %s,@%s (word)' % (opn, wrj(idx), wrj(data[pc+2] >> 4)), 3, None, None
        if rk == 0xB: return '%s %s,@%s' % (opn, dst, drk(data[pc+2] >> 4)), 3, None, None
        if rk == 0xD: return '%s %s,%s (dword)' % (opn, drk(idx), dir8(data[pc+2])), 3, None, None
        if rk == 0xE: return '%s %s,@%s (dword)' % (opn, drk(idx), wrj(data[pc+2] >> 4)), 3, None, None
        if rk == 0xF: return '%s %s,%s' % (opn, drk(idx), dir16((data[pc+2]<<8)|data[pc+3])), 4, None, None
        return '%s ?' % opn, 2, None, None
    return '%s ?' % opn, 2, None, None

# A5 前缀 (2 字节)
def disasm_a5(data, pc):
    op1 = data[pc+1]; hi = op1 >> 4; lo = op1 & 0xF
    if lo >= 8:
        n = lo & 7
        names = {0x0:'INC', 0x1:'DEC', 0x2:'ADD A,', 0x3:'ADDC A,', 0x4:'ORL A,',
                 0x5:'ANL A,', 0x6:'XRL A,', 0x7:'MOV Rn,#d', 0x8:'MOV dir8,Rn',
                 0x9:'SUBB A,', 0xA:'MOV Rn,dir8', 0xB:'CJNE', 0xC:'XCH A,',
                 0xD:'DJNZ', 0xE:'MOV A,', 0xF:'MOV Rn,A'}
        nm = names.get(hi, '?')
        if hi == 0x0: return 'INC %s' % reg8(n), 2, None, None
        if hi == 0x1: return 'DEC %s' % reg8(n), 2, None, None
        if hi == 0x7: return 'MOV %s,#0x%02X' % (reg8(n), data[pc+2]), 3, None, None
        if hi == 0x8: return 'MOV %s,%s' % (dir8(data[pc+2]), reg8(n)), 3, None, None
        if hi == 0xA: return 'MOV %s,%s' % (reg8(n), dir8(data[pc+2])), 3, None, None
        if hi == 0xB: return 'CJNE %s,#d,rel' % reg8(n), 4, None, None
        if hi == 0xC: return 'XCH A,%s' % reg8(n), 2, None, None
        if hi == 0xD: return 'DJNZ %s,rel' % reg8(n), 3, None, None
        if hi == 0xE: return 'MOV A,%s' % reg8(n), 2, None, None
        if hi == 0xF: return 'MOV %s,A' % reg8(n), 2, None, None
        return 'A5 %s' % nm, 2, None, None
    else:
        i = lo & 1
        names = {0x0:'INC @R', 0x1:'DEC @R', 0x2:'ADD A,@R', 0x3:'ADDC A,@R',
                 0x4:'ORL A,@R', 0x5:'ANL A,@R', 0x6:'XRL A,@R', 0x7:'MOV @Ri,#d',
                 0x8:'MOV dir8,@Ri', 0x9:'SUBB A,@R', 0xA:'MOV @Ri,dir8',
                 0xB:'CJNE @Ri,#d,rel', 0xC:'XCH A,@R', 0xD:'XCHD A,@R',
                 0xE:'MOV A,@R', 0xF:'MOV @Ri,A'}
        nm = names.get(hi, '?')
        if hi == 0x0: return 'INC @R%d' % i, 2, None, None
        if hi == 0x1: return 'DEC @R%d' % i, 2, None, None
        if hi == 0x7: return 'MOV @R%d,#0x%02X' % (i, data[pc+2]), 3, None, None
        if hi == 0x8: return 'MOV %s,@R%d' % (dir8(data[pc+2]), i), 3, None, None
        if hi == 0xA: return 'MOV @R%d,%s' % (i, dir8(data[pc+2])), 3, None, None
        if hi == 0xB: return 'CJNE @R%d,#d,rel' % i, 4, None, None
        if hi == 0xC: return 'XCH A,@R%d' % i, 2, None, None
        if hi == 0xD: return 'XCHD A,@R%d' % i, 2, None, None
        if hi == 0xE: return 'MOV A,@R%d' % i, 2, None, None
        if hi == 0xF: return 'MOV @R%d,A' % i, 2, None, None
        return 'A5 %s' % nm, 2, None, None

# 8051 标准指令
def disasm_8051(data, pc):
    op = data[pc]
    def b1(): return data[pc+1] if pc+1 < len(data) else 0
    def rel8_target():
        r = b1(); return (pc + 2 + (r if r < 128 else r-256)) & 0xFFFF
    T = {0x00:('NOP',1), 0x02:('LJMP %s'%dir16((data[pc+1]<<8)|data[pc+2]),3),
         0x03:('RR A',1), 0x04:('INC A',1), 0x05:('INC %s'%dir8(b1()),2),
         0x06:('INC @R0',1), 0x07:('INC @R1',1),
         0x10:('JBC %s,rel'%bit8051(b1()),3), 0x11:('ACALL',2),
         0x12:('LCALL %s'%dir16((data[pc+1]<<8)|data[pc+2]),3),
         0x13:('RRC A',1), 0x14:('DEC A',1), 0x15:('DEC %s'%dir8(b1()),2),
         0x16:('DEC @R0',1), 0x17:('DEC @R1',1),
         0x20:('JB %s,rel'%bit8051(b1()),3), 0x21:('AJMP',2),
         0x22:('RET',1), 0x23:('RL A',1), 0x24:('ADD A,#0x%02X'%b1(),2),
         0x25:('ADD A,%s'%dir8(b1()),2), 0x26:('ADD A,@R0',1), 0x27:('ADD A,@R1',1),
         0x30:('JNB %s,rel'%bit8051(b1()),3), 0x31:('ACALL',2),
         0x32:('RETI',1), 0x33:('RLC A',1), 0x34:('ADDC A,#0x%02X'%b1(),2),
         0x35:('ADDC A,%s'%dir8(b1()),2), 0x36:('ADDC A,@R0',1), 0x37:('ADDC A,@R1',1),
         0x41:('ACALL',2), 0x42:('ORL %s,A'%dir8(b1()),2),
         0x43:('ORL %s,#0x%02X'%(dir8(b1()), data[pc+2] if pc+2<len(data) else 0),3),
         0x44:('ORL A,#0x%02X'%b1(),2), 0x45:('ORL A,%s'%dir8(b1()),2),
         0x46:('ORL A,@R0',1), 0x47:('ORL A,@R1',1),
         0x51:('ACALL',2), 0x52:('ANL %s,A'%dir8(b1()),2),
         0x53:('ANL %s,#0x%02X'%(dir8(b1()), data[pc+2] if pc+2<len(data) else 0),3),
         0x54:('ANL A,#0x%02X'%b1(),2), 0x55:('ANL A,%s'%dir8(b1()),2),
         0x56:('ANL A,@R0',1), 0x57:('ANL A,@R1',1),
         0x61:('AJMP',2), 0x62:('XRL %s,A'%dir8(b1()),2),
         0x63:('XRL %s,#0x%02X'%(dir8(b1()), data[pc+2] if pc+2<len(data) else 0),3),
         0x64:('XRL A,#0x%02X'%b1(),2), 0x65:('XRL A,%s'%dir8(b1()),2),
         0x66:('XRL A,@R0',1), 0x67:('XRL A,@R1',1),
         0x71:('ACALL',2), 0x72:('ORL C,%s'%bit8051(b1()),2),
         0x73:('JMP @A+DPTR',1), 0x74:('MOV A,#0x%02X'%b1(),2),
         0x75:('MOV %s,#0x%02X'%(dir8(b1()), data[pc+2] if pc+2<len(data) else 0),3),
         0x76:('MOV @R0,#0x%02X'%b1(),2), 0x77:('MOV @R1,#0x%02X'%b1(),2),
         0x80:('SJMP %s'%rel8_str(pc+2, b1()),2),
         0x81:('ACALL',2), 0x82:('ANL C,%s'%bit8051(b1()),2),
         0x83:('MOVC A,@A+PC',1), 0x84:('DIV AB',1), 0x85:('MOV %s,%s'%(dir8(b1()),dir8(data[pc+2] if pc+2<len(data) else 0)),3),
         0x86:('MOV %s,@R0'%dir8(b1()),2), 0x87:('MOV %s,@R1'%dir8(b1()),2),
         0x90:('MOV DPTR,#0x%04X'%((data[pc+1]<<8)|data[pc+2]),3),
         0x91:('ACALL',2), 0x92:('MOV %s,C'%bit8051(b1()),2),
         0x93:('MOVC A,@A+DPTR',1), 0x94:('SUBB A,#0x%02X'%b1(),2),
         0x95:('SUBB A,%s'%dir8(b1()),2), 0x96:('SUBB A,@R0',1), 0x97:('SUBB A,@R1',1),
         0xA1:('AJMP',2), 0xA2:('MOV C,%s'%bit8051(b1()),2),
         0xA3:('INC DPTR',1), 0xA4:('MUL AB',1),
         0xA5:('(A5 前缀)',2), 0xA6:('MOV @R0,%s'%dir8(b1()),2), 0xA7:('MOV @R1,%s'%dir8(b1()),2),
         0xA8:('MOV R0,%s'%dir8(b1()),2), 0xA9:('(A9 位前缀)',3),
         0xAA:('MOV R2,%s'%dir8(b1()),2), 0xAB:('MOV R3,%s'%dir8(b1()),2),
         0xAC:('MOV R4,%s'%dir8(b1()),2), 0xAD:('MOV R5,%s'%dir8(b1()),2),
         0xAE:('MOV R6,%s'%dir8(b1()),2), 0xAF:('MOV R7,%s'%dir8(b1()),2),
         0xB1:('ACALL',2), 0xB2:('CPL %s'%bit8051(b1()),2),
         0xB3:('CPL C',1), 0xB4:('CJNE A,#0x%02X,rel'%b1(),3),
         0xB5:('CJNE A,%s,rel'%dir8(b1()),3), 0xB6:('CJNE @R0,#d,rel',3), 0xB7:('CJNE @R1,#d,rel',3),
         0xB8:('CJNE R0,#d,rel',3), 0xB9:('CJNE R1,#d,rel',3), 0xBA:('CJNE R2,#d,rel',3),
         0xBB:('CJNE R3,#d,rel',3), 0xBC:('CJNE R4,#d,rel',3), 0xBD:('CJNE R5,#d,rel',3),
         0xBE:('CJNE R6,#d,rel',3), 0xBF:('CJNE R7,#d,rel',3),
         0xC0:('PUSH %s'%dir8(b1()),2), 0xC1:('AJMP',2), 0xC2:('CLR %s'%bit8051(b1()),2),
         0xC3:('CLR C',1), 0xC4:('SWAP A',1), 0xC5:('XCH A,%s'%dir8(b1()),2),
         0xC6:('XCH A,@R0',1), 0xC7:('XCH A,@R1',1), 0xC8:('XCH A,R0',1),
         0xC9:('XCH A,R1',1), 0xCA:('XCH A,R2',1), 0xCB:('XCH A,R3',1),
         0xCC:('XCH A,R4',1), 0xCD:('XCH A,R5',1), 0xCE:('XCH A,R6',1),
         0xCF:('XCH A,R7',1), 0xD0:('POP %s'%dir8(b1()),2), 0xD1:('ACALL',2),
         0xD2:('SETB %s'%bit8051(b1()),2), 0xD3:('SETB C',1), 0xD4:('DA A',1),
         0xD5:('DJNZ %s,rel'%dir8(b1()),3), 0xD6:('XCHD A,@R0',1), 0xD7:('XCHD A,@R1',1),
         0xD8:('DJNZ R0,rel',2), 0xD9:('DJNZ R1,rel',2), 0xDA:('DJNZ R2,rel',2),
         0xDB:('DJNZ R3,rel',2), 0xDC:('DJNZ R4,rel',2), 0xDD:('DJNZ R5,rel',2),
         0xDE:('DJNZ R6,rel',2), 0xDF:('DJNZ R7,rel',2),
         0xE0:('MOVX A,@DPTR',1), 0xE1:('AJMP',2), 0xE2:('MOVX A,@R0',1), 0xE3:('MOVX A,@R1',1),
         0xE4:('CLR A',1), 0xE5:('MOV A,%s'%dir8(b1()),2), 0xE6:('MOV A,@R0',1), 0xE7:('MOV A,@R1',1),
         0xE8:('MOV A,R0',1), 0xE9:('MOV A,R1',1), 0xEA:('MOV A,R2',1), 0xEB:('MOV A,R3',1),
         0xEC:('MOV A,R4',1), 0xED:('MOV A,R5',1), 0xEE:('MOV A,R6',1), 0xEF:('MOV A,R7',1),
         0xF0:('MOVX @DPTR,A',1), 0xF1:('ACALL',2), 0xF2:('MOVX @R0,A',1), 0xF3:('MOVX @R1,A',1),
         0xF4:('CLR A',1), 0xF5:('MOV %s,A'%dir8(b1()),2), 0xF6:('MOV @R0,A',1), 0xF7:('MOV @R1,A',1),
         0xF8:('MOV R0,A',1), 0xF9:('MOV R1,A',1), 0xFA:('MOV R2,A',1), 0xFB:('MOV R3,A',1),
         0xFC:('MOV R4,A',1), 0xFD:('MOV R5,A',1), 0xFE:('MOV R6,A',1), 0xFF:('MOV R7,A',1),
    }
    if op in T:
        m, ln = T[op]
        if op == 0x80: return m, ln, rel8_target(), 'rel8'
        if op == 0x02: return m, ln, ((data[pc+1]<<8)|data[pc+2]) & 0xFFFF, 'addr16'
        if op == 0x12: return m, ln, ((data[pc+1]<<8)|data[pc+2]) & 0xFFFF, 'call16'
        if op == 0x60 and False: pass
        # 条件跳转 rel8 (2 字节)
        if op in (0x40, 0x50): return m, ln, rel8_target(), 'rel8'
        if op in (0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xD5, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF):
            return m, ln, None, 'rel8'
        if op in (0x20, 0x30, 0x10): return m, ln, None, 'rel8'  # JB/JNB/JBC 目标需要计算
        return m, ln, None, None
    # 未识别的 8051 opcode (可能是 source-mode 替换遗漏)
    return '?? 0x%02X' % op, 1, None, None

# ------------------------------------------------------------------
# 主流程
# ------------------------------------------------------------------
def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__); return 1
    hexpath = args[0]
    check_jumps = '--check-jumps' in args
    sympath = None
    at_addr = None
    rng = None
    for i, a in enumerate(args):
        if a == '-sym' and i+1 < len(args): sympath = args[i+1]
        if a == '--at' and i+1 < len(args): at_addr = int(args[i+1], 16)
        if a == '--range' and i+2 < len(args):
            rng = (int(args[i+1], 16), int(args[i+2], 16))
    data, lo, hi = load_hex(hexpath)
    syms = load_sym(sympath) if sympath else []
    print('; %s: code 0x%04X-0x%04X (%d bytes)' % (hexpath, lo, hi, hi-lo))
    if at_addr is not None:
        m, ln, tgt, jt = disasm_one(data, at_addr, lo, hi)
        f = func_at(syms, at_addr)
        print('0x%04X: %-44s  %s' % (at_addr, ' '.join('%02X'%b for b in data[at_addr:at_addr+ln]), m))
        if f: print('    in %s @0x%04X' % (f[1], f[0]))
        return 0
    start = rng[0] if rng else 0
    end = rng[1] if rng else 0x10000
    pc = start
    curf = None
    bad_jumps = []
    while pc < end and pc < len(data) - 1:
        if data[pc] == 0xFF and all(b == 0xFF for b in data[pc:pc+16]):
            # 跳到下一个非 FF
            nxt = pc
            while nxt < len(data) and data[nxt] == 0xFF: nxt += 1
            if nxt >= end: break
            pc = nxt; continue
        f = func_at(syms, pc)
        if f and f != curf:
            print('\n; --- %s @0x%04X ---' % (f[1], f[0]))
            curf = f
        try:
            m, ln, tgt, jt = disasm_one(data, pc, lo, hi)
        except Exception as e:
            print('0x%04X: ?? (%s)' % (pc, e)); pc += 1; continue
        line = '0x%04X: %-36s %s' % (pc, ' '.join('%02X'%b for b in data[pc:pc+ln]), m)
        if tgt is not None and jt:
            in_range = lo <= tgt <= hi
            mark = '' if in_range else '  <<< OUT-OF-RANGE'
            line += '  [->0x%04X%s]' % (tgt, mark)
            if not in_range:
                bad_jumps.append((pc, m, tgt))
        print(line)
        pc += ln
    if check_jumps and bad_jumps:
        print('\n=== 越界跳转 (%d) ===' % len(bad_jumps))
        for a, m, t in bad_jumps[:40]:
            f = func_at(syms, a)
            print('  0x%04X %-30s -> 0x%04X  %s' % (a, m, t, f[1] if f else ''))
    return 0

if __name__ == '__main__':
    sys.exit(main())
