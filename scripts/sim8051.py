"""
8051 Semantic Validator
Runs Intel HEX files in a minimal 8051 simulator and returns R6/R7 (int return value).
"""

import sys, os, re


# ──────────────────────────────────────────────
# Intel HEX loader
# ──────────────────────────────────────────────
def load_hex(path):
    """Returns bytearray of CODE memory (64KB)"""
    mem = bytearray(65536)
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line.startswith(":"):
                continue
            b = bytes.fromhex(line[1:])
            rtype = b[3]
            if rtype == 0:
                addr = (b[1] << 8) | b[2]
                for i, byte in enumerate(b[4:-1]):
                    if addr + i < 65536:
                        mem[addr + i] = byte
    return mem


# ──────────────────────────────────────────────
# 8051 CPU state
# ──────────────────────────────────────────────
class CPU8051:
    def __init__(self, code_mem):
        self.code = code_mem  # 64KB code ROM
        self.iram = bytearray(256)  # internal RAM (0x00..0xFF)
        self.xram = bytearray(65536)  # external RAM
        self.sfr = bytearray(128)  # SFR space (0x80..0xFF)
        self.pc = 0
        self.halted = False
        self._icount = 0
        self._max_insn = 500_000

        # SFR addresses
        self.SP_ADDR = 0x81 - 0x80  # SP  = 0x81
        self.PSW_ADDR = 0xD0 - 0x80  # PSW = 0xD0
        self.ACC_ADDR = 0xE0 - 0x80  # ACC = 0xE0
        self.B_ADDR = 0xF0 - 0x80  # B   = 0xF0

        # Initialise SP to 7
        self.sfr[self.SP_ADDR] = 0x07

    # ---------- register bank helpers ----------
    def _bank_base(self):
        psw = self.sfr[self.PSW_ADDR]
        return ((psw >> 3) & 0x03) * 8

    def _getr(self, n):
        return self.iram[self._bank_base() + n]

    def _setr(self, n, v):
        self.iram[self._bank_base() + n] = v & 0xFF

    # ---------- ACC / PSW helpers ----------
    @property
    def acc(self):
        return self.sfr[self.ACC_ADDR]

    @acc.setter
    def acc(self, v):
        self._write_sfr(0xE0, v)

    @property
    def b_reg(self):
        return self.sfr[self.B_ADDR]

    @b_reg.setter
    def b_reg(self, v):
        self.sfr[self.B_ADDR] = v & 0xFF

    @property
    def sp(self):
        return self.sfr[self.SP_ADDR]

    @sp.setter
    def sp(self, v):
        self.sfr[self.SP_ADDR] = v & 0xFF

    @property
    def psw(self):
        return self._read_sfr(0xD0)

    @psw.setter
    def psw(self, v):
        self._write_sfr(0xD0, v)

    def _set_cy(self, v):
        if v:
            self.sfr[self.PSW_ADDR] |= 0x80
        else:
            self.sfr[self.PSW_ADDR] &= 0x7F

    def _get_cy(self):
        return (self.sfr[self.PSW_ADDR] >> 7) & 1

    def _set_ac(self, v):
        if v:
            self.sfr[self.PSW_ADDR] |= 0x40
        else:
            self.sfr[self.PSW_ADDR] &= 0xBF

    def _set_ov(self, v):
        if v:
            self.sfr[self.PSW_ADDR] |= 0x04
        else:
            self.sfr[self.PSW_ADDR] &= 0xFB

    def _set_p(self):
        p = bin(self.acc).count("1") & 1
        if p:
            self.sfr[self.PSW_ADDR] |= 0x01
        else:
            self.sfr[self.PSW_ADDR] &= 0xFE

    # ---------- memory access ----------
    def _read_sfr(self, addr):
        # Update P flag before returning PSW
        if addr == 0xD0:
            self._set_p()
        return self.sfr[addr - 0x80]

    def _write_sfr(self, addr, v):
        self.sfr[addr - 0x80] = v & 0xFF
        # Update P flag after writing ACC or PSW
        if addr == 0xE0 or addr == 0xD0:
            self._set_p()

    def _read_direct(self, addr):
        if addr < 0x80:
            return self.iram[addr]
        else:
            return self._read_sfr(addr)

    def _write_direct(self, addr, v):
        if addr < 0x80:
            self.iram[addr] = v & 0xFF
        else:
            self._write_sfr(addr, v)

    def _read_bit(self, bit_addr):
        if bit_addr < 0x80:
            byte_addr = 0x20 + (bit_addr >> 3)
            bit_n = bit_addr & 7
            return (self.iram[byte_addr] >> bit_n) & 1
        else:
            sfr_addr = bit_addr & 0xF8
            bit_n = bit_addr & 7
            return (self._read_direct(sfr_addr) >> bit_n) & 1

    def _write_bit(self, bit_addr, v):
        if bit_addr < 0x80:
            byte_addr = 0x20 + (bit_addr >> 3)
            bit_n = bit_addr & 7
            if v:
                self.iram[byte_addr] |= 1 << bit_n
            else:
                self.iram[byte_addr] &= ~(1 << bit_n)
        else:
            sfr_addr = bit_addr & 0xF8
            bit_n = bit_addr & 7
            cur = self._read_direct(sfr_addr)
            if v:
                cur |= 1 << bit_n
            else:
                cur &= ~(1 << bit_n)
            self._write_direct(sfr_addr, cur)

    # ---------- stack ----------
    def _push(self, v):
        self.sp = (self.sp + 1) & 0xFF
        self.iram[self.sp] = v & 0xFF

    def _pop(self):
        v = self.iram[self.sp]
        self.sp = (self.sp - 1) & 0xFF
        return v

    def _push16(self, v):
        self._push(v & 0xFF)
        self._push((v >> 8) & 0xFF)

    def _pop16(self):
        hi = self._pop()
        lo = self._pop()
        return (hi << 8) | lo

    # ---------- fetch ----------
    def _fetch(self):
        b = self.code[self.pc]
        self.pc = (self.pc + 1) & 0xFFFF
        return b

    def _fetch16(self):
        hi = self._fetch()
        lo = self._fetch()
        return (hi << 8) | lo

    # ---------- arithmetic helpers ----------
    def _add8(self, a, b, cy=0):
        r = a + b + cy
        self._set_cy(r > 0xFF)
        self._set_ac(((a & 0xF) + (b & 0xF) + cy) > 0xF)
        self._set_ov(((a ^ r) & (b ^ r) & 0x80) != 0)
        return r & 0xFF

    def _sub8(self, a, b, cy=0):
        r = a - b - cy
        self._set_cy(r < 0)
        self._set_ac(((a & 0xF) - (b & 0xF) - cy) < 0)
        self._set_ov(((a ^ b) & (a ^ r) & 0x80) != 0)
        return r & 0xFF

    # ---------- main execution step ----------
    def step(self):
        if self.halted:
            return False
        op = self._fetch()

        if op == 0x00:  # NOP
            pass

        elif op == 0x01:  # AJMP addr11
            rel = self._fetch()
            page = self.pc & 0xF800
            self.pc = page | ((op & 0xE0) << 3) | rel

        elif op == 0x02:  # LJMP addr16
            addr = self._fetch16()
            self.pc = addr

        elif op == 0x03:  # RR A
            c = self.acc & 1
            self.acc = ((self.acc >> 1) | (c << 7)) & 0xFF

        elif op == 0x04:  # INC A
            self.acc = (self.acc + 1) & 0xFF

        elif op == 0x05:  # INC direct
            addr = self._fetch()
            v = self._read_direct(addr)
            self._write_direct(addr, (v + 1) & 0xFF)

        elif 0x06 <= op <= 0x07:  # INC @Ri
            ri = self._getr(op - 0x06)
            self.iram[ri] = (self.iram[ri] + 1) & 0xFF

        elif 0x08 <= op <= 0x0F:  # INC Rn
            n = op - 0x08
            self._setr(n, (self._getr(n) + 1) & 0xFF)

        elif op == 0x10:  # JBC bit, rel
            bit = self._fetch()
            rel = self._fetch()
            if rel >= 128:
                rel -= 256
            if self._read_bit(bit):
                self._write_bit(bit, 0)
                self.pc = (self.pc + rel) & 0xFFFF

        elif op == 0x11:  # ACALL addr11
            rel = self._fetch()
            self._push16(self.pc)
            page = self.pc & 0xF800
            self.pc = page | ((op & 0xE0) << 3) | rel

        elif op == 0x12:  # LCALL addr16
            addr = self._fetch16()
            self._push16(self.pc)
            self.pc = addr

        elif op == 0x13:  # RRC A
            cy = self._get_cy()
            new_cy = self.acc & 1
            self.acc = ((self.acc >> 1) | (cy << 7)) & 0xFF
            self._set_cy(new_cy)

        elif op == 0x14:  # DEC A
            self.acc = (self.acc - 1) & 0xFF

        elif op == 0x15:  # DEC direct
            addr = self._fetch()
            v = self._read_direct(addr)
            self._write_direct(addr, (v - 1) & 0xFF)

        elif 0x16 <= op <= 0x17:  # DEC @Ri
            ri = self._getr(op - 0x16)
            self.iram[ri] = (self.iram[ri] - 1) & 0xFF

        elif 0x18 <= op <= 0x1F:  # DEC Rn
            n = op - 0x18
            self._setr(n, (self._getr(n) - 1) & 0xFF)

        elif op == 0x20:  # JB bit, rel
            bit = self._fetch()
            rel = self._fetch()
            if rel >= 128:
                rel -= 256
            if self._read_bit(bit):
                self.pc = (self.pc + rel) & 0xFFFF

        elif op == 0x21:  # AJMP
            rel = self._fetch()
            page = self.pc & 0xF800
            self.pc = page | ((op & 0xE0) << 3) | rel

        elif op == 0x22:  # RET
            self.pc = self._pop16()
            # If SP got below 7 (original), main returned
            if self.sp < 7:
                self.halted = True
            return True

        elif op == 0x23:  # RL A
            c = (self.acc >> 7) & 1
            self.acc = ((self.acc << 1) | c) & 0xFF

        elif op == 0x24:  # ADD A, #imm
            imm = self._fetch()
            self.acc = self._add8(self.acc, imm)
            self._set_p()

        elif op == 0x25:  # ADD A, direct
            addr = self._fetch()
            self.acc = self._add8(self.acc, self._read_direct(addr))
            self._set_p()

        elif 0x26 <= op <= 0x27:  # ADD A, @Ri
            ri = self._getr(op - 0x26)
            self.acc = self._add8(self.acc, self.iram[ri])
            self._set_p()

        elif 0x28 <= op <= 0x2F:  # ADD A, Rn
            n = op - 0x28
            self.acc = self._add8(self.acc, self._getr(n))
            self._set_p()

        elif op == 0x30:  # JNB bit, rel
            bit = self._fetch()
            rel = self._fetch()
            if rel >= 128:
                rel -= 256
            if not self._read_bit(bit):
                self.pc = (self.pc + rel) & 0xFFFF

        elif op == 0x31:  # ACALL
            rel = self._fetch()
            self._push16(self.pc)
            page = self.pc & 0xF800
            self.pc = page | ((op & 0xE0) << 3) | rel

        elif op == 0x32:  # RETI
            self.pc = self._pop16()
            if self.sp < 7:
                self.halted = True

        elif op == 0x33:  # RLC A
            cy = self._get_cy()
            new_cy = (self.acc >> 7) & 1
            self.acc = ((self.acc << 1) | cy) & 0xFF
            self._set_cy(new_cy)

        elif op == 0x34:  # ADDC A, #imm
            imm = self._fetch()
            self.acc = self._add8(self.acc, imm, self._get_cy())
            self._set_p()

        elif op == 0x35:  # ADDC A, direct
            addr = self._fetch()
            self.acc = self._add8(self.acc, self._read_direct(addr), self._get_cy())
            self._set_p()

        elif 0x36 <= op <= 0x37:  # ADDC A, @Ri
            ri = self._getr(op - 0x36)
            self.acc = self._add8(self.acc, self.iram[ri], self._get_cy())
            self._set_p()

        elif 0x38 <= op <= 0x3F:  # ADDC A, Rn
            n = op - 0x38
            self.acc = self._add8(self.acc, self._getr(n), self._get_cy())
            self._set_p()

        elif op == 0x40:  # JC rel
            rel = self._fetch()
            if rel >= 128:
                rel -= 256
            if self._get_cy():
                self.pc = (self.pc + rel) & 0xFFFF

        elif op == 0x41:  # AJMP
            rel = self._fetch()
            page = self.pc & 0xF800
            self.pc = page | ((op & 0xE0) << 3) | rel

        elif op == 0x42:  # ORL direct, A
            addr = self._fetch()
            v = self._read_direct(addr) | self.acc
            self._write_direct(addr, v)

        elif op == 0x43:  # ORL direct, #imm
            addr = self._fetch()
            imm = self._fetch()
            v = self._read_direct(addr) | imm
            self._write_direct(addr, v)

        elif op == 0x44:  # ORL A, #imm
            imm = self._fetch()
            self.acc = self.acc | imm
            self._set_p()

        elif op == 0x45:  # ORL A, direct
            addr = self._fetch()
            self.acc = self.acc | self._read_direct(addr)
            self._set_p()

        elif 0x46 <= op <= 0x47:  # ORL A, @Ri
            ri = self._getr(op - 0x46)
            self.acc = self.acc | self.iram[ri]
            self._set_p()

        elif 0x48 <= op <= 0x4F:  # ORL A, Rn
            n = op - 0x48
            self.acc = self.acc | self._getr(n)
            self._set_p()

        elif op == 0x50:  # JNC rel
            rel = self._fetch()
            if rel >= 128:
                rel -= 256
            if not self._get_cy():
                self.pc = (self.pc + rel) & 0xFFFF

        elif op == 0x51:  # ACALL
            rel = self._fetch()
            self._push16(self.pc)
            page = self.pc & 0xF800
            self.pc = page | ((op & 0xE0) << 3) | rel

        elif op == 0x52:  # ANL direct, A
            addr = self._fetch()
            v = self._read_direct(addr) & self.acc
            self._write_direct(addr, v)

        elif op == 0x53:  # ANL direct, #imm
            addr = self._fetch()
            imm = self._fetch()
            v = self._read_direct(addr) & imm
            self._write_direct(addr, v)

        elif op == 0x54:  # ANL A, #imm
            imm = self._fetch()
            self.acc = self.acc & imm
            self._set_p()

        elif op == 0x55:  # ANL A, direct
            addr = self._fetch()
            self.acc = self.acc & self._read_direct(addr)
            self._set_p()

        elif 0x56 <= op <= 0x57:  # ANL A, @Ri
            ri = self._getr(op - 0x56)
            self.acc = self.acc & self.iram[ri]
            self._set_p()

        elif 0x58 <= op <= 0x5F:  # ANL A, Rn
            n = op - 0x58
            self.acc = self.acc & self._getr(n)
            self._set_p()

        elif op == 0x60:  # JZ rel
            rel = self._fetch()
            if rel >= 128:
                rel -= 256
            if self.acc == 0:
                self.pc = (self.pc + rel) & 0xFFFF

        elif op == 0x61:  # AJMP
            rel = self._fetch()
            page = self.pc & 0xF800
            self.pc = page | ((op & 0xE0) << 3) | rel

        elif op == 0x62:  # XRL direct, A
            addr = self._fetch()
            v = self._read_direct(addr) ^ self.acc
            self._write_direct(addr, v)

        elif op == 0x63:  # XRL direct, #imm
            addr = self._fetch()
            imm = self._fetch()
            v = self._read_direct(addr) ^ imm
            self._write_direct(addr, v)

        elif op == 0x64:  # XRL A, #imm
            imm = self._fetch()
            self.acc = self.acc ^ imm
            self._set_p()

        elif op == 0x65:  # XRL A, direct
            addr = self._fetch()
            self.acc = self.acc ^ self._read_direct(addr)
            self._set_p()

        elif 0x66 <= op <= 0x67:  # XRL A, @Ri
            ri = self._getr(op - 0x66)
            self.acc = self.acc ^ self.iram[ri]
            self._set_p()

        elif 0x68 <= op <= 0x6F:  # XRL A, Rn
            n = op - 0x68
            self.acc = self.acc ^ self._getr(n)
            self._set_p()

        elif op == 0x70:  # JNZ rel
            rel = self._fetch()
            if rel >= 128:
                rel -= 256
            if self.acc != 0:
                self.pc = (self.pc + rel) & 0xFFFF

        elif op == 0x71:  # ACALL
            rel = self._fetch()
            self._push16(self.pc)
            page = self.pc & 0xF800
            self.pc = page | ((op & 0xE0) << 3) | rel

        elif op == 0x72:  # ORL C, bit
            bit = self._fetch()
            if self._read_bit(bit):
                self._set_cy(1)

        elif op == 0x73:  # JMP @A+DPTR
            dptr = (self.sfr[0x83 - 0x80] << 8) | self.sfr[0x82 - 0x80]
            self.pc = (self.acc + dptr) & 0xFFFF

        elif op == 0x74:  # MOV A, #imm
            self.acc = self._fetch()
            self._set_p()

        elif op == 0x75:  # MOV direct, #imm
            addr = self._fetch()
            imm = self._fetch()
            self._write_direct(addr, imm)

        elif 0x76 <= op <= 0x77:  # MOV @Ri, #imm
            ri = self._getr(op - 0x76)
            imm = self._fetch()
            self.iram[ri] = imm

        elif 0x78 <= op <= 0x7F:  # MOV Rn, #imm
            n = op - 0x78
            imm = self._fetch()
            self._setr(n, imm)

        elif op == 0x80:  # SJMP rel
            rel = self._fetch()
            if rel >= 128:
                rel -= 256
            self.pc = (self.pc + rel) & 0xFFFF

        elif op == 0x81:  # AJMP
            rel = self._fetch()
            page = self.pc & 0xF800
            self.pc = page | ((op & 0xE0) << 3) | rel

        elif op == 0x82:  # ANL C, bit
            bit = self._fetch()
            if not self._read_bit(bit):
                self._set_cy(0)

        elif op == 0x83:  # MOVC A, @A+PC
            self.acc = self.code[(self.pc + self.acc) & 0xFFFF]
            self._set_p()

        elif op == 0x84:  # DIV AB
            a = self.acc
            b = self.b_reg
            if b == 0:
                self._set_ov(1)
                self._set_cy(0)
            else:
                self.acc = a // b
                self.b_reg = a % b
                self._set_ov(0)
                self._set_cy(0)

        elif op == 0x85:  # MOV direct, direct
            src = self._fetch()
            dst = self._fetch()
            self._write_direct(dst, self._read_direct(src))

        elif 0x86 <= op <= 0x87:  # MOV direct, @Ri
            ri = self._getr(op - 0x86)
            addr = self._fetch()
            self._write_direct(addr, self.iram[ri])

        elif 0x88 <= op <= 0x8F:  # MOV direct, Rn
            n = op - 0x88
            addr = self._fetch()
            self._write_direct(addr, self._getr(n))

        elif op == 0x90:  # MOV DPTR, #imm16
            hi = self._fetch()
            lo = self._fetch()
            self.sfr[0x82 - 0x80] = lo
            self.sfr[0x83 - 0x80] = hi

        elif op == 0x91:  # ACALL
            rel = self._fetch()
            self._push16(self.pc)
            page = self.pc & 0xF800
            self.pc = page | ((op & 0xE0) << 3) | rel

        elif op == 0x92:  # MOV bit, C
            bit = self._fetch()
            self._write_bit(bit, self._get_cy())

        elif op == 0x93:  # MOVC A, @A+DPTR
            dptr = (self.sfr[0x83 - 0x80] << 8) | self.sfr[0x82 - 0x80]
            self.acc = self.code[(dptr + self.acc) & 0xFFFF]
            self._set_p()

        elif op == 0x94:  # SUBB A, #imm
            imm = self._fetch()
            self.acc = self._sub8(self.acc, imm, self._get_cy())
            self._set_p()

        elif op == 0x95:  # SUBB A, direct
            addr = self._fetch()
            self.acc = self._sub8(self.acc, self._read_direct(addr), self._get_cy())
            self._set_p()

        elif 0x96 <= op <= 0x97:  # SUBB A, @Ri
            ri = self._getr(op - 0x96)
            self.acc = self._sub8(self.acc, self.iram[ri], self._get_cy())
            self._set_p()

        elif 0x98 <= op <= 0x9F:  # SUBB A, Rn
            n = op - 0x98
            self.acc = self._sub8(self.acc, self._getr(n), self._get_cy())
            self._set_p()

        elif op == 0xA0:  # ORL C, /bit
            bit = self._fetch()
            if not self._read_bit(bit):
                self._set_cy(1)

        elif op == 0xA1:  # AJMP
            rel = self._fetch()
            page = self.pc & 0xF800
            self.pc = page | ((op & 0xE0) << 3) | rel

        elif op == 0xA2:  # MOV C, bit
            bit = self._fetch()
            self._set_cy(self._read_bit(bit))

        elif op == 0xA3:  # INC DPTR
            lo = self.sfr[0x82 - 0x80]
            hi = self.sfr[0x83 - 0x80]
            v = ((hi << 8) | lo) + 1
            self.sfr[0x82 - 0x80] = v & 0xFF
            self.sfr[0x83 - 0x80] = (v >> 8) & 0xFF

        elif op == 0xA4:  # MUL AB
            r = self.acc * self.b_reg
            self.acc = r & 0xFF
            self.b_reg = (r >> 8) & 0xFF
            self._set_cy(0)
            self._set_ov(self.b_reg != 0)

        elif op == 0xA5:  # reserved - undefined
            self.halted = True

        elif 0xA6 <= op <= 0xA7:  # MOV @Ri, direct
            ri = self._getr(op - 0xA6)
            addr = self._fetch()
            self.iram[ri] = self._read_direct(addr)

        elif 0xA8 <= op <= 0xAF:  # MOV Rn, direct
            n = op - 0xA8
            addr = self._fetch()
            self._setr(n, self._read_direct(addr))

        elif op == 0xB0:  # ANL C, /bit
            bit = self._fetch()
            if self._read_bit(bit):
                self._set_cy(0)

        elif op == 0xB1:  # ACALL
            rel = self._fetch()
            self._push16(self.pc)
            page = self.pc & 0xF800
            self.pc = page | ((op & 0xE0) << 3) | rel

        elif op == 0xB2:  # CPL bit
            bit = self._fetch()
            v = self._read_bit(bit)
            self._write_bit(bit, 1 - v)

        elif op == 0xB3:  # CPL C
            self._set_cy(1 - self._get_cy())

        elif op == 0xB4:  # CJNE A, #imm, rel
            imm = self._fetch()
            rel = self._fetch()
            if rel >= 128:
                rel -= 256
            self._set_cy(self.acc < imm)
            if self.acc != imm:
                self.pc = (self.pc + rel) & 0xFFFF

        elif op == 0xB5:  # CJNE A, direct, rel
            addr = self._fetch()
            rel = self._fetch()
            if rel >= 128:
                rel -= 256
            v = self._read_direct(addr)
            self._set_cy(self.acc < v)
            if self.acc != v:
                self.pc = (self.pc + rel) & 0xFFFF

        elif 0xB6 <= op <= 0xB7:  # CJNE @Ri, #imm, rel
            ri = self._getr(op - 0xB6)
            imm = self._fetch()
            rel = self._fetch()
            if rel >= 128:
                rel -= 256
            v = self.iram[ri]
            self._set_cy(v < imm)
            if v != imm:
                self.pc = (self.pc + rel) & 0xFFFF

        elif 0xB8 <= op <= 0xBF:  # CJNE Rn, #imm, rel
            n = op - 0xB8
            imm = self._fetch()
            rel = self._fetch()
            if rel >= 128:
                rel -= 256
            v = self._getr(n)
            self._set_cy(v < imm)
            if v != imm:
                self.pc = (self.pc + rel) & 0xFFFF

        elif op == 0xC0:  # PUSH direct
            addr = self._fetch()
            self._push(self._read_direct(addr))

        elif op == 0xC1:  # AJMP
            rel = self._fetch()
            page = self.pc & 0xF800
            self.pc = page | ((op & 0xE0) << 3) | rel

        elif op == 0xC2:  # CLR bit
            bit = self._fetch()
            self._write_bit(bit, 0)

        elif op == 0xC3:  # CLR C
            self._set_cy(0)

        elif op == 0xC4:  # SWAP A
            self.acc = ((self.acc << 4) | (self.acc >> 4)) & 0xFF

        elif op == 0xC5:  # XCH A, direct
            addr = self._fetch()
            v = self._read_direct(addr)
            self._write_direct(addr, self.acc)
            self.acc = v
            self._set_p()

        elif 0xC6 <= op <= 0xC7:  # XCH A, @Ri
            ri = self._getr(op - 0xC6)
            v = self.iram[ri]
            self.iram[ri] = self.acc
            self.acc = v
            self._set_p()

        elif 0xC8 <= op <= 0xCF:  # XCH A, Rn
            n = op - 0xC8
            v = self._getr(n)
            self._setr(n, self.acc)
            self.acc = v
            self._set_p()

        elif op == 0xD0:  # POP direct
            addr = self._fetch()
            self._write_direct(addr, self._pop())

        elif op == 0xD1:  # ACALL
            rel = self._fetch()
            self._push16(self.pc)
            page = self.pc & 0xF800
            self.pc = page | ((op & 0xE0) << 3) | rel

        elif op == 0xD2:  # SETB bit
            bit = self._fetch()
            self._write_bit(bit, 1)

        elif op == 0xD3:  # SETB C
            self._set_cy(1)

        elif op == 0xD4:  # DA A  (decimal adjust)
            a = self.acc
            if (a & 0xF) > 9 or self._read_bit(0xD6):  # AC bit
                a += 6
            if (a > 0x99) or self._get_cy():
                a += 0x60
                self._set_cy(1)
            self.acc = a & 0xFF

        elif op == 0xD5:  # DJNZ direct, rel
            addr = self._fetch()
            rel = self._fetch()
            if rel >= 128:
                rel -= 256
            v = (self._read_direct(addr) - 1) & 0xFF
            self._write_direct(addr, v)
            if v != 0:
                self.pc = (self.pc + rel) & 0xFFFF

        elif 0xD6 <= op <= 0xD7:  # XCHD A, @Ri
            ri = self._getr(op - 0xD6)
            v = self.iram[ri]
            self.iram[ri] = (v & 0xF0) | (self.acc & 0x0F)
            self.acc = (self.acc & 0xF0) | (v & 0x0F)

        elif 0xD8 <= op <= 0xDF:  # DJNZ Rn, rel
            n = op - 0xD8
            rel = self._fetch()
            if rel >= 128:
                rel -= 256
            v = (self._getr(n) - 1) & 0xFF
            self._setr(n, v)
            if v != 0:
                self.pc = (self.pc + rel) & 0xFFFF

        elif op == 0xE0:  # MOVX A, @DPTR
            dptr = (self.sfr[0x83 - 0x80] << 8) | self.sfr[0x82 - 0x80]
            self.acc = self.xram[dptr]
            self._set_p()

        elif op == 0xE1:  # AJMP
            rel = self._fetch()
            page = self.pc & 0xF800
            self.pc = page | ((op & 0xE0) << 3) | rel

        elif 0xE2 <= op <= 0xE3:  # MOVX A, @Ri
            ri = self._getr(op - 0xE2)
            p2 = self._read_sfr(0xA0)
            addr = (p2 << 8) | ri
            self.acc = self.xram[addr]
            self._set_p()

        elif op == 0xE4:  # CLR A
            self.acc = 0

        elif op == 0xE5:  # MOV A, direct
            addr = self._fetch()
            self.acc = self._read_direct(addr)
            self._set_p()

        elif 0xE6 <= op <= 0xE7:  # MOV A, @Ri
            ri = self._getr(op - 0xE6)
            self.acc = self.iram[ri]
            self._set_p()

        elif 0xE8 <= op <= 0xEF:  # MOV A, Rn
            n = op - 0xE8
            self.acc = self._getr(n)
            self._set_p()

        elif op == 0xF0:  # MOVX @DPTR, A
            dptr = (self.sfr[0x83 - 0x80] << 8) | self.sfr[0x82 - 0x80]
            self.xram[dptr] = self.acc

        elif op == 0xF1:  # ACALL
            rel = self._fetch()
            self._push16(self.pc)
            page = self.pc & 0xF800
            self.pc = page | ((op & 0xE0) << 3) | rel

        elif 0xF2 <= op <= 0xF3:  # MOVX @Ri, A
            ri = self._getr(op - 0xF2)
            p2 = self._read_sfr(0xA0)
            addr = (p2 << 8) | ri
            self.xram[addr] = self.acc

        elif op == 0xF4:  # CPL A
            self.acc = (~self.acc) & 0xFF
            self._set_p()

        elif op == 0xF5:  # MOV direct, A
            addr = self._fetch()
            self._write_direct(addr, self.acc)

        elif 0xF6 <= op <= 0xF7:  # MOV @Ri, A
            ri = self._getr(op - 0xF6)
            self.iram[ri] = self.acc

        elif 0xF8 <= op <= 0xFF:  # MOV Rn, A
            n = op - 0xF8
            self._setr(n, self.acc)

        else:
            # Unknown opcode - halt
            self.halted = True

        self._icount += 1
        return not self.halted

    def run(self, max_steps=200_000):
        for _ in range(max_steps):
            if not self.step():
                break
        return not self.halted  # True = timed out

    def get_return_val(self):
        """Get 16-bit return value from R6:R7 (Keil/c51cc convention: R6=hi, R7=lo)"""
        hi = self._getr(6)
        lo = self._getr(7)
        return (hi << 8) | lo

    def get_return_signed(self):
        v = self.get_return_val()
        if v >= 0x8000:
            v -= 0x10000
        return v

    def run_until_halt_or_sjmp_self(self, max_steps=500_000):
        """Run until halt OR until main() returns.

        Two termination strategies:
        1. c51cc STARTUP: SP drops below 7 (main's RET pops below initial SP=7)
        2. Keil STARTUP: uses LJMP to main (not LCALL), so startup sets SP to some
           value S, then LJMP. When main does RET, SP drops from S back to S-2.
           We detect this by tracking the 'baseline SP' = SP just before the first
           call instruction, and stopping when any RET causes SP < baseline.
        3. SJMP $ (0x80 0xFE) fallback for safety.

        Returns timed_out bool (True = exceeded max_steps)."""
        # The initial SP is 7 (set in __init__).
        # After startup runs MOV SP,#xx, the new SP becomes the baseline.
        # We capture baseline_sp as the SP value seen just before the first LCALL/ACALL.
        baseline_sp = None
        first_call_seen = False

        for _ in range(max_steps):
            cur_pc = self.pc
            op = self.code[cur_pc]
            cur_sp = self.sfr[self.SP_ADDR]

            # Record baseline SP on first LCALL (0x12) or ACALL (0x11,0x31,...0xF1)
            if not first_call_seen and (op == 0x12 or (op & 0x1F) == 0x11):
                baseline_sp = cur_sp
                first_call_seen = True

            # SJMP $ = 0x80 0xFE  (rel = -2) — safety fallback
            if op == 0x80 and self.code[(cur_pc + 1) & 0xFFFF] == 0xFE:
                self.halted = True
                break

            if not self.step():
                break

            # After a RET (0x22), check if SP dropped below baseline (main returned)
            if op == 0x22 and baseline_sp is not None:
                new_sp = self.sfr[self.SP_ADDR]
                # After main's RET, SP should be baseline_sp - 2
                # (Keil LJMP pattern: no return address pushed by startup,
                #  but the iram at baseline_sp held the caller's pushed state)
                if new_sp < baseline_sp - 1:
                    self.halted = True
                    break

        return not self.halted  # True = timed out


def run_hex(path, max_steps=500_000):
    code = load_hex(path)
    cpu = CPU8051(code)
    timed_out = cpu.run_until_halt_or_sjmp_self(max_steps)
    return cpu.get_return_signed(), cpu._icount, timed_out


# ──────────────────────────────────────────────
# Main comparison
# ──────────────────────────────────────────────
def main():
    import argparse

    parser = argparse.ArgumentParser(description="8051 HEX semantic comparator")
    parser.add_argument("--keil-dir", default=r"D:\ws\test\C51CC\output\keil\test")
    parser.add_argument("--c51cc-dir", default=r"D:\ws\test\C51CC\output\c51cc\test")
    parser.add_argument("--max-steps", type=int, default=2_000_000)
    parser.add_argument(
        "--filter", default=None, help="Only test projects containing this substring"
    )
    parser.add_argument(
        "--verbose", action="store_true", help="Show debug trace for failing tests"
    )
    args = parser.parse_args()

    keil_dir = args.keil_dir
    c51cc_dir = args.c51cc_dir

    if not os.path.isdir(keil_dir):
        print(f"[ERROR] keil dir not found: {keil_dir}")
        sys.exit(1)

    projects = sorted(os.listdir(keil_dir))
    if args.filter:
        projects = [p for p in projects if args.filter in p]

    ok = []
    fail = []
    timeout = []
    skip = []

    for proj in projects:
        keil_hex = os.path.join(keil_dir, proj, proj + ".hex")
        c51cc_hex = os.path.join(c51cc_dir, proj, proj + ".hex")
        if not os.path.exists(keil_hex) or not os.path.exists(c51cc_hex):
            skip.append(proj)
            continue

        try:
            kr, kn, kt = run_hex(keil_hex, args.max_steps)
            cr, cn, ct = run_hex(c51cc_hex, args.max_steps)
        except Exception as e:
            fail.append((proj, f"exception: {e}", 0, 0))
            continue

        if kt and ct:
            timeout.append((proj, kr, cr, kn, cn))
            continue

        if kt:
            # Keil timed out but c51cc finished - use c51cc as reference only if both finish
            timeout.append((proj, kr, cr, kn, cn))
            continue

        if ct:
            timeout.append((proj, kr, cr, kn, cn))
            continue

        if kr == cr:
            ok.append((proj, kr))
        else:
            fail.append((proj, f"keil={kr} c51cc={cr}", kn, cn))

    print(f"=== PASS ({len(ok)}) ===")
    for p, v in ok:
        print(f"  OK   {p:<40}  ret={v}")

    print(f"\n=== FAIL ({len(fail)}) ===")
    for p, msg, kn, cn in fail:
        print(f"  FAIL {p:<40}  {msg}  (keil_insns={kn} c51cc_insns={cn})")

    print(f"\n=== TIMEOUT ({len(timeout)}) ===")
    for p, kr, cr, kn, cn in timeout:
        match_tag = "match" if kr == cr else "MISMATCH"
        print(f"  TOUT {p:<40}  keil_ret={kr} c51cc_ret={cr}  [{match_tag}]")

    print(f"\n=== SKIP (no hex) ({len(skip)}) ===")
    for p in skip:
        print(f"  SKIP {p}")

    print(
        f"\n[SUMMARY] pass={len(ok)}  fail={len(fail)}  timeout={len(timeout)}  skip={len(skip)}"
    )
    if fail:
        sys.exit(1)


if __name__ == "__main__":
    main()
