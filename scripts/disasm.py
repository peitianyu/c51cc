"""Simple 8051 disassembler for debugging"""
from sim8051 import load_hex

OPCODES_1 = {
    0x00: "NOP", 0x22: "RET", 0x32: "RETI", 0xC3: "CLR C", 0xD3: "SETB C",
    0xE4: "CLR A", 0xF4: "CPL A", 0x03: "RR A", 0x13: "RRC A",
    0x23: "RL A", 0x33: "RLC A", 0x84: "DIV AB", 0xA4: "MUL AB",
    0xC4: "SWAP A",
}

def dis8051(mem, start, end):
    pc = start
    while pc < end:
        op = mem[pc]
        addr = pc
        
        # Rn instructions
        if op & 0xF8 == 0xE8:  # MOV A, Rn
            r = op & 7
            print(f"  {addr:04X}: {op:02X}       MOV A, R{r}")
            pc += 1
        elif op & 0xF8 == 0xF8:  # MOV Rn, A
            r = op & 7
            print(f"  {addr:04X}: {op:02X}       MOV R{r}, A")
            pc += 1
        elif op & 0xF8 == 0x28:  # ADD A, Rn
            r = op & 7
            print(f"  {addr:04X}: {op:02X}       ADD A, R{r}")
            pc += 1
        elif op & 0xF8 == 0x38:  # ADDC A, Rn
            r = op & 7
            print(f"  {addr:04X}: {op:02X}       ADDC A, R{r}")
            pc += 1
        elif op & 0xF8 == 0x78:  # MOV Rn, #imm
            r = op & 7
            imm = mem[pc+1]
            print(f"  {addr:04X}: {op:02X} {imm:02X}    MOV R{r}, #{imm}")
            pc += 2
        elif op & 0xF8 == 0xA8:  # MOV Rn, direct
            r = op & 7
            d = mem[pc+1]
            print(f"  {addr:04X}: {op:02X} {d:02X}    MOV R{r}, {d:02X}h")
            pc += 2
        elif op & 0xF8 == 0x88:  # MOV direct, Rn
            r = op & 7
            d = mem[pc+1]
            print(f"  {addr:04X}: {op:02X} {d:02X}    MOV {d:02X}h, R{r}")
            pc += 2
        elif op & 0xF8 == 0xD8:  # DJNZ Rn, rel
            r = op & 7
            rel = mem[pc+1]
            if rel >= 128: rel -= 256
            target = pc + 2 + rel
            print(f"  {addr:04X}: {op:02X} {mem[pc+1]:02X}    DJNZ R{r}, {target:04X}")
            pc += 2
        elif op == 0x74:  # MOV A, #imm
            imm = mem[pc+1]
            print(f"  {addr:04X}: 74 {imm:02X}    MOV A, #{imm}")
            pc += 2
        elif op == 0x75:  # MOV direct, #imm
            d = mem[pc+1]
            imm = mem[pc+2]
            print(f"  {addr:04X}: 75 {d:02X} {imm:02X} MOV {d:02X}h, #{imm}")
            pc += 3
        elif op == 0x24:  # ADD A, #imm
            imm = mem[pc+1]
            print(f"  {addr:04X}: 24 {imm:02X}    ADD A, #{imm}")
            pc += 2
        elif op == 0x34:  # ADDC A, #imm
            imm = mem[pc+1]
            print(f"  {addr:04X}: 34 {imm:02X}    ADDC A, #{imm}")
            pc += 2
        elif op == 0x94:  # SUBB A, #imm
            imm = mem[pc+1]
            print(f"  {addr:04X}: 94 {imm:02X}    SUBB A, #{imm}")
            pc += 2
        elif op == 0x60:  # JZ rel
            rel = mem[pc+1]
            if rel >= 128: rel -= 256
            target = pc + 2 + rel
            print(f"  {addr:04X}: 60 {mem[pc+1]:02X}    JZ {target:04X}")
            pc += 2
        elif op == 0x70:  # JNZ rel
            rel = mem[pc+1]
            if rel >= 128: rel -= 256
            target = pc + 2 + rel
            print(f"  {addr:04X}: 70 {mem[pc+1]:02X}    JNZ {target:04X}")
            pc += 2
        elif op == 0x80:  # SJMP rel
            rel = mem[pc+1]
            if rel >= 128: rel -= 256
            target = pc + 2 + rel
            print(f"  {addr:04X}: 80 {mem[pc+1]:02X}    SJMP {target:04X}")
            pc += 2
        elif op == 0x02:  # LJMP addr16
            hi = mem[pc+1]
            lo = mem[pc+2]
            target = (hi << 8) | lo
            print(f"  {addr:04X}: 02 {hi:02X} {lo:02X} LJMP {target:04X}")
            pc += 3
        elif op == 0x12:  # LCALL addr16
            hi = mem[pc+1]
            lo = mem[pc+2]
            target = (hi << 8) | lo
            print(f"  {addr:04X}: 12 {hi:02X} {lo:02X} LCALL {target:04X}")
            pc += 3
        elif op == 0xF6:  # MOV @R0, A
            print(f"  {addr:04X}: F6       MOV @R0, A")
            pc += 1
        elif op == 0xF7:  # MOV @R1, A
            print(f"  {addr:04X}: F7       MOV @R1, A")
            pc += 1
        elif op == 0x64:  # XRL A, #imm
            imm = mem[pc+1]
            print(f"  {addr:04X}: 64 {imm:02X}    XRL A, #{imm}")
            pc += 2
        elif op == 0x40:  # JC rel
            rel = mem[pc+1]
            if rel >= 128: rel -= 256
            target = pc + 2 + rel
            print(f"  {addr:04X}: 40 {mem[pc+1]:02X}    JC {target:04X}")
            pc += 2
        elif op == 0x50:  # JNC rel
            rel = mem[pc+1]
            if rel >= 128: rel -= 256
            target = pc + 2 + rel
            print(f"  {addr:04X}: 50 {mem[pc+1]:02X}    JNC {target:04X}")
            pc += 2
        elif op & 0xF8 == 0x08:  # INC Rn
            r = op & 7
            print(f"  {addr:04X}: {op:02X}       INC R{r}")
            pc += 1
        elif op & 0xF8 == 0x18:  # DEC Rn
            r = op & 7
            print(f"  {addr:04X}: {op:02X}       DEC R{r}")
            pc += 1
        elif op == 0x04:  # INC A
            print(f"  {addr:04X}: 04       INC A")
            pc += 1
        elif op == 0x14:  # DEC A
            print(f"  {addr:04X}: 14       DEC A")
            pc += 1
        elif op in OPCODES_1:
            print(f"  {addr:04X}: {op:02X}       {OPCODES_1[op]}")
            pc += 1
        elif op & 0xF8 == 0xC8:  # XCH A, Rn
            r = op & 7
            print(f"  {addr:04X}: {op:02X}       XCH A, R{r}")
            pc += 1
        elif op == 0x8F:  # MOV direct, R7 (used for args)
            d = mem[pc+1]
            print(f"  {addr:04X}: 8F {d:02X}    MOV {d:02X}h, R7")
            pc += 2
        elif op == 0x8E:  # MOV direct, R6
            d = mem[pc+1]
            print(f"  {addr:04X}: 8E {d:02X}    MOV {d:02X}h, R6")
            pc += 2
        elif op == 0xEF:  # MOV A, R7
            print(f"  {addr:04X}: EF       MOV A, R7")
            pc += 1
        elif op == 0xEE:  # MOV A, R6
            print(f"  {addr:04X}: EE       MOV A, R6")
            pc += 1
        elif op == 0xFF:  # MOV R7, A
            print(f"  {addr:04X}: FF       MOV R7, A")
            pc += 1
        elif op == 0xFE:  # MOV R6, A
            print(f"  {addr:04X}: FE       MOV R6, A")
            pc += 1
        elif op == 0xFD:  # MOV R5, A
            print(f"  {addr:04X}: FD       MOV R5, A")
            pc += 1
        elif op == 0xFC:  # MOV R4, A
            print(f"  {addr:04X}: FC       MOV R4, A")
            pc += 1
        elif op == 0xFB:  # MOV R3, A
            print(f"  {addr:04X}: FB       MOV R3, A")
            pc += 1
        elif op == 0xFA:  # MOV R2, A
            print(f"  {addr:04X}: FA       MOV R2, A")
            pc += 1
        elif op == 0xF9:  # MOV R1, A
            print(f"  {addr:04X}: F9       MOV R1, A")
            pc += 1
        elif op == 0xF8:  # MOV R0, A
            print(f"  {addr:04X}: F8       MOV R0, A")
            pc += 1
        elif op == 0x9F:  # SUBB A, R7
            print(f"  {addr:04X}: 9F       SUBB A, R7")
            pc += 1
        elif op == 0x9E:  # SUBB A, R6
            print(f"  {addr:04X}: 9E       SUBB A, R6")
            pc += 1
        else:
            print(f"  {addr:04X}: {op:02X}       ???")
            pc += 1

import sys
hex_path = sys.argv[1]
start = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0
end = int(sys.argv[3], 16) if len(sys.argv) > 3 else start + 64
mem = load_hex(hex_path)
dis8051(mem, start, end)
