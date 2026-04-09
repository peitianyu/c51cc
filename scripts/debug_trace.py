"""Debug trace script for individual tests"""
import sys
from sim8051 import load_hex, CPU8051

def trace_test(hex_path, skip_startup=254, max_steps=300):
    mem = load_hex(hex_path)
    cpu = CPU8051(mem)
    for i in range(max_steps):
        if cpu.halted:
            print(f'HALTED at step {i}')
            break
        pc = cpu.pc
        op = mem[pc]
        r = [cpu._getr(j) for j in range(8)]
        a = cpu.acc
        sp = cpu.sfr[cpu.SP_ADDR]
        iram_28 = cpu.iram[0x28] if 0x28 < 256 else 0
        iram_29 = cpu.iram[0x29] if 0x29 < 256 else 0
        if i >= skip_startup:
            print(f'  [{i:3d}] PC=0x{pc:04X} OP=0x{op:02X} A={a:3d} '
                  f'R0-7=[{" ".join(f"{x:02X}" for x in r)}] '
                  f'SP={sp:02X} IRAM28={iram_28:02X} IRAM29={iram_29:02X}')
        cpu.step()
    r6 = cpu._getr(6)
    r7 = cpu._getr(7)
    val = (r6 << 8) | r7
    if val >= 32768:
        val -= 65536
    print(f'Final: R6={r6:02X} R7={r7:02X} = {val}')

if __name__ == '__main__':
    hex_path = sys.argv[1]
    skip = int(sys.argv[2]) if len(sys.argv) > 2 else 254
    max_s = int(sys.argv[3]) if len(sys.argv) > 3 else 300
    trace_test(hex_path, skip, max_s)
