import subprocess, glob, os, re, sys
sys.path.insert(0, 'scripts')
from sim8051 import load_hex, CPU8051
CC = sys.argv[1] if len(sys.argv) > 1 else 'scripts/c51cc_clang'
passed = failed = 0
fails = []
for f in sorted(glob.glob('test/suite/*.c')):
    name = os.path.basename(f)
    txt = open(f, encoding='utf-8', errors='replace').read()
    r = subprocess.run([CC, '-hex', f], capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        fails.append((name, 'compile')); failed += 1; continue
    open('out.hex','w').write(r.stdout)
    cpu = CPU8051(load_hex('out.hex'))
    to = cpu.run_until_halt_or_sjmp_self(2000000)
    if to:
        fails.append((name, 'hang')); failed += 1; continue
    v = (cpu._getr(6)<<8)|cpu._getr(7)
    m = re.search(r'return\s+(-?\d+)\s*;', txt)
    exp = int(m.group(1)) if m else None
    if exp is not None and v != (exp & 0xFFFF):
        fails.append((name, f'ret={v} expect={exp}')); failed += 1; continue
    passed += 1
print(f"suite({os.path.basename(CC)}): PASS {passed} / FAIL {failed}")
for n, w in fails: print("  ", n, w)
