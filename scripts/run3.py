import sys, os
sys.path.insert(0, "scripts")
import run_sdcc_tests as R
os.makedirs(R.WORK, exist_ok=True)
env = dict(os.environ); env["SDCC_HOME"] = R.SDCC_HOME
for name in ["bug-1292721","bug-2175","bug-2582"]:
    fn = os.path.join(R.TEST_DIR, name + ".c")
    txt = open(fn, encoding="utf-8", errors="replace").read()
    tests = R.extract_tests(fn)
    wf = os.path.join(R.WORK, f"{name}.wrap.c")
    open(wf, "w").write(R.gen_wrapper(tests))
    cr = R.run([R.C51CC, "-hex", "-I"+R.STUB_INC, fn, wf])
    if cr is None or cr.returncode != 0:
        print(f"== {name}: c51cc_err: {(cr.stderr or '')[:200] if cr else 'timeout'}"); continue
    open(os.path.join(R.WORK, f"{name}.c51cc.hex"), "w").write(cr.stdout)
    sr1 = R.run([R.SDCC, "-c", "-mmcs51", "--model-small", "-I"+R.STUB_INC, fn, "-o", os.path.join(R.WORK, f"{name}.test.rel")], env=env)
    sr2 = R.run([R.SDCC, "-c", "-mmcs51", "--model-small", "-I"+R.STUB_INC, wf, "-o", os.path.join(R.WORK, f"{name}.wrap.rel")], env=env)
    sr3 = R.run([R.SDCC, "-mmcs51", "--model-small", os.path.join(R.WORK, f"{name}.test.rel"), os.path.join(R.WORK, f"{name}.wrap.rel"), "-o", os.path.join(R.WORK, f"{name}.ihx")], env=env)
    if sr1.returncode or sr2.returncode or sr3.returncode:
        print(f"== {name}: sdcc_err {(sr1.stderr or sr2.stderr or sr3.stderr or b'')[-200:]}"); continue
    cval, cto = R.sim_ret(os.path.join(R.WORK, f"{name}.c51cc.hex"))
    sval, sto = R.sim_ret(os.path.join(R.WORK, f"{name}.ihx"), use_dptr=True)
    print(f"== {name}: c51cc={cval}(to={cto}) sdcc={sval}(to={sto}) {'PASS' if cval==sval and not (cto or sto) else 'DIFF'}")
