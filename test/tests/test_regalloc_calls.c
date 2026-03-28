// Register allocation test for calling convention pressure (many args)

int callee_many_args(int a, int b, int c, int d, int e, int f) {
    return a + b + c + d + e + f;
}

int reg_calls(void) {
    int r1 = 1, r2 = 2, r3 = 3, r4 = 4, r5 = 5, r6 = 6, r7 = 7, r8 = 8;
    int s = 0;
    s += callee_many_args(r1, r2, r3, r4, r5, r6);
    s += callee_many_args(r3, r4, r5, r6, r7, r8);
    s += callee_many_args(r8, r7, r6, r5, r4, r3);
    // keep values live across calls
    s += r1 + r2 + r3 + r4 + r5 + r6 + r7 + r8;
    return s;
}
