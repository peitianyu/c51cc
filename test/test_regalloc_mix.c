static int mix_call(int a, int b, int c, int d, int e, int f) {
    return a + b + c + d + e + f;
}

int reg_mix(int a) {
    int x1 = a + 1;
    int x2 = x1 + 2;
    int x3 = x2 + 3;
    int x4 = x3 + 4;
    int x5 = x4 + 5;
    int x6 = x5 + 6;
    int x7 = x6 + 7;
    int x8 = x7 + 8;
    int m1 = (x1 ^ x8) + (x2 & x7);
    int m2 = (x3 | x6) - (x4 ^ x5);
    int b1 = m1 == m2;
    int b2 = m1 != x4;
    int b3 = x2 < x7;
    int b4 = x8 >= x3;
    int r1 = mix_call(x1, x2, x3, x4, x5, x6);
    int r2 = mix_call(x3, x4, x5, x6, x7, x8);
    return r1 + r2 + m1 + m2 + b1 + b2 + b3 + b4 + x7 + x8;
}
