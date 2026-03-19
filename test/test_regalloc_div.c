int reg_div(int a, int b, int c) {
    int x1 = a + 17;
    int x2 = b + 9;
    int x3 = c + 5;
    int x4 = x1 * 3 + x2;
    int x5 = x2 * 5 + x3;
    int q1 = x4 / (x3 | 1);
    int r1 = x5 % (x1 | 1);
    int q2 = (x4 + x5) / ((x2 & 7) + 1);
    int r2 = (x5 - x3) % ((x1 & 3) + 1);
    char c1 = (char)q1;
    int z1 = (int)c1;
    return x1 + x2 + x3 + x4 + x5 + q1 + r1 + q2 + r2 + z1;
}
