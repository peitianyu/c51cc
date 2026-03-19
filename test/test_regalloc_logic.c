static int mix_logic_sink(int a, int b, int c, int d, int e, int f) {
    return a + b - c + d - e + f;
}

int reg_logic(int a, int b, int c, int d) {
    int v1 = (a + 3) ^ (b + 5);
    int v2 = (b + 7) | (c + 9);
    int v3 = (c + 11) & (d + 13);
    int v4 = ~(a + d);
    int v5 = v1 + v2;
    int v6 = v3 - v4;
    int c1 = v1 == v2;
    int c2 = v3 != v4;
    int c3 = v5 < v6;
    int c4 = v6 >= v1;
    int c5 = !v2;
    int c6 = !v6;
    int v7 = (v5 ^ v6) + (v1 & v3);
    int v8 = (v2 | v4) - (v3 ^ v5);
    return mix_logic_sink(c1 + c2, c3 + c4, c5 + c6, v1, v7, v8)
         + v2 + v3 + v4 + v5 + v6;
}
