static int sel_pick(int c, int x, int y) {
    return c ? x : y;
}

int reg_select(int a, int b, int c) {
    int v1 = a + 1;
    int v2 = b + 2;
    int v3 = c + 3;
    int v4 = v1 + v2;
    int v5 = v2 + v3;
    int v6 = v4 - v3;
    int c1 = v4 < v5;
    int c2 = v6 != v1;
    int s1 = sel_pick(c1, v4, v5);
    int s2 = sel_pick(c2, v6, v2);
    int s3 = c1 ? (s1 + v1) : (s2 + v3);
    int s4 = c2 ? (s2 - v2) : (s1 - v1);
    return v1 + v2 + v3 + v4 + v5 + v6 + c1 + c2 + s1 + s2 + s3 + s4;
}
