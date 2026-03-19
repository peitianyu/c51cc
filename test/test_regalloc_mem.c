static int mem_data[] = { 3, 5, 8, 13, 21, 34, 55, 89, 144, 233 };

int reg_mem(int x, int y) {
    int* p = mem_data;
    int a0 = p[0] + x;
    int a1 = p[1] + y;
    int a2 = p[2] + a0;
    int a3 = p[3] + a1;
    int a4 = p[4] + a2;
    int a5 = p[5] + a3;
    int a6 = p[(x + 1) & 3] + a4;
    int a7 = p[(y + 2) & 3] + a5;
    int c1 = a2 == a6;
    int c2 = a3 != a7;
    int c3 = a4 < a5;
    int c4 = a7 >= a1;
    return a0 + a1 + a2 + a3 + a4 + a5 + a6 + a7 + c1 + c2 + c3 + c4;
}
