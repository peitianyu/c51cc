/* 55_register_pressure: 寄存器压力测试 (多个活跃变量) */

int main(void) {
    int a = 1, b = 2, c = 3, d = 4;
    int e = 5, f = 6;
    int r;

    /* 所有变量同时活跃 */
    r = a + b + c + d + e + f;         /* 21 */
    r = r + (a * b) + (c * d) + (e * f); /* 21 + 2 + 12 + 30 = 65 */
    r = r + (a & d) + (b | e) + (c ^ f); /* 65 + 0 + 7 + 5 = 77 */

    return r;  /* 77 */
}
