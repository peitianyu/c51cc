/* 22_func_multi_param: 多参数函数 (测试参数传递) */

int add4(int a, int b, int c, int d) {
    return a + b + c + d;
}

int weighted_sum(int a, int b, int c) {
    return a * 1 + b * 2 + c * 3;
}

int main(void) {
    int r = 0;
    r = r + add4(1, 2, 3, 4);        /* 10 */
    r = r + weighted_sum(1, 2, 3);    /* 1+4+9 = 14 */
    return r;                          /* 24 */
}
