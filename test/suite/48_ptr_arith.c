/* 48_ptr_arith: 指针运算 (通过数组下标) */

int g_arr[5] = {10, 20, 30, 40, 50};

int main(void) {
    int *p = g_arr;
    int r = 0;
    r = r + p[0];     /* 10 */
    r = r + p[2];     /* 30 */
    r = r + p[4];     /* 50 */
    return r;          /* 90 */
}
