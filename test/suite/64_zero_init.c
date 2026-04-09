/* 64_zero_init: 零初始化/未初始化变量 */

int g_zero;         /* BSS, 应该是0 */
int g_arr[3];       /* BSS, 应该是0 */

int main(void) {
    int local = 0;
    return g_zero + g_arr[0] + g_arr[1] + g_arr[2] + local;  /* 0 */
}
