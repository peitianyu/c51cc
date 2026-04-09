/* 53_global_init_expr: 全局变量初始化表达式 */

int g_a = 1 + 2;           /* 3 */
int g_b = 10 * 5;          /* 50 */
int g_c = (1 << 4) | 3;   /* 19 */
int g_d = 100 / 3;         /* 33 */
int g_e = 7 & 0x03;        /* 3 */

int main(void) {
    return g_a + g_b + g_c + g_d + g_e;
    /* 3 + 50 + 19 + 33 + 3 = 108 */
}
