/* 03_global_vars: 全局变量读写 */

int g_a = 10;
int g_b = 20;
int g_c;

int main(void) {
    g_c = g_a + g_b;
    return g_c;   /* 30 */
}
