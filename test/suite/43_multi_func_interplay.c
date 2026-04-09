/* 43_multi_func_interplay: 多函数交互 */

int g_val = 0;

void set_val(int x) {
    g_val = x;
}

int get_val(void) {
    return g_val;
}

int inc_val(void) {
    g_val = g_val + 1;
    return g_val;
}

int main(void) {
    set_val(10);
    int a = get_val();    /* 10 */
    int b = inc_val();    /* 11 */
    int c = inc_val();    /* 12 */
    int d = get_val();    /* 12 */
    return a + b + c + d; /* 10+11+12+12 = 45 */
}
