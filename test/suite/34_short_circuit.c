/* 34_short_circuit: 短路求值 */

int g_count = 0;

int side_effect(int x) {
    g_count = g_count + 1;
    return x;
}

int main(void) {
    int r = 0;

    /* && 短路: 左边为false时, 右边不执行 */
    g_count = 0;
    if (0 && side_effect(1)) r = r + 1;
    r = r + g_count;  /* g_count 应该还是0, r=0 */

    /* || 短路: 左边为true时, 右边不执行 */
    g_count = 0;
    if (1 || side_effect(1)) r = r + 10;
    r = r + g_count;  /* g_count 应该还是0, r=10 */

    /* && 不短路: 左边为true, 右边执行 */
    g_count = 0;
    if (1 && side_effect(1)) r = r + 100;
    r = r + g_count;  /* g_count=1, r=10+100+1=111 */

    return r;  /* 111 */
}
