/* 54_loop_counter: 各种循环计数模式 */

int count_down(int n) {
    int s = 0;
    while (n > 0) {
        s = s + n;
        n = n - 1;
    }
    return s;
}

int count_by_2(int n) {
    int s = 0;
    int i;
    for (i = 0; i < n; i = i + 2) {
        s = s + 1;
    }
    return s;
}

int main(void) {
    int r = 0;
    r = r + count_down(5);    /* 5+4+3+2+1 = 15 */
    r = r + count_by_2(10);   /* i=0,2,4,6,8 => 5 */
    return r;                  /* 20 */
}
