/* 20_switch_case: switch/case语句 */

int test_switch(int x) {
    int r;
    switch (x) {
    case 0: r = 10; break;
    case 1: r = 20; break;
    case 2: r = 30; break;
    case 3: r = 40; break;
    default: r = -1; break;
    }
    return r;
}

int main(void) {
    int r = 0;
    r = r + test_switch(0);   /* 10 */
    r = r + test_switch(1);   /* 20 */
    r = r + test_switch(2);   /* 30 */
    r = r + test_switch(3);   /* 40 */
    r = r + test_switch(99);  /* -1 */
    return r;                  /* 99 */
}
