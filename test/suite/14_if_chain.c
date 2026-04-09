/* 14_if_chain: if/else if/else 链 */

int classify(int x) {
    if (x < 0) {
        return -1;
    } else if (x == 0) {
        return 0;
    } else if (x < 10) {
        return 1;
    } else {
        return 2;
    }
}

int main(void) {
    int r = 0;
    r = r + classify(-5);   /* -1 */
    r = r + classify(0);    /* 0 */
    r = r + classify(7);    /* 1 */
    r = r + classify(100);  /* 2 */
    return r;                /* 2 */
}
