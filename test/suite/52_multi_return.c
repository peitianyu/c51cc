/* 52_multi_return: 多个return路径 */

int classify(int x) {
    if (x > 100) return 4;
    if (x > 50)  return 3;
    if (x > 10)  return 2;
    if (x > 0)   return 1;
    return 0;
}

int main(void) {
    int r = 0;
    r = r + classify(200);  /* 4 */
    r = r + classify(75);   /* 3 */
    r = r + classify(25);   /* 2 */
    r = r + classify(5);    /* 1 */
    r = r + classify(-1);   /* 0 */
    return r;                /* 10 */
}
