/* 15_while_loop: while循环 */

int main(void) {
    int i = 0;
    int sum = 0;
    while (i < 10) {
        sum = sum + i;
        i = i + 1;
    }
    return sum;  /* 0+1+2+...+9 = 45 */
}
