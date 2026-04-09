/* 16_for_loop: for循环 */

int main(void) {
    int sum = 0;
    int i;
    for (i = 1; i <= 10; i = i + 1) {
        sum = sum + i;
    }
    return sum;  /* 1+2+...+10 = 55 */
}
