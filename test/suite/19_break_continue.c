/* 19_break_continue: break和continue */

int main(void) {
    int i;
    int sum = 0;
    for (i = 0; i < 20; i = i + 1) {
        if (i % 2 == 0) {
            continue;  /* 跳过偶数 */
        }
        if (i > 10) {
            break;     /* 超过10就停 */
        }
        sum = sum + i;
    }
    return sum;  /* 1+3+5+7+9 = 25 */
}
