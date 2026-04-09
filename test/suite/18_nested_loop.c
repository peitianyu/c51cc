/* 18_nested_loop: 嵌套循环 */

int main(void) {
    int i;
    int j;
    int sum = 0;
    for (i = 0; i < 5; i = i + 1) {
        for (j = 0; j < 3; j = j + 1) {
            sum = sum + 1;
        }
    }
    return sum;  /* 5 * 3 = 15 */
}
