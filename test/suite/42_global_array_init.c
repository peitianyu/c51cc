/* 42_global_array_init: 全局数组初始化 */

int g_arr[4] = {10, 20, 30, 40};
char g_str[] = "AB";

int main(void) {
    int sum = 0;
    int i;
    for (i = 0; i < 4; i = i + 1) {
        sum = sum + g_arr[i];
    }
    /* sum = 10+20+30+40 = 100 */
    sum = sum + g_str[0] + g_str[1];  /* 'A'=65, 'B'=66 */
    return sum;  /* 100 + 65 + 66 = 231 */
}
