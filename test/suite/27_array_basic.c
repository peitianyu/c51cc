/* 27_array_basic: 数组基础 */

int g_arr[5] = {10, 20, 30, 40, 50};

int main(void) {
    int local_arr[3];
    int sum = 0;
    int i;

    local_arr[0] = 1;
    local_arr[1] = 2;
    local_arr[2] = 3;

    for (i = 0; i < 5; i = i + 1) {
        sum = sum + g_arr[i];
    }
    /* sum = 10+20+30+40+50 = 150 */

    for (i = 0; i < 3; i = i + 1) {
        sum = sum + local_arr[i];
    }
    /* sum = 150+1+2+3 = 156 */

    return sum;
}
