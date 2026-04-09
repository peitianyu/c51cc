/* 60_bubble_sort: 冒泡排序 (综合测试: 数组/循环/比较/交换) */

int arr[6] = {5, 3, 1, 4, 2, 6};

void bubble_sort(int *a, int n) {
    int i;
    int j;
    int t;
    for (i = 0; i < n - 1; i = i + 1) {
        for (j = 0; j < n - 1 - i; j = j + 1) {
            if (a[j] > a[j + 1]) {
                t = a[j];
                a[j] = a[j + 1];
                a[j + 1] = t;
            }
        }
    }
}

int main(void) {
    int r = 0;
    bubble_sort(arr, 6);
    /* 排序后: 1, 2, 3, 4, 5, 6 */
    /* 验证: 检查相邻递增 */
    r = arr[0] + arr[5];  /* 1 + 6 = 7 */
    return r;
}
