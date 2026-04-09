/* 28_array_ptr: 数组与指针互操作 */

int sum_array(int *arr, int n) {
    int i;
    int s = 0;
    for (i = 0; i < n; i = i + 1) {
        s = s + arr[i];
    }
    return s;
}

int main(void) {
    int arr[4] = {5, 10, 15, 20};
    return sum_array(arr, 4);  /* 50 */
}
