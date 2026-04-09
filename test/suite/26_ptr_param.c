/* 26_ptr_param: 指针作为函数参数 */

void swap(int *a, int *b) {
    int t = *a;
    *a = *b;
    *b = t;
}

int deref_add(int *p, int *q) {
    return *p + *q;
}

int main(void) {
    int x = 10;
    int y = 20;
    swap(&x, &y);
    /* 现在 x=20, y=10 */
    return deref_add(&x, &y);  /* 20 + 10 = 30 */
}
