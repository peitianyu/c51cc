/* 70_define_macro: 宏定义 */

#define ADD(a, b) ((a) + (b))
#define MUL(a, b) ((a) * (b))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#define SQUARE(x) ((x) * (x))
#define ARRAY_SIZE 5

int main(void) {
    int arr[ARRAY_SIZE] = {1, 2, 3, 4, 5};
    int r = 0;
    r = r + ADD(10, 20);    /* 30 */
    r = r + MUL(3, 4);      /* 12 */
    r = r + MAX(15, 8);     /* 15 */
    r = r + SQUARE(3);      /* 9 */
    return r;                /* 66 */
}
