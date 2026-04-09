/* 09_shift_ops: 移位操作 */

int main(void) {
    int a = 1;
    int b = a << 4;   /* 16 */
    int c = b >> 2;   /* 4 */
    int d = 0x80;
    int e = d << 1;   /* 0x100 = 256 */
    return b + c + e; /* 276 */
}
