/* 08_bitwise_ops: 位运算 AND OR XOR NOT */

int main(void) {
    int a = 0x5A;
    int b = 0xA5;
    int r = 0;
    r = r + (a & b);      /* 0x00 = 0 */
    r = r + (a | b);      /* 0xFF = 255 */
    r = r + (a ^ b);      /* 0xFF = 255 */
    r = r + (~a & 0xFF);  /* 0xA5 = 165 */
    return r;              /* 675 */
}
