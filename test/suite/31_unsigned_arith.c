/* 31_unsigned_arith: unsigned int 运算 */

int main(void) {
    unsigned int a = 50000;
    unsigned int b = 30000;
    unsigned int c = a - b;    /* 20000 */
    unsigned int d = a + b;    /* 80000 -> 溢出16位 = 14464 */
    /* 注意: 8051的int是16位, 50000+30000=80000, 80000 & 0xFFFF = 14464 */
    return c;                   /* 20000 */
}
