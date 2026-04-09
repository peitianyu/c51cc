/* 65_edge_values: 边界值测试 */

int main(void) {
    int max_int = 32767;    /* 0x7FFF */
    int min_int = -32768;   /* 0x8000 */
    unsigned int max_uint = 65535;  /* 0xFFFF */

    int r = 0;
    if (max_int > 0)  r = r + 1;
    if (min_int < 0)  r = r + 2;
    if (max_uint > 0) r = r + 4;

    /* 溢出测试 */
    int overflow = max_int + 1;  /* 应该变成 -32768 */
    if (overflow < 0) r = r + 8;

    return r;  /* 1+2+4+8 = 15 */
}
