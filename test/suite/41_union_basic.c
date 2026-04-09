/* 41_union_basic: 联合体 */

union U {
    int i;
    char c[2];
};

int main(void) {
    union U u;
    u.i = 0x1234;
    /* 8051 is big-endian: c[0]=0x12, c[1]=0x34 */
    /* Keil C51 stores int big-endian */
    return u.c[0] + u.c[1];  /* depends on endianness */
}
