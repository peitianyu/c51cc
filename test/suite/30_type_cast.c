/* 30_type_cast: 类型转换 (char <-> int) */

int widen_u8(unsigned char x) {
    return x;  /* zero-extend to int */
}

int widen_s8(char x) {
    return x;  /* sign-extend to int */
}

int narrow_to_u8(int x) {
    unsigned char c = x;
    return c;
}

int main(void) {
    int r = 0;
    r = r + widen_u8(200);      /* 200 */
    r = r + widen_s8(-5);       /* -5, 有符号扩展 */
    r = r + narrow_to_u8(300);  /* 300 & 0xFF = 44 */
    return r;                    /* 200 + (-5) + 44 = 239 */
}
