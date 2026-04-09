/* 50_typedef: typedef 类型别名 */

typedef unsigned char u8;
typedef unsigned int u16;
typedef int s16;

u16 widen(u8 x) {
    return x;
}

s16 negate(s16 x) {
    return -x;
}

int main(void) {
    u8 a = 200;
    u16 b = widen(a);       /* 200 */
    s16 c = negate(100);    /* -100 */
    return b + c;            /* 200 + (-100) = 100 */
}
