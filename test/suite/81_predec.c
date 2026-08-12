/* EXPECT 680 */
/* pre-decrement --n loop 回归 */
unsigned char g_buf[16];
int main(void) {
    unsigned int n = 5;
    unsigned int i, s = 0;
    for (i = 0; i < 16; i++) g_buf[i] = 0;
    while (--n) g_buf[n] = 0xAA;
    for (i = 0; i < 5; i++) s += g_buf[i];
    return s;
}
