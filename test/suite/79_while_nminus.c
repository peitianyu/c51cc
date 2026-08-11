/* while(n--) post-decrement loop — 回归: 循环计数变量比较寄存器错误 */
unsigned int g_n = 5;
volatile unsigned char g_buf[16];
int main(void) {
    unsigned int n = g_n;
    unsigned int i;
    for (i = 0; i < 16; i++) g_buf[i] = 0;
    while (n--) g_buf[n] = 0xAA;
    return g_buf[0] + g_buf[1] + g_buf[2] + g_buf[3] + g_buf[4];
}
