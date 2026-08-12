/* fold_off_test: @WRj+dis16 常量折叠专项测试
 *
 * 场景: OFFSET(ADDR @sym, 常量 index) 折叠成 MOV WRj,#sym + @WRj+off。
 * 覆盖:
 *   1. char 数组 (字节访问, 0x09/0x19 编码应可用)
 *   2. int 数组 (字访问, 需字级位移寻址)
 *   3. 同 OFFSET 多消费 (fold 安全性: 地址不含 off 时非 LOAD/STORE 消费会错)
 *   4. 跨块 OFFSET (循环)
 */
/* EXPECT 0 */

unsigned char g_c[4] = { 0xAA, 0xBB, 0xCC, 0xDD };
int g_i[4] = { 10, 20, 30, 40 };

int main(void) {
    int r = 0;
    /* 1. char 数组字节访问 (常量 index) */
    if (g_c[0] != 0xAA) r |= 1;
    if (g_c[1] != 0xBB) r |= 2;
    if (g_c[3] != 0xDD) r |= 4;
    /* 2. int 数组字访问 (常量 index) */
    if (g_i[0] != 10)  r |= 8;
    if (g_i[1] != 20)  r |= 16;
    if (g_i[3] != 40)  r |= 32;
    /* 3. 同 OFFSET 多消费: g_i[2] 读两次 */
    if (g_i[2] + g_i[2] != 60) r |= 64;
    /* 4. 循环内 OFFSET (跨块) */
    {
        int s = 0, k;
        for (k = 0; k < 4; k++) s += g_c[k];
        if (s != 0xAA + 0xBB + 0xCC + 0xDD) r |= 128;
    }
    return r;
}
