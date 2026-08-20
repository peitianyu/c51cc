/* 110_long_array: long 数组与指针 (硬件测试, 返回 0=通过)
 * 覆盖: long 数组下标寻址 (元素 4 字节), long 指针步进/差。 */
long g_arr[8];

int main(void) {
    int i;
    for (i = 0; i < 8; i++)
        g_arr[i] = (long)(i + 1) * 100000L;
    for (i = 0; i < 8; i++) {
        if (g_arr[i] != (long)(i + 1) * 100000L) return 1;
    }

    /* long 指针步进 (sizeof(long) = 4) */
    {
        long *p = g_arr;
        if (p[3] != 400000L) return 2;
        p += 2;
        if (*p != 300000L) return 3;
        if (*(p + 3) != 600000L) return 4;
        p = p + 1;
        if (*p != 400000L) return 5;
        /* 指针差: (char*) 差值应为 4 的倍数 */
        if ((char*)(p + 1) - (char*)p != 4) return 6;
        if (p - g_arr != 3) return 7;
        p--;
        if (*p != 300000L) return 8;
        if (p - g_arr != 2) return 9;
    }

    /* 32 位元素读写高字 */
    g_arr[1] = 0x12345678L;
    if (g_arr[1] != 0x12345678L) return 10;
    if (g_arr[0] != 100000L) return 11;

    /* long 局部数组 */
    {
        long loc[4];
        for (i = 0; i < 4; i++) loc[i] = 1000L * (i + 1);
        if (loc[3] != 4000L) return 12;
        if (loc[1] + loc[2] != 5000L) return 13;
    }

    return 0;
}
