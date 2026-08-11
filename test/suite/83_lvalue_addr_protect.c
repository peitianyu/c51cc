/* 83_lvalue_addr_protect: 寄存器地址 lvalue 跨 RHS 求值存活 (2026-08-10 修复)。
   buf[i]=RHS 的地址物化在 WR6, RHS 用 WR6/WR4 scratch 覆写地址 →
   写错地址/高字节。覆盖三个根因:
   1. protect vtop[-1]→vtop[0] off-by-one + lvalue 地址保护 (三元条件
      CMP 用 WR6 覆写地址, save_regs 在条件求值后才跑)
   2. PTR-ADD LHS 用 MOV DR4,#buf 覆写 len (16 位 WR 形式修复)
   3. @WR byte store 存 WR 高字节 (16 位值 → u8 目标取低字节 R(m+1))
   每个子测试独立函数, main 返回 OR (0 = 全过)。 */
/* 预期: 0 */

static unsigned char g_buf[8];

/* 子问题 1: 简单数组元素写 + 16 位算术 RHS (值在 WR8 → u8 存低字节) */
static int t_arr_int_arith(void)
{
    int i = 1, a = 20;
    g_buf[i] = a + 11;              /* 期望 31 */
    return (g_buf[1] == 31) ? 0 : 1;
}

/* 子问题 2: 数组元素写 + 三元 RHS (条件 CMP 覆写地址) */
static int t_arr_ternary(void)
{
    int i = 1;
    g_buf[i] = (i < 2) ? 'A' : 'B'; /* 期望 'A' = 65 */
    return (g_buf[1] == 'A') ? 0 : 2;
}

/* 子问题 3: buf[len++] + 三元 (PTR-ADD len 丢失 + 三元地址覆写) */
static int t_arr_postinc_tern(void)
{
    unsigned char buf[8];
    int len = 0, n = 0x12, base = 16;
    do {
        int d = n % base;
        buf[len++] = (d < 10) ? ('0' + d) : ('A' + d - 10);
        n /= base;
    } while (n);
    return (buf[0] == '2' && buf[1] == '1') ? 0 : 4;
}

/* 子问题 4: 指针解引用 RHS (MOV DR4,f 覆写 MUL 结果 WR6) */
static int t_arr_mul_deref(void)
{
    static unsigned char fmt[4] = { '2', 'x', 0, 0 };
    const unsigned char *f = fmt;
    int width = 0;
    while (*f >= '0' && *f <= '9') {
        width = width * 10 + (*f - '0');
        f++;
    }
    return (width == 2) ? 0 : 8;
}

/* 子问题 5: 局部 buf[i] + 16 位算术 (VT_LOCAL 地址 + WR8 值) */
static int t_local_arr_arith(void)
{
    unsigned char buf[4];
    int i = 1, a = 7;
    buf[i] = a * 5 + 1;             /* 期望 36 */
    return (buf[1] == 36) ? 0 : 16;
}

int main(void)
{
    int r = 0;
    r |= t_arr_int_arith();
    r |= t_arr_ternary();
    r |= t_arr_postinc_tern();
    r |= t_arr_mul_deref();
    r |= t_local_arr_arith();
    return r;
}
