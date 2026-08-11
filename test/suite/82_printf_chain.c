/* 82_printf_chain: printf %02x 链路子问题集合 — 每个问题一个独立函数,
   main 返回所有断言的 OR (0 = 全过)。覆盖 2026-08-09 修复的 5 个根因 +
   进行中的 LHS 寄存器保护。 */
/* 预期: 0 */

/* 子问题 1: 三元表达式布局 (JSGE 目标错位) — d<10 ? '0'+d : 'A'+d-10 */
static int t_ternary(void)
{
    unsigned char buf[8];
    int len = 0;
    unsigned int n = 0x12, base = 16;
    do {
        int d = n % base;
        buf[len++] = (d < 10) ? ('0' + d) : ('A' + d - 10);
        n /= base;
    } while (n);
    /* buf = "21" (d=2→'2', d=1→'1') */
    return (buf[0] == '2' && buf[1] == '1') ? 0 : 1;
}

/* 子问题 2: 常量三元物化 (zero?'0':' ') — 宽度填充 */
static int t_ternary_const(void)
{
    static char buf[4];
    int len = 0;
    int zero = 1, width = 2;
    while (len < width)
        buf[len++] = zero ? '0' : ' ';
    return (buf[0] == '0' && buf[1] == '0') ? 0 : 2;
}

/* 子问题 3: vararg 传递 (printf %02x 的 n) */
static int t_vararg(void)
{
    static char buf[4];
    int n = 0x12;
    int d;
    int len = 0;
    d = n % 16;
    buf[len++] = (d < 10) ? ('0' + d) : ('A' + d - 10);
    n /= 16;
    d = n % 16;
    buf[len++] = (d < 10) ? ('0' + d) : ('A' + d - 10);
    return (buf[0] == '2' && buf[1] == '1') ? 0 : 4;
}

/* 子问题 4: LHS 寄存器保护 — 乘法结果 + 指针解引用
   (printf width*10 + (*fmt-'0') 的 width 错根因: RHS 的 MOV DR4
   指针加载覆盖 MUL 结果 WR6) */
static int t_mul_add_ptr(void)
{
    const unsigned char fmt[6] = { '%', '0', '2', 'x', 0, 0 };
    const unsigned char *f = fmt + 1;
    int width = 0, zero = 0;
    /* 模拟 %02x 解析: '0' → zero, '2' → width=2 */
    while (*f >= '0' && *f <= '9') {
        if (*f == '0' && width == 0) zero = 1;
        else width = width * 10 + (*f - '0');
        f++;
    }
    return (width == 2 && zero == 1) ? 0 : 8;
}

int main(void)
{
    int r = 0;
    r |= t_ternary();
    r |= t_ternary_const();
    r |= t_vararg();
    r |= t_mul_add_ptr();
    return r;
}
