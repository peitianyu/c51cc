// 综合覆盖测试：尽量覆盖 C51 后端常见路径
// 说明：本测试偏向编译/生成 ASM 覆盖，而非运行正确性

/* ===== 全局/地址空间 ===== */
int g_i = 1234;
unsigned int g_u = 65535;
char g_c = -3;
unsigned char g_uc = 250;
long g_l = 0x12345678;

int g_arr[4] = {1, 2, 3, 4};
char g_str[] = "abc";

// xdata/code/bit 等修饰在语法层是否支持，若支持可取消注释
// xdata int gx = 7;
// code const char gc[] = "ROM";

/* ===== SFR / SBIT（用 register 关键字映射） ===== */
register char P0 = 0x80;   // P0
register char P1 = 0x90;   // P1
register bool P0_0 = 0x80; // P0.0
register bool P1_7 = 0x97; // P1.7

/* ===== 结构体/联合体 ===== */
struct S {
    int a;
    int b;
};

union U {
    int i;
    char c[2];
};

struct S g_s = {1, 2};
union U g_u2 = { .i = 0x1234 };

/* ===== 内联函数/多参 ===== */
int add4(int a, int b, int c, int d) {
    return a + b + c + d;
}

/* ===== 运算/比较/移位 ===== */
int test_ops(int x, int y) {
    int r = 0;
    r += x + y;
    r += x - y;
    r += x * y;
    if (y) r += x / y;
    if (y) r += x % y;
    r += (x & y);
    r += (x | y);
    r += (x ^ y);
    r += (x << 1);
    r += (x >> 1);
    r += (x < y);
    r += (x <= y);
    r += (x > y);
    r += (x >= y);
    r += (x == y);
    r += (x != y);
    return r;
}

/* ===== 控制流 ===== */
int test_ctrl(int x) {
    int sum = 0;
    for (int i = 0; i < 8; i = i + 1) sum = sum + i;
    int j = 3;
    while (j) { j = j - 1; sum = sum + j; }
    if (x & 1) sum = sum + 10; else sum = sum + 20;
    switch (x & 3) {
    case 0: sum = sum + 1; break;
    case 1: sum = sum + 2; break;
    default: sum = sum + 3; break;
    }
    return sum;
}

/* ===== 指针/数组/结构体 ===== */
int test_ptr_struct(void) {
    struct S s = {3, 4};
    struct S s2 = {.a = 5, .b = 6};
    int *p = g_arr;
    int r = p[1] + p[2];
    r += s.a + s.b;
    r += s2.a + s2.b;
    return r;
}

/* ===== SFR/SBIT 访问 ===== */
int test_sfr(void) {
    P0 = 0x5A;
    P1 = 0xA5;
    P0_0 = 1;
    if (P1_7) return P0;
    return P1;
}

// 中断函数测试（IRQ 0，寄存器组 0）
void interrupt_func(1, 1) {
    P0_0 = 1;
}

/* ===== 调用约定/多参数/栈参数 ===== */
int test_call(void) {
    return add4(1, 2, 3, 4) + add4(5, 6, 7, 8);
}

int main() {
    int r = 0;
    r += test_ops(g_i, g_u);
    r += test_ctrl(g_i);
    r += test_ptr_struct();
    r += test_sfr();
    r += test_call();
    return r;
}
