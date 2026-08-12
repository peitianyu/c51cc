/* c251_libc.c — C251 后端系统库 (c251cc 的运行时库源码)
 *
 * 位置: src/core/c251/ — 与 c251_gen/isel/encode/output 同属 C251 后端;
 * 注意 build_compiler.bat 已排除本文件, 不会编译进 c251cc.exe 二进制
 * (它是“编译器消费的源码”, 不是“编译进编译器的代码”).
 *
 * 用途: test/execute 的测试声明并调用标准库函数 (strlen/calloc/...),
 * 但单文件编译时这些函数没有定义。simssa 检测到未定义直接调用时,
 * 将本文件与测试一起编译 (-ssa 多编译单元合并), 让库函数获得真实的
 * SSA 定义, 从而可被逐指令仿真执行 (与任何普通函数同等验证)。
 * 未来编译器也可自动链接本库以补齐标准函数。
 *
 * 约束 (c251cc 前端已知限制):
 *  - 数组衰减后不能在表达式中直接做指针算术 (`_heap + n` 会崩溃),
 *    必须先 `char *b = _heap;` 再 `b = b + n;`
 *  - 无变参/无 long long/无 float
 *  - 堆是裸机 bump 分配器, 无 free (仿真场景足够)
 *  - 返回类型必须与测试中的声明一致 (如 int *calloc(int, int))
 */

/* ── 字符串 ────────────────────────────────────────────── */

int strlen(char *s)
{
    int n = 0;
    while (*s) {
        s = s + 1;
        n = n + 1;
    }
    return n;
}

int strcmp(char *a, char *b)
{
    while (*a && *a == *b) {
        a = a + 1;
        b = b + 1;
    }
    return *a - *b;
}

char *strcpy(char *dst, char *src)
{
    char *d = dst;
    while (*src) {
        *d = *src;
        d = d + 1;
        src = src + 1;
    }
    *d = 0;
    return dst;
}

char *strcat(char *dst, char *src)
{
    char *d = dst;
    while (*d) d = d + 1;
    while (*src) {
        *d = *src;
        d = d + 1;
        src = src + 1;
    }
    *d = 0;
    return dst;
}

/* ── 内存 ──────────────────────────────────────────────── */

char *memcpy(char *dst, char *src, int n)
{
    int i = 0;
    while (i < n) {
        dst[i] = src[i];
        i = i + 1;
    }
    return dst;
}

char *memset(char *dst, int c, int n)
{
    int i = 0;
    while (i < n) {
        dst[i] = (char)c;
        i = i + 1;
    }
    return dst;
}

int memcmp(char *a, char *b, int n)
{
    int i = 0;
    while (i < n) {
        if (a[i] != b[i]) return a[i] - b[i];
        i = i + 1;
    }
    return 0;
}

/* ── 堆 (bump 分配器, 无 free) ─────────────────────────── */

static char _heap[1024];
static int _heap_top;

int *calloc(int n, int size)
{
    int total = n * size;
    char *base = _heap;          /* 数组衰减 (不能在表达式中直接 + 偏移) */
    base = base + _heap_top;
    _heap_top = _heap_top + total;
    {
        int i = 0;
        while (i < total) {
            base[i] = 0;
            i = i + 1;
        }
    }
    return base;
}
