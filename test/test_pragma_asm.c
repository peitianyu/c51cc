/* 最小 asm 测试：只使用 __asm__("...") */

static int foo(void)
{
    __asm__( "nop\n"
             "nop\n"
             "nop\n");
    return 0;
}

int main(void)
{
    return foo();
}
