static int foo(void)
{
    __asm__("push r7\n"
             "mov A, #0\n"
             "pop r7\n"
             "ret\n"
            "nop\n"
             "nop\n"
             "nop\n");
    return 0;
}

int main(void)
{
    return foo();
}
