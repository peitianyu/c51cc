__asm__("BOOT_LABEL:\n"
        "nop\n");

register char IE = 0xA8;
register bool EA = 0xAF;

int tick;

int read_flag(void) {
    if (EA)
        return IE;
    return 0;
}

int add1(int x) {
    __asm__("INC R7\n"
            "NOP\n");
    return x;
}

void interrupt_func(1, 1) {
    EA = 0;
    tick = tick + 1;
    __asm__("NOP\n"
            "NOP\n");
}

int main(void) {
    IE = 0;
    EA = 1;
    return add1(read_flag());
}