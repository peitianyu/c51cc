char add_sub(char a, char b);
char mul_div_mod(char a, char b);
unsigned char shl_shr(unsigned char v, char s);
char logic_ops(char a, char b);
char cmp_ops(char a, char b);

char main(void) {
    char a = 13;
    char b = 5;
    unsigned char v = 0x14;
    return add_sub(a, b)
         + mul_div_mod(a, b)
         + (char)shl_shr(v, 3)
         + logic_ops(a, b)
         + cmp_ops(a, b);
}
