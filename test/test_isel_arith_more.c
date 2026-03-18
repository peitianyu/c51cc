// Additional arithmetic operator tests for instruction selection

char add_const(char a) {
    return a + 100;
}

char sub_const(char a) {
    return a - 100;
}

char add_signed_unsigned(char a, unsigned char b) {
    return a + b;
}

unsigned char unsigned_div(unsigned char a, unsigned char b) {
    return a / b;
}

char neg_op(char a) {
    return -a;
}

char inc_dec(char a) {
    a++;
    a--;
    return a;
}

char mixed_arith(char a, char b, char c) {
    return a * b + c - (a ^ b);
}

char shifts(char a, char s) {
    return (a << s) + (a >> s);
}

char big_mul(char a, char b) {
    // force multiply path
    return a * b;
}

char div_mod_combo(char a, char b) {
    return (a / b) + (a % b);
}
