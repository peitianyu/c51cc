// Instruction selection tests: arithmetic/bit/shift/compare

// char ret_param(char x) {
//     return x;
// }

// char add_sub(char a, char b) {
//     return (a + b) ^ (a - b);
// }

// char add_ptr(char *p, char x) {
//     return *p + x;
// }

// char add_op(char a, char b) {
//     return a + b;
// }

// char sub_op(char a, char b) {
//     return a - b;
// }

// char mul_op(char a, char b) {
//     return a * b;
// }

// char div_op(char a, char b) {
//     return a / b;
// }

// char mod_op(char a, char b) {
//     return a % b;
// }

// char mul_div_mod(char a, char b) {
//     return a * b + a / b + a % b;
// }

unsigned char shl_shr(unsigned char v, char s) {
    return (v << s) | (v >> s);
}

// char logic_ops(char a, char b) {
//     return ~((a & b) | (a ^ b));
// }

// char cmp_ops(char a, char b) {
//     return (a == b) * 1
//          + (a != b) * 2
//          + (a <  b) * 4
//          + (a <= b) * 8
//          + (a >  b) * 16
//          + (a >= b) * 32;
// }

// char main(void) {
//     char a = 13;
//     char b = 5;
//     unsigned char v = 0x14;
//     return add_sub(a, b)
//          + mul_div_mod(a, b)
//          + (char)shl_shr(v, 3)
//          + logic_ops(a, b)
//          + cmp_ops(a, b);
// }
