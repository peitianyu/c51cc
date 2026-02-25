// char cmp_pack(char a, char b) {
//     char r = 0;
//     r += (a == b);
//     r += (a != b);
//     r += (a < b);
//     r += (a <= b);
//     r += (a > b);
//     r += (a >= b);
//     return r;
// }

// char arith_mix(char a, char b) {
//     char m = a * b;
//     char d = b ? (a / b) : 0;
//     char k = b ? (a % b) : 0;
//     char n = -a;
//     return m + d + k + n;
// }

char shift_mix(char x, char s) {
    char l = x << s;
    char r = x >> s;
    return l ^ r;
}

// char select_mix(char a, char b, char c) {
//     char x = (a > b) ? a : b;
//     char y = (x > c) ? x : c;
//     return y;
// }

// char cast_mix(char c, unsigned char uc) {
//     char s = (char)c;
//     char u = (char)uc;
//     char t = (char)(s + u);
//     return (char)t + s + u;
// }

// char ptr_mix(void) {
//     char arr[4] = {3, 5, 7, 11};
//     char* p = arr;
//     return p[0] + p[1] + p[2] + p[3];
// }

// char loop_phi(char n) {
//     char i = 0;
//     char s = 0;
//     while (i < n) {
//         s = s + i;
//         i = i + 1;
//     }
//     return s;
// }

// char main(void) {
//     char r = 0;
//     r += cmp_pack(7, 3);
//     r += arith_mix(17, 5);
//     r += shift_mix(0x1234, 2);
//     r += select_mix(3, 9, 4);
//     r += cast_mix(-7, 250);
//     r += ptr_mix();
//     r += loop_phi(6);
//     return r;
// }
