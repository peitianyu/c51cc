/* 29_char_type: char类型操作 */

int main(void) {
    char a = 'A';       /* 65 */
    char b = 'Z';       /* 90 */
    char c = b - a;     /* 25 */
    unsigned char d = 200;
    unsigned char e = 100;
    int sum = a + c + d + e;  /* 65+25+200+100 = 390 */
    return sum;
}
