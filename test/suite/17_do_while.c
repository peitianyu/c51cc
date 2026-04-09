/* 17_do_while: do-while循环 */

int main(void) {
    int i = 1;
    int product = 1;
    do {
        product = product * i;
        i = i + 1;
    } while (i <= 5);
    return product;  /* 1*2*3*4*5 = 120 */
}
