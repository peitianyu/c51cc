register unsigned char P1 = 0x90;

void delay_short(void) {
    int count = 200;
    while (count > 0) {
        count = count - 1;
    }
}

int main(void) {
    while (1) {
        P1 = 0x01;
        delay_short();
        P1 = 0x02;
        delay_short();
        P1 = 0x04;
        delay_short();
        P1 = 0x08;
        delay_short();
    }
    return 0;
}
