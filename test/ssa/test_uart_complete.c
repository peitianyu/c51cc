/* test/test_uart_complete.c - UART init using Timer1 + send routine that waits TI
 * This example configures Timer1 in mode 2 (auto-reload) to drive baud rate
 * and implements uart_putc that writes SBUF and waits for TI flag.
 */

register unsigned char SCON = 0x98;
register unsigned char SBUF = 0x99;
register unsigned char TMOD = 0x89;
register unsigned char TCON = 0x88;
register unsigned char TH1  = 0x8D;
register unsigned char TL1  = 0x8B;
register bool TI = SCON^1; 

/* Basic UART init: Timer1 mode2, TH1 reload, start TR1, set SCON mode1 */
void uart_init(void) {
    TMOD = 0x20;    /* Timer1 in mode 2 (8-bit auto-reload) */
    TH1 = 0xFD;     /* reload value (example) */
    TL1 = TH1;
    TCON |= 0x40;   /* set TR1 (start Timer1) */
    SCON = 0x50;    /* mode1, REN=1 */
}

/* Send a character and wait for TI flag */
void uart_putc(char c) {
    SBUF = (unsigned char)c;
    /* wait for TI sbit */
    while (!TI) {
        ;
    }
    /* clear TI sbit */
    TI = 0;
}

void uart_puts(const char* str) {
    while (*str) {
        uart_putc(*str++);
    }
    uart_putc('\n');
}

void uart_emit_specials(void) {
    uart_putc('\r');
    uart_putc('\n');
    uart_putc('\t');
    uart_putc('\\');
}

int main(void) {
    uart_init();
    uart_puts("Hello, UART!");
    uart_emit_specials();
    return 0;
}

/* Timer1 ISR: increment tick and set TI to simulate transmission completion */
volatile int tick = 0;

void interrupt_func(3, 1) {
    tick++;
    TI = 1;
}
