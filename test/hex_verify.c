// register char P1 = 0x90;

// void delay()
// {
//     int i, j;

//     for (i=0; i<1000; i++)
//     for (j=0; j<500; j++);
// }

// int main(void)
// {
//     while (1)
//     {
//         P1 = 0x00;
//         delay();
//         P1 = 0xff;
//         delay();
//     }
//     return 0;
// }

register char  SCON  = 0x98;
register bool  TI    = 0x99;
register char  SBUF  = 0x99;
register char  TMOD  = 0x89;
register char  TH1   = 0x8D;
register char  TL1   = 0x8B;
register char  TR1   = 0x8E;


void putc(char c)
{
    SBUF = c;
    while (!TI);     
    TI = 0;
}

void puts(char *s)
{
    while (*s) putc(*s++);
}

void uart_init(void)
{
    TMOD |= 0x20;      
    TH1 = TL1 = 0xFD;
    TR1 = 1;           
    SCON = 0x50;      
}

void main(void)
{
    uart_init();
    puts("hello C51");
    while (1);        
}