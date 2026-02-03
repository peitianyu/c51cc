register char P1 = 0x90;

void delay()
{
    int i, j;

    for (i=0; i<1000; i++)
    for (j=0; j<500; j++);
}

int main(void)
{
    while (1)
    {
        P1 = 0x00;
        delay();
        P1 = 0xff;
        delay();
    }
    return 0;
}