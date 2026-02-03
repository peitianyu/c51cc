register char P1 = 0x90;

int main(void)
{
    P1 = 0;
    if(P1 == 0)
    {
        P1 = 0b00001111;
    }
    else
    {
        P1 = 0b10101010;
    }

    while(1)
    {
        P1 = ~P1;
    }
    return 0;
}