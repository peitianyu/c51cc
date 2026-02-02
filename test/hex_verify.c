register char P1 = 0x90;

int main(void)
{
    P1 = 0;
    if(P1 == 0)
    {
        P1 = 0xFF;
    }
    else
    {
        P1 = 0x00;
    }
    return 0;
}