register char P1 = 0x90;

int main(void)
{
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