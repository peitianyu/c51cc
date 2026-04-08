int div_signed(int a,int b){ return a / b; }

int main()
{
    return div_signed(42, 2) + div_signed(-42, 2) + div_signed(42, -2) + div_signed(-42, -2);
}