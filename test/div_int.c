int div_int(int a, int b) { return a / b; }

int main()
{
    return div_int(42, 2) + div_int(-42, 2) + div_int(42, -2) + div_int(-42, -2);
}