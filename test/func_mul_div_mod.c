char mul_div_mod(char a, char b) {
    return a * b + a / b + a % b;
}

int main()
{
    return mul_div_mod(42, 5) + mul_div_mod(-42, 5) + mul_div_mod(42, -5) + mul_div_mod(-42, -5);
}