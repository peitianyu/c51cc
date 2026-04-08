int mul_int(int a, int b) { return a * b; }

int main()
{
    return mul_int(42, 5) + mul_int(-42, 5) + mul_int(42, -5) + mul_int(-42, -5);
}