char mul_op(char a, char b) {
    return a * b;
}

int main()
{
    return mul_op(42, 5) + mul_op(-42, 5) + mul_op(42, -5) + mul_op(-42, -5);
}