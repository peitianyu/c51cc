char div_op(char a, char b) {
    return a / b;
}

int main()
{
    return div_op(42, 2) + div_op(-42, 2) + div_op(42, -2) + div_op(-42, -2);
}