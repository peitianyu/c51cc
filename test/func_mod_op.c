char mod_op(char a, char b) {
    return a % b;
}

int main()
{
    return mod_op(42, 5) + mod_op(-42, 5) + mod_op(42, -5) + mod_op(-42, -5);
}