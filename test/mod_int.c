int mod_int(int a, int b) { return a % b; }

int main()
{
    return mod_int(42, 5) + mod_int(-42, 5) + mod_int(42, -5) + mod_int(-42, -5);
}