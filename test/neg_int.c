int neg_int(int a) { return -a; }

int main()
{
    return neg_int(42) + neg_int(-1) + neg_int(127) + neg_int(-128);
}