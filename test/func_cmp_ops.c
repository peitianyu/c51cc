char cmp_ops(char a, char b) {
    return (a == b) * 1
         + (a != b) * 2
         + (a <  b) * 4
         + (a <= b) * 8
         + (a >  b) * 16
         + (a >= b) * 32;
}

int main()
{
    return cmp_ops(1, 2) + cmp_ops(-1, -1) + cmp_ops(127, 127) + cmp_ops(-128, 127);
}