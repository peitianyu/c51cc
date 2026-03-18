char cmp_ops(char a, char b) {
    return (a == b) * 1
         + (a != b) * 2
         + (a <  b) * 4
         + (a <= b) * 8
         + (a >  b) * 16
         + (a >= b) * 32;
}
