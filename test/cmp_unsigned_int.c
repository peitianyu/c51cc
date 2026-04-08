unsigned int cmp_unsigned_lt(unsigned int a,unsigned int b){ return a < b; }
unsigned int cmp_unsigned_le(unsigned int a,unsigned int b){ return a <= b; }
unsigned int cmp_unsigned_gt(unsigned int a,unsigned int b){ return a > b; }
unsigned int cmp_unsigned_ge(unsigned int a,unsigned int b){ return a >= b; }
unsigned int cmp_unsigned_eq(unsigned int a,unsigned int b){ return a == b; }
unsigned int cmp_unsigned_ne(unsigned int a,unsigned int b){ return a != b; }

int main()
{
    return cmp_unsigned_lt(0, 1) + cmp_unsigned_le(0, 1) + cmp_unsigned_gt(1, 0) + cmp_unsigned_ge(1, 0) +
           cmp_unsigned_eq(42, 42) + cmp_unsigned_ne(42, 43);
}