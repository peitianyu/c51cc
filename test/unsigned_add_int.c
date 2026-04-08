unsigned int unsigned_add_int(unsigned int a, unsigned int b) { return a + b; }

int main()
{
    return unsigned_add_int(123, 123) + unsigned_add_int(321, 31) + unsigned_add_int(321, 312) + unsigned_add_int(12, 12);
}