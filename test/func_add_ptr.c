char add_ptr(char *p, char x) {
    return *p + x;
}

int main()
{
    return add_ptr((char *)0x1234, 42);
}