typedef unsigned char u8;
typedef unsigned int u16;

u8 b_lt(u8 i) {
    if ((u16)i < 8) return 1;
    return 0;
}

u8 b_le(u8 i) {
    if ((u16)i <= 8) return 1;
    return 0;
}

u8 b_eq(u8 i) {
    if ((u16)i == 3) return 1;
    return 0;
}

u8 b_ne(u8 i) {
    if ((u16)i != 3) return 1;
    return 0;
}

u8 loop_lt(u8 start) {
    u8 i = start;
    while ((u16)i < 8) {
        i = i + 1;
    }
    return i;
}

int main()
{
    return b_lt(7) + b_le(8) + b_eq(3) + b_ne(4) + loop_lt(0);
}
