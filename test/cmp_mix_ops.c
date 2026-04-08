typedef unsigned char u8;
typedef unsigned int u16;

u8 f_lt(u8 i) { return i < 8; }
u8 f_le(u8 i) { return i <= 8; }
u8 f_eq(u8 i) { return i == 3; }
u8 f_ne(u8 i) { return i != 3; }

u16 f_sel(u8 c, u8 a, u8 b) {
    return c ? a : b;
}

int main()
{
    return f_lt(7) + f_le(8) + f_eq(3) + f_ne(4) +
           f_sel(1, 42, 24) + f_sel(0, 42, 24);
}