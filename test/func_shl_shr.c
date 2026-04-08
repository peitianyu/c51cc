unsigned char shl_shr(unsigned char v, char s) {
    return (v << s) | (v >> s);
}

int main()
{
    return shl_shr(0xFF, 1) + shl_shr(0xFF, 2) + shl_shr(0xFF, 3) + shl_shr(0xFF, 4) +
           shl_shr(0xFF, 5) + shl_shr(0xFF, 6) + shl_shr(0xFF, 7);
}