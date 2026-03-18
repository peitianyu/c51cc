char logic_ops(char a, char b) {
    return ~((a & b) | (a ^ b));
}
