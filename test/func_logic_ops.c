char logic_ops(char a, char b) {
    return ~((a & b) | (a ^ b) | (a || b) | (!a && !b)); /* 逻辑非、与、异或、或 */
}

int main()
{
    return logic_ops(1, 2) + logic_ops(-1, -1) + logic_ops(127, 127) + logic_ops(-128, 127);
}