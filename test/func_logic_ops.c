char logic_ops(char a, char b) {
    return ~((a & b) | (a ^ b) | (a || b) | (!a && !b)); /* 逻辑非、与、异或、或 */
}
