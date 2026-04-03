/*
 * test_ssa_irop.c
 * 目标：通过写一组小函数尽量覆盖 `ssa` 中的每个 IROP 指令。
 * 把函数结果在 `main` 中累加并返回，方便通过编译器/SSA阶段观察生成的 IR。
 */

/* 算术/常量/参数/取反/取模/等 */
char irop_arith(char a, char b) {
    char c = 42;            /* CONST */
    char s = a + b;         /* ADD */
    s = s - 3;             /* SUB */
    s = s * 2;             /* MUL */
    s = s / 4;             /* DIV */
    s = s % 5;             /* MOD */
    s = -s;                /* NEG */
    return s + c;
}

/* 位运算与移位 */
char irop_bit(char a, char b) {
    char r = a & b;         /* AND */
    r = r | a;             /* OR */
    r = r ^ b;             /* XOR */
    r = ~r;                /* NOT */
    r = r << 2;            /* SHL */
    r = r >> 1;            /* SHR */
    return r;
}

/* 比较与逻辑 */
char irop_cmp(char a, char b) {
    char r = (a == b);      /* EQ */
    r += (a < b);          /* LT */
    r += (a > b);          /* GT */
    r += (a <= b);         /* LE */
    r += (a >= b);         /* GE */
    r += (a != b);         /* NE */
    r += !a;               /* LNOT */
    r += (a && b);         /* LAND */
    r += (a || b);         /* LOR */
    return r;
}

/* 截断/扩展/位重解释/指针<->整数/地址计算/选择 */
char irop_casts_and_ptrs(char a) {
    char tc = (char)a;                      /* TRUNC */
    unsigned char uz = (unsigned char)a;    /* ZEXT (unsigned) */
    char ss = (char)a;                      /* SEXT (signed char) */

    /* BITCAST: 通过 union 把 float 的位解释为 char */
    union { float f; char i; } ub;
    char bitcast_i = ub.i;                  /* BITCAST */
    void *p = (void*)(int)0x4000;           /* INTTOPTR */
    int ip = (int)&a;                       /* PTRTOINT */
    char arr[4] = {1,2,3,4};
    char *ptr = &arr[1];                    /* ADDR */
    char load = ptr[0];                     /* LOAD / OFFSET */
    char sel = (a > 0) ? a : -a;            /* SELECT */
    ub.f = 1.5f;

    /* INTTOPTR / PTRTOINT */

    /* OFFSET / LOAD / STORE */
    ptr[0] = load + 7;                      /* STORE */

    /* SELECT (三元运算) */

    /* 将部分结果用于返回，保证变量不被优化掉 */
    return tc + (char)uz + ss + bitcast_i + load + sel;
}

/* 控制流：条件分支、跳转、PHI 产生场景 */
char irop_cf_and_phi(char x, char y) {
    char v;
    if (x > y) {
        v = x + 1;    /* 分支1，后续会在合并处产生 PHI */
        goto L1;      /* JMP */
    } else {
        v = y - 1;    /* 分支2 */
    }
L1:
    if (v & 1) {     /* BR (条件跳转) */
        v = v + 2;
    }
    return v;        /* RET */
}

/* 调用/参数/返回 */
char helper_call(char a, char b) {
    return a - b;
}

char irop_call_and_param(char p, char q) {
    char r = helper_call(p, q); /* CALL + PARAM */
    return r;
}

/* 内联汇编（产生 IROP_ASM） */
char irop_asm(void) {
    __asm__("nop\n");
    return 0;
}

/* 顶层测试入口：调用所有上面的函数并累加返回值 */
char main(void) {
    char res = 0;
    res += irop_arith(10, 3);
    res += irop_bit(5, 2);
    res += irop_cmp(7, 4);
    res += irop_casts_and_ptrs(12345);
    res += irop_cf_and_phi(8, 3);
    res += irop_call_and_param(9, 4);
    res += irop_asm();
    return res;
}
