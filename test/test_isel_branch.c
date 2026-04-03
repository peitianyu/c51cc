/* Instruction selection tests: branches/loops/short-circuit */

int if_else(int a, int b) {
    if (a > b) {
        return 1;
    } else {
        return 2;
    }
}

int while_loop(int n) {
    int i = 0;
    int s = 0;
    while (i < n) {
        s = s + i;
        i = i + 1;
    }
    return s;
}

int loop_sum(int n) {
    int i = 0;
    int s = 0;
    while (i < n) {
        if (i & 1) {
            s = s + i;
        } else {
            s = s - i;
        }
        i = i + 1;
    }
    return s;
}

int for_sum(int n) {
    int s = 0;
    int i;
    for (i = 0; i < n; i = i + 1) {
        s = s + i;
    }
    return s;
}

int do_sum(int n) {
    int s = 0;
    int i = 0;
    if (n <= 0) {
        return 0;
    }
    do {
        s = s + i;
        i = i + 1;
    } while (i < n);
    return s;
}

int short_circuit(int a, int b) {
    int r = 0;
    if (a && b) {
        r = r + 1;
    }
    if (a || b) {
        r = r + 2;
    }
    if (a && (b - 1)) {
        r = r + 4;
    }
    return r;
}

int branch_chain(int x) {
    int r;
    if (x < 0) {
        r = -1;
    } else if (x == 0) {
        r = 0;
    } else if (x < 4) {
        r = x + 10;
    } else {
        r = x - 10;
    }
    return r;
}

int loop_break_continue(int n) {
    int i = 0;
    int s = 0;
    while (i < n) {
        i = i + 1;
        if ((i & 1) == 0) {
            continue;
        }
        if (i > 7) {
            break;
        }
        s = s + i;
    }
    return s;
}

int nested_branch_phi(int n) {
    int i = 0;
    int s = 0;
        int t;
    while (i < n) {
        if (i < 3) {
            t = i + 1;
        } else {
            if (i & 1) {
                t = i + 2;
            } else {
                t = i - 2;
            }
        }
        s = s + t;
        i = i + 1;
    }
    return s;
}

int main(void) {
    int a = 7;
    int b = 3;
    int r = 0;
    r = r + if_else(a, b);
    r = r + while_loop(6);
    r = r + loop_sum(7);
    r = r + for_sum(6);
    r = r + do_sum(5);
    r = r + short_circuit(a, b);
    r = r + branch_chain(-2);
    r = r + branch_chain(0);
    r = r + branch_chain(3);
    r = r + branch_chain(9);
    r = r + loop_break_continue(12);
    r = r + nested_branch_phi(8);
    return r;
}
