// Instruction selection tests: branches/loops/short-circuit

int loop_sum(int n) {
    int i = 0;
    int s = 0;
    while (i < n) {
        if (i & 1) {
            s += i;
        } else {
            s -= i;
        }
        i++;
    }
    return s;
}

int for_sum(int n) {
    int s = 0;
    int i;
    for (i = 0; i < n; i++) {
        s = s + i;
    }
    return s;
}

int do_sum(int n) {
    int s = 0;
    int i = 0;
    if (n <= 0) return 0;
    do {
        s += i;
        i++;
    } while (i < n);
    return s;
}

int short_circuit(int a, int b) {
    int r = 0;
    if (a && b) r += 1;
    if (a || b) r += 2;
    return r;
}

int main(void) {
    int a = 7;
    int b = 3;
    return loop_sum(8) + for_sum(8) + do_sum(6) + short_circuit(a, b);
}
