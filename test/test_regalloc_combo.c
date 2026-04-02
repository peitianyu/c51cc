static int combo_data[] = { 4, 7, 11, 18, 29, 47, 76, 123 };

static int helper_mix(int a, int b, int c, int d) {
    return a + b - c + d;
}

static int helper_pick(int cond, int left, int right) {
    return cond ? left : right;
}

int regalloc_combo(int a, int b, int c) {
    int* base = combo_data;
    int idx1 = (a + 1) & 3;
    int idx2 = (b + 2) & 3;
    int p0 = base[idx1] + a;
    int p1 = base[idx2] + b;
    int p2 = base[(c + 3) & 3] + c;
    int cond1 = p0 < p1;
    int cond2 = p2 != p0;
    int sel1 = helper_pick(cond1, p0 + p2, p1 + c);
    int live1 = p0 + p1 + p2;
    int call1 = helper_mix(sel1, live1, p1, p2);
    int sel2 = cond2 ? (call1 + p0) : (call1 - p1);
    int call2 = helper_mix(sel2, helper_pick(cond2, p2, p0), live1, sel1);
    int acc = 0;

    if (call2 > sel1) {
        acc = call2 + base[(idx1 + idx2) & 3];
    } else {
        acc = sel1 + base[(idx2 + 1) & 3];
    }

    return p0 + p1 + p2 + cond1 + cond2 + sel1 + live1 + call1 + sel2 + call2 + acc;
}

int main(void) {
    return regalloc_combo(5, 9, 3);
}