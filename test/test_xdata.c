xdata char gx;
code char gc = 7;

int touch(int v) {
    gx = v;
    return gx + gc;
}

int main(void) {
    return touch(5);
}


