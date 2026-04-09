/* 67_array_of_struct: 结构体数组 */

struct Item {
    int value;
    int weight;
};

int total_value(struct Item *items, int n) {
    int sum = 0;
    int i;
    for (i = 0; i < n; i = i + 1) {
        sum = sum + items[i].value;
    }
    return sum;
}

int main(void) {
    struct Item items[3];
    items[0].value = 10; items[0].weight = 1;
    items[1].value = 20; items[1].weight = 2;
    items[2].value = 30; items[2].weight = 3;
    return total_value(items, 3);  /* 60 */
}
