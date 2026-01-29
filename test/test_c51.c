/* C51_Feature_Test.c
 * 用于测试 Keil C51 编译器特性，与 MUZUCC SSA 后端对比
 *  zero header dependency, 单文件实现
 */

/* 最小化 SFR 定义（仅测试需要） */
register char  P1      = 0x90;
register char  PSW     = 0xD0;
register bool P1_0    = 0X90;

/* 测试全局变量在不同存储区的情况 */
char  gv_data;      // data 区
char  xdata gv_xdata;   // xdata 区（外部 RAM）
char  code gv_code[] = {0x01, 0x02, 0x03};  // code 区常量

/* 场景1：简单算术与寄存器分配测试 */
char arith_test(char a, char b, char c) {
    char t1 = a + b;      // 测试双操作数
    char t2 = t1 * c;     // 测试乘法（C51会调用库函数）
    char t3 = t2 - a;     // 测试变量复用
    return t3;
}

/* 场景2：if-else 嵌套（SSA merge 节点测试） */
char control_if(char x, char y) {
    char r;
    if (x > 0) {
        if (y > 0)
            r = x + y;    // path1
        else
            r = x - y;    // path2
    } else {
        r = 0;            // path3
    }
    return r;             // 关键：3路 merge
}

/* 场景3：while 循环（SSA phi 节点测试） */
char control_while(char n) {
    char sum = 0;
    char i = 1;
    while (i <= n) {      // 循环头需要 phi(sum), phi(i)
        sum = sum + i;
        i = i + 1;
    }
    return sum;
}

/* 场景4：for 循环（更复杂的 phi） */
char control_for(char arr[]) {
    char sum = 0;
    char i;
    for (i = 0; i < 3; i = i + 1) {  // phi(sum), phi(i), phi(arr base?)
        sum = sum + arr[i];
    }
    return sum;
}

/* 场景5：break/continue（临界边与 phi 放置） */
char control_break(char n) {
    char r = 0;
    char i = 0;
    while (i < 10) {
        if (i == n)
            break;        // 跳转到循环 exits
        if (i & 0x01) {
            i = i + 1;    // continue（可选：加进来测试）
            continue;
        }
        r = r + i;
        i = i + 1;
    }
    return r;
}

/* 场景6：switch-case（跳转表 vs 链式比较） */
char control_switch(char x) {
    switch (x) {
        case 0: return 10;
        case 1: return 20;
        case 2: return 30;
        default: return 0;
    }
}

/* 场景7：指针别名与内存访问（SSA 内存对象分析） */
void pointer_test(void) {
    char data buf[4];
    char *p = buf;
    *p = 1;       // buf[0]
    *(p + 1) = 2; // buf[1]
    p[2] = 3;     // 数组下标语法
}

/* 场景8：位变量（C51 特有，MUZUCC 可能不支持但仍需对比） */
bool bit_logic_test(bool a, bool b) {
    bool c = a & b;
    return !c;
}

/* 场景10：递归（栈帧布局测试） */
char fib(char n) {
    if (n <= 1) return n;
    return fib(n - 1) + fib(n - 2);
}

/* 主函数：驱动测试 */
void main(void) {
    char a = 5, b = 3, c = 2;
    char r;
    
    r = arith_test(a, b, c);
    r = control_if(r, a);
    r = control_while(r);
    
    P1 = r;  // 输出结果到外设观察
    
    while (1){}
}