// ============================================
// 精简 C51 存储空间与 SFR 测试套件
// ============================================

// ----- 1. 基础 SFR 定义 (仅保留实际使用的) -----
register char  P1      = 0x90;
register char  ACC     = 0xE0;
register char  B       = 0xF0;
register char  SCON    = 0x98;
register char  SBUF    = 0x99;
register char  IE      = 0xA8;
register char  TCON    = 0x88;

// ----- 2. SBIT 定义（位寻址）-----
register bool  P1_0    = 0x90;  // P1.0
register bool  P1_7    = 0x97;  // P1.7
register bool  EA      = 0xAF;  // IE.7
register bool  ES      = 0xAC;  // IE.4
register bool  TR0     = 0x8C;  // TCON.4
register bool  TI      = 0x99;  // SCON.1

// ----- 3. 各存储区变量 -----
unsigned char data   g_data   = 0x01;
unsigned char idata  g_idata  = 0x02;
unsigned char xdata  g_xdata  = 0x03;
unsigned char code   g_code   = 0x04;

// ----- 4. 位寻址区变量 -----
unsigned char  g_bdata  = 0x00;
register bool  g_bit0 = 0x00;
register bool  g_bit7 = 0x07;

// ----- 5. 指针测试 -----
unsigned data  char * ptr_data;
unsigned idata char * ptr_idata;
unsigned xdata char * ptr_xdata;
unsigned code  char * ptr_code;
unsigned char *cod = "Hello, Code Space!";

// ----- 6. 基础存储区访问测试 -----
int test_data_rw(int v) {
    unsigned char data local;
    g_data = (unsigned char)v;
    local = g_data;
    g_data = local + 1;
    return g_data;
}

// int test_idata_rw(int v) {
//     unsigned char idata local;
//     g_idata = (unsigned char)v;
//     local = g_idata;
//     g_idata = local - 1;
//     return g_idata;
// }

// int test_xdata_rw(int v) {
//     unsigned char xdata local;
//     g_xdata = (unsigned char)v;
//     local = g_xdata;
//     g_xdata = local ^ 0xFF;
//     return g_xdata;
// }

// int test_code_read(void) {
//     return g_code + 1;
// }

// // ----- 7. 位操作测试 -----
// int test_bit_operations(void) {
//     int result = 0;
    
//     g_bdata = 0x00;
//     g_bit0 = 1;
//     if (g_bit0) result |= 0x01;
    
//     g_bit7 = 1;
//     if (g_bit7) result |= 0x80;
    
//     P1 = 0x00;
//     P1_0 = 1;
//     P1_7 = 1;
//     if (P1_0 && P1_7) result |= 0x02;
    
//     g_bit0 = 0;
//     if (!g_bit0) result |= 0x04;
    
//     return result;
// }

// // ----- 8. SFR 复杂操作测试 -----
// int test_sfr_complex(int v) {
//     int result = 0;
    
//     P1 = (char)v;
//     P1 = P1 & 0x0F;
//     P1 = P1 | 0x30;
//     P1 = P1 ^ 0x01;
//     P1 = ~P1;
//     result = P1;
    
//     ACC = (char)v;
//     ACC = ACC + 1;
//     ACC = ACC << 1;
//     result += ACC;
    
//     B = (char)v;
//     ACC = B;
//     B = B + ACC;
//     result += B;
    
//     return result;
// }

// // ----- 9. 中断控制测试 -----
// int test_interrupt_control(int enable) {
//     int old_state = EA;
    
//     if (enable) {
//         EA = 1;
//         ES = 1;
//         TR0 = 1;
//     } else {
//         EA = 0;
//         TR0 = 0;
//     }
    
//     return old_state;
// }

// // ----- 10. 指针操作测试 -----
// int test_pointers(void) {
//     int result = 0;
    
//     ptr_data = &g_data;
//     *ptr_data = 0x55;
//     result += *ptr_data;
    
//     ptr_idata = &g_idata;
//     *ptr_idata = 0xAA;
//     result += *ptr_idata;
    
//     ptr_xdata = &g_xdata;
//     *ptr_xdata = 0x12;
//     result += *ptr_xdata;
    
//     ptr_code = &g_code;
//     result += *ptr_code;
    
//     return result;
// }

// // ----- 11. 条件表达式与存储区 -----
// int test_conditional_ops(int flag) {
//     unsigned char data a = 0x10;
//     unsigned char data b = 0x20;
//     unsigned char xdata x = 0x30;
    
//     P1_0 = (flag & 0x01) ? 1 : 0;
    
//     g_data = P1_0 ? a : b;
//     g_xdata = P1_0 ? x : a;
    
//     if (P1_0) {
//         g_bdata = 0xFF;
//     } else {
//         g_bdata = 0x00;
//     }
    
//     return g_bdata;
// }

// // ----- 12. 混合存储区运算 -----
// int test_mixed_spaces(void) {
//     unsigned char data  d = 5;
//     unsigned char idata i = 10;
//     unsigned char xdata x = 20;
//     unsigned char code  c = 30;
    
//     g_data = d + i;
//     g_idata = x - c;
//     g_xdata = d * 2;
    
//     ptr_data = &g_data;
//     ptr_xdata = &g_xdata;
//     *ptr_data = *ptr_xdata + i;
    
//     return (int)g_data + g_idata + g_xdata;
// }

// // ----- 13. 边界与别名测试 -----
// int test_aliasing(void) {
//     register char *p = 0x20;
//     g_bdata = 0xA5;
    
//     g_bit0 = 0;
//     g_bit7 = 0;
    
//     unsigned char val = g_bdata;
//     unsigned char val2 = *p;
    
//     return (val == val2) ? val : -1;
// }

// // ----- 14. 压力测试：复杂控制流 -----
// int test_control_flow(int n) {
//     int sum = 0;
//     int i;
    
//     for (i = 0; i < n; i++) {
//         g_data = (unsigned char)i;
//         g_idata = g_data + 1;
//         g_xdata = g_idata + 1;
//         sum += g_xdata;
        
//         if (i & 0x01) {
//             P1_0 = !P1_0;
//         }
//     }
    
//     while (sum > 0) {
//         if (P1_0) {
//             if (g_data > 100) {
//                 sum -= g_code;
//             } else {
//                 sum -= g_idata;
//             }
//         } else {
//             sum -= g_xdata;
//         }
        
//         if (sum < 0) sum = 0;
//     }
    
//     return sum;
// }

// void putc(char c) {
//     SBUF = c;
//     while (!TI);     
//     TI = 0;
// }

// void puts(char *s) {
//     while (*s) putc(*s++);
// }

// // ===== 主函数：汇总测试 =====
// int main(void) {
//     int result = 0;
    
//     result += test_data_rw(0x12);
//     result += test_idata_rw(0x34);
//     result += test_xdata_rw(0x56);
//     result += test_code_read();
//     result += test_bit_operations();
//     result += test_sfr_complex(0xAB);
//     result += test_interrupt_control(1);
//     result += test_interrupt_control(0);
//     result += test_pointers();
//     result += test_conditional_ops(0x03);
//     result += test_mixed_spaces();
//     result += test_aliasing();
//     result += test_control_flow(5);
    
//     P1 = (char)result;
//     P1_0 = 1;
//     if (P1_0) {
//         P1 = (char)(P1 + 1);
//     }
//     result += P1;

//     puts("Test completed.\n");
    
//     return result;
// }