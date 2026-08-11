/* 77_far_mem: far 24 位指针访问 (硬件测试, 返回 0=通过)
 * 覆盖: far 扩展 SFR (XFR 0x7EFE 窗口) 读写回, far xram 区读写回。
 * 依赖 sim251 far 内存路由 (0x7E/0x00 窗口 → xram, 可读写回)。
 */
typedef unsigned char u8;
typedef unsigned int  u16;

#define P0PU  (*(unsigned char volatile far *)0x7efe10)
#define P0PD  (*(unsigned char volatile far *)0x7efe11)
#define P1PU  (*(unsigned char volatile far *)0x7efe12)
#define P1PD  (*(unsigned char volatile far *)0x7efe13)
#define FARX  (*(unsigned char volatile far *)0x000100)

int main(void) {
    /* 扩展 SFR (XFR) 读写回 */
    P0PU = 0x5A;  if (P0PU != 0x5A) return 1;
    P0PD = 0xA5;  if (P0PD != 0xA5) return 2;
    P1PU = 0x0F;  if (P1PU != 0x0F) return 3;
    P1PD = 0xF0;  if (P1PD != 0xF0) return 4;
    /* far xram 读写回 */
    FARX = 0x3C;  if (FARX != 0x3C) return 5;
    FARX = 0x00;  if (FARX != 0x00) return 6;
    return 0;
}
