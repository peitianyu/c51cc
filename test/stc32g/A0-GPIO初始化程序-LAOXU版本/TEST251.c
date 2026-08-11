/*---------------------------------------------------------------------*/
/* --- Web: www.STCAI.com ---------------------------------------------*/
/*---------------------------------------------------------------------*/
/* 本例程使用IO口初始化库函数由热心用户LAOXU提供，有兴趣的用户可参考使用   */
/* 例程来源：https://www.stcaimcu.com/forum.php?mod=viewthread&tid=818 */
/*---------------------------------------------------------------------*/

#include <STC32G.H> 
#include <STC_GPIO.H> 
#include "stdio.h"

#define MAIN_Fosc     22118400L   //定义主时钟
#define Baudrate      115200L
#define TM            (65536 -(MAIN_Fosc/Baudrate/4))

/******************** 串口打印函数 ********************/
void UartInit(void)
{
	SCON = (SCON & 0x3f) | 0x40; 
	T2L  = TM;
	T2H  = TM>>8;
	AUXR |= 0x15;
}

void UartPutc(unsigned char dat)
{
	SBUF = dat; 
	while(TI==0);
	TI = 0;
}

char putchar(char c)
{
	UartPutc(c);
	return c;
}

void main(void)
{  	
//			    ===========编 程 实 例===========
    UartInit();
//                               ------Cortex-M051风格1------

//1.void GPIO_SET_MODE(Pn, b7,b6,b5,b4,b3,b2,b1,b0);          // 设置IO口输入输出模式(n=0-7)    

//  使用方式：
    GPIO_SET_MODE(P1, GPIO_PullUp,GPIO_HighZ,GPIO_PullUp,GPIO_HighZ,GPIO_OUT_PP,GPIO_OUT_OD,GPIO_OUT_PP,GPIO_OUT_OD);
                 // 设置P1口的bit.7-bit.0位，依次为PullUp,HighZ,PullUp,HighZ,OUT_PP,OUT_OD,OUT_PP,OUT_OD模式 
	//  P1M1 = 0x55;  // Bin(0101,0101);  0: PullUp, 0: OUT_PP, 1: HighZ; 1: OUT_OD
	//  P1M0 = 0x0f;  // Bin(0000,1111);  0:         1:         0:        1:
    printf("1.P1M1=0x%02x,P1M0=0x%02x\r\n",P1M1,P1M0);

//2.void GPIO_SET_PIN_MODE(Port, Pin_Mode);                 // 设置IO口其中1位或数位输入输出模式(N=0-7,i=0-7)  

//  例如：
    GPIO_SET_PIN_MODE(P1, GPIO_OUT_PP_6);        // 设置P1口的第bit.6位为OUT_PP模式
		//  P1M0 |= 0x40; P1M1 &= ~0x40; 
		 // P1M0 = 0x4F; P1M1 = 0x15; 
	//  P1M1 = 0x15;  // Bin(0001,0101);  0: PullUp, 0: OUT_PP, 1: HighZ; 1: OUT_OD
	//  P1M0 = 0x4f;  // Bin(0100,1111);  0:         1:         0:        1:
    GPIO_SET_PIN_MODE(P2, GPIO_PullUp_7 | GPIO_OUT_PP_2 | GPIO_HighZ_0);        // 设置P2口的第bit.5位为PullUp模式,第bit.2位为OUT_PP模式,第bit.0位为HighZ模式 
		// P2M0 = (P2M0 & ~0x81) | 0x04; P2M1 = (P2M1 & ~0x84) | 0x01; 
	//  P2M1 = 0x7B;  // Bin(0111,1011);  0: PullUp, 0: OUT_PP, 1: HighZ; 1: OUT_OD
	//  P2M0 = 0x04;  // Bin(0000,0100);  0:         1:         0:        1:
    printf("2.P1M1=0x%02x,P1M0=0x%02x\r\n",P1M1,P1M0);
    printf("2.P2M1=0x%02x,P2M0=0x%02x\r\n",P2M1,P2M0);

//                              ------Cortex-M051风格2------

//3.void Pn_SET_MODE(b7,b6,b5,b4,b3,b2,b1,b0);          // 设置Pn IO口输入输出模式(n=0-4)    

//  使用方式：
    P1_SET_MODE(GPIO_OUT_PP,GPIO_PullUp,GPIO_OUT_OD,GPIO_HighZ,GPIO_OUT_PP,GPIO_OUT_OD,GPIO_PullUp,GPIO_PullUp);
                 // 设置P1口的bit.7-bit.0位，依次为PullUp,HighZ,PullUp,HighZ,OUT_PP,OUT_OD,PullUp,PullUp模式 
	//  P1M1 = 0x34;  // Bin(0011,0100);  0: PullUp, 0: OUT_PP, 1: HighZ; 1: OUT_OD
	//  P1M0 = 0xAC;  // Bin(1010,1100);  0:         1:         0:        1:
    printf("3.P1M1=0x%02x,P1M0=0x%02x\r\n",P1M1,P1M0);


//4.void Pn_SET_PIN_MODE(Pin_Mode);                 // 设置Pn IO口其中1位或数位输入输出模式(N=0-7,i=0-7)  

//  例如：
    P1_SET_PIN_MODE(GPIO_OUT_OD_5);        // 设置P1口的第bit.5位为OUT_OD模式
		 // P1M0 |= 0x20; P1M1 &= ~0x20; 
	//  P1M1 = 0x34;  // Bin(0011,0100);  0: PullUp, 0: OUT_PP, 1: HighZ; 1: OUT_OD
	//  P1M0 = 0xAC;  // Bin(1010,1100);  0:         1:         0:        1:
    P2_SET_PIN_MODE(GPIO_PullUp_7 | GPIO_OUT_PP_2 | GPIO_HighZ_4);        // 设置P2口的第bit.5位为PullUp模式,第bit.2位为OUT_PP模式,第bit.4位为HighZ模式 
     // P2M0 = (P2M0 & ~0x90) | 0x04; P2M1 = (P2M1 & ~0x84) | 0x10; 
	//  P2M1 = 0x7B;  // Bin(0111,1011);  0: PullUp, 0: OUT_PP, 1: HighZ; 1: OUT_OD
	//  P2M0 = 0x04;  // Bin(0000,0100);  0:         1:         0:        1:
    printf("4.P1M1=0x%02x,P1M0=0x%02x\r\n",P1M1,P1M0);
    printf("4.P2M1=0x%02x,P2M0=0x%02x\r\n",P2M1,P2M0);

//                               -------51系列风格-------

//5.u8 GPIO_Mode(b7,b6,b5,b4,b3,b2,b1,b0);  设置IO口输入输出模式  

//  使用方式：
//  PnMode = GPIO_Mode(b7,b6,b5,b4,b3,b2,b1,b0);  设置IO口输入输出模式 

    P1Mode = GPIO_Mode(GPIO_PullUp,GPIO_HighZ,GPIO_PullUp,GPIO_HighZ,GPIO_OUT_PP,GPIO_OUT_OD,GPIO_OUT_PP,GPIO_OUT_OD);
                 // 设置P1口的bit.7-bit.0位，依次为PullUp,HighZ,PullUp,HighZ,OUT_PP,OUT_OD,OUT_PP,OUT_OD模式 
	//  P1M1 = 0x55;  // Bin(0101,0101);  0: PullUp, 0: OUT_PP, 1: HighZ; 1: OUT_OD
	//  P1M0 = 0x0f;  // Bin(0000,1111);  0:         1:         0:        1:
    printf("5.P1M1=0x%02x,P1M0=0x%02x\r\n",P1M1,P1M0);

							 
    while(1);
}