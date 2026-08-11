/*---------------------------------------------------------------------*/
/* --- Web: www.STCAI.com ---------------------------------------------*/
/*---------------------------------------------------------------------*/

#include	"config.h"
#include	"STC32G_GPIO.h"
#include	"STC32G_UART.h"
#include	"STC32G_NVIC.h"
#include	"STC32G_Delay.h"
#include	"STC32G_Switch.h"

/*************	功能说明	**************

双串口全双工中断方式收发通讯程序。

通过PC向MCU发送数据, MCU收到后通过串口把收到的数据原样返回, 默认波特率：115200,N,8,1.

通过开启 STC32G_UART.h 头文件里面的 UART1~UART4 定义，启动不同通道的串口通信。

用定时器做波特率发生器，建议使用1T模式(除非低波特率用12T)，并选择可被波特率整除的时钟频率，以提高精度。

下载时, 选择时钟 22.1184MHz (可以在配置文件"config.h"中修改).

******************************************/

/*************	本地常量声明	**************/


/*************	本地变量声明	**************/


/*************	本地函数声明	**************/


/*************  外部函数和变量声明 *****************/


/******************* IO配置函数 *******************/
void	GPIO_config(void)
{
	GPIO_InitTypeDef	GPIO_InitStructure;		//结构定义

	GPIO_InitStructure.Pin  = GPIO_Pin_2 | GPIO_Pin_3;		//指定要初始化的IO, GPIO_Pin_0 ~ GPIO_Pin_7
	GPIO_InitStructure.Mode = GPIO_PullUp;	//指定IO的输入或输出方式,GPIO_PullUp,GPIO_HighZ,GPIO_OUT_OD,GPIO_OUT_PP
	GPIO_Inilize(GPIO_P0,&GPIO_InitStructure);	//初始化
}

/***************  串口初始化函数 *****************/
void	UART_config(void)
{
	COMx_InitDefine		COMx_InitStructure;					//结构定义
	COMx_InitStructure.UART_Mode      = UART_8bit_BRTx;		//模式,   UART_ShiftRight,UART_8bit_BRTx,UART_9bit,UART_9bit_BRTx
	COMx_InitStructure.UART_BRT_Use   = BRT_Timer4;			//选择波特率发生器,   BRT_Timer2, BRT_Timer4 (注意: 串口2固定使用BRT_Timer2)
	COMx_InitStructure.UART_BaudRate  = 115200ul;			//波特率,     110 ~ 115200
	COMx_InitStructure.UART_RxEnable  = ENABLE;				//接收允许,   ENABLE或DISABLE
	UART_Configuration(UART4, &COMx_InitStructure);		//初始化串口4 UART1,UART2,UART3,UART4
	NVIC_UART4_Init(ENABLE,Priority_1);		//中断使能, ENABLE/DISABLE; 优先级(低到高) Priority_0,Priority_1,Priority_2,Priority_3

	UART4_SW(UART4_SW_P02_P03);		//UART4_SW_P02_P03,UART4_SW_P52_P53
}

/**********************************************/
void main(void)
{
	u8	i;

	WTST = 0;		//设置程序指令延时参数，赋值为0可将CPU执行指令的速度设置为最快
	EAXSFR();		//扩展SFR(XFR)访问使能 
	CKCON = 0;      //提高访问XRAM速度

	GPIO_config();
	UART_config();
	EA = 1;
	
	PrintString4("STC32G UART4 Test Programme!\r\n");	//UART4发送一个字符串

	while (1)
	{
		delay_ms(1);
		if(COM4.RX_TimeOut > 0)		//超时计数
		{
			if(--COM4.RX_TimeOut == 0)
			{
				if(COM4.RX_Cnt > 0)
				{
					for(i=0; i<COM4.RX_Cnt; i++)	TX4_write2buff(RX4_Buffer[i]);	//收到的数据原样返回
				}
				COM4.RX_Cnt = 0;
			}
		}
	}
}



