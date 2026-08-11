/*---------------------------------------------------------------------*/
/* --- Web: www.STCAI.com ---------------------------------------------*/
/*---------------------------------------------------------------------*/

#include	"config.h"
#include	"STC32G_Exti.h"
#include	"STC32G_GPIO.h"
#include	"STC32G_UART.h"
#include	"STC32G_NVIC.h"
#include	"STC32G_Delay.h"
#include	"STC32G_Switch.h"

/*************	功能说明	**************

演示INT0~INT4 5个唤醒源将MCU从休眠唤醒.

从串口输出唤醒源跟唤醒次数，115200,N,8,1.

下载时, 选择时钟 22.1184MHz (用户可在"config.h"修改频率).

******************************************/

/*************	本地常量声明	**************/

sbit INT0 = P3^2;
sbit INT1 = P3^3;
sbit INT2 = P3^6;
sbit INT3 = P3^7;
sbit INT4 = P3^0;

/*************	本地变量声明	**************/

u8 WakeUpCnt;

/*************	本地函数声明	**************/



/*************  外部函数和变量声明 *****************/



/******************** IO口配置 ********************/
void GPIO_config(void)
{
	P3_MODE_IO_PU(GPIO_Pin_All);		//P3.0~P3.7 设置为准双向口
	P3_PULL_UP_ENABLE(GPIO_Pin_All);//P3 口内部上拉电阻使能
	P4_MODE_IO_PU(GPIO_Pin_6 | GPIO_Pin_7);	//P4.6,P4.7 设置为准双向口
}

/******************** INT配置 ********************/
void Exti_config(void)
{
	EXTI_InitTypeDef	Exti_InitStructure;							//结构定义

	Exti_InitStructure.EXTI_Mode      = EXT_MODE_Fall;//中断模式,   EXT_MODE_RiseFall,EXT_MODE_Fall
	Ext_Inilize(EXT_INT0,&Exti_InitStructure);				//初始化
	NVIC_INT0_Init(ENABLE,Priority_0);		//中断使能, ENABLE/DISABLE; 优先级(低到高) Priority_0,Priority_1,Priority_2,Priority_3

	Exti_InitStructure.EXTI_Mode      = EXT_MODE_Fall;//中断模式,   EXT_MODE_RiseFall,EXT_MODE_Fall
	Ext_Inilize(EXT_INT1,&Exti_InitStructure);				//初始化
	NVIC_INT1_Init(ENABLE,Priority_0);		//中断使能, ENABLE/DISABLE; 优先级(低到高) Priority_0,Priority_1,Priority_2,Priority_3

	NVIC_INT2_Init(ENABLE,NULL);		//中断使能, ENABLE/DISABLE; 无优先级
	NVIC_INT3_Init(ENABLE,NULL);		//中断使能, ENABLE/DISABLE; 无优先级
//	NVIC_INT4_Init(ENABLE,NULL);		//中断使能, ENABLE/DISABLE; 无优先级
}

/****************  串口初始化函数 *****************/
void UART_config(void)
{
	COMx_InitDefine		COMx_InitStructure;					//结构定义
	COMx_InitStructure.UART_Mode      = UART_8bit_BRTx;		//模式,   UART_ShiftRight,UART_8bit_BRTx,UART_9bit,UART_9bit_BRTx
	COMx_InitStructure.UART_BRT_Use   = BRT_Timer2;			//选择波特率发生器, BRT_Timer2 (注意: 串口2固定使用BRT_Timer2)
	COMx_InitStructure.UART_BaudRate  = 115200ul;			//波特率,     110 ~ 115200
	COMx_InitStructure.UART_RxEnable  = ENABLE;				//接收允许,   ENABLE或DISABLE
	UART_Configuration(UART1, &COMx_InitStructure);		//初始化串口 UART1,UART2,UART3,UART4
	NVIC_UART1_Init(ENABLE,Priority_1);		//中断使能, ENABLE/DISABLE; 优先级(低到高) Priority_0,Priority_1,Priority_2,Priority_3

//	UART2_SW(UART2_SW_P46_P47);		//UART2_SW_P10_P11,UART2_SW_P46_P47
}

/******************** 主函数***********************/
void main(void)
{
	WTST = 0;		//设置程序指令延时参数，赋值为0可将CPU执行指令的速度设置为最快
	EAXSFR();		//扩展SFR(XFR)访问使能 
	CKCON = 0;      //提高访问XRAM速度

	GPIO_config();
	UART_config();
	Exti_config();
	EA  = 1;		//Enable all interrupt

	PrintString1("STC32G EXINT Wakeup Test Programme!\r\n");	//UART发送一个字符串
	
	while(1)
	{
		while(!INT0);	//等待外中断为高电平
		while(!INT1);	//等待外中断为高电平
		while(!INT2);	//等待外中断为高电平
		while(!INT3);	//等待外中断为高电平
//		while(!INT4);	//等待外中断为高电平
		delay_ms(10);	//delay 10ms

		while(!INT0);	//等待外中断为高电平
		while(!INT1);	//等待外中断为高电平
		while(!INT2);	//等待外中断为高电平
		while(!INT3);	//等待外中断为高电平
//		while(!INT4);	//等待外中断为高电平

		WakeUpSource = 0;
		PrintString1("MCU进入休眠状态！\r\n");

		PD = 1;		//Sleep
		_nop_();
		_nop_();
		_nop_();
		_nop_();
		_nop_();
		_nop_();
		_nop_();
		_nop_();
		
		if(WakeUpSource == 1)	PrintString1("外中断INT0唤醒  ");
		if(WakeUpSource == 2)	PrintString1("外中断INT1唤醒  ");
		if(WakeUpSource == 3)	PrintString1("外中断INT2唤醒  ");
		if(WakeUpSource == 4)	PrintString1("外中断INT3唤醒  ");
		if(WakeUpSource == 5)	PrintString1("外中断INT4唤醒  ");
		
		WakeUpCnt++;
		TX1_write2buff((u8)(WakeUpCnt/100+'0'));
		TX1_write2buff((u8)(WakeUpCnt%100/10+'0'));
		TX1_write2buff((u8)(WakeUpCnt%10+'0'));
		PrintString1("次唤醒\r\n");
	}

}

