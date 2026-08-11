/*---------------------------------------------------------------------*/
/* --- Web: www.STCAI.com ---------------------------------------------*/
/*---------------------------------------------------------------------*/

#include	"config.h"
#include	"STC32G_I2C.h"
#include	"STC32G_GPIO.h"
#include	"STC32G_NVIC.h"
#include	"STC32G_UART.h"
#include	"STC32G_Timer.h"
#include	"STC32G_Switch.h"
#include	"STC32G_Soft_I2C.h"

/*************	功能说明	**************

内部集成I2C串行总线控制器做从机模式，SCL->P3.2, SDA->P3.3;
IO口模拟I2C做主机模式，SCL->P0.0, SDA->P0.1;
通过外部飞线连接 P0.0->P3.2, P0.1->P3.3，实现I2C自发自收功能。

使用Timer0的16位自动重装来产生1ms节拍,程序运行于这个节拍下,用户修改MCU主时钟频率时,自动定时于1ms.
计数器每秒钟加1, 计数范围为0~9999.

上电后主机每秒钟发送一次计数数据，通过串口打印收发数据。

下载时, 选择时钟 24MHz (可以在配置文件"config.h"中修改).

******************************************/

/*************	本地常量声明	**************/


/*************	本地变量声明	**************/

u16 msecond;
u16 second;   //测试用的秒计数变量
u8  tmp[4];     //通用数组

/*************	本地函数声明	**************/


/*************  外部函数和变量声明 *****************/



/******************** IO口配置 ********************/
void GPIO_config(void)
{
	P0_MODE_IO_PU(GPIO_Pin_0 | GPIO_Pin_1);		//P0.0,P0.1 设置为准双向口
	P3_MODE_IO_PU(GPIO_Pin_2 | GPIO_Pin_3);		//P3.2,P3.3 设置为准双向口
}

/************************ 定时器配置 ****************************/
void Timer_config(void)
{
	TIM_InitTypeDef		TIM_InitStructure;					//结构定义
	TIM_InitStructure.TIM_Mode      = TIM_16BitAutoReload;	//指定工作模式,   TIM_16BitAutoReload,TIM_16Bit,TIM_8BitAutoReload,TIM_16BitAutoReloadNoMask
	TIM_InitStructure.TIM_ClkSource = TIM_CLOCK_1T;		//指定时钟源,     TIM_CLOCK_1T,TIM_CLOCK_12T,TIM_CLOCK_Ext
	TIM_InitStructure.TIM_ClkOut    = DISABLE;			//是否输出高速脉冲, ENABLE或DISABLE
	TIM_InitStructure.TIM_Value     = (u16)(65536UL - (MAIN_Fosc / 1000UL));	//中断频率, 1000次/秒
	TIM_InitStructure.TIM_PS        = 0;				//8位预分频器(n+1), 0~255
	TIM_InitStructure.TIM_Run       = ENABLE;			//是否初始化后启动定时器, ENABLE或DISABLE
	Timer_Inilize(Timer0,&TIM_InitStructure);			//初始化Timer0	  Timer0,Timer1,Timer2,Timer3,Timer4
	NVIC_Timer0_Init(ENABLE,Priority_0);		//中断使能, ENABLE/DISABLE; 优先级(低到高) Priority_0,Priority_1,Priority_2,Priority_3
}

/****************  串口初始化函数 *****************/
void UART_config(void)
{
    COMx_InitDefine COMx_InitStructure; //结构定义

    COMx_InitStructure.UART_Mode      = UART_8bit_BRTx; //模式, UART_ShiftRight,UART_8bit_BRTx,UART_9bit,UART_9bit_BRTx
    COMx_InitStructure.UART_BRT_Use   = BRT_Timer1;     //选择波特率发生器, BRT_Timer1, BRT_Timer2 (注意: 串口2固定使用BRT_Timer2)
    COMx_InitStructure.UART_BaudRate  = 115200ul;       //波特率, 一般 110 ~ 115200
//    COMx_InitStructure.UART_RxEnable  = ENABLE;         //接收允许,   ENABLE 或 DISABLE
    UART_Configuration(UART1, &COMx_InitStructure);     //初始化串口1 UART1,UART2,UART3,UART4
    NVIC_UART1_Init(ENABLE,Priority_1);        //中断使能, ENABLE/DISABLE; 优先级(低到高) Priority_0,Priority_1,Priority_2,Priority_3

    UART1_SW(UART1_SW_P30_P31);         //UART1_SW_P30_P31,UART1_SW_P36_P37,UART1_SW_P16_P17,UART1_SW_P43_P44
}
/****************  I2C初始化函数 *****************/
void I2C_config(void)
{
	I2C_InitTypeDef		I2C_InitStructure;
	I2C_InitStructure.I2C_Mode      = I2C_Mode_Slave;		//主从选择   I2C_Mode_Master, I2C_Mode_Slave
	I2C_InitStructure.I2C_Enable    = ENABLE;				//I2C功能使能,   ENABLE, DISABLE
	I2C_InitStructure.I2C_SL_MA     = ENABLE;				//使能从机地址比较功能,   ENABLE, DISABLE
	I2C_InitStructure.I2C_SL_ADR    = 0x2d;					//从机设备地址,  0~127  (0x2d<<1 = 0x5a)
	I2C_Init(&I2C_InitStructure);
	NVIC_I2C_Init(I2C_Mode_Slave,I2C_ESTAI|I2C_ERXI|I2C_ETXI|I2C_ESTOI,Priority_0);	//主从模式, I2C_Mode_Master, I2C_Mode_Slave; 中断使能, I2C_ESTAI/I2C_ERXI/I2C_ETXI/I2C_ESTOI/DISABLE; 优先级(低到高) Priority_0,Priority_1,Priority_2,Priority_3

	I2C_SW(I2C_P33_P32);					//I2C_P14_P15,I2C_P24_P25,I2C_P76_P77,I2C_P33_P32
}

/******************** task A **************************/
void main(void)
{
	u8  i;
	
	WTST = 0;		//设置程序指令延时参数，赋值为0可将CPU执行指令的速度设置为最快
	EAXSFR();		//扩展SFR(XFR)访问使能 
	CKCON = 0;      //提高访问XRAM速度

	GPIO_config();
	Timer_config();
    UART_config();
	I2C_config();
	EA = 1;

	printf("STC32G I2C主从收发测试程序\r\n");

	while (1)
	{
		if(DisplayFlag)
		{
			DisplayFlag = 0;

            printf("I2C Read: ");
            for(i=0; i<4; i++)  printf("%d",I2C_Buffer[i]);
            printf("\r\n");
		}
		
		if(T0_1ms)
		{
			T0_1ms = 0;
			
			if(++msecond >= 1000)   //1秒到
			{
				msecond = 0;        //清1000ms计数
				second++;         //秒计数+1
				if(second >= 10000)    second = 0;   //秒计数范围为0~9999
                
                printf("I2C Send: %04u\r\n",second);

				tmp[0] = second / 1000;
				tmp[1] = (second % 1000) / 100;
				tmp[2] = (second % 100) / 10;
				tmp[3] = second % 10;

				SI2C_WriteNbyte(SLAW, 0, tmp, 4);
			}
		}
	}
}
