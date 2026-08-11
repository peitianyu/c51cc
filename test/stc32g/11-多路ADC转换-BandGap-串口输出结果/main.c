/*---------------------------------------------------------------------*/
/* --- Web: www.STCAI.com ---------------------------------------------*/
/*---------------------------------------------------------------------*/

#include	"config.h"
#include	"STC32G_GPIO.h"
#include	"STC32G_ADC.h"
#include	"STC32G_UART.h"
#include	"STC32G_NVIC.h"
#include	"STC32G_Delay.h"
#include	"STC32G_Switch.h"

/*************	功能说明	**************

程序演示多路ADC查询采样，通过串口2(P4.6,P4.7)发送给上位机，波特率115200,N,8,1。

说明:
    ADC的第15通道是用来测试内部BandGap参考电压的,由于内部BandGap参考电
压很稳定,不会随芯片的工作电压的改变而变化,所以可以通过测量内部BandGap
参考电压,然后通过ADC的值便可反推出VCC的电压,从而用户可以实现自己的低
压检测功能.
    ADC的第15通道的测量方法:通过ADC的第15通道读取当前内部BandGap参考电压值.
    用户实现自己的低压检测功能的实现方法:首先用户需要在VCC很精准的情况下
(比如5.0V),测量出内部BandGap参考电压的ADC转换值(比如为BGV5),并这个值保存
到EEPROM中,然后在低压检测的代码中,在实际VCC变化后,所测量出的内部BandGap
参考电压的ADC转换值(比如为BGVx),通过计算公式: 实际VCC = 5.0V * BGV5 / BGVx,
即可计算出实际的VCC电压值,需要注意的是,第一步的BGV5的基准测量一定要精确.

标定内部基准Vref, 提供一个稳定的工作电压Vcc, 读内部基准Nref. 
计算内部基准(10位AD) Vref = Nref * Vcc / 1024.
计算内部基准(12位AD) Vref = Nref * Vcc / 4096.

测量某个电压, 读ADC值Nx, 则电压 Ux = Vref * Nx / Nref. 一般Vref = 1190mV.

下载时, 选择时钟 22.1184MHz (可以在配置文件"config.h"中修改).

******************************************/

/*************	本地常量声明	**************/


/*************	本地变量声明	**************/

u16	Nref;

/*************	本地函数声明	**************/


/*************  外部函数和变量声明 *****************/


/******************* IO配置函数 *******************/
void	GPIO_config(void)
{
	P1_MODE_IN_HIZ(GPIO_Pin_LOW);		//P1.0~P1.4 设置为高阻输入
	P4_MODE_IO_PU(GPIO_Pin_6 | GPIO_Pin_7);	//P4.6,P4.7 设置为准双向口
}

/******************* AD配置函数 *******************/
void	ADC_config(void)
{
	ADC_InitTypeDef		ADC_InitStructure;		//结构定义
	ADC_InitStructure.ADC_SMPduty   = 31;		//ADC 模拟信号采样时间控制, 0~31（注意： SMPDUTY 一定不能设置小于 10）
	ADC_InitStructure.ADC_CsSetup   = 0;		//ADC 通道选择时间控制 0(默认),1
	ADC_InitStructure.ADC_CsHold    = 1;		//ADC 通道选择保持时间控制 0,1(默认),2,3
	ADC_InitStructure.ADC_Speed     = ADC_SPEED_2X16T;		//设置 ADC 工作时钟频率	ADC_SPEED_2X1T~ADC_SPEED_2X16T
	ADC_InitStructure.ADC_AdjResult = ADC_RIGHT_JUSTIFIED;	//ADC结果调整,	ADC_LEFT_JUSTIFIED,ADC_RIGHT_JUSTIFIED
	ADC_Inilize(&ADC_InitStructure);		//初始化
	ADC_PowerControl(ENABLE);						//ADC电源开关, ENABLE或DISABLE
	NVIC_ADC_Init(DISABLE,Priority_0);		//中断使能, ENABLE/DISABLE; 优先级(低到高) Priority_0,Priority_1,Priority_2,Priority_3
}

/***************  串口初始化函数 *****************/
void	UART_config(void)
{
	COMx_InitDefine		COMx_InitStructure;					//结构定义
	COMx_InitStructure.UART_Mode      = UART_8bit_BRTx;		//模式,   UART_ShiftRight,UART_8bit_BRTx,UART_9bit,UART_9bit_BRTx
	COMx_InitStructure.UART_BRT_Use   = BRT_Timer2;			//选择波特率发生器, BRT_Timer2 (注意: 串口2固定使用BRT_Timer2)
	COMx_InitStructure.UART_BaudRate  = 115200ul;			//波特率,     110 ~ 115200
	COMx_InitStructure.UART_RxEnable  = ENABLE;				//接收允许,   ENABLE或DISABLE
	UART_Configuration(UART2, &COMx_InitStructure);		//初始化串口 UART1,UART2,UART3,UART4
	NVIC_UART2_Init(ENABLE,Priority_1);		//中断使能, ENABLE/DISABLE; 优先级(低到高) Priority_0,Priority_1,Priority_2,Priority_3

	UART2_SW(UART2_SW_P46_P47);		//UART2_SW_P10_P11,UART2_SW_P46_P47
}

/**********************************************/
void main(void)
{
	u8	i;
	u16	j;

	WTST = 0;		//设置程序指令延时参数，赋值为0可将CPU执行指令的速度设置为最快
	EAXSFR();		//扩展SFR(XFR)访问使能 
	CKCON = 0;      //提高访问XRAM速度

	GPIO_config();
	UART_config();
	ADC_config();
	EA = 1;

	printf("STC32G AD to UART Test Programme!\r\n");	//UART发送一个字符串
	j = Get_ADCResult(15);	//读内部基准电压, 读15通道
	Nref = j;

	while (1)
	{
		for(i=0; i<4; i++)
		{
			delay_ms(250);		//为了让发送的速度慢一点，延时250ms

			if(i < 3)	//ADC0~ADC2
			{
				j = Get_ADCResult(i);	//参数0~14,查询方式做一次ADC, 返回值就是结果, == 4096 为错误
				printf("AD%d=%04d  ",i,j);
			}
			else		//内基准
			{
				j = Get_ADCResult(15);	//读内部基准电压, 读15通道
				Nref = j;
				printf("ADref=%04d  ",j);
			}
			printf("V=%04.3f  ",((float)1.190 * j) / Nref);
		}
		printf("\r\n");
	}
}



