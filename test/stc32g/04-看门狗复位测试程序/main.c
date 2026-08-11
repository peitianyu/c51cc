/*---------------------------------------------------------------------*/
/* --- Web: www.STCAI.com ---------------------------------------------*/
/*---------------------------------------------------------------------*/

#include	"config.h"
#include	"STC32G_WDT.h"
#include	"STC32G_GPIO.h"
#include	"STC32G_Delay.h"

/*************   功能说明   ***************

初始化翻转电平, 5秒后不喂狗, 等待看门狗复位.

下载时, 选择时钟 24MHz (用户可在"config.h"修改频率).

******************************************/

/*************	本地常量声明	**************/


/*************	本地变量声明	**************/
u16 ms_cnt;
u8  second;    //测试用的计数变量

/*************	本地函数声明	**************/


/*************  外部函数和变量声明 *****************/



/******************** IO口配置 ********************/
void	GPIO_config(void)
{
	GPIO_InitTypeDef	GPIO_InitStructure;			//结构定义

	GPIO_InitStructure.Pin  = GPIO_Pin_7;			//指定要初始化的IO, GPIO_Pin_0 ~ GPIO_Pin_7, 或操作
	GPIO_InitStructure.Mode = GPIO_PullUp;			//指定IO的输入或输出方式,GPIO_PullUp,GPIO_HighZ,GPIO_OUT_OD,GPIO_OUT_PP
	GPIO_Inilize(GPIO_P4,&GPIO_InitStructure);	    //初始化
}

/******************** WDT配置 ********************/
void	WDT_config(void)
{
	WDT_InitTypeDef	WDT_InitStructure;					//结构定义

	WDT_InitStructure.WDT_Enable     = ENABLE;			//看门狗使能   ENABLE或DISABLE
	WDT_InitStructure.WDT_IDLE_Mode  = WDT_IDLE_STOP;	//IDLE模式是否停止计数		WDT_IDLE_STOP,WDT_IDLE_RUN
	WDT_InitStructure.WDT_PS         = WDT_SCALE_16;	//看门狗定时器时钟分频系数	WDT_SCALE_2,WDT_SCALE_4,WDT_SCALE_8,WDT_SCALE_16,WDT_SCALE_32,WDT_SCALE_64,WDT_SCALE_128,WDT_SCALE_256
	WDT_Inilize(&WDT_InitStructure);					//初始化
}

/******************** 主函数***********************/
void main(void)
{
	WTST = 0;		//设置程序指令延时参数，赋值为0可将CPU执行指令的速度设置为最快
	EAXSFR();		//扩展SFR(XFR)访问使能 
	CKCON = 0;      //提高访问XRAM速度

	GPIO_config();
	
	P47 = 0;
	delay_ms(200);
	P47 = 1;
	delay_ms(200);
	P47 = 0;
	delay_ms(200);
	P47 = 1;
	delay_ms(200);
	
	WDT_config();

	RSTFLAG |= 0x04;   //设置看门狗复位需要检测P3.2的状态，否则看门狗复位后进入USB下载模式

	while(1)
	{
		delay_ms(1);    //延时1ms
		if(second <= 5)    //5秒后不喂狗, 将复位,
			WDT_Clear();    // 喂狗

		if(++ms_cnt >= 1000)
		{
			ms_cnt = 0;
			second++;
		}
	}
}

