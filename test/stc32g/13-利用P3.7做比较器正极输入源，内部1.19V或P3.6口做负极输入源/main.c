/*---------------------------------------------------------------------*/
/* --- Web: www.STCAI.com ---------------------------------------------*/
/*---------------------------------------------------------------------*/

/*************  功能说明    **************

比较器的正极可以是 P3.7/P5.0/P5.1 端口或者 ADC 的模拟输入通道，

而负极可以是 P3.6 端口或者是内部 BandGap 经过 OP 后的 REFV 电压（1.19V内部固定比较电压）。

通过中断或者查询方式读取比较器比较结果，CMP+的电平低于CMP-的电平P47口输出低电平，反之输出高电平。

下载时, 选择时钟 24MHz (可以在配置文件"config.h"中修改).

******************************************/

#include	"config.h"
#include	"STC32G_GPIO.h"
#include	"STC32G_NVIC.h"
#include	"STC32G_Compare.h"

/*************	本地常量声明	**************/


/*************	本地变量声明	**************/


/*************	本地函数声明	**************/


/*************  外部函数和变量声明 *****************/


/************************ 比较器配置 ****************************/
void	CMP_config(void)
{
	CMP_InitDefine CMP_InitStructure;						//结构定义
	CMP_InitStructure.CMP_EN = ENABLE;								//允许比较器		ENABLE,DISABLE
	CMP_InitStructure.CMP_P_Select     = CMP_P_P37;		//比较器输入正极选择, CMP_P_P37/CMP_P_P50/CMP_P_P51, CMP_P_ADC: 由ADC模拟输入端做正输入.
	CMP_InitStructure.CMP_N_Select     = CMP_N_GAP;		//比较器输入负极选择, CMP_N_GAP: 选择内部BandGap经过OP后的电压做负输入, CMP_N_P36: 选择P3.6做负输入.
	CMP_InitStructure.CMP_InvCMPO      = DISABLE;			//比较器输出取反, 	ENABLE,DISABLE
	CMP_InitStructure.CMP_100nsFilter  = ENABLE;			//内部0.1us滤波,  	ENABLE,DISABLE
	CMP_InitStructure.CMP_Outpt_En     = ENABLE;			//允许比较结果输出,ENABLE,DISABLE
	CMP_InitStructure.CMP_OutDelayDuty = 16;					//比较结果变化延时周期数, 0~63
	CMP_Inilize(&CMP_InitStructure);				//初始化比较器
	NVIC_CMP_Init(RISING_EDGE|FALLING_EDGE,Priority_0);	//中断使能, RISING_EDGE/FALLING_EDGE/DISABLE; 优先级(低到高) Priority_0,Priority_1,Priority_2,Priority_3
}

/************************ IO口配置 ****************************/
void	GPIO_config(void)
{
	GPIO_InitTypeDef	GPIO_InitStructure;				//结构定义
	GPIO_InitStructure.Pin  = GPIO_Pin_6 | GPIO_Pin_7;				//指定要初始化的IO, GPIO_Pin_0 ~ GPIO_Pin_7, 或操作
	GPIO_InitStructure.Mode = GPIO_HighZ;				//指定IO的输入或输出方式,GPIO_PullUp,GPIO_HighZ,GPIO_OUT_OD,GPIO_OUT_PP
	GPIO_Inilize(GPIO_P3,&GPIO_InitStructure);	//初始化

	GPIO_InitStructure.Pin  = GPIO_Pin_7;				//指定要初始化的IO, GPIO_Pin_0 ~ GPIO_Pin_7, 或操作
	GPIO_InitStructure.Mode = GPIO_PullUp;			//指定IO的输入或输出方式,GPIO_PullUp,GPIO_HighZ,GPIO_OUT_OD,GPIO_OUT_PP
	GPIO_Inilize(GPIO_P4,&GPIO_InitStructure);	//初始化
}

/************************ 定时器配置 ****************************/

/******************** task A **************************/
void main(void)
{
	WTST = 0;		//设置程序指令延时参数，赋值为0可将CPU执行指令的速度设置为最快
	EAXSFR();		//扩展SFR(XFR)访问使能 
	CKCON = 0;      //提高访问XRAM速度

	GPIO_config();
	CMP_config();

	EA = 1;
	while (1);
}
