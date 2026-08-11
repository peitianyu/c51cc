/*---------------------------------------------------------------------*/
/* --- Web: www.STCAI.com ---------------------------------------------*/
/*---------------------------------------------------------------------*/

#include	"STC32G_PWM.h"
#include	"STC32G_GPIO.h"
#include	"STC32G_NVIC.h"
#include	"STC32G_Delay.h"
#include	"STC32G_Clock.h"

/*************   功能说明   ***************

高速高级PWM定时器 PWM1P/PWM1N,PWM2P/PWM2N,PWM3P/PWM3N,PWM4P/PWM4N 每个通道都可独立实现PWM输出，或者两两互补对称输出.

8个通道PWM设置对应P6的8个端口.

通过P6口上连接的8个LED灯，利用PWM实现呼吸灯效果.

高级PWM定时器 PWM5,PWM6,PWM7,PWM8 每个通道都可独立实现PWM输出.

4个通道PWM根据需要设置对应输出口，可通过示波器观察输出的信号.

PWM周期和占空比可以根据需要自行设置，最高可达65535.

下载时, 选择时钟 24MHz (用户可在"config.h"修改频率).

******************************************/


/*************	本地常量声明	**************/


/*************	本地变量声明	**************/

PWMx_Duty PWMA_Duty;
bit PWM1_Flag;
bit PWM2_Flag;
bit PWM3_Flag;
bit PWM4_Flag;

PWMx_Duty PWMB_Duty;
bit PWM5_Flag;
bit PWM6_Flag;
bit PWM7_Flag;
bit PWM8_Flag;

/*************	本地函数声明	**************/


/*************  外部函数和变量声明 *****************/


/******************** IO口配置 ********************/
void GPIO_config(void)
{
	PWM1_USE_P60P61();
	PWM2_USE_P62P63();
	PWM3_USE_P64P65();
	PWM4_USE_P66P67();

	PWM5_USE_P74();
	PWM6_USE_P75();
	PWM7_USE_P76();
	PWM8_USE_P77();
	
	P4_MODE_IO_PU(GPIO_Pin_0);			//P4.0 设置为准双向口
	P40 = 0;		//打开实验箱LED电源
}

/******************** SPI 配置 ********************/
void HSPWM_config(void)
{
	HSPWMx_InitDefine		PWMx_InitStructure;

	PWMx_InitStructure.PWM_EnoSelect= ENO1P|ENO1N|ENO2P|ENO2N|ENO3P|ENO3N|ENO4P|ENO4N;	//输出通道选择,	ENO1P,ENO1N,ENO2P,ENO2N,ENO3P,ENO3N,ENO4P,ENO4N / ENO5P,ENO6P,ENO7P,ENO8P
	PWMx_InitStructure.PWM_Period   = 2047;							//周期时间,   0~65535
	PWMx_InitStructure.PWM_DeadTime = 0;								//死区发生器设置, 0~255
	PWMx_InitStructure.PWM_MainOutEnable= ENABLE;				//主输出使能, ENABLE,DISABLE
	PWMx_InitStructure.PWM_CEN_Enable   = ENABLE;				//使能计数器, ENABLE,DISABLE
	HSPWM_Configuration(PWMA, &PWMx_InitStructure, &PWMA_Duty);				//初始化PWM通用寄存器,  PWMA,PWMB
	PWMx_InitStructure.PWM_EnoSelect= ENO5P|ENO6P|ENO7P|ENO8P;	//输出通道选择,	ENO1P,ENO1N,ENO2P,ENO2N,ENO3P,ENO3N,ENO4P,ENO4N / ENO5P,ENO6P,ENO7P,ENO8P
	HSPWM_Configuration(PWMB, &PWMx_InitStructure, &PWMB_Duty);				//初始化PWM通用寄存器,  PWMA,PWMB

	HSPllClkConfig(MCLKSEL_HIRC,PLL_96M,0);    //系统时钟选择,PLL时钟选择,时钟分频系数
	NVIC_PWM_Init(PWMA,DISABLE,Priority_0);
	NVIC_PWM_Init(PWMB,DISABLE,Priority_0);
}

/**********************************************/
void main(void)
{
	WTST = 0;		//设置程序指令延时参数，赋值为0可将CPU执行指令的速度设置为最快
	EAXSFR();		//扩展SFR(XFR)访问使能 
	CKCON = 0;      //提高访问XRAM速度

	GPIO_config();
	HSPWM_config();
	EA = 1;

	PWMA_Duty.PWM1_Duty = 128;
	PWMA_Duty.PWM2_Duty = 256;
	PWMA_Duty.PWM3_Duty = 512;
	PWMA_Duty.PWM4_Duty = 1024;

	PWMB_Duty.PWM5_Duty = 128;
	PWMB_Duty.PWM6_Duty = 256;
	PWMB_Duty.PWM7_Duty = 512;
	PWMB_Duty.PWM8_Duty = 1024;
	
	while (1)
	{
		delay_ms(1);
		
		if(!PWM1_Flag)
		{
			PWMA_Duty.PWM1_Duty++;
			if(PWMA_Duty.PWM1_Duty >= 2047) PWM1_Flag = 1;
		}
		else
		{
			PWMA_Duty.PWM1_Duty--;
			if(PWMA_Duty.PWM1_Duty <= 0) PWM1_Flag = 0;
		}

		if(!PWM2_Flag)
		{
			PWMA_Duty.PWM2_Duty++;
			if(PWMA_Duty.PWM2_Duty >= 2047) PWM2_Flag = 1;
		}
		else
		{
			PWMA_Duty.PWM2_Duty--;
			if(PWMA_Duty.PWM2_Duty <= 0) PWM2_Flag = 0;
		}

		if(!PWM3_Flag)
		{
			PWMA_Duty.PWM3_Duty++;
			if(PWMA_Duty.PWM3_Duty >= 2047) PWM3_Flag = 1;
		}
		else
		{
			PWMA_Duty.PWM3_Duty--;
			if(PWMA_Duty.PWM3_Duty <= 0) PWM3_Flag = 0;
		}

		if(!PWM4_Flag)
		{
			PWMA_Duty.PWM4_Duty++;
			if(PWMA_Duty.PWM4_Duty >= 2047) PWM4_Flag = 1;
		}
		else
		{
			PWMA_Duty.PWM4_Duty--;
			if(PWMA_Duty.PWM4_Duty <= 0) PWM4_Flag = 0;
		}
		
		if(!PWM5_Flag)
		{
			PWMB_Duty.PWM5_Duty++;
			if(PWMB_Duty.PWM5_Duty >= 2047) PWM5_Flag = 1;
		}
		else
		{
			PWMB_Duty.PWM5_Duty--;
			if(PWMB_Duty.PWM5_Duty <= 0) PWM5_Flag = 0;
		}

		if(!PWM6_Flag)
		{
			PWMB_Duty.PWM6_Duty++;
			if(PWMB_Duty.PWM6_Duty >= 2047) PWM6_Flag = 1;
		}
		else
		{
			PWMB_Duty.PWM6_Duty--;
			if(PWMB_Duty.PWM6_Duty <= 0) PWM6_Flag = 0;
		}

		if(!PWM7_Flag)
		{
			PWMB_Duty.PWM7_Duty++;
			if(PWMB_Duty.PWM7_Duty >= 2047) PWM7_Flag = 1;
		}
		else
		{
			PWMB_Duty.PWM7_Duty--;
			if(PWMB_Duty.PWM7_Duty <= 0) PWM7_Flag = 0;
		}

		if(!PWM8_Flag)
		{
			PWMB_Duty.PWM8_Duty++;
			if(PWMB_Duty.PWM8_Duty >= 2047) PWM8_Flag = 1;
		}
		else
		{
			PWMB_Duty.PWM8_Duty--;
			if(PWMB_Duty.PWM8_Duty <= 0) PWM8_Flag = 0;
		}
		
		UpdateHSPwm(PWMA, &PWMA_Duty);
		UpdateHSPwm(PWMB, &PWMB_Duty);
	}
}
