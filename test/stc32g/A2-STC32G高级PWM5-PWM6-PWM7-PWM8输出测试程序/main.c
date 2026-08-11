/*---------------------------------------------------------------------*/
/* --- Web: www.STCAI.com ---------------------------------------------*/
/*---------------------------------------------------------------------*/

#include	"stc32g.h"
//#include	"stc32g_pwma.h"
#include	"stc32g_pwmb.h"

/*************	功能说明	**************

本例程基于STC32G12K128为主控芯片的实验箱进行编写测试.

高级PWM定时器 PWM5,PWM6,PWM7,PWM8 每个通道都可独立实现PWM输出.

4个通道PWM根据需要设置对应输出口，可通过示波器观察输出的信号.

PWM周期和占空比可以根据需要自行设置，最高可达65535.

******************************************/

/*************	本地常量声明	**************/

#define CCR1_Val  ((uint16_t)1024)
#define CCR2_Val  ((uint16_t)512)
#define CCR3_Val  ((uint16_t)256)
#define CCR4_Val  ((uint16_t)128)

/*************	本地变量声明	**************/


/*************	本地函数声明	**************/



/*************  外部函数和变量声明 *****************/



/***************  PWM初始化函数 *****************/
void PWM_config(void)
{
    PWMB_DeInit();

    /* PWM Base configuration */
    /*
    PWMB_Period = 4095
    PWMB_Prescaler = 0
    PWMB_CounterMode = PWMB_COUNTERMODE_UP
    PWMB_RepetitionCounter = 0
    */

    PWMB_ENO   = ENO5P | ENO6P | ENO7P | ENO8P;	//输出通道选择,	ENO1P,ENO1N,ENO2P,ENO2N,ENO3P,ENO3N,ENO4P,ENO4N / ENO5P,ENO6P,ENO7P,ENO8P
    PWMB_PS      = PWM5_SW_P20| PWM6_SW_P21 | PWM7_SW_P22 | PWM8_SW_P23;	//切换端口,		PWM5_SW_P20,PWM5_SW_P17,PWM5_SW_P00,PWM5_SW_P74

    PWMB_TimeBaseInit(0, PWMB_COUNTERMODE_UP, 2047, 0);



    /* Channel 1, 2,3 and 4 Configuration in PWM mode */

    /*
    PWMB_OCMode = PWMB_OCMODE_PWM2
    PWMB_OutputState = PWMB_OUTPUTSTATE_ENABLE
    PWMB_OutputNState = PWMB_OUTPUTNSTATE_ENABLE
    PWMB_Pulse = CCR1_Val
    PWMB_OCPolarity = PWMB_OCPOLARITY_LOW
    PWMB_OCNPolarity = PWMB_OCNPOLARITY_HIGH
    PWMB_OCIdleState = PWMB_OCIDLESTATE_SET
    PWMB_OCNIdleState = PWMB_OCIDLESTATE_RESET

    */
    PWMB_OC5Init(PWMB_OCMODE_PWM2, PWMB_OUTPUTSTATE_ENABLE, CCR1_Val, PWMB_OCPOLARITY_LOW,
               PWMB_OCIDLESTATE_SET); 

    /*PWMB_Pulse = CCR2_Val*/
    PWMB_OC6Init(PWMB_OCMODE_PWM2, PWMB_OUTPUTSTATE_ENABLE, CCR2_Val, PWMB_OCPOLARITY_LOW,
               PWMB_OCIDLESTATE_SET);

    /*PWMB_Pulse = CCR3_Val*/
    PWMB_OC7Init(PWMB_OCMODE_PWM2, PWMB_OUTPUTSTATE_ENABLE, CCR3_Val, PWMB_OCPOLARITY_LOW,
               PWMB_OCIDLESTATE_SET);

    /*PWMB_Pulse = CCR4_Val*/
    PWMB_OC8Init(PWMB_OCMODE_PWM2, PWMB_OUTPUTSTATE_ENABLE, CCR4_Val, PWMB_OCPOLARITY_LOW,
               PWMB_OCIDLESTATE_SET);

    /* TIM1 counter enable */
    PWMB_Cmd(ENABLE);

    /* TIM1 Main Output Enable */
    PWMB_CtrlPWMOutputs(ENABLE);
}

/******************** 主函数**************************/
void main(void)
{
    EAXSFR();       //扩展寄存器访问使能
	PWM_config();

	while (1);
}



