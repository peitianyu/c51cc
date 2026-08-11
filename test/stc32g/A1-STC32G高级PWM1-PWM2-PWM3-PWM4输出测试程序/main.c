/*---------------------------------------------------------------------*/
/* --- Web: www.STCAI.com ---------------------------------------------*/
/*---------------------------------------------------------------------*/

#include	"stc32g.h"
#include	"stc32g_pwma.h"
//#include	"stc32g_pwmb.h"

/*************	功能说明	**************

本例程基于STC32G12K128为主控芯片的实验箱进行编写测试.

高级PWM定时器 PWM1P/PWM1N,PWM2P/PWM2N,PWM3P/PWM3N,PWM4P/PWM4N 每个通道都可独立实现PWM输出，或者两两互补对称输出.

8个通道PWM设置对应P6的8个端口.

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
    PWMA_DeInit();

    /* PWM Base configuration */
    /*
    PWMA_Period = 4095
    PWMA_Prescaler = 0
    PWMA_CounterMode = PWMA_COUNTERMODE_UP
    PWMA_RepetitionCounter = 0
    */
    PWMA_ENO = ENO1P | ENO1N | ENO2P | ENO2N | ENO3P | ENO3N | ENO4P | ENO4N;		
    PWMA_PS = PWM1_SW_P60_P61| PWM2_SW_P62_P63 | PWM3_SW_P64_P65 | PWM4_SW_P66_P67;	//切换端口,		PWM1_SW_P10_P11,PWM1_SW_P20_P21,PWM1_SW_P60_P61
    PWMA_TimeBaseInit(0, PWMA_COUNTERMODE_UP, 2047, 0);


    /* Channel 1, 2,3 and 4 Configuration in PWM mode */

    /*
    PWMA_OCMode = PWMA_OCMODE_PWM2
    PWMA_OutputState = PWMA_OUTPUTSTATE_ENABLE
    PWMA_OutputNState = PWMA_OUTPUTNSTATE_ENABLE
    PWMA_Pulse = CCR1_Val
    PWMA_OCPolarity = PWMA_OCPOLARITY_LOW
    PWMA_OCNPolarity = PWMA_OCNPOLARITY_HIGH
    PWMA_OCIdleState = PWMA_OCIDLESTATE_SET
    PWMA_OCNIdleState = PWMA_OCIDLESTATE_RESET

    */
    PWMA_OC1Init(PWMA_OCMODE_PWM2, PWMA_OUTPUTSTATE_ENABLE, PWMA_OUTPUTNSTATE_ENABLE,
               CCR1_Val, PWMA_OCPOLARITY_LOW, PWMA_OCNPOLARITY_HIGH, PWMA_OCIDLESTATE_SET,
               PWMA_OCNIDLESTATE_RESET); 

    /*PWMA_Pulse = CCR2_Val*/
    PWMA_OC2Init(PWMA_OCMODE_PWM2, PWMA_OUTPUTSTATE_ENABLE, PWMA_OUTPUTNSTATE_ENABLE, CCR2_Val,
               PWMA_OCPOLARITY_LOW, PWMA_OCNPOLARITY_HIGH, PWMA_OCIDLESTATE_SET, 
               PWMA_OCNIDLESTATE_RESET);

    /*PWMA_Pulse = CCR3_Val*/
    PWMA_OC3Init(PWMA_OCMODE_PWM2, PWMA_OUTPUTSTATE_ENABLE, PWMA_OUTPUTNSTATE_ENABLE,
               CCR3_Val, PWMA_OCPOLARITY_LOW, PWMA_OCNPOLARITY_HIGH, PWMA_OCIDLESTATE_SET,
               PWMA_OCNIDLESTATE_RESET);

    /*PWMA_Pulse = CCR4_Val*/
    PWMA_OC4Init(PWMA_OCMODE_PWM2, PWMA_OUTPUTSTATE_ENABLE, PWMA_OUTPUTNSTATE_ENABLE,
               CCR4_Val, PWMA_OCPOLARITY_LOW, PWMA_OCNPOLARITY_HIGH, PWMA_OCIDLESTATE_SET,
               PWMA_OCNIDLESTATE_RESET);

    /* PWMA counter enable */
    PWMA_Cmd(ENABLE);

    /* PWMA Main Output Enable */
    PWMA_CtrlPWMOutputs(ENABLE);
}

/******************** 主函数**************************/
void main(void)
{
    EAXSFR();       //扩展寄存器访问使能
	PWM_config();

	while (1);
}



