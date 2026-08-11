/*---------------------------------------------------------------------*/
/* --- Web: www.STCAI.com ---------------------------------------------*/
/*---------------------------------------------------------------------*/

#ifndef		__TYPE_DEF_H
#define		__TYPE_DEF_H

//========================================================================
//                               类型定义
//========================================================================

/*!< Signed integer types  */
typedef   signed char     int8_t;
typedef   signed short    int16_t;
typedef   signed long     int32_t;

/*!< Unsigned integer types  */
typedef unsigned char     uint8_t;
typedef unsigned short    uint16_t;
typedef unsigned long     uint32_t;

//========================================================================

typedef enum {RESET = 0, SET = !RESET} FlagStatus, ITStatus, BitStatus, BitAction;

typedef enum {DISABLE = 0, ENABLE = !DISABLE} FunctionalState;

typedef enum {ERROR = 0, SUCCESS = !ERROR} ErrorStatus;

#define IS_FUNCTIONALSTATE_OK(STATE) (((STATE) == DISABLE) || ((STATE) == ENABLE))

//========================================================================

#define ENO1P       0x01
#define ENO1N       0x02
#define ENO2P       0x04
#define ENO2N       0x08
#define ENO3P       0x10
#define ENO3N       0x20
#define ENO4P       0x40
#define ENO4N       0x80

#define ENO5P       0x01
#define ENO6P       0x04
#define ENO7P       0x10
#define ENO8P       0x40

#define	PWMA	1
#define	PWMB	2

#define	PWM1_SW_P10_P11		0
#define	PWM1_SW_P20_P21		1
#define	PWM1_SW_P60_P61		2

#define	PWM2_SW_P12_P13		0
#define	PWM2_SW_P22_P23		(1<<2)
#define	PWM2_SW_P62_P63		(2<<2)

#define	PWM3_SW_P14_P15		0
#define	PWM3_SW_P24_P25		(1<<4)
#define	PWM3_SW_P64_P65		(2<<4)

#define	PWM4_SW_P16_P17		0
#define	PWM4_SW_P26_P27		(1<<6)
#define	PWM4_SW_P66_P67		(2<<6)
#define	PWM4_SW_P34_P33		(3<<6)

#define	PWM5_SW_P20				0
#define	PWM5_SW_P17				1
#define	PWM5_SW_P00				2
#define	PWM5_SW_P74				3

#define	PWM6_SW_P21				0
#define	PWM6_SW_P54				(1<<2)
#define	PWM6_SW_P01				(2<<2)
#define	PWM6_SW_P75				(3<<2)

#define	PWM7_SW_P22				0
#define	PWM7_SW_P33				(1<<4)
#define	PWM7_SW_P02				(2<<4)
#define	PWM7_SW_P76				(3<<4)

#define	PWM8_SW_P23				0
#define	PWM8_SW_P34				(1<<6)
#define	PWM8_SW_P03				(2<<6)
#define	PWM8_SW_P77				(3<<6)

/** PWMA_Registers_Reset_Value */

#define PWMA_CR1_RESET_VALUE   ((uint8_t)0x00)
#define PWMA_CR2_RESET_VALUE   ((uint8_t)0x00)
#define PWMB_CR2_RESET_VALUE   ((uint8_t)0x00)

#define PWMA_SMCR_RESET_VALUE  ((uint8_t)0x00)
#define PWMA_ETR_RESET_VALUE   ((uint8_t)0x00)

#define PWMB_SMCR_RESET_VALUE  ((uint8_t)0x00)
#define PWMB_ETR_RESET_VALUE   ((uint8_t)0x00)

#define PWMA_IER_RESET_VALUE   ((uint8_t)0x00)
#define PWMA_SR1_RESET_VALUE   ((uint8_t)0x00)
#define PWMA_SR2_RESET_VALUE   ((uint8_t)0x00)
#define PWMA_EGR_RESET_VALUE   ((uint8_t)0x00)
#define PWMA_CCMR1_RESET_VALUE ((uint8_t)0x00)
#define PWMA_CCMR2_RESET_VALUE ((uint8_t)0x00)
#define PWMA_CCMR3_RESET_VALUE ((uint8_t)0x00)
#define PWMA_CCMR4_RESET_VALUE ((uint8_t)0x00)

#define PWMA_CCER1_RESET_VALUE ((uint8_t)0x00)
#define PWMA_CCER2_RESET_VALUE ((uint8_t)0x00)
#define PWMA_CNTRH_RESET_VALUE ((uint8_t)0x00)
#define PWMA_CNTRL_RESET_VALUE ((uint8_t)0x00)
#define PWMA_PSCRH_RESET_VALUE ((uint8_t)0x00)
#define PWMA_PSCRL_RESET_VALUE ((uint8_t)0x00)
#define PWMA_ARRH_RESET_VALUE  ((uint8_t)0xFF)
#define PWMA_ARRL_RESET_VALUE  ((uint8_t)0xFF)
#define PWMA_RCR_RESET_VALUE   ((uint8_t)0x00)
#define PWMB_RCR_RESET_VALUE   ((uint8_t)0x00)
#define PWMA_CCR1H_RESET_VALUE ((uint8_t)0x00)
#define PWMA_CCR1L_RESET_VALUE ((uint8_t)0x00)
#define PWMA_CCR2H_RESET_VALUE ((uint8_t)0x00)
#define PWMA_CCR2L_RESET_VALUE ((uint8_t)0x00)
#define PWMA_CCR3H_RESET_VALUE ((uint8_t)0x00)
#define PWMA_CCR3L_RESET_VALUE ((uint8_t)0x00)
#define PWMA_CCR4H_RESET_VALUE ((uint8_t)0x00)
#define PWMA_CCR4L_RESET_VALUE ((uint8_t)0x00)

#define PWMA_BKR_RESET_VALUE   ((uint8_t)0x00)
#define PWMA_DTR_RESET_VALUE   ((uint8_t)0x00)
#define PWMA_OISR_RESET_VALUE  ((uint8_t)0x00)

#define PWMB_BKR_RESET_VALUE   ((uint8_t)0x00)
#define PWMB_DTR_RESET_VALUE   ((uint8_t)0x00)
#define PWMB_OISR_RESET_VALUE  ((uint8_t)0x00)

/* PWMB_Registers_Reset_Value */

#define PWMB_CR1_RESET_VALUE   ((uint8_t)0x00)
#define PWMB_IER_RESET_VALUE   ((uint8_t)0x00)
#define PWMB_SR1_RESET_VALUE   ((uint8_t)0x00)
#define PWMB_SR2_RESET_VALUE   ((uint8_t)0x00)
#define PWMB_EGR_RESET_VALUE   ((uint8_t)0x00)
#define PWMB_CCMR1_RESET_VALUE ((uint8_t)0x00)
#define PWMB_CCMR2_RESET_VALUE ((uint8_t)0x00)
#define PWMB_CCMR3_RESET_VALUE ((uint8_t)0x00)
#define PWMB_CCMR4_RESET_VALUE ((uint8_t)0x00)
#define PWMB_CCER1_RESET_VALUE ((uint8_t)0x00)
#define PWMB_CCER2_RESET_VALUE ((uint8_t)0x00)
#define PWMB_CNTRH_RESET_VALUE ((uint8_t)0x00)
#define PWMB_CNTRL_RESET_VALUE ((uint8_t)0x00)
#define PWMB_PSCR_RESET_VALUE  ((uint8_t)0x00)
#define PWMB_PSCRH_RESET_VALUE  ((uint8_t)0x00)
#define PWMB_PSCRL_RESET_VALUE  ((uint8_t)0x00)

#define PWMB_ARRH_RESET_VALUE  ((uint8_t)0xFF)
#define PWMB_ARRL_RESET_VALUE  ((uint8_t)0xFF)
#define PWMB_CCR5H_RESET_VALUE ((uint8_t)0x00)
#define PWMB_CCR5L_RESET_VALUE ((uint8_t)0x00)
#define PWMB_CCR6H_RESET_VALUE ((uint8_t)0x00)
#define PWMB_CCR6L_RESET_VALUE ((uint8_t)0x00)
#define PWMB_CCR7H_RESET_VALUE ((uint8_t)0x00)
#define PWMB_CCR7L_RESET_VALUE ((uint8_t)0x00)
#define PWMB_CCR8H_RESET_VALUE ((uint8_t)0x00)
#define PWMB_CCR8L_RESET_VALUE ((uint8_t)0x00)

/** PWMA_Registers_Bits_Definition */
/* CR1*/
#define PWMA_CR1_ARPE    ((uint8_t)0x80) /*!< Auto-Reload Preload Enable mask. */
#define PWMA_CR1_CMS     ((uint8_t)0x60) /*!< Center-aligned Mode Selection mask. */
#define PWMA_CR1_DIR     ((uint8_t)0x10) /*!< Direction mask. */
#define PWMA_CR1_OPM     ((uint8_t)0x08) /*!< One Pulse Mode mask. */
#define PWMA_CR1_URS     ((uint8_t)0x04) /*!< Update Request Source mask. */
#define PWMA_CR1_UDIS    ((uint8_t)0x02) /*!< Update DIsable mask. */
#define PWMA_CR1_CEN     ((uint8_t)0x01) /*!< Counter Enable mask. */
/* CR2*/
#define PWMA_CR2_TI1S    ((uint8_t)0x80) /*!< TI1S Selection mask. */
#define PWMA_CR2_MMS     ((uint8_t)0x70) /*!< MMS Selection mask. */
#define PWMA_CR2_COMS    ((uint8_t)0x04) /*!< Capture/Compare Control Update Selection mask. */
#define PWMA_CR2_CCPC    ((uint8_t)0x01) /*!< Capture/Compare Preloaded Control mask. */
/* SMCR*/
#define PWMA_SMCR_MSM    ((uint8_t)0x80) /*!< Master/Slave Mode mask. */
#define PWMA_SMCR_TS     ((uint8_t)0x70) /*!< Trigger Selection mask. */
#define PWMA_SMCR_SMS_    ((uint8_t)0x07) /*!< Slave Mode Selection mask. */
/*ETR*/
#define PWMA_ETR_ETP     ((uint8_t)0x80) /*!< External Trigger Polarity mask. */
#define PWMA_ETR_ECE     ((uint8_t)0x40)/*!< External Clock mask. */
#define PWMA_ETR_ETPS    ((uint8_t)0x30) /*!< External Trigger Prescaler mask. */
#define PWMA_ETR_ETF     ((uint8_t)0x0F) /*!< External Trigger Filter mask. */
/*IER*/
#define PWMA_IER_BIE     ((uint8_t)0x80) /*!< Break Interrupt Enable mask. */
#define PWMA_IER_TIE     ((uint8_t)0x40) /*!< Trigger Interrupt Enable mask. */
#define PWMA_IER_COMIE   ((uint8_t)0x20) /*!<  Commutation Interrupt Enable mask.*/
#define PWMA_IER_CC4IE   ((uint8_t)0x10) /*!< Capture/Compare 4 Interrupt Enable mask. */
#define PWMA_IER_CC3IE   ((uint8_t)0x08) /*!< Capture/Compare 3 Interrupt Enable mask. */
#define PWMA_IER_CC2IE   ((uint8_t)0x04) /*!< Capture/Compare 2 Interrupt Enable mask. */
#define PWMA_IER_CC1IE   ((uint8_t)0x02) /*!< Capture/Compare 1 Interrupt Enable mask. */
#define PWMA_IER_UIE     ((uint8_t)0x01) /*!< Update Interrupt Enable mask. */
/*SR1*/
#define PWMA_SR1_BIF     ((uint8_t)0x80) /*!< Break Interrupt Flag mask. */
#define PWMA_SR1_TIF     ((uint8_t)0x40) /*!< Trigger Interrupt Flag mask. */
#define PWMA_SR1_COMIF   ((uint8_t)0x20) /*!< Commutation Interrupt Flag mask. */
#define PWMA_SR1_CC4IF   ((uint8_t)0x10) /*!< Capture/Compare 4 Interrupt Flag mask. */
#define PWMA_SR1_CC3IF   ((uint8_t)0x08) /*!< Capture/Compare 3 Interrupt Flag mask. */
#define PWMA_SR1_CC2IF   ((uint8_t)0x04) /*!< Capture/Compare 2 Interrupt Flag mask. */
#define PWMA_SR1_CC1IF   ((uint8_t)0x02) /*!< Capture/Compare 1 Interrupt Flag mask. */
#define PWMA_SR1_UIF     ((uint8_t)0x01) /*!< Update Interrupt Flag mask. */
/*SR2*/
#define PWMA_SR2_CC4OF   ((uint8_t)0x10) /*!< Capture/Compare 4 Overcapture Flag mask. */
#define PWMA_SR2_CC3OF   ((uint8_t)0x08) /*!< Capture/Compare 3 Overcapture Flag mask. */
#define PWMA_SR2_CC2OF   ((uint8_t)0x04) /*!< Capture/Compare 2 Overcapture Flag mask. */
#define PWMA_SR2_CC1OF   ((uint8_t)0x02) /*!< Capture/Compare 1 Overcapture Flag mask. */
/*EGR*/
#define PWMA_EGR_BG      ((uint8_t)0x80) /*!< Break Generation mask. */
#define PWMA_EGR_TG      ((uint8_t)0x40) /*!< Trigger Generation mask. */
#define PWMA_EGR_COMG    ((uint8_t)0x20) /*!< Capture/Compare Control Update Generation mask. */
#define PWMA_EGR_CC4G    ((uint8_t)0x10) /*!< Capture/Compare 4 Generation mask. */
#define PWMA_EGR_CC3G    ((uint8_t)0x08) /*!< Capture/Compare 3 Generation mask. */
#define PWMA_EGR_CC2G    ((uint8_t)0x04) /*!< Capture/Compare 2 Generation mask. */
#define PWMA_EGR_CC1G    ((uint8_t)0x02) /*!< Capture/Compare 1 Generation mask. */
#define PWMA_EGR_UG      ((uint8_t)0x01) /*!< Update Generation mask. */
/*CCMR*/
#define PWMA_CCMR_ICxPSC ((uint8_t)0x0C) /*!< Input Capture x Prescaler mask. */
#define PWMA_CCMR_ICxF   ((uint8_t)0xF0) /*!< Input Capture x Filter mask. */
#define PWMA_CCMR_OCM    ((uint8_t)0x70) /*!< Output Compare x Mode mask. */
#define PWMA_CCMR_OCxPE  ((uint8_t)0x08) /*!< Output Compare x Preload Enable mask. */
#define PWMA_CCMR_OCxFE  ((uint8_t)0x04) /*!< Output Compare x Fast Enable mask. */
#define PWMA_CCMR_CCxS   ((uint8_t)0x03) /*!< Capture/Compare x Selection mask. */

#define CCMR_TIxDirect_Set ((uint8_t)0x01)
/*CCER1*/
#define PWMA_CCER1_CC2NP ((uint8_t)0x80) /*!< Capture/Compare 2 Complementary output Polarity mask. */
#define PWMA_CCER1_CC2NE ((uint8_t)0x40) /*!< Capture/Compare 2 Complementary output enable mask. */
#define PWMA_CCER1_CC2P  ((uint8_t)0x20) /*!< Capture/Compare 2 output Polarity mask. */
#define PWMA_CCER1_CC2E  ((uint8_t)0x10) /*!< Capture/Compare 2 output enable mask. */
#define PWMA_CCER1_CC1NP ((uint8_t)0x08) /*!< Capture/Compare 1 Complementary output Polarity mask. */
#define PWMA_CCER1_CC1NE ((uint8_t)0x04) /*!< Capture/Compare 1 Complementary output enable mask. */
#define PWMA_CCER1_CC1P  ((uint8_t)0x02) /*!< Capture/Compare 1 output Polarity mask. */
#define PWMA_CCER1_CC1E  ((uint8_t)0x01) /*!< Capture/Compare 1 output enable mask. */
/*CCER2*/
#define PWMA_CCER2_CC4NP  ((uint8_t)0x80) /*!< Capture/Compare 4 output Polarity mask. */
#define PWMA_CCER2_CC4NE  ((uint8_t)0x40) /*!< Capture/Compare 4 output enable mask. */

#define PWMA_CCER2_CC4P  ((uint8_t)0x20) /*!< Capture/Compare 4 output Polarity mask. */
#define PWMA_CCER2_CC4E  ((uint8_t)0x10) /*!< Capture/Compare 4 output enable mask. */
#define PWMA_CCER2_CC3NP ((uint8_t)0x08) /*!< Capture/Compare 3 Complementary output Polarity mask. */
#define PWMA_CCER2_CC3NE ((uint8_t)0x04) /*!< Capture/Compare 3 Complementary output enable mask. */
#define PWMA_CCER2_CC3P  ((uint8_t)0x02) /*!< Capture/Compare 3 output Polarity mask. */
#define PWMA_CCER2_CC3E  ((uint8_t)0x01) /*!< Capture/Compare 3 output enable mask. */
/*CNTRH*/
#define PWMA_CNTRH_CNT   ((uint8_t)0xFF) /*!< Counter Value (MSB) mask. */
/*CNTRL*/
#define PWMA_CNTRL_CNT   ((uint8_t)0xFF) /*!< Counter Value (LSB) mask. */
/*PSCH*/
#define PWMA_PSCH_PSC    ((uint8_t)0xFF) /*!< Prescaler Value (MSB) mask. */
/*PSCL*/
#define PWMA_PSCL_PSC    ((uint8_t)0xFF) /*!< Prescaler Value (LSB) mask. */
/*ARR*/
#define PWMA_ARRH_ARR    ((uint8_t)0xFF) /*!< Autoreload Value (MSB) mask. */
#define PWMA_ARRL_ARR    ((uint8_t)0xFF) /*!< Autoreload Value (LSB) mask. */
/*RCR*/
#define PWMA_RCR_REP     ((uint8_t)0xFF) /*!< Repetition Counter Value mask. */
/*CCR1*/
#define PWMA_CCR1H_CCR1  ((uint8_t)0xFF) /*!< Capture/Compare 1 Value (MSB) mask. */
#define PWMA_CCR1L_CCR1  ((uint8_t)0xFF) /*!< Capture/Compare 1 Value (LSB) mask. */
/*CCR2*/
#define PWMA_CCR2H_CCR2  ((uint8_t)0xFF) /*!< Capture/Compare 2 Value (MSB) mask. */
#define PWMA_CCR2L_CCR2  ((uint8_t)0xFF) /*!< Capture/Compare 2 Value (LSB) mask. */
/*CCR3*/
#define PWMA_CCR3H_CCR3  ((uint8_t)0xFF) /*!< Capture/Compare 3 Value (MSB) mask. */
#define PWMA_CCR3L_CCR3  ((uint8_t)0xFF) /*!< Capture/Compare 3 Value (LSB) mask. */
/*CCR4*/
#define PWMA_CCR4H_CCR4  ((uint8_t)0xFF) /*!< Capture/Compare 4 Value (MSB) mask. */
#define PWMA_CCR4L_CCR4  ((uint8_t)0xFF) /*!< Capture/Compare 4 Value (LSB) mask. */
/*BKR*/
#define PWMA_BKR_MOE     ((uint8_t)0x80) /*!< Main Output Enable mask. */
#define PWMA_BKR_AOE     ((uint8_t)0x40) /*!< Automatic Output Enable mask. */
#define PWMA_BKR_BKP     ((uint8_t)0x20) /*!< Break Polarity mask. */
#define PWMA_BKR_BKE     ((uint8_t)0x10) /*!< Break Enable mask. */
#define PWMA_BKR_OSSR    ((uint8_t)0x08) /*!< Off-State Selection for Run mode mask. */
#define PWMA_BKR_OSSI    ((uint8_t)0x04) /*!< Off-State Selection for Idle mode mask. */
#define PWMA_BKR_LOCK    ((uint8_t)0x03) /*!< Lock Configuration mask. */
/*DTR*/
#define PWMA_DTR_DTG     ((uint8_t)0xFF) /*!< Dead-Time Generator set-up mask. */
/*OISR*/
#define PWMA_OISR_OIS4N   ((uint8_t)0x80) /*!< Output Idle state 4 (OC4 output) mask. */

#define PWMA_OISR_OIS4   ((uint8_t)0x40) /*!< Output Idle state 4 (OC4 output) mask. */
#define PWMA_OISR_OIS3N  ((uint8_t)0x20) /*!< Output Idle state 3 (OC3N output) mask. */
#define PWMA_OISR_OIS3   ((uint8_t)0x10) /*!< Output Idle state 3 (OC3 output) mask. */
#define PWMA_OISR_OIS2N  ((uint8_t)0x08) /*!< Output Idle state 2 (OC2N output) mask. */
#define PWMA_OISR_OIS2   ((uint8_t)0x04) /*!< Output Idle state 2 (OC2 output) mask. */
#define PWMA_OISR_OIS1N  ((uint8_t)0x02) /*!< Output Idle state 1 (OC1N output) mask. */
#define PWMA_OISR_OIS1   ((uint8_t)0x01) /*!< Output Idle state 1 (OC1 output) mask. */


////PWMB
/* CR1*/
#define PWMB_CR1_ARPE    ((uint8_t)0x80) /*!< Auto-Reload Preload Enable mask. */
#define PWMB_CR1_CMS     ((uint8_t)0x60) /*!< Center-aligned Mode Selection mask. */
#define PWMB_CR1_DIR     ((uint8_t)0x10) /*!< Direction mask. */
#define PWMB_CR1_OPM     ((uint8_t)0x08) /*!< One Pulse Mode mask. */
#define PWMB_CR1_URS     ((uint8_t)0x04) /*!< Update Request Source mask. */
#define PWMB_CR1_UDIS    ((uint8_t)0x02) /*!< Update DIsable mask. */
#define PWMB_CR1_CEN     ((uint8_t)0x01) /*!< Counter Enable mask. */
/* CR2*/
#define PWMB_CR2_TI1S    ((uint8_t)0x80) /*!< TI1S Selection mask. */
#define PWMB_CR2_MMS     ((uint8_t)0x70) /*!< MMS Selection mask. */
#define PWMB_CR2_COMS    ((uint8_t)0x04) /*!< Capture/Compare Control Update Selection mask. */
#define PWMB_CR2_CCPC    ((uint8_t)0x01) /*!< Capture/Compare Preloaded Control mask. */
/* SMCR*/
#define PWMB_SMCR_MSM    ((uint8_t)0x80) /*!< Master/Slave Mode mask. */
#define PWMB_SMCR_TS     ((uint8_t)0x70) /*!< Trigger Selection mask. */
#define PWMB_SMCR_SMS_    ((uint8_t)0x07) /*!< Slave Mode Selection mask. */
/*ETR*/
#define PWMB_ETR_ETP     ((uint8_t)0x80) /*!< External Trigger Polarity mask. */
#define PWMB_ETR_ECE     ((uint8_t)0x40)/*!< External Clock mask. */
#define PWMB_ETR_ETPS    ((uint8_t)0x30) /*!< External Trigger Prescaler mask. */
#define PWMB_ETR_ETF     ((uint8_t)0x0F) /*!< External Trigger Filter mask. */
/*IER*/
#define PWMB_IER_BIE     ((uint8_t)0x80) /*!< Break Interrupt Enable mask. */
#define PWMB_IER_TIE     ((uint8_t)0x40) /*!< Trigger Interrupt Enable mask. */
#define PWMB_IER_COMIE   ((uint8_t)0x20) /*!<  Commutation Interrupt Enable mask.*/
#define PWMB_IER_CC8IE   ((uint8_t)0x10) /*!< Capture/Compare 8 Interrupt Enable mask. */
#define PWMB_IER_CC7IE   ((uint8_t)0x08) /*!< Capture/Compare 7 Interrupt Enable mask. */
#define PWMB_IER_CC6IE   ((uint8_t)0x04) /*!< Capture/Compare 6 Interrupt Enable mask. */
#define PWMB_IER_CC5IE   ((uint8_t)0x02) /*!< Capture/Compare 5 Interrupt Enable mask. */
#define PWMB_IER_UIE     ((uint8_t)0x01) /*!< Update Interrupt Enable mask. */
/*SR1*/
#define PWMB_SR1_BIF     ((uint8_t)0x80) /*!< Break Interrupt Flag mask. */
#define PWMB_SR1_TIF     ((uint8_t)0x40) /*!< Trigger Interrupt Flag mask. */
#define PWMB_SR1_COMIF   ((uint8_t)0x20) /*!< Commutation Interrupt Flag mask. */
#define PWMB_SR1_CC8IF   ((uint8_t)0x10) /*!< Capture/Compare 8 Interrupt Flag mask. */
#define PWMB_SR1_CC7IF   ((uint8_t)0x08) /*!< Capture/Compare 7 Interrupt Flag mask. */
#define PWMB_SR1_CC6IF   ((uint8_t)0x04) /*!< Capture/Compare 6 Interrupt Flag mask. */
#define PWMB_SR1_CC5IF   ((uint8_t)0x02) /*!< Capture/Compare 5 Interrupt Flag mask. */
#define PWMB_SR1_UIF     ((uint8_t)0x01) /*!< Update Interrupt Flag mask. */
/*SR2*/
#define PWMB_SR2_CC8OF   ((uint8_t)0x10) /*!< Capture/Compare 8 Overcapture Flag mask. */
#define PWMB_SR2_CC7OF   ((uint8_t)0x08) /*!< Capture/Compare 7 Overcapture Flag mask. */
#define PWMB_SR2_CC6OF   ((uint8_t)0x04) /*!< Capture/Compare 6 Overcapture Flag mask. */
#define PWMB_SR2_CC5OF   ((uint8_t)0x02) /*!< Capture/Compare 5 Overcapture Flag mask. */
/*EGR*/
#define PWMB_EGR_BG      ((uint8_t)0x80) /*!< Break Generation mask. */
#define PWMB_EGR_TG      ((uint8_t)0x40) /*!< Trigger Generation mask. */
#define PWMB_EGR_COMG    ((uint8_t)0x20) /*!< Capture/Compare Control Update Generation mask. */
#define PWMB_EGR_CC8G    ((uint8_t)0x10) /*!< Capture/Compare 8 Generation mask. */
#define PWMB_EGR_CC7G    ((uint8_t)0x08) /*!< Capture/Compare 7 Generation mask. */
#define PWMB_EGR_CC6G    ((uint8_t)0x04) /*!< Capture/Compare 6 Generation mask. */
#define PWMB_EGR_CC5G    ((uint8_t)0x02) /*!< Capture/Compare 5 Generation mask. */
#define PWMB_EGR_UG      ((uint8_t)0x01) /*!< Update Generation mask. */
/*CCMR*/
#define PWMB_CCMR_ICxPSC ((uint8_t)0x0C) /*!< Input Capture x Prescaler mask. */
#define PWMB_CCMR_ICxF   ((uint8_t)0xF0) /*!< Input Capture x Filter mask. */
#define PWMB_CCMR_OCM    ((uint8_t)0x70) /*!< Output Compare x Mode mask. */
#define PWMB_CCMR_OCxPE  ((uint8_t)0x08) /*!< Output Compare x Preload Enable mask. */
#define PWMB_CCMR_OCxFE  ((uint8_t)0x04) /*!< Output Compare x Fast Enable mask. */
#define PWMB_CCMR_CCxS   ((uint8_t)0x03) /*!< Capture/Compare x Selection mask. */

#define CCMR_TIxDirect_Set ((uint8_t)0x01)
/*CCER1*/
#define PWMB_CCER1_CC6P  ((uint8_t)0x20) /*!< Capture/Compare 6 output Polarity mask. */
#define PWMB_CCER1_CC6E  ((uint8_t)0x10) /*!< Capture/Compare 6 output enable mask. */
#define PWMB_CCER1_CC5P  ((uint8_t)0x02) /*!< Capture/Compare 5 output Polarity mask. */
#define PWMB_CCER1_CC5E  ((uint8_t)0x01) /*!< Capture/Compare 5 output enable mask. */
/*CCER2*/
#define PWMB_CCER2_CC8P  ((uint8_t)0x20) /*!< Capture/Compare 8 output Polarity mask. */
#define PWMB_CCER2_CC8E  ((uint8_t)0x10) /*!< Capture/Compare 8 output enable mask. */
#define PWMB_CCER2_CC7P  ((uint8_t)0x02) /*!< Capture/Compare 7 output Polarity mask. */
#define PWMB_CCER2_CC7E  ((uint8_t)0x01) /*!< Capture/Compare 7 output enable mask. */
/*CNTRH*/
#define PWMB_CNTRH_CNT   ((uint8_t)0xFF) /*!< Counter Value (MSB) mask. */
/*CNTRL*/
#define PWMB_CNTRL_CNT   ((uint8_t)0xFF) /*!< Counter Value (LSB) mask. */
/*PSCH*/
#define PWMB_PSCH_PSC    ((uint8_t)0xFF) /*!< Prescaler Value (MSB) mask. */
/*PSCL*/
#define PWMB_PSCL_PSC    ((uint8_t)0xFF) /*!< Prescaler Value (LSB) mask. */
/*ARR*/
#define PWMB_ARRH_ARR    ((uint8_t)0xFF) /*!< Autoreload Value (MSB) mask. */
#define PWMB_ARRL_ARR    ((uint8_t)0xFF) /*!< Autoreload Value (LSB) mask. */
/*RCR*/
#define PWMB_RCR_REP     ((uint8_t)0xFF) /*!< Repetition Counter Value mask. */
/*CCR1*/
#define PWMB_CCR5H_CCR5  ((uint8_t)0xFF) /*!< Capture/Compare 5 Value (MSB) mask. */
#define PWMB_CCR5L_CCR5  ((uint8_t)0xFF) /*!< Capture/Compare 5 Value (LSB) mask. */
/*CCR2*/
#define PWMB_CCR6H_CCR6  ((uint8_t)0xFF) /*!< Capture/Compare 6 Value (MSB) mask. */
#define PWMB_CCR6L_CCR6  ((uint8_t)0xFF) /*!< Capture/Compare 6 Value (LSB) mask. */
/*CCR3*/
#define PWMB_CCR7H_CCR7  ((uint8_t)0xFF) /*!< Capture/Compare 7 Value (MSB) mask. */
#define PWMB_CCR7L_CCR7  ((uint8_t)0xFF) /*!< Capture/Compare 7 Value (LSB) mask. */
/*CCR4*/
#define PWMB_CCR8H_CCR8  ((uint8_t)0xFF) /*!< Capture/Compare 8 Value (MSB) mask. */
#define PWMB_CCR8L_CCR8  ((uint8_t)0xFF) /*!< Capture/Compare 8 Value (LSB) mask. */
/*BKR*/
#define PWMB_BKR_MOE     ((uint8_t)0x80) /*!< Main Output Enable mask. */
#define PWMB_BKR_AOE     ((uint8_t)0x40) /*!< Automatic Output Enable mask. */
#define PWMB_BKR_BKP     ((uint8_t)0x20) /*!< Break Polarity mask. */
#define PWMB_BKR_BKE     ((uint8_t)0x10) /*!< Break Enable mask. */
#define PWMB_BKR_OSSR    ((uint8_t)0x08) /*!< Off-State Selection for Run mode mask. */
#define PWMB_BKR_OSSI    ((uint8_t)0x04) /*!< Off-State Selection for Idle mode mask. */
#define PWMB_BKR_LOCK    ((uint8_t)0x03) /*!< Lock Configuration mask. */
/*DTR*/
#define PWMB_DTR_DTG     ((uint8_t)0xFF) /*!< Dead-Time Generator set-up mask. */
/*OISR*/
#define PWMB_OISR_OIS8   ((uint8_t)0x40) /*!< Output Idle state 8 (OC8 output) mask. */
#define PWMB_OISR_OIS7   ((uint8_t)0x10) /*!< Output Idle state 7 (OC7 output) mask. */
#define PWMB_OISR_OIS6   ((uint8_t)0x04) /*!< Output Idle state 6 (OC6 output) mask. */
#define PWMB_OISR_OIS5   ((uint8_t)0x01) /*!< Output Idle state 5 (OC5 output) mask. */

#endif
