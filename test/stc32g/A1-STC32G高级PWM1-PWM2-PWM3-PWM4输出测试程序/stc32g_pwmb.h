/*---------------------------------------------------------------------*/
/* --- Web: www.STCAI.com ---------------------------------------------*/
/*---------------------------------------------------------------------*/

#ifndef __STC32G_PWMB_H
#define __STC32G_PWMB_H

#include "Type_def.h"

/** PWMA Output Compare and PWM modes */

typedef enum
{
  PWMB_OCMODE_TIMING     = ((uint8_t)0x00),
  PWMB_OCMODE_ACTIVE     = ((uint8_t)0x10),
  PWMB_OCMODE_INACTIVE   = ((uint8_t)0x20),
  PWMB_OCMODE_TOGGLE     = ((uint8_t)0x30),
  PWMB_OCMODE_PWM1       = ((uint8_t)0x60),
  PWMB_OCMODE_PWM2       = ((uint8_t)0x70)
}PWMB_OCMode_TypeDef;

#define IS_PWMB_OC_MODE_OK(MODE) (((MODE) ==  PWMB_OCMODE_TIMING) || \
                                  ((MODE) == PWMB_OCMODE_ACTIVE) || \
                                  ((MODE) == PWMB_OCMODE_INACTIVE) || \
                                  ((MODE) == PWMB_OCMODE_TOGGLE)|| \
                                  ((MODE) == PWMB_OCMODE_PWM1) || \
                                  ((MODE) == PWMB_OCMODE_PWM2))

#define IS_PWMB_OCM_OK(MODE)(((MODE) ==  PWMB_OCMODE_TIMING) || \
                             ((MODE) == PWMB_OCMODE_ACTIVE) || \
                             ((MODE) == PWMB_OCMODE_INACTIVE) || \
                             ((MODE) == PWMB_OCMODE_TOGGLE)|| \
                             ((MODE) == PWMB_OCMODE_PWM1) || \
                             ((MODE) == PWMB_OCMODE_PWM2) || \
                             ((MODE) == (uint8_t)PWMB_FORCEDACTION_ACTIVE) || \
                             ((MODE) == (uint8_t)PWMB_FORCEDACTION_INACTIVE))

/** PWMA One Pulse Mode */
typedef enum
{
  PWMB_OPMODE_SINGLE                 = ((uint8_t)0x01),
  PWMB_OPMODE_REPETITIVE             = ((uint8_t)0x00)
}PWMB_OPMode_TypeDef;

#define IS_PWMB_OPM_MODE_OK(MODE) (((MODE) == PWMB_OPMODE_SINGLE) || \
                                   ((MODE) == PWMB_OPMODE_REPETITIVE))

/** PWMA Channel */

typedef enum
{
  PWMB_CHANNEL_1                     = ((uint8_t)0x00),
  PWMB_CHANNEL_2                     = ((uint8_t)0x01),
  PWMB_CHANNEL_3                     = ((uint8_t)0x02),
  PWMB_CHANNEL_4                     = ((uint8_t)0x03)
}PWMB_Channel_TypeDef;


#define IS_PWMB_CHANNEL_OK(CHANNEL) (((CHANNEL) == PWMB_CHANNEL_1) || \
                                     ((CHANNEL) == PWMB_CHANNEL_2) || \
                                     ((CHANNEL) == PWMB_CHANNEL_3) || \
                                     ((CHANNEL) == PWMB_CHANNEL_4))

#define IS_PWMB_PWMI_CHANNEL_OK(CHANNEL) (((CHANNEL) == PWMB_CHANNEL_1) || \
    ((CHANNEL) == PWMB_CHANNEL_2))

#define IS_PWMB_COMPLEMENTARY_CHANNEL_OK(CHANNEL) (((CHANNEL) == PWMB_CHANNEL_1) || \
    ((CHANNEL) == PWMB_CHANNEL_2) || \
    ((CHANNEL) == PWMB_CHANNEL_3))


/** PWMA Counter Mode */
typedef enum
{
  PWMB_COUNTERMODE_UP                = ((uint8_t)0x00),
  PWMB_COUNTERMODE_DOWN              = ((uint8_t)0x10),
  PWMB_COUNTERMODE_CENTERALIGNED1    = ((uint8_t)0x20),
  PWMB_COUNTERMODE_CENTERALIGNED2    = ((uint8_t)0x40),
  PWMB_COUNTERMODE_CENTERALIGNED3    = ((uint8_t)0x60)
}PWMB_CounterMode_TypeDef;

#define IS_PWMB_COUNTER_MODE_OK(MODE) (((MODE) == PWMB_COUNTERMODE_UP) || \
                                       ((MODE) == PWMB_COUNTERMODE_DOWN) || \
                                       ((MODE) == PWMB_COUNTERMODE_CENTERALIGNED1) || \
                                       ((MODE) == PWMB_COUNTERMODE_CENTERALIGNED2) || \
                                       ((MODE) == PWMB_COUNTERMODE_CENTERALIGNED3))

/** PWMA Output Compare Polarity */
typedef enum
{
  PWMB_OCPOLARITY_HIGH               = ((uint8_t)0x00),
  PWMB_OCPOLARITY_LOW                = ((uint8_t)0x22)
}PWMB_OCPolarity_TypeDef;

#define IS_PWMB_OC_POLARITY_OK(POLARITY) (((POLARITY) == PWMB_OCPOLARITY_HIGH) || \
    ((POLARITY) == PWMB_OCPOLARITY_LOW))

/** PWMA Output Compare N Polarity */
typedef enum
{
  PWMB_OCNPOLARITY_HIGH              = ((uint8_t)0x00),
  PWMB_OCNPOLARITY_LOW               = ((uint8_t)0x88)
}PWMB_OCNPolarity_TypeDef;

#define IS_PWMB_OCN_POLARITY_OK(POLARITY) (((POLARITY) == PWMB_OCNPOLARITY_HIGH) || \
    ((POLARITY) == PWMB_OCNPOLARITY_LOW))

/** PWMA Output Compare states */
typedef enum
{
  PWMB_OUTPUTSTATE_DISABLE           = ((uint8_t)0x00),
  PWMB_OUTPUTSTATE_ENABLE            = ((uint8_t)0x11)
}PWMB_OutputState_TypeDef;

#define IS_PWMB_OUTPUT_STATE_OK(STATE) (((STATE) == PWMB_OUTPUTSTATE_DISABLE) || \
                                        ((STATE) == PWMB_OUTPUTSTATE_ENABLE))

/** PWMA Output Compare N States */
typedef enum
{
  PWMB_OUTPUTNSTATE_DISABLE = ((uint8_t)0x00),
  PWMB_OUTPUTNSTATE_ENABLE  = ((uint8_t)0x44)
} PWMB_OutputNState_TypeDef;

#define IS_PWMB_OUTPUTN_STATE_OK(STATE) (((STATE) == PWMB_OUTPUTNSTATE_DISABLE) ||\
    ((STATE) == PWMB_OUTPUTNSTATE_ENABLE))

/** PWMA Break Input enable/disable */
typedef enum
{
  PWMB_BREAK_ENABLE                  = ((uint8_t)0x10),
  PWMB_BREAK_DISABLE                 = ((uint8_t)0x00)
}PWMB_BreakState_TypeDef;
#define IS_PWMB_BREAK_STATE_OK(STATE) (((STATE) == PWMB_BREAK_ENABLE) || \
                                       ((STATE) == PWMB_BREAK_DISABLE))

/** PWMA Break Polarity */
typedef enum
{
  PWMB_BREAKPOLARITY_LOW             = ((uint8_t)0x00),
  PWMB_BREAKPOLARITY_HIGH            = ((uint8_t)0x20)
}PWMB_BreakPolarity_TypeDef;
#define IS_PWMB_BREAK_POLARITY_OK(POLARITY) (((POLARITY) == PWMB_BREAKPOLARITY_LOW) || \
    ((POLARITY) == PWMB_BREAKPOLARITY_HIGH))

/** PWMA AOE Bit Set/Reset */
typedef enum
{
  PWMB_AUTOMATICOUTPUT_ENABLE        = ((uint8_t)0x40),
  PWMB_AUTOMATICOUTPUT_DISABLE       = ((uint8_t)0x00)
}PWMB_AutomaticOutput_TypeDef;

#define IS_PWMB_AUTOMATIC_OUTPUT_STATE_OK(STATE) (((STATE) == PWMB_AUTOMATICOUTPUT_ENABLE) || \
    ((STATE) == PWMB_AUTOMATICOUTPUT_DISABLE))

/** PWMA Lock levels */
typedef enum
{
  PWMB_LOCKLEVEL_OFF                 = ((uint8_t)0x00),
  PWMB_LOCKLEVEL_1                   = ((uint8_t)0x01),
  PWMB_LOCKLEVEL_2                   = ((uint8_t)0x02),
  PWMB_LOCKLEVEL_3                   = ((uint8_t)0x03)
}PWMB_LockLevel_TypeDef;

#define IS_PWMB_LOCK_LEVEL_OK(LEVEL) (((LEVEL) == PWMB_LOCKLEVEL_OFF) || \
                                      ((LEVEL) == PWMB_LOCKLEVEL_1) || \
                                      ((LEVEL) == PWMB_LOCKLEVEL_2) || \
                                      ((LEVEL) == PWMB_LOCKLEVEL_3))

/** PWMA OSSI: Off-State Selection for Idle mode states */
typedef enum
{
  PWMB_OSSISTATE_ENABLE              = ((uint8_t)0x04),
  PWMB_OSSISTATE_DISABLE             = ((uint8_t)0x00)
}PWMB_OSSIState_TypeDef;

#define IS_PWMB_OSSI_STATE_OK(STATE) (((STATE) == PWMB_OSSISTATE_ENABLE) || \
                                      ((STATE) == PWMB_OSSISTATE_DISABLE))

/** PWMA Output Compare Idle State */
typedef enum
{
  PWMB_OCIDLESTATE_SET               = ((uint8_t)0x55),
  PWMB_OCIDLESTATE_RESET             = ((uint8_t)0x00)
}PWMB_OCIdleState_TypeDef;

#define IS_PWMB_OCIDLE_STATE_OK(STATE) (((STATE) == PWMB_OCIDLESTATE_SET) || \
                                        ((STATE) == PWMB_OCIDLESTATE_RESET))

/** PWMA Output Compare N Idle State */
typedef enum
{
  PWMB_OCNIDLESTATE_SET             = ((uint8_t)0x2A),
  PWMB_OCNIDLESTATE_RESET           = ((uint8_t)0x00)
}PWMB_OCNIdleState_TypeDef;

#define IS_PWMB_OCNIDLE_STATE_OK(STATE) (((STATE) == PWMB_OCNIDLESTATE_SET) || \
    ((STATE) == PWMB_OCNIDLESTATE_RESET))

/** PWMA Input Capture Polarity */
typedef enum
{
  PWMB_ICPOLARITY_RISING            = ((uint8_t)0x00),
  PWMB_ICPOLARITY_FALLING           = ((uint8_t)0x01)
}PWMB_ICPolarity_TypeDef;

#define IS_PWMB_IC_POLARITY_OK(POLARITY) (((POLARITY) == PWMB_ICPOLARITY_RISING) || \
    ((POLARITY) == PWMB_ICPOLARITY_FALLING))

/** PWMA Input Capture Selection */
typedef enum
{
  PWMB_ICSELECTION_DIRECTTI          = ((uint8_t)0x01),
  PWMB_ICSELECTION_INDIRECTTI        = ((uint8_t)0x02),
  PWMB_ICSELECTION_TRGI              = ((uint8_t)0x03)
}PWMB_ICSelection_TypeDef;

#define IS_PWMB_IC_SELECTION_OK(SELECTION) (((SELECTION) == PWMB_ICSELECTION_DIRECTTI) || \
    ((SELECTION) == PWMB_ICSELECTION_INDIRECTTI) || \
    ((SELECTION) == PWMB_ICSELECTION_TRGI))

/** PWMA Input Capture Prescaler */
typedef enum
{ 
  PWMB_ICPSC_DIV1                    = ((uint8_t)0x00),
  PWMB_ICPSC_DIV2                    = ((uint8_t)0x04),
  PWMB_ICPSC_DIV4                    = ((uint8_t)0x08),
  PWMB_ICPSC_DIV8                    = ((uint8_t)0x0C)
}PWMB_ICPSC_TypeDef;

#define IS_PWMB_IC_PRESCALER_OK(PRESCALER) (((PRESCALER) == PWMB_ICPSC_DIV1) || \
    ((PRESCALER) == PWMB_ICPSC_DIV2) || \
    ((PRESCALER) == PWMB_ICPSC_DIV4) || \
    ((PRESCALER) == PWMB_ICPSC_DIV8))

/** PWMA Input Capture Filer Value */

#define IS_PWMB_IC_FILTER_OK(ICFILTER) ((ICFILTER) <= 0x0F)

/** PWMA External Trigger Filer Value */
#define IS_PWMB_EXT_TRG_FILTER_OK(FILTER) ((FILTER) <= 0x0F)

/** PWMA interrupt sources */
typedef enum
{
  PWMB_IT_UPDATE                     = ((uint8_t)0x01),
  PWMB_IT_CC1                        = ((uint8_t)0x02),
  PWMB_IT_CC2                        = ((uint8_t)0x04),
  PWMB_IT_CC3                        = ((uint8_t)0x08),
  PWMB_IT_CC4                        = ((uint8_t)0x10),
  PWMB_IT_COM                        = ((uint8_t)0x20),
  PWMB_IT_TRIGGER                    = ((uint8_t)0x40),
  PWMB_IT_BREAK                      = ((uint8_t)0x80)
}PWMB_IT_TypeDef;

#define IS_PWMB_IT_OK(IT) ((IT) != 0x00)

#define IS_PWMB_GET_IT_OK(IT) (((IT) == PWMB_IT_UPDATE) || \
                               ((IT) == PWMB_IT_CC1) || \
                               ((IT) == PWMB_IT_CC2) || \
                               ((IT) == PWMB_IT_CC3) || \
                               ((IT) == PWMB_IT_CC4) || \
                               ((IT) == PWMB_IT_COM) || \
                               ((IT) == PWMB_IT_TRIGGER) || \
                               ((IT) == PWMB_IT_BREAK))


/** PWMA External Trigger Prescaler */
typedef enum
{
  PWMB_EXTTRGPSC_OFF                 = ((uint8_t)0x00),
  PWMB_EXTTRGPSC_DIV2                = ((uint8_t)0x10),
  PWMB_EXTTRGPSC_DIV4                = ((uint8_t)0x20),
  PWMB_EXTTRGPSC_DIV8                = ((uint8_t)0x30)
}PWMB_ExtTRGPSC_TypeDef;

#define IS_PWMB_EXT_PRESCALER_OK(PRESCALER) (((PRESCALER) == PWMB_EXTTRGPSC_OFF) || \
    ((PRESCALER) == PWMB_EXTTRGPSC_DIV2) || \
    ((PRESCALER) == PWMB_EXTTRGPSC_DIV4) || \
    ((PRESCALER) == PWMB_EXTTRGPSC_DIV8))

/** PWMA Internal Trigger Selection */
typedef enum
{
  PWMB_TS_TIM6                       = ((uint8_t)0x00),  /*!< TRIG Input source =  TIM6 TRIG Output  */
  PWMB_TS_TIM5                       = ((uint8_t)0x30),  /*!< TRIG Input source =  TIM5 TRIG Output  */
  PWMB_TS_TI1F_ED                    = ((uint8_t)0x40),
  PWMB_TS_TI1FP1                     = ((uint8_t)0x50),
  PWMB_TS_TI2FP2                     = ((uint8_t)0x60),
  PWMB_TS_ETRF                       = ((uint8_t)0x70)
}PWMB_TS_TypeDef;

#define IS_PWMB_TRIGGER_SELECTION_OK(SELECTION) (((SELECTION) == PWMB_TS_TI1F_ED) || \
    ((SELECTION) == PWMB_TS_TI1FP1) || \
    ((SELECTION) == PWMB_TS_TI2FP2) || \
    ((SELECTION) == PWMB_TS_ETRF) || \
    ((SELECTION) == PWMB_TS_TIM5) || \
    ((SELECTION) == PWMB_TS_TIM6))


#define IS_PWMB_TIX_TRIGGER_SELECTION_OK(SELECTION) (((SELECTION) == PWMB_TS_TI1F_ED) || \
    ((SELECTION) == PWMB_TS_TI1FP1) || \
    ((SELECTION) == PWMB_TS_TI2FP2))

/** PWMA TIx External Clock Source */
typedef enum
{
  PWMB_TIXEXTERNALCLK1SOURCE_TI1ED   = ((uint8_t)0x40),
  PWMB_TIXEXTERNALCLK1SOURCE_TI1     = ((uint8_t)0x50),
  PWMB_TIXEXTERNALCLK1SOURCE_TI2     = ((uint8_t)0x60)
}PWMB_TIxExternalCLK1Source_TypeDef;

#define IS_PWMB_TIXCLK_SOURCE_OK(SOURCE)  (((SOURCE) == PWMB_TIXEXTERNALCLK1SOURCE_TI1ED) || \
    ((SOURCE) == PWMB_TIXEXTERNALCLK1SOURCE_TI2) || \
    ((SOURCE) == PWMB_TIXEXTERNALCLK1SOURCE_TI1))

/** PWMA External Trigger Polarity */
typedef enum
{
  PWMB_EXTTRGPOLARITY_INVERTED       = ((uint8_t)0x80),
  PWMB_EXTTRGPOLARITY_NONINVERTED    = ((uint8_t)0x00)
}PWMB_ExtTRGPolarity_TypeDef;

#define IS_PWMB_EXT_POLARITY_OK(POLARITY) (((POLARITY) == PWMB_EXTTRGPOLARITY_INVERTED) || \
    ((POLARITY) == PWMB_EXTTRGPOLARITY_NONINVERTED))

/** PWMA Prescaler Reload Mode */
typedef enum
{
  PWMB_PSCRELOADMODE_UPDATE          = ((uint8_t)0x00),
  PWMB_PSCRELOADMODE_IMMEDIATE       = ((uint8_t)0x01)
}PWMB_PSCReloadMode_TypeDef;

#define IS_PWMB_PRESCALER_RELOAD_OK(RELOAD) (((RELOAD) == PWMB_PSCRELOADMODE_UPDATE) || \
    ((RELOAD) == PWMB_PSCRELOADMODE_IMMEDIATE))

/** PWMA Encoder Mode */
typedef enum
{
  PWMB_ENCODERMODE_TI1               = ((uint8_t)0x01),
  PWMB_ENCODERMODE_TI2               = ((uint8_t)0x02),
  PWMB_ENCODERMODE_TI12              = ((uint8_t)0x03)
}PWMB_EncoderMode_TypeDef;

#define IS_PWMB_ENCODER_MODE_OK(MODE) (((MODE) == PWMB_ENCODERMODE_TI1) || \
                                       ((MODE) == PWMB_ENCODERMODE_TI2) || \
                                       ((MODE) == PWMB_ENCODERMODE_TI12))

/** PWMA Event Source */
typedef enum
{
  PWMB_EVENTSOURCE_UPDATE            = ((uint8_t)0x01),
  PWMB_EVENTSOURCE_CC1               = ((uint8_t)0x02),
  PWMB_EVENTSOURCE_CC2               = ((uint8_t)0x04),
  PWMB_EVENTSOURCE_CC3               = ((uint8_t)0x08),
  PWMB_EVENTSOURCE_CC4               = ((uint8_t)0x10),
  PWMB_EVENTSOURCE_COM               = ((uint8_t)0x20),
  PWMB_EVENTSOURCE_TRIGGER           = ((uint8_t)0x40),
  PWMB_EVENTSOURCE_BREAK             = ((uint8_t)0x80)
}PWMB_EventSource_TypeDef;

#define IS_PWMB_EVENT_SOURCE_OK(SOURCE) ((SOURCE) != 0x00)

/** PWMA Update Source */
typedef enum
{
  PWMB_UPDATESOURCE_GLOBAL           = ((uint8_t)0x00),
  PWMB_UPDATESOURCE_REGULAR          = ((uint8_t)0x01)
}PWMB_UpdateSource_TypeDef;

#define IS_PWMB_UPDATE_SOURCE_OK(SOURCE) (((SOURCE) == PWMB_UPDATESOURCE_GLOBAL) || \
    ((SOURCE) == PWMB_UPDATESOURCE_REGULAR))

/** PWMA Trigger Output Source */
typedef enum
{
  PWMB_TRGOSOURCE_RESET              = ((uint8_t)0x00),
  PWMB_TRGOSOURCE_ENABLE             = ((uint8_t)0x10),
  PWMB_TRGOSOURCE_UPDATE             = ((uint8_t)0x20),
  PWMB_TRGOSource_OC1                = ((uint8_t)0x30),
  PWMB_TRGOSOURCE_OC1REF             = ((uint8_t)0x40),
  PWMB_TRGOSOURCE_OC2REF             = ((uint8_t)0x50),
  PWMB_TRGOSOURCE_OC3REF             = ((uint8_t)0x60)
}PWMB_TRGOSource_TypeDef;

#define IS_PWMB_TRGO_SOURCE_OK(SOURCE) (((SOURCE) == PWMB_TRGOSOURCE_RESET) || \
                                        ((SOURCE) == PWMB_TRGOSOURCE_ENABLE) || \
                                        ((SOURCE) == PWMB_TRGOSOURCE_UPDATE) || \
                                        ((SOURCE) == PWMB_TRGOSource_OC1)  || \
                                        ((SOURCE) == PWMB_TRGOSOURCE_OC1REF) || \
                                        ((SOURCE) == PWMB_TRGOSOURCE_OC2REF) || \
                                        ((SOURCE) == PWMB_TRGOSOURCE_OC3REF))

/** PWMA Slave Mode */
typedef enum
{
  PWMB_SLAVEMODE_RESET               = ((uint8_t)0x04),
  PWMB_SLAVEMODE_GATED               = ((uint8_t)0x05),
  PWMB_SLAVEMODE_TRIGGER             = ((uint8_t)0x06),
  PWMB_SLAVEMODE_EXTERNAL1           = ((uint8_t)0x07)
}PWMB_SlaveMode_TypeDef;

#define IS_PWMB_SLAVE_MODE_OK(MODE) (((MODE) == PWMB_SLAVEMODE_RESET) || \
                                     ((MODE) == PWMB_SLAVEMODE_GATED) || \
                                     ((MODE) == PWMB_SLAVEMODE_TRIGGER) || \
                                     ((MODE) == PWMB_SLAVEMODE_EXTERNAL1))

/** PWMA Flags */
typedef enum
{
  PWMB_FLAG_UPDATE                   = ((uint16_t)0x0001),
  PWMB_FLAG_CC1                      = ((uint16_t)0x0002),
  PWMB_FLAG_CC2                      = ((uint16_t)0x0004),
  PWMB_FLAG_CC3                      = ((uint16_t)0x0008),
  PWMB_FLAG_CC4                      = ((uint16_t)0x0010),
  PWMB_FLAG_COM                      = ((uint16_t)0x0020),
  PWMB_FLAG_TRIGGER                  = ((uint16_t)0x0040),
  PWMB_FLAG_BREAK                    = ((uint16_t)0x0080),
  PWMB_FLAG_CC1OF                    = ((uint16_t)0x0200),
  PWMB_FLAG_CC2OF                    = ((uint16_t)0x0400),
  PWMB_FLAG_CC3OF                    = ((uint16_t)0x0800),
  PWMB_FLAG_CC4OF                    = ((uint16_t)0x1000)
}PWMB_FLAG_TypeDef;

#define IS_PWMB_GET_FLAG_OK(FLAG) (((FLAG) == PWMB_FLAG_UPDATE) || \
                                   ((FLAG) == PWMB_FLAG_CC1) || \
                                   ((FLAG) == PWMB_FLAG_CC2) || \
                                   ((FLAG) == PWMB_FLAG_CC3) || \
                                   ((FLAG) == PWMB_FLAG_CC4) || \
                                   ((FLAG) == PWMB_FLAG_COM) || \
                                   ((FLAG) == PWMB_FLAG_TRIGGER) || \
                                   ((FLAG) == PWMB_FLAG_BREAK) || \
                                   ((FLAG) == PWMB_FLAG_CC1OF) || \
                                   ((FLAG) == PWMB_FLAG_CC2OF) || \
                                   ((FLAG) == PWMB_FLAG_CC3OF) || \
                                   ((FLAG) == PWMB_FLAG_CC4OF))

#define IS_PWMB_CLEAR_FLAG_OK(FLAG) ((((uint16_t)(FLAG) & (uint16_t)0xE100) == 0x0000) && ((FLAG) != 0x0000))

/** PWMA Forced Action */
typedef enum
{
  PWMB_FORCEDACTION_ACTIVE           = ((uint8_t)0x50),
  PWMB_FORCEDACTION_INACTIVE         = ((uint8_t)0x40)
}PWMB_ForcedAction_TypeDef;

#define IS_PWMB_FORCED_ACTION_OK(ACTION) (((ACTION) == PWMB_FORCEDACTION_ACTIVE) || \
    ((ACTION) == PWMB_FORCEDACTION_INACTIVE))


/** PWMB_Exported_Functions */

void PWMB_DeInit(void);
void PWMB_TimeBaseInit(uint16_t PWMB_Prescaler, 
                       PWMB_CounterMode_TypeDef PWMB_CounterMode,
                       uint16_t PWMB_Period, uint8_t PWMB_RepetitionCounter);
void PWMB_OC5Init(PWMB_OCMode_TypeDef PWMB_OCMode, 
                  PWMB_OutputState_TypeDef PWMB_OutputState,          
                  uint16_t PWMB_Pulse, PWMB_OCPolarity_TypeDef PWMB_OCPolarity,           
                  PWMB_OCIdleState_TypeDef PWMB_OCIdleState );
void PWMB_OC6Init(PWMB_OCMode_TypeDef PWMB_OCMode, 
                  PWMB_OutputState_TypeDef PWMB_OutputState,          
                  uint16_t PWMB_Pulse, PWMB_OCPolarity_TypeDef PWMB_OCPolarity,           
                  PWMB_OCIdleState_TypeDef PWMB_OCIdleState );
void PWMB_OC7Init(PWMB_OCMode_TypeDef PWMB_OCMode, 
                  PWMB_OutputState_TypeDef PWMB_OutputState,          
                  uint16_t PWMB_Pulse, PWMB_OCPolarity_TypeDef PWMB_OCPolarity,           
                  PWMB_OCIdleState_TypeDef PWMB_OCIdleState );
void PWMB_OC8Init(PWMB_OCMode_TypeDef PWMB_OCMode, 
                  PWMB_OutputState_TypeDef PWMB_OutputState, uint16_t PWMB_Pulse,
                  PWMB_OCPolarity_TypeDef PWMB_OCPolarity, 
                  PWMB_OCIdleState_TypeDef PWMB_OCIdleState);
void PWMB_BDTRConfig(PWMB_OSSIState_TypeDef PWMB_OSSIState, 
                     PWMB_LockLevel_TypeDef PWMB_LockLevel, uint8_t PWMB_DeadTime,
                     PWMB_BreakState_TypeDef PWMB_Break, 
                     PWMB_BreakPolarity_TypeDef PWMB_BreakPolarity, 
                     PWMB_AutomaticOutput_TypeDef PWMB_AutomaticOutput);
void PWMB_ICInit(PWMB_Channel_TypeDef PWMB_Channel, 
                 PWMB_ICPolarity_TypeDef PWMB_ICPolarity, 
                 PWMB_ICSelection_TypeDef PWMB_ICSelection, 
                 PWMB_ICPSC_TypeDef PWMB_ICPrescaler, uint8_t PWMB_ICFilter);
void PWMB_PWMIConfig(PWMB_Channel_TypeDef PWMB_Channel, 
                     PWMB_ICPolarity_TypeDef PWMB_ICPolarity, 
                     PWMB_ICSelection_TypeDef PWMB_ICSelection, 
                     PWMB_ICPSC_TypeDef PWMB_ICPrescaler, uint8_t PWMB_ICFilter);
void PWMB_Cmd(FunctionalState NewState);
void PWMB_CtrlPWMOutputs(FunctionalState NewState);
void PWMB_ITConfig(PWMB_IT_TypeDef PWMB_IT, FunctionalState NewState);
void PWMB_InternalClockConfig(void);
void PWMB_ETRClockMode1Config(PWMB_ExtTRGPSC_TypeDef PWMB_ExtTRGPrescaler, 
                              PWMB_ExtTRGPolarity_TypeDef PWMB_ExtTRGPolarity, 
                              uint8_t ExtTRGFilter);
void PWMB_ETRClockMode2Config(PWMB_ExtTRGPSC_TypeDef PWMB_ExtTRGPrescaler, 
                              PWMB_ExtTRGPolarity_TypeDef PWMB_ExtTRGPolarity, 
                              uint8_t ExtTRGFilter);
void PWMB_ETRConfig(PWMB_ExtTRGPSC_TypeDef PWMB_ExtTRGPrescaler, 
                    PWMB_ExtTRGPolarity_TypeDef PWMB_ExtTRGPolarity, 
                    uint8_t ExtTRGFilter);
void PWMB_TIxExternalClockConfig(PWMB_TIxExternalCLK1Source_TypeDef PWMB_TIxExternalCLKSource, 
                                 PWMB_ICPolarity_TypeDef PWMB_ICPolarity, 
                                 uint8_t ICFilter);
void PWMB_SelectInputTrigger(PWMB_TS_TypeDef PWMB_InputTriggerSource);
void PWMB_UpdateDisableConfig(FunctionalState NewState);
void PWMB_UpdateRequestConfig(PWMB_UpdateSource_TypeDef PWMB_UpdateSource);
void PWMB_SelectHallSensor(FunctionalState NewState);
void PWMB_SelectOnePulseMode(PWMB_OPMode_TypeDef PWMB_OPMode);
void PWMB_SelectOutputTrigger(PWMB_TRGOSource_TypeDef PWMB_TRGOSource);
void PWMB_SelectSlaveMode(PWMB_SlaveMode_TypeDef PWMB_SlaveMode);
void PWMB_SelectMasterSlaveMode(FunctionalState NewState);
void PWMB_EncoderInterfaceConfig(PWMB_EncoderMode_TypeDef PWMB_EncoderMode, 
                                 PWMB_ICPolarity_TypeDef PWMB_IC1Polarity, 
                                 PWMB_ICPolarity_TypeDef PWMB_IC2Polarity);
void PWMB_PrescalerConfig(uint16_t Prescaler, PWMB_PSCReloadMode_TypeDef PWMB_PSCReloadMode);
void PWMB_CounterModeConfig(PWMB_CounterMode_TypeDef PWMB_CounterMode);
void PWMB_ForcedOC1Config(PWMB_ForcedAction_TypeDef PWMB_ForcedAction);
void PWMB_ForcedOC2Config(PWMB_ForcedAction_TypeDef PWMB_ForcedAction);
void PWMB_ForcedOC3Config(PWMB_ForcedAction_TypeDef PWMB_ForcedAction);
void PWMB_ForcedOC4Config(PWMB_ForcedAction_TypeDef PWMB_ForcedAction);
void PWMB_ARRPreloadConfig(FunctionalState NewState);
void PWMB_SelectCOM(FunctionalState NewState);
void PWMB_CCPreloadControl(FunctionalState NewState);
void PWMB_OC1PreloadConfig(FunctionalState NewState);
void PWMB_OC2PreloadConfig(FunctionalState NewState);
void PWMB_OC3PreloadConfig(FunctionalState NewState);
void PWMB_OC4PreloadConfig(FunctionalState NewState);
void PWMB_OC1FastConfig(FunctionalState NewState);
void PWMB_OC2FastConfig(FunctionalState NewState);
void PWMB_OC3FastConfig(FunctionalState NewState);
void PWMB_OC4FastConfig(FunctionalState NewState);
void PWMB_GenerateEvent(PWMB_EventSource_TypeDef PWMB_EventSource);
void PWMB_OC1PolarityConfig(PWMB_OCPolarity_TypeDef PWMB_OCPolarity);
void PWMB_OC1NPolarityConfig(PWMB_OCNPolarity_TypeDef PWMB_OCNPolarity);
void PWMB_OC2PolarityConfig(PWMB_OCPolarity_TypeDef PWMB_OCPolarity);
void PWMB_OC2NPolarityConfig(PWMB_OCNPolarity_TypeDef PWMB_OCNPolarity);
void PWMB_OC3PolarityConfig(PWMB_OCPolarity_TypeDef PWMB_OCPolarity);
void PWMB_OC3NPolarityConfig(PWMB_OCNPolarity_TypeDef PWMB_OCNPolarity);

void PWMB_DeInit(void);
void PWMB_TimeBaseInit(uint16_t PWMB_Prescaler, 
                       PWMB_CounterMode_TypeDef PWMB_CounterMode,
                       uint16_t PWMB_Period, uint8_t PWMB_RepetitionCounter);
void PWMB_OC5Init(PWMB_OCMode_TypeDef PWMB_OCMode, 
                  PWMB_OutputState_TypeDef PWMB_OutputState,          
                  uint16_t PWMB_Pulse, PWMB_OCPolarity_TypeDef PWMB_OCPolarity,           
                  PWMB_OCIdleState_TypeDef PWMB_OCIdleState );
void PWMB_OC6Init(PWMB_OCMode_TypeDef PWMB_OCMode, 
                  PWMB_OutputState_TypeDef PWMB_OutputState,          
                  uint16_t PWMB_Pulse, PWMB_OCPolarity_TypeDef PWMB_OCPolarity,           
                  PWMB_OCIdleState_TypeDef PWMB_OCIdleState );
void PWMB_OC7Init(PWMB_OCMode_TypeDef PWMB_OCMode, 
                  PWMB_OutputState_TypeDef PWMB_OutputState,          
                  uint16_t PWMB_Pulse, PWMB_OCPolarity_TypeDef PWMB_OCPolarity,           
                  PWMB_OCIdleState_TypeDef PWMB_OCIdleState );
void PWMB_OC8Init(PWMB_OCMode_TypeDef PWMB_OCMode, 
                  PWMB_OutputState_TypeDef PWMB_OutputState, uint16_t PWMB_Pulse,
                  PWMB_OCPolarity_TypeDef PWMB_OCPolarity, 
                  PWMB_OCIdleState_TypeDef PWMB_OCIdleState);

void PWMB_ICInit(PWMB_Channel_TypeDef PWMB_Channel, 
                 PWMB_ICPolarity_TypeDef PWMB_ICPolarity, 
                 PWMB_ICSelection_TypeDef PWMB_ICSelection, 
                 PWMB_ICPSC_TypeDef PWMB_ICPrescaler, uint8_t PWMB_ICFilter);
void PWMB_PWMIConfig(PWMB_Channel_TypeDef PWMB_Channel, 
                     PWMB_ICPolarity_TypeDef PWMB_ICPolarity, 
                     PWMB_ICSelection_TypeDef PWMB_ICSelection, 
                     PWMB_ICPSC_TypeDef PWMB_ICPrescaler, uint8_t PWMB_ICFilter);
void PWMB_Cmd(FunctionalState NewState);
void PWMB_CtrlPWMOutputs(FunctionalState NewState);
void PWMB_ITConfig(PWMB_IT_TypeDef PWMB_IT, FunctionalState NewState);
void PWMB_InternalClockConfig(void);
void PWMB_ETRClockMode1Config(PWMB_ExtTRGPSC_TypeDef PWMB_ExtTRGPrescaler, 
                              PWMB_ExtTRGPolarity_TypeDef PWMB_ExtTRGPolarity, 
                              uint8_t ExtTRGFilter);
void PWMB_ETRClockMode2Config(PWMB_ExtTRGPSC_TypeDef PWMB_ExtTRGPrescaler, 
                              PWMB_ExtTRGPolarity_TypeDef PWMB_ExtTRGPolarity, 
                              uint8_t ExtTRGFilter);
void PWMB_ETRConfig(PWMB_ExtTRGPSC_TypeDef PWMB_ExtTRGPrescaler, 
                    PWMB_ExtTRGPolarity_TypeDef PWMB_ExtTRGPolarity, 
                    uint8_t ExtTRGFilter);
void PWMB_TIxExternalClockConfig(PWMB_TIxExternalCLK1Source_TypeDef PWMB_TIxExternalCLKSource, 
                                 PWMB_ICPolarity_TypeDef PWMB_ICPolarity, 
                                 uint8_t ICFilter);
void PWMB_SelectInputTrigger(PWMB_TS_TypeDef PWMB_InputTriggerSource);
void PWMB_UpdateDisableConfig(FunctionalState NewState);
void PWMB_UpdateRequestConfig(PWMB_UpdateSource_TypeDef PWMB_UpdateSource);
void PWMB_SelectHallSensor(FunctionalState NewState);
void PWMB_SelectOnePulseMode(PWMB_OPMode_TypeDef PWMB_OPMode);
void PWMB_SelectOutputTrigger(PWMB_TRGOSource_TypeDef PWMB_TRGOSource);
void PWMB_SelectSlaveMode(PWMB_SlaveMode_TypeDef PWMB_SlaveMode);
void PWMB_SelectMasterSlaveMode(FunctionalState NewState);
void PWMB_EncoderInterfaceConfig(PWMB_EncoderMode_TypeDef PWMB_EncoderMode, 
                                 PWMB_ICPolarity_TypeDef PWMB_IC1Polarity, 
                                 PWMB_ICPolarity_TypeDef PWMB_IC2Polarity);
void PWMB_PrescalerConfig(uint16_t Prescaler, PWMB_PSCReloadMode_TypeDef PWMB_PSCReloadMode);
void PWMB_CounterModeConfig(PWMB_CounterMode_TypeDef PWMB_CounterMode);
void PWMB_ForcedOC5Config(PWMB_ForcedAction_TypeDef PWMB_ForcedAction);
void PWMB_ForcedOC6Config(PWMB_ForcedAction_TypeDef PWMB_ForcedAction);
void PWMB_ForcedOC7Config(PWMB_ForcedAction_TypeDef PWMB_ForcedAction);
void PWMB_ForcedOC8Config(PWMB_ForcedAction_TypeDef PWMB_ForcedAction);
void PWMB_ARRPreloadConfig(FunctionalState NewState);
void PWMB_SelectCOM(FunctionalState NewState);
void PWMB_CCPreloadControl(FunctionalState NewState);
void PWMB_OC5PreloadConfig(FunctionalState NewState);
void PWMB_OC6PreloadConfig(FunctionalState NewState);
void PWMB_OC7PreloadConfig(FunctionalState NewState);
void PWMB_OC8PreloadConfig(FunctionalState NewState);
void PWMB_OC5FastConfig(FunctionalState NewState);
void PWMB_OC6FastConfig(FunctionalState NewState);
void PWMB_OC7FastConfig(FunctionalState NewState);
void PWMB_OC8FastConfig(FunctionalState NewState);
void PWMB_GenerateEvent(PWMB_EventSource_TypeDef PWMB_EventSource);

void PWMB_OC5PolarityConfig(PWMB_OCPolarity_TypeDef PWMB_OCPolarity);

void PWMB_OC6PolarityConfig(PWMB_OCPolarity_TypeDef PWMB_OCPolarity);

void PWMB_OC7PolarityConfig(PWMB_OCPolarity_TypeDef PWMB_OCPolarity);

void PWMB_OC8PolarityConfig(PWMB_OCPolarity_TypeDef PWMB_OCPolarity);

void PWMB_CCxCmd(PWMB_Channel_TypeDef PWMB_Channel, FunctionalState NewState);
void PWMB_CCxNCmd(PWMB_Channel_TypeDef PWMB_Channel, FunctionalState NewState);
void PWMB_SelectOCxM(PWMB_Channel_TypeDef PWMB_Channel, PWMB_OCMode_TypeDef PWMB_OCMode);
void PWMB_SetCounter(uint16_t Counter);
void PWMB_SetAutoreload(uint16_t Autoreload);
void PWMB_SetCompare5(uint16_t Compare1);
void PWMB_SetCompare6(uint16_t Compare2);
void PWMB_SetCompare7(uint16_t Compare3);
void PWMB_SetCompare8(uint16_t Compare4);
void PWMB_SetIC5Prescaler(PWMB_ICPSC_TypeDef PWMB_IC1Prescaler);
void PWMB_SetIC6Prescaler(PWMB_ICPSC_TypeDef PWMB_IC2Prescaler);
void PWMB_SetIC7Prescaler(PWMB_ICPSC_TypeDef PWMB_IC3Prescaler);
void PWMB_SetIC8Prescaler(PWMB_ICPSC_TypeDef PWMB_IC4Prescaler);
uint16_t PWMB_GetCapture5(void);
uint16_t PWMB_GetCapture6(void);
uint16_t PWMB_GetCapture7(void);
uint16_t PWMB_GetCapture8(void);
uint16_t PWMB_GetCounter(void);
uint16_t PWMB_GetPrescaler(void);
FlagStatus PWMB_GetFlagStatus(PWMB_FLAG_TypeDef PWMB_FLAG);
void PWMB_ClearFlag(PWMB_FLAG_TypeDef PWMB_FLAG);
ITStatus PWMB_GetITStatus(PWMB_IT_TypeDef PWMB_IT);
void PWMB_ClearITPendingBit(PWMB_IT_TypeDef PWMB_IT);

#endif /* __STC32G_PWMB_H */
