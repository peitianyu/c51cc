/*---------------------------------------------------------------------*/
/* --- Web: www.STCAI.com ---------------------------------------------*/
/*---------------------------------------------------------------------*/

#ifndef __STC32G_PWMA_H
#define __STC32G_PWMA_H

#include "Type_def.h"

/** PWMA Output Compare and PWM modes */

typedef enum
{
  PWMA_OCMODE_TIMING     = ((uint8_t)0x00),
  PWMA_OCMODE_ACTIVE     = ((uint8_t)0x10),
  PWMA_OCMODE_INACTIVE   = ((uint8_t)0x20),
  PWMA_OCMODE_TOGGLE     = ((uint8_t)0x30),
  PWMA_OCMODE_PWM1       = ((uint8_t)0x60),
  PWMA_OCMODE_PWM2       = ((uint8_t)0x70)
}PWMA_OCMode_TypeDef;

#define IS_PWMA_OC_MODE_OK(MODE) (((MODE) ==  PWMA_OCMODE_TIMING) || \
                                  ((MODE) == PWMA_OCMODE_ACTIVE) || \
                                  ((MODE) == PWMA_OCMODE_INACTIVE) || \
                                  ((MODE) == PWMA_OCMODE_TOGGLE)|| \
                                  ((MODE) == PWMA_OCMODE_PWM1) || \
                                  ((MODE) == PWMA_OCMODE_PWM2))

#define IS_PWMA_OCM_OK(MODE)(((MODE) ==  PWMA_OCMODE_TIMING) || \
                             ((MODE) == PWMA_OCMODE_ACTIVE) || \
                             ((MODE) == PWMA_OCMODE_INACTIVE) || \
                             ((MODE) == PWMA_OCMODE_TOGGLE)|| \
                             ((MODE) == PWMA_OCMODE_PWM1) || \
                             ((MODE) == PWMA_OCMODE_PWM2) || \
                             ((MODE) == (uint8_t)PWMA_FORCEDACTION_ACTIVE) || \
                             ((MODE) == (uint8_t)PWMA_FORCEDACTION_INACTIVE))

/** PWMA One Pulse Mode */
typedef enum
{
  PWMA_OPMODE_SINGLE                 = ((uint8_t)0x01),
  PWMA_OPMODE_REPETITIVE             = ((uint8_t)0x00)
}PWMA_OPMode_TypeDef;

#define IS_PWMA_OPM_MODE_OK(MODE) (((MODE) == PWMA_OPMODE_SINGLE) || \
                                   ((MODE) == PWMA_OPMODE_REPETITIVE))

/** PWMA Channel */

typedef enum
{
  PWMA_CHANNEL_1                     = ((uint8_t)0x00),
  PWMA_CHANNEL_2                     = ((uint8_t)0x01),
  PWMA_CHANNEL_3                     = ((uint8_t)0x02),
  PWMA_CHANNEL_4                     = ((uint8_t)0x03)
}PWMA_Channel_TypeDef;


#define IS_PWMA_CHANNEL_OK(CHANNEL) (((CHANNEL) == PWMA_CHANNEL_1) || \
                                     ((CHANNEL) == PWMA_CHANNEL_2) || \
                                     ((CHANNEL) == PWMA_CHANNEL_3) || \
                                     ((CHANNEL) == PWMA_CHANNEL_4))

#define IS_PWMA_PWMI_CHANNEL_OK(CHANNEL) (((CHANNEL) == PWMA_CHANNEL_1) || \
    ((CHANNEL) == PWMA_CHANNEL_2))

#define IS_PWMA_COMPLEMENTARY_CHANNEL_OK(CHANNEL) (((CHANNEL) == PWMA_CHANNEL_1) || \
    ((CHANNEL) == PWMA_CHANNEL_2) || \
    ((CHANNEL) == PWMA_CHANNEL_3))


/** PWMA Counter Mode */
typedef enum
{
  PWMA_COUNTERMODE_UP                = ((uint8_t)0x00),
  PWMA_COUNTERMODE_DOWN              = ((uint8_t)0x10),
  PWMA_COUNTERMODE_CENTERALIGNED1    = ((uint8_t)0x20),
  PWMA_COUNTERMODE_CENTERALIGNED2    = ((uint8_t)0x40),
  PWMA_COUNTERMODE_CENTERALIGNED3    = ((uint8_t)0x60)
}PWMA_CounterMode_TypeDef;

#define IS_PWMA_COUNTER_MODE_OK(MODE) (((MODE) == PWMA_COUNTERMODE_UP) || \
                                       ((MODE) == PWMA_COUNTERMODE_DOWN) || \
                                       ((MODE) == PWMA_COUNTERMODE_CENTERALIGNED1) || \
                                       ((MODE) == PWMA_COUNTERMODE_CENTERALIGNED2) || \
                                       ((MODE) == PWMA_COUNTERMODE_CENTERALIGNED3))

/** PWMA Output Compare Polarity */
typedef enum
{
  PWMA_OCPOLARITY_HIGH               = ((uint8_t)0x00),
  PWMA_OCPOLARITY_LOW                = ((uint8_t)0x22)
}PWMA_OCPolarity_TypeDef;

#define IS_PWMA_OC_POLARITY_OK(POLARITY) (((POLARITY) == PWMA_OCPOLARITY_HIGH) || \
    ((POLARITY) == PWMA_OCPOLARITY_LOW))

/** PWMA Output Compare N Polarity */
typedef enum
{
  PWMA_OCNPOLARITY_HIGH              = ((uint8_t)0x00),
  PWMA_OCNPOLARITY_LOW               = ((uint8_t)0x88)
}PWMA_OCNPolarity_TypeDef;

#define IS_PWMA_OCN_POLARITY_OK(POLARITY) (((POLARITY) == PWMA_OCNPOLARITY_HIGH) || \
    ((POLARITY) == PWMA_OCNPOLARITY_LOW))

/** PWMA Output Compare states */
typedef enum
{
  PWMA_OUTPUTSTATE_DISABLE           = ((uint8_t)0x00),
  PWMA_OUTPUTSTATE_ENABLE            = ((uint8_t)0x11)
}PWMA_OutputState_TypeDef;

#define IS_PWMA_OUTPUT_STATE_OK(STATE) (((STATE) == PWMA_OUTPUTSTATE_DISABLE) || \
                                        ((STATE) == PWMA_OUTPUTSTATE_ENABLE))

/** PWMA Output Compare N States */
typedef enum
{
  PWMA_OUTPUTNSTATE_DISABLE = ((uint8_t)0x00),
  PWMA_OUTPUTNSTATE_ENABLE  = ((uint8_t)0x44)
} PWMA_OutputNState_TypeDef;

#define IS_PWMA_OUTPUTN_STATE_OK(STATE) (((STATE) == PWMA_OUTPUTNSTATE_DISABLE) ||\
    ((STATE) == PWMA_OUTPUTNSTATE_ENABLE))

/** PWMA Break Input enable/disable */
typedef enum
{
  PWMA_BREAK_ENABLE                  = ((uint8_t)0x10),
  PWMA_BREAK_DISABLE                 = ((uint8_t)0x00)
}PWMA_BreakState_TypeDef;
#define IS_PWMA_BREAK_STATE_OK(STATE) (((STATE) == PWMA_BREAK_ENABLE) || \
                                       ((STATE) == PWMA_BREAK_DISABLE))

/** PWMA Break Polarity */
typedef enum
{
  PWMA_BREAKPOLARITY_LOW             = ((uint8_t)0x00),
  PWMA_BREAKPOLARITY_HIGH            = ((uint8_t)0x20)
}PWMA_BreakPolarity_TypeDef;
#define IS_PWMA_BREAK_POLARITY_OK(POLARITY) (((POLARITY) == PWMA_BREAKPOLARITY_LOW) || \
    ((POLARITY) == PWMA_BREAKPOLARITY_HIGH))

/** PWMA AOE Bit Set/Reset */
typedef enum
{
  PWMA_AUTOMATICOUTPUT_ENABLE        = ((uint8_t)0x40),
  PWMA_AUTOMATICOUTPUT_DISABLE       = ((uint8_t)0x00)
}PWMA_AutomaticOutput_TypeDef;

#define IS_PWMA_AUTOMATIC_OUTPUT_STATE_OK(STATE) (((STATE) == PWMA_AUTOMATICOUTPUT_ENABLE) || \
    ((STATE) == PWMA_AUTOMATICOUTPUT_DISABLE))

/** PWMA Lock levels */
typedef enum
{
  PWMA_LOCKLEVEL_OFF                 = ((uint8_t)0x00),
  PWMA_LOCKLEVEL_1                   = ((uint8_t)0x01),
  PWMA_LOCKLEVEL_2                   = ((uint8_t)0x02),
  PWMA_LOCKLEVEL_3                   = ((uint8_t)0x03)
}PWMA_LockLevel_TypeDef;

#define IS_PWMA_LOCK_LEVEL_OK(LEVEL) (((LEVEL) == PWMA_LOCKLEVEL_OFF) || \
                                      ((LEVEL) == PWMA_LOCKLEVEL_1) || \
                                      ((LEVEL) == PWMA_LOCKLEVEL_2) || \
                                      ((LEVEL) == PWMA_LOCKLEVEL_3))

/** PWMA OSSI: Off-State Selection for Idle mode states */
typedef enum
{
  PWMA_OSSISTATE_ENABLE              = ((uint8_t)0x04),
  PWMA_OSSISTATE_DISABLE             = ((uint8_t)0x00)
}PWMA_OSSIState_TypeDef;

#define IS_PWMA_OSSI_STATE_OK(STATE) (((STATE) == PWMA_OSSISTATE_ENABLE) || \
                                      ((STATE) == PWMA_OSSISTATE_DISABLE))

/** PWMA Output Compare Idle State */
typedef enum
{
  PWMA_OCIDLESTATE_SET               = ((uint8_t)0x55),
  PWMA_OCIDLESTATE_RESET             = ((uint8_t)0x00)
}PWMA_OCIdleState_TypeDef;

#define IS_PWMA_OCIDLE_STATE_OK(STATE) (((STATE) == PWMA_OCIDLESTATE_SET) || \
                                        ((STATE) == PWMA_OCIDLESTATE_RESET))

/** PWMA Output Compare N Idle State */
typedef enum
{
  PWMA_OCNIDLESTATE_SET             = ((uint8_t)0x2A),
  PWMA_OCNIDLESTATE_RESET           = ((uint8_t)0x00)
}PWMA_OCNIdleState_TypeDef;

#define IS_PWMA_OCNIDLE_STATE_OK(STATE) (((STATE) == PWMA_OCNIDLESTATE_SET) || \
    ((STATE) == PWMA_OCNIDLESTATE_RESET))

/** PWMA Input Capture Polarity */
typedef enum
{
  PWMA_ICPOLARITY_RISING            = ((uint8_t)0x00),
  PWMA_ICPOLARITY_FALLING           = ((uint8_t)0x01)
}PWMA_ICPolarity_TypeDef;

#define IS_PWMA_IC_POLARITY_OK(POLARITY) (((POLARITY) == PWMA_ICPOLARITY_RISING) || \
    ((POLARITY) == PWMA_ICPOLARITY_FALLING))

/** PWMA Input Capture Selection */
typedef enum
{
  PWMA_ICSELECTION_DIRECTTI          = ((uint8_t)0x01),
  PWMA_ICSELECTION_INDIRECTTI        = ((uint8_t)0x02),
  PWMA_ICSELECTION_TRGI              = ((uint8_t)0x03)
}PWMA_ICSelection_TypeDef;

#define IS_PWMA_IC_SELECTION_OK(SELECTION) (((SELECTION) == PWMA_ICSELECTION_DIRECTTI) || \
    ((SELECTION) == PWMA_ICSELECTION_INDIRECTTI) || \
    ((SELECTION) == PWMA_ICSELECTION_TRGI))

/** PWMA Input Capture Prescaler */
typedef enum
{
  PWMA_ICPSC_DIV1                    = ((uint8_t)0x00),
  PWMA_ICPSC_DIV2                    = ((uint8_t)0x04),
  PWMA_ICPSC_DIV4                    = ((uint8_t)0x08),
  PWMA_ICPSC_DIV8                    = ((uint8_t)0x0C)
}PWMA_ICPSC_TypeDef;

#define IS_PWMA_IC_PRESCALER_OK(PRESCALER) (((PRESCALER) == PWMA_ICPSC_DIV1) || \
    ((PRESCALER) == PWMA_ICPSC_DIV2) || \
    ((PRESCALER) == PWMA_ICPSC_DIV4) || \
    ((PRESCALER) == PWMA_ICPSC_DIV8))

/** PWMA Input Capture Filer Value */

#define IS_PWMA_IC_FILTER_OK(ICFILTER) ((ICFILTER) <= 0x0F)

/** PWMA External Trigger Filer Value */
#define IS_PWMA_EXT_TRG_FILTER_OK(FILTER) ((FILTER) <= 0x0F)

/** PWMA interrupt sources */
typedef enum
{
  PWMA_IT_UPDATE                     = ((uint8_t)0x01),
  PWMA_IT_CC1                        = ((uint8_t)0x02),
  PWMA_IT_CC2                        = ((uint8_t)0x04),
  PWMA_IT_CC3                        = ((uint8_t)0x08),
  PWMA_IT_CC4                        = ((uint8_t)0x10),
  PWMA_IT_COM                        = ((uint8_t)0x20),
  PWMA_IT_TRIGGER                    = ((uint8_t)0x40),
  PWMA_IT_BREAK                      = ((uint8_t)0x80)
}PWMA_IT_TypeDef;

#define IS_PWMA_IT_OK(IT) ((IT) != 0x00)

#define IS_PWMA_GET_IT_OK(IT) (((IT) == PWMA_IT_UPDATE) || \
                               ((IT) == PWMA_IT_CC1) || \
                               ((IT) == PWMA_IT_CC2) || \
                               ((IT) == PWMA_IT_CC3) || \
                               ((IT) == PWMA_IT_CC4) || \
                               ((IT) == PWMA_IT_COM) || \
                               ((IT) == PWMA_IT_TRIGGER) || \
                               ((IT) == PWMA_IT_BREAK))


/** PWMA External Trigger Prescaler */
typedef enum
{
  PWMA_EXTTRGPSC_OFF                 = ((uint8_t)0x00),
  PWMA_EXTTRGPSC_DIV2                = ((uint8_t)0x10),
  PWMA_EXTTRGPSC_DIV4                = ((uint8_t)0x20),
  PWMA_EXTTRGPSC_DIV8                = ((uint8_t)0x30)
}PWMA_ExtTRGPSC_TypeDef;

#define IS_PWMA_EXT_PRESCALER_OK(PRESCALER) (((PRESCALER) == PWMA_EXTTRGPSC_OFF) || \
    ((PRESCALER) == PWMA_EXTTRGPSC_DIV2) || \
    ((PRESCALER) == PWMA_EXTTRGPSC_DIV4) || \
    ((PRESCALER) == PWMA_EXTTRGPSC_DIV8))

/** PWMA Internal Trigger Selection */
typedef enum
{
  PWMA_TS_TIM6                       = ((uint8_t)0x00),  /*!< TRIG Input source =  TIM6 TRIG Output  */
  PWMA_TS_TIM5                       = ((uint8_t)0x30),  /*!< TRIG Input source =  TIM5 TRIG Output  */
  PWMA_TS_TI1F_ED                    = ((uint8_t)0x40),
  PWMA_TS_TI1FP1                     = ((uint8_t)0x50),
  PWMA_TS_TI2FP2                     = ((uint8_t)0x60),
  PWMA_TS_ETRF                       = ((uint8_t)0x70)
}PWMA_TS_TypeDef;

#define IS_PWMA_TRIGGER_SELECTION_OK(SELECTION) (((SELECTION) == PWMA_TS_TI1F_ED) || \
    ((SELECTION) == PWMA_TS_TI1FP1) || \
    ((SELECTION) == PWMA_TS_TI2FP2) || \
    ((SELECTION) == PWMA_TS_ETRF) || \
    ((SELECTION) == PWMA_TS_TIM5) || \
    ((SELECTION) == PWMA_TS_TIM6))


#define IS_PWMA_TIX_TRIGGER_SELECTION_OK(SELECTION) (((SELECTION) == PWMA_TS_TI1F_ED) || \
    ((SELECTION) == PWMA_TS_TI1FP1) || \
    ((SELECTION) == PWMA_TS_TI2FP2))

/** PWMA TIx External Clock Source */
typedef enum
{
  PWMA_TIXEXTERNALCLK1SOURCE_TI1ED   = ((uint8_t)0x40),
  PWMA_TIXEXTERNALCLK1SOURCE_TI1     = ((uint8_t)0x50),
  PWMA_TIXEXTERNALCLK1SOURCE_TI2     = ((uint8_t)0x60)
}PWMA_TIxExternalCLK1Source_TypeDef;

#define IS_PWMA_TIXCLK_SOURCE_OK(SOURCE)  (((SOURCE) == PWMA_TIXEXTERNALCLK1SOURCE_TI1ED) || \
    ((SOURCE) == PWMA_TIXEXTERNALCLK1SOURCE_TI2) || \
    ((SOURCE) == PWMA_TIXEXTERNALCLK1SOURCE_TI1))

/** PWMA External Trigger Polarity */
typedef enum
{
  PWMA_EXTTRGPOLARITY_INVERTED       = ((uint8_t)0x80),
  PWMA_EXTTRGPOLARITY_NONINVERTED    = ((uint8_t)0x00)
}PWMA_ExtTRGPolarity_TypeDef;

#define IS_PWMA_EXT_POLARITY_OK(POLARITY) (((POLARITY) == PWMA_EXTTRGPOLARITY_INVERTED) || \
    ((POLARITY) == PWMA_EXTTRGPOLARITY_NONINVERTED))

/** PWMA Prescaler Reload Mode */
typedef enum
{
  PWMA_PSCRELOADMODE_UPDATE          = ((uint8_t)0x00),
  PWMA_PSCRELOADMODE_IMMEDIATE       = ((uint8_t)0x01)
}PWMA_PSCReloadMode_TypeDef;

#define IS_PWMA_PRESCALER_RELOAD_OK(RELOAD) (((RELOAD) == PWMA_PSCRELOADMODE_UPDATE) || \
    ((RELOAD) == PWMA_PSCRELOADMODE_IMMEDIATE))

/** PWMA Encoder Mode */
typedef enum
{
  PWMA_ENCODERMODE_TI1               = ((uint8_t)0x01),
  PWMA_ENCODERMODE_TI2               = ((uint8_t)0x02),
  PWMA_ENCODERMODE_TI12              = ((uint8_t)0x03)
}PWMA_EncoderMode_TypeDef;

#define IS_PWMA_ENCODER_MODE_OK(MODE) (((MODE) == PWMA_ENCODERMODE_TI1) || \
                                       ((MODE) == PWMA_ENCODERMODE_TI2) || \
                                       ((MODE) == PWMA_ENCODERMODE_TI12))

/** PWMA Event Source */
typedef enum
{
  PWMA_EVENTSOURCE_UPDATE            = ((uint8_t)0x01),
  PWMA_EVENTSOURCE_CC1               = ((uint8_t)0x02),
  PWMA_EVENTSOURCE_CC2               = ((uint8_t)0x04),
  PWMA_EVENTSOURCE_CC3               = ((uint8_t)0x08),
  PWMA_EVENTSOURCE_CC4               = ((uint8_t)0x10),
  PWMA_EVENTSOURCE_COM               = ((uint8_t)0x20),
  PWMA_EVENTSOURCE_TRIGGER           = ((uint8_t)0x40),
  PWMA_EVENTSOURCE_BREAK             = ((uint8_t)0x80)
}PWMA_EventSource_TypeDef;

#define IS_PWMA_EVENT_SOURCE_OK(SOURCE) ((SOURCE) != 0x00)

/** PWMA Update Source */
typedef enum
{
  PWMA_UPDATESOURCE_GLOBAL           = ((uint8_t)0x00),
  PWMA_UPDATESOURCE_REGULAR          = ((uint8_t)0x01)
}PWMA_UpdateSource_TypeDef;

#define IS_PWMA_UPDATE_SOURCE_OK(SOURCE) (((SOURCE) == PWMA_UPDATESOURCE_GLOBAL) || \
    ((SOURCE) == PWMA_UPDATESOURCE_REGULAR))

/** PWMA Trigger Output Source */
typedef enum
{
  PWMA_TRGOSOURCE_RESET              = ((uint8_t)0x00),
  PWMA_TRGOSOURCE_ENABLE             = ((uint8_t)0x10),
  PWMA_TRGOSOURCE_UPDATE             = ((uint8_t)0x20),
  PWMA_TRGOSource_OC1                = ((uint8_t)0x30),
  PWMA_TRGOSOURCE_OC1REF             = ((uint8_t)0x40),
  PWMA_TRGOSOURCE_OC2REF             = ((uint8_t)0x50),
  PWMA_TRGOSOURCE_OC3REF             = ((uint8_t)0x60)
}PWMA_TRGOSource_TypeDef;

#define IS_PWMA_TRGO_SOURCE_OK(SOURCE) (((SOURCE) == PWMA_TRGOSOURCE_RESET) || \
                                        ((SOURCE) == PWMA_TRGOSOURCE_ENABLE) || \
                                        ((SOURCE) == PWMA_TRGOSOURCE_UPDATE) || \
                                        ((SOURCE) == PWMA_TRGOSource_OC1)  || \
                                        ((SOURCE) == PWMA_TRGOSOURCE_OC1REF) || \
                                        ((SOURCE) == PWMA_TRGOSOURCE_OC2REF) || \
                                        ((SOURCE) == PWMA_TRGOSOURCE_OC3REF))

/** PWMA Slave Mode */
typedef enum
{
  PWMA_SLAVEMODE_RESET               = ((uint8_t)0x04),
  PWMA_SLAVEMODE_GATED               = ((uint8_t)0x05),
  PWMA_SLAVEMODE_TRIGGER             = ((uint8_t)0x06),
  PWMA_SLAVEMODE_EXTERNAL1           = ((uint8_t)0x07)
}PWMA_SlaveMode_TypeDef;

#define IS_PWMA_SLAVE_MODE_OK(MODE) (((MODE) == PWMA_SLAVEMODE_RESET) || \
                                     ((MODE) == PWMA_SLAVEMODE_GATED) || \
                                     ((MODE) == PWMA_SLAVEMODE_TRIGGER) || \
                                     ((MODE) == PWMA_SLAVEMODE_EXTERNAL1))

/** PWMA Flags */
typedef enum
{
  PWMA_FLAG_UPDATE                   = ((uint16_t)0x0001),
  PWMA_FLAG_CC1                      = ((uint16_t)0x0002),
  PWMA_FLAG_CC2                      = ((uint16_t)0x0004),
  PWMA_FLAG_CC3                      = ((uint16_t)0x0008),
  PWMA_FLAG_CC4                      = ((uint16_t)0x0010),
  PWMA_FLAG_COM                      = ((uint16_t)0x0020),
  PWMA_FLAG_TRIGGER                  = ((uint16_t)0x0040),
  PWMA_FLAG_BREAK                    = ((uint16_t)0x0080),
  PWMA_FLAG_CC1OF                    = ((uint16_t)0x0200),
  PWMA_FLAG_CC2OF                    = ((uint16_t)0x0400),
  PWMA_FLAG_CC3OF                    = ((uint16_t)0x0800),
  PWMA_FLAG_CC4OF                    = ((uint16_t)0x1000)
}PWMA_FLAG_TypeDef;

#define IS_PWMA_GET_FLAG_OK(FLAG) (((FLAG) == PWMA_FLAG_UPDATE) || \
                                   ((FLAG) == PWMA_FLAG_CC1) || \
                                   ((FLAG) == PWMA_FLAG_CC2) || \
                                   ((FLAG) == PWMA_FLAG_CC3) || \
                                   ((FLAG) == PWMA_FLAG_CC4) || \
                                   ((FLAG) == PWMA_FLAG_COM) || \
                                   ((FLAG) == PWMA_FLAG_TRIGGER) || \
                                   ((FLAG) == PWMA_FLAG_BREAK) || \
                                   ((FLAG) == PWMA_FLAG_CC1OF) || \
                                   ((FLAG) == PWMA_FLAG_CC2OF) || \
                                   ((FLAG) == PWMA_FLAG_CC3OF) || \
                                   ((FLAG) == PWMA_FLAG_CC4OF))

#define IS_PWMA_CLEAR_FLAG_OK(FLAG) ((((uint16_t)(FLAG) & (uint16_t)0xE100) == 0x0000) && ((FLAG) != 0x0000))

/** PWMA Forced Action */
typedef enum
{
  PWMA_FORCEDACTION_ACTIVE           = ((uint8_t)0x50),
  PWMA_FORCEDACTION_INACTIVE         = ((uint8_t)0x40)
}PWMA_ForcedAction_TypeDef;

#define IS_PWMA_FORCED_ACTION_OK(ACTION) (((ACTION) == PWMA_FORCEDACTION_ACTIVE) || \
    ((ACTION) == PWMA_FORCEDACTION_INACTIVE))

/** PWMA_Exported_Functions */

void PWMA_DeInit(void);
void PWMA_TimeBaseInit(uint16_t PWMA_Prescaler, 
                       PWMA_CounterMode_TypeDef PWMA_CounterMode,
                       uint16_t PWMA_Period, uint8_t PWMA_RepetitionCounter);
void PWMA_OC1Init(PWMA_OCMode_TypeDef PWMA_OCMode, 
                  PWMA_OutputState_TypeDef PWMA_OutputState, 
                  PWMA_OutputNState_TypeDef PWMA_OutputNState, 
                  uint16_t PWMA_Pulse, PWMA_OCPolarity_TypeDef PWMA_OCPolarity, 
                  PWMA_OCNPolarity_TypeDef PWMA_OCNPolarity, 
                  PWMA_OCIdleState_TypeDef PWMA_OCIdleState, 
                  PWMA_OCNIdleState_TypeDef PWMA_OCNIdleState);
void PWMA_OC2Init(PWMA_OCMode_TypeDef PWMA_OCMode, 
                  PWMA_OutputState_TypeDef PWMA_OutputState, 
                  PWMA_OutputNState_TypeDef PWMA_OutputNState, 
                  uint16_t PWMA_Pulse, PWMA_OCPolarity_TypeDef PWMA_OCPolarity, 
                  PWMA_OCNPolarity_TypeDef PWMA_OCNPolarity, 
                  PWMA_OCIdleState_TypeDef PWMA_OCIdleState, 
                  PWMA_OCNIdleState_TypeDef PWMA_OCNIdleState);
void PWMA_OC3Init(PWMA_OCMode_TypeDef PWMA_OCMode, 
                  PWMA_OutputState_TypeDef PWMA_OutputState, 
                  PWMA_OutputNState_TypeDef PWMA_OutputNState, 
                  uint16_t PWMA_Pulse, PWMA_OCPolarity_TypeDef PWMA_OCPolarity, 
                  PWMA_OCNPolarity_TypeDef PWMA_OCNPolarity, 
                  PWMA_OCIdleState_TypeDef PWMA_OCIdleState, 
                  PWMA_OCNIdleState_TypeDef PWMA_OCNIdleState);
void PWMA_OC4Init(PWMA_OCMode_TypeDef PWMA_OCMode,
                  PWMA_OutputState_TypeDef PWMA_OutputState,
                  PWMA_OutputNState_TypeDef PWMA_OutputNState,
                  uint16_t PWMA_Pulse,
                  PWMA_OCPolarity_TypeDef PWMA_OCPolarity,
                  PWMA_OCNPolarity_TypeDef PWMA_OCNPolarity,
                  PWMA_OCIdleState_TypeDef PWMA_OCIdleState,
                  PWMA_OCNIdleState_TypeDef PWMA_OCNIdleState);

void PWMA_BDTRConfig(PWMA_OSSIState_TypeDef PWMA_OSSIState, 
                     PWMA_LockLevel_TypeDef PWMA_LockLevel, uint8_t PWMA_DeadTime,
                     PWMA_BreakState_TypeDef PWMA_Break, 
                     PWMA_BreakPolarity_TypeDef PWMA_BreakPolarity, 
                     PWMA_AutomaticOutput_TypeDef PWMA_AutomaticOutput);
void PWMA_ICInit(PWMA_Channel_TypeDef PWMA_Channel, 
                 PWMA_ICPolarity_TypeDef PWMA_ICPolarity, 
                 PWMA_ICSelection_TypeDef PWMA_ICSelection, 
                 PWMA_ICPSC_TypeDef PWMA_ICPrescaler, uint8_t PWMA_ICFilter);
void PWMA_PWMIConfig(PWMA_Channel_TypeDef PWMA_Channel, 
                     PWMA_ICPolarity_TypeDef PWMA_ICPolarity, 
                     PWMA_ICSelection_TypeDef PWMA_ICSelection, 
                     PWMA_ICPSC_TypeDef PWMA_ICPrescaler, uint8_t PWMA_ICFilter);
void PWMA_Cmd(FunctionalState NewState);
void PWMA_CtrlPWMOutputs(FunctionalState NewState);
void PWMA_ITConfig(PWMA_IT_TypeDef PWMA_IT, FunctionalState NewState);
void PWMA_InternalClockConfig(void);
void PWMA_ETRClockMode1Config(PWMA_ExtTRGPSC_TypeDef PWMA_ExtTRGPrescaler, 
                              PWMA_ExtTRGPolarity_TypeDef PWMA_ExtTRGPolarity, 
                              uint8_t ExtTRGFilter);
void PWMA_ETRClockMode2Config(PWMA_ExtTRGPSC_TypeDef PWMA_ExtTRGPrescaler, 
                              PWMA_ExtTRGPolarity_TypeDef PWMA_ExtTRGPolarity, 
                              uint8_t ExtTRGFilter);
void PWMA_ETRConfig(PWMA_ExtTRGPSC_TypeDef PWMA_ExtTRGPrescaler, 
                    PWMA_ExtTRGPolarity_TypeDef PWMA_ExtTRGPolarity, 
                    uint8_t ExtTRGFilter);
void PWMA_TIxExternalClockConfig(PWMA_TIxExternalCLK1Source_TypeDef PWMA_TIxExternalCLKSource, 
                                 PWMA_ICPolarity_TypeDef PWMA_ICPolarity, 
                                 uint8_t ICFilter);
void PWMA_SelectInputTrigger(PWMA_TS_TypeDef PWMA_InputTriggerSource);
void PWMA_UpdateDisableConfig(FunctionalState NewState);
void PWMA_UpdateRequestConfig(PWMA_UpdateSource_TypeDef PWMA_UpdateSource);
void PWMA_SelectHallSensor(FunctionalState NewState);
void PWMA_SelectOnePulseMode(PWMA_OPMode_TypeDef PWMA_OPMode);
void PWMA_SelectOutputTrigger(PWMA_TRGOSource_TypeDef PWMA_TRGOSource);
void PWMA_SelectSlaveMode(PWMA_SlaveMode_TypeDef PWMA_SlaveMode);
void PWMA_SelectMasterSlaveMode(FunctionalState NewState);
void PWMA_EncoderInterfaceConfig(PWMA_EncoderMode_TypeDef PWMA_EncoderMode, 
                                 PWMA_ICPolarity_TypeDef PWMA_IC1Polarity, 
                                 PWMA_ICPolarity_TypeDef PWMA_IC2Polarity);
void PWMA_PrescalerConfig(uint16_t Prescaler, PWMA_PSCReloadMode_TypeDef PWMA_PSCReloadMode);
void PWMA_CounterModeConfig(PWMA_CounterMode_TypeDef PWMA_CounterMode);
void PWMA_ForcedOC1Config(PWMA_ForcedAction_TypeDef PWMA_ForcedAction);
void PWMA_ForcedOC2Config(PWMA_ForcedAction_TypeDef PWMA_ForcedAction);
void PWMA_ForcedOC3Config(PWMA_ForcedAction_TypeDef PWMA_ForcedAction);
void PWMA_ForcedOC4Config(PWMA_ForcedAction_TypeDef PWMA_ForcedAction);
void PWMA_ARRPreloadConfig(FunctionalState NewState);
void PWMA_SelectCOM(FunctionalState NewState);
void PWMA_CCPreloadControl(FunctionalState NewState);
void PWMA_OC1PreloadConfig(FunctionalState NewState);
void PWMA_OC2PreloadConfig(FunctionalState NewState);
void PWMA_OC3PreloadConfig(FunctionalState NewState);
void PWMA_OC4PreloadConfig(FunctionalState NewState);
void PWMA_OC1FastConfig(FunctionalState NewState);
void PWMA_OC2FastConfig(FunctionalState NewState);
void PWMA_OC3FastConfig(FunctionalState NewState);
void PWMA_OC4FastConfig(FunctionalState NewState);
void PWMA_GenerateEvent(PWMA_EventSource_TypeDef PWMA_EventSource);
void PWMA_OC1PolarityConfig(PWMA_OCPolarity_TypeDef PWMA_OCPolarity);
void PWMA_OC1NPolarityConfig(PWMA_OCNPolarity_TypeDef PWMA_OCNPolarity);
void PWMA_OC2PolarityConfig(PWMA_OCPolarity_TypeDef PWMA_OCPolarity);
void PWMA_OC2NPolarityConfig(PWMA_OCNPolarity_TypeDef PWMA_OCNPolarity);
void PWMA_OC3PolarityConfig(PWMA_OCPolarity_TypeDef PWMA_OCPolarity);
void PWMA_OC3NPolarityConfig(PWMA_OCNPolarity_TypeDef PWMA_OCNPolarity);
void PWMA_OC4PolarityConfig(PWMA_OCPolarity_TypeDef PWMA_OCPolarity);
void PWMA_OC4NPolarityConfig(PWMA_OCPolarity_TypeDef PWMA_OCPolarity);

void PWMA_CCxCmd(PWMA_Channel_TypeDef PWMA_Channel, FunctionalState NewState);
void PWMA_CCxNCmd(PWMA_Channel_TypeDef PWMA_Channel, FunctionalState NewState);
void PWMA_SelectOCxM(PWMA_Channel_TypeDef PWMA_Channel, PWMA_OCMode_TypeDef PWMA_OCMode);
void PWMA_SetCounter(uint16_t Counter);
void PWMA_SetAutoreload(uint16_t Autoreload);
void PWMA_SetCompare1(uint16_t Compare1);
void PWMA_SetCompare2(uint16_t Compare2);
void PWMA_SetCompare3(uint16_t Compare3);
void PWMA_SetCompare4(uint16_t Compare4);
void PWMA_SetIC1Prescaler(PWMA_ICPSC_TypeDef PWMA_IC1Prescaler);
void PWMA_SetIC2Prescaler(PWMA_ICPSC_TypeDef PWMA_IC2Prescaler);
void PWMA_SetIC3Prescaler(PWMA_ICPSC_TypeDef PWMA_IC3Prescaler);
void PWMA_SetIC4Prescaler(PWMA_ICPSC_TypeDef PWMA_IC4Prescaler);
uint16_t PWMA_GetCapture1(void);
uint16_t PWMA_GetCapture2(void);
uint16_t PWMA_GetCapture3(void);
uint16_t PWMA_GetCapture4(void);
uint16_t PWMA_GetCounter(void);
uint16_t PWMA_GetPrescaler(void);
FlagStatus PWMA_GetFlagStatus(PWMA_FLAG_TypeDef PWMA_FLAG);
void PWMA_ClearFlag(PWMA_FLAG_TypeDef PWMA_FLAG);
ITStatus PWMA_GetITStatus(PWMA_IT_TypeDef PWMA_IT);
void PWMA_ClearITPendingBit(PWMA_IT_TypeDef PWMA_IT);

#endif /* __STC32G_PWMA_H */
