/**
 * \author Mr.Nobody
 * \file SAes_Reg.h
 * \ingroup SAes
 * \brief SAes module Reg component header file.
 *
 * This component contains functionality for register operations. It is private
 * to the module (the register access is not shared with other modules).
 *
 */

#ifndef SAES_SAES_REG_H
#define SAES_SAES_REG_H

#ifdef __cplusplus
extern "C" {
#endif

/* ============================= INCLUDES =================================== */
#include "SAes_Types.h"                      /* Module types definition        */
#include "SAes.h"                            /* Register field raw values      */
/* ============================= TYPEDEFS =================================== */

/** \brief List of SAES registers (RM0481, 38.8: AES_TypeDef layout shared with the AES peripheral) */
typedef enum
{
    SAES_REG_CR = 0u, /**< SAES control register                           */
    SAES_REG_SR,      /**< SAES status register                            */
    SAES_REG_DINR,    /**< SAES data input register                        */
    SAES_REG_DOUTR,   /**< SAES data output register                       */
    SAES_REG_KEYR0,   /**< SAES key register 0 (bits 31:0)                 */
    SAES_REG_KEYR1,   /**< SAES key register 1 (bits 63:32)                */
    SAES_REG_KEYR2,   /**< SAES key register 2 (bits 95:64)                */
    SAES_REG_KEYR3,   /**< SAES key register 3 (bits 127:96)               */
    SAES_REG_IVR0,    /**< SAES IV register 0 (bits 31:0)                  */
    SAES_REG_IVR1,    /**< SAES IV register 1 (bits 63:32)                 */
    SAES_REG_IVR2,    /**< SAES IV register 2 (bits 95:64)                 */
    SAES_REG_IVR3,    /**< SAES IV register 3 (bits 127:96)                */
    SAES_REG_KEYR4,   /**< SAES key register 4 (bits 159:128), 256-bit key */
    SAES_REG_KEYR5,   /**< SAES key register 5 (bits 191:160)              */
    SAES_REG_KEYR6,   /**< SAES key register 6 (bits 223:192)              */
    SAES_REG_KEYR7,   /**< SAES key register 7 (bits 255:224)              */
    SAES_REG_SUSP0R,  /**< SAES suspend register 0                         */
    SAES_REG_SUSP1R,  /**< SAES suspend register 1                         */
    SAES_REG_SUSP2R,  /**< SAES suspend register 2                         */
    SAES_REG_SUSP3R,  /**< SAES suspend register 3                         */
    SAES_REG_SUSP4R,  /**< SAES suspend register 4                         */
    SAES_REG_SUSP5R,  /**< SAES suspend register 5                         */
    SAES_REG_SUSP6R,  /**< SAES suspend register 6                         */
    SAES_REG_SUSP7R,  /**< SAES suspend register 7                         */
    SAES_REG_IER,     /**< SAES interrupt enable register                  */
    SAES_REG_ISR,     /**< SAES interrupt status register                  */
    SAES_REG_ICR,     /**< SAES interrupt clear register                   */
    SAES_REG_CNT      /**< Count of available SAES registers               */
}   sAes_RegId_t;

/** \brief Outcome of a bounded register wait (\ref SAes_Reg_Wait_KeyValid / \ref SAes_Reg_Wait_Ccf) */
typedef enum
{
    SAES_REG_WAIT_OK = 0u, /**< The expected flag was set, no error flag                 */
    SAES_REG_WAIT_TIMEOUT, /**< Neither the expected flag nor an error flag was ever set */
    SAES_REG_WAIT_HW_ERROR /**< KEIF / RWEIF / RNGEIF was set while waiting              */
}   sAes_RegWaitResult_t;

/* ========================= SYMBOLIC CONSTANTS ============================= */

/* ========================= EXPORTED MACROS ================================ */

/* ========================= EXPORTED VARIABLES ============================= */

/* ======================== EXPORTED FUNCTIONS ============================== */

/* ---------------------------- Generic accessors --------------------------- */

void                        SAes_Set_RegBit             ( sAes_RegId_t regId, uint32_t bitMask );
void                        SAes_Reset_RegBit           ( sAes_RegId_t regId, uint32_t bitMask );
uint32_t                    SAes_Get_RegBit             ( sAes_RegId_t regId, uint32_t bitMask );

void                        SAes_Set_RegVal             ( sAes_RegId_t regId, uint32_t regMask, uint32_t regValue );
uint32_t                    SAes_Get_RegVal             ( sAes_RegId_t regId, uint32_t regMask );

/* ----------------------------- Register protocol --------------------------- */

sAes_RequestState_t        SAes_Reg_Set_Enable         ( void );
void                        SAes_Reg_Set_Disable        ( void );
sAes_FunctionState_t        SAes_Reg_Get_EnableState    ( void );

sAes_FunctionState_t        SAes_Reg_Get_BusyState      ( void );
sAes_FunctionState_t        SAes_Reg_Get_KeyValidState  ( void );

sAes_RegWaitResult_t        SAes_Reg_Wait_KeyValid      ( void );
sAes_RegWaitResult_t        SAes_Reg_Wait_Ccf           ( void );
sAes_RegWaitResult_t        SAes_Reg_Wait_BusyCleared   ( void );

void                        SAes_Reg_Clear_Ccf          ( void );
void                        SAes_Reg_Clear_Keif         ( void );
void                        SAes_Reg_Clear_Rweif        ( void );
void                        SAes_Reg_Clear_Rngeif       ( void );
void                        SAes_Reg_Clear_AllFlags     ( void );

sAes_XferError_t            SAes_Reg_Get_XferError      ( void );

/* ------------------------------- Data access -------------------------------- */

void                        SAes_Reg_Write_Key          ( const sAes_Data_t * const keyBytes,
                                                          sAes_KeySize_t keySize );
void                        SAes_Reg_Write_Iv           ( const sAes_Data_t * const ivBytes );
void                        SAes_Reg_Read_Iv            ( sAes_Data_t * const ivBytes );

void                        SAes_Reg_Write_Block        ( const sAes_Data_t * const inBytes );
void                        SAes_Reg_Read_Block         ( sAes_Data_t * const outBytes );

void                        SAes_Reg_Write_Suspend      ( const uint32_t * const suspendWords );
void                        SAes_Reg_Read_Suspend       ( uint32_t * const suspendWords );

#ifdef __cplusplus
}
#endif

#endif /* SAES_SAES_REG_H */
