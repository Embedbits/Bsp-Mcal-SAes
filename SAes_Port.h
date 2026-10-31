/**
 * \author Mr.Nobody
 * \file SAes_Port.h
 * \ingroup SAes
 * \brief SAes module public functionality
 *
 * This file contains all available public functionality, any other files shall not
 * be used outside of the module.
 *
 */

#ifndef SAES_SAES_PORT_H
#define SAES_SAES_PORT_H

#ifdef __cplusplus
extern "C" {
#endif

/* ============================== INCLUDES ================================== */
#include "SAes_Types.h"                     /* Module types definition        */
/* ============================== TYPEDEFS ================================== */

/* ========================== SYMBOLIC CONSTANTS ============================ */

/* ========================== EXPORTED MACROS =============================== */

/* ========================== EXPORTED VARIABLES ============================ */

/* ========================= EXPORTED FUNCTIONS ============================= */

sAes_ModuleVersion_t SAes_Get_ModuleVersion  ( void );

sAes_RequestState_t  SAes_Init               ( const sAes_Config_t * const sAesConfig );
sAes_RequestState_t  SAes_Deinit             ( void );
void                 SAes_Task               ( void );
sAes_RequestState_t  SAes_Get_DefaultConfig  ( sAes_Config_t * const sAesConfig );

/* -------------------------- Capability and state ---------------------------- */

sAes_RequestState_t  SAes_Get_Capability     ( sAes_KeySource_t keySource,
                                               sAes_Mode_t mode,
                                               sAes_FunctionState_t * const supported );
sAes_RequestState_t  SAes_Get_State          ( sAes_State_t * const sAesState );
sAes_RequestState_t  SAes_Get_KeyState       ( sAes_KeyState_t * const keyState );
sAes_RequestState_t  SAes_Get_XferError      ( sAes_XferError_t * const xferError );

/* ------------------------------ Key management ------------------------------ */

sAes_RequestState_t  SAes_Set_KeyLoad        ( const sAes_KeyConfig_t * const keyConfig );
sAes_RequestState_t  SAes_Set_KeyWrap        ( const sAes_WrapConfig_t * const wrapConfig,
                                               const sAes_Data_t * const plainKey,
                                               sAes_Data_t * const wrappedKey );
sAes_RequestState_t  SAes_Set_KeyUnwrap      ( const sAes_WrapConfig_t * const wrapConfig,
                                               const sAes_Data_t * const wrappedKey );
sAes_RequestState_t  SAes_Set_KeyShare       ( sAes_ShareTarget_t shareTarget );
sAes_RequestState_t  SAes_Set_KeyClear       ( void );

/* -------------------------------- One-shot ----------------------------------- */

sAes_RequestState_t  SAes_Set_Process        ( const sAes_Request_t * const request );

/* ------------------------------- Incremental ---------------------------------- */

sAes_RequestState_t  SAes_Set_Start          ( const sAes_Request_t * const request );
sAes_RequestState_t  SAes_Set_UpdateAad      ( const sAes_Data_t * const aad, sAes_DataLen_t aadLen );
sAes_RequestState_t  SAes_Set_Update         ( const sAes_Data_t * const input,
                                               sAes_Data_t * const output,
                                               sAes_DataLen_t dataLen );
sAes_RequestState_t  SAes_Set_Finish         ( sAes_Data_t * const tag, sAes_DataCnt_t tagLen );
sAes_RequestState_t  SAes_Set_Abort          ( void );

/* ---------------------------- Suspend and resume ------------------------------ */

sAes_RequestState_t  SAes_Get_Context        ( sAes_Context_t * const context );
sAes_RequestState_t  SAes_Set_Context        ( const sAes_Context_t * const context );

/* -------------------------------- Interrupts ----------------------------------- */

sAes_RequestState_t  SAes_Set_IrqPriority    ( sAes_IrqPrio_t irqPriority );
sAes_RequestState_t  SAes_Get_IrqPriority    ( sAes_IrqPrio_t * const irqPriority );

#ifdef __cplusplus
}
#endif

#endif /* SAES_SAES_PORT_H */
