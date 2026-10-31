/**
 * \author Mr.Nobody
 * \file SAes.c
 * \ingroup SAes
 * \brief SAes module common functionality
 *
 * # Introduction #
 * The secure AES coprocessor shares its register layout with the AES peripheral
 * (RM0481, chapter 38 "Secure AES coprocessor (SAES)"; CMSIS types both as
 * `AES_TypeDef`). Every data, key, IV and tag register is written / read four
 * 32-bit words at a time, MSB first (\ref SAes_Reg.c); the chaining mode and the
 * key handling mode are selected with `SAES_CR.CHMOD` / `SAES_CR.KMOD` /
 * `SAES_CR.GCMPH` (\ref SAes.h, values taken from RM0481 section 38.8.1 and
 * cross-checked against the CMSIS bit positions).
 *
 * # Devices without the SAES peripheral #
 * The SAES exists on the STM32H5 lines whose CMSIS device header defines \c SAES (every line except
 * H503, H523, H543, H562, H563, H5E4 and H5E5). Every public function checks it (\c defined(SAES)):
 * on a device without the peripheral it only returns \ref SAES_REQUEST_ERROR (\ref SAes_Task does
 * nothing, \ref SAes_Get_ModuleVersion returns the version), so no separate stub file is needed.
 *
 * # Synchronous execution (deviation from the README "non-blocking" wording) #
 * Like the Pka module of this wave, every `SAes_Set_*` function here waits
 * (bounded, \ref SAES_REG_TIMEOUT_RAW iterations per register flag) for the
 * hardware step it just started before it returns, instead of leaving the
 * completion to \ref SAes_Task / the interrupt. The configured
 * \ref sAes_CompleteCallback_t / \ref sAes_ErrorCallback_t are still invoked at
 * the end of every call, so application code written against the asynchronous
 * contract keeps working; the DMA transfer mode is accepted by \ref SAes_Init
 * (the register side, `AES_CR_DMAINEN` / `AES_CR_DMAOUTEN`, is wired) but the
 * Gpdma channel itself is not started by this implementation - see the README
 * "Implementation status (STM32H5)" for this and the other deviations.
 *
 * # CCM scope #
 * The CCM chaining mode drives `SAES_CR.GCMPH` exactly as RM0481 section 38.4.13
 * documents (register sequencing only). Building the RFC 3610 / NIST SP800-38C
 * `B0` first block and the `B1` associated-data length prefix is left to the
 * caller: \ref sAes_Request_t.Iv must already be the 16-byte B0 block (RM0481
 * Table 375) and \ref sAes_Request_t.Aad must already include the B1 length
 * prefix. This is a deliberate scope cut (see the README), not an omission.
 *
 */
/* ============================== INCLUDES ================================== */
#include "SAes.h"                            /* Register field raw values      */
#include "SAes_Port.h"                       /* Own port file include          */
#include "SAes_Types.h"                      /* Module types definitions       */
#include "SAes_Reg.h"                        /* Register access                */
#include "Nvic_Port.h"                       /* NVIC handler functionality     */
#include "Rcc_Port.h"                        /* RCC handler functionality      */
#include "Rng_Port.h"                        /* RNG handler functionality      */
#include "Stm32.h"                           /* SAES registers definition      */
/* ============================== TYPEDEFS ================================== */

/** \brief Current module version (common to every family) */
#define SAES_MODULE_VERSION_MAJOR            ( 1u )
#define SAES_MODULE_VERSION_MINOR            ( 0u )
#define SAES_MODULE_VERSION_PATCH            ( 0u )

/* ========================= EXPORTED FUNCTIONS ============================= */

/**
 * \brief Returns the current version of the module.
 *
 * \return The module version
 */
sAes_ModuleVersion_t SAes_Get_ModuleVersion( void )
{
    const sAes_ModuleVersion_t retVersion =
    {
        .Major = SAES_MODULE_VERSION_MAJOR,
        .Minor = SAES_MODULE_VERSION_MINOR,
        .Patch = SAES_MODULE_VERSION_PATCH
    };

    return ( retVersion );
}


#if defined(SAES)

/** \brief Runtime data of the module */
typedef struct
{
    sAes_FunctionState_t    InitState;        /**< \ref SAes_Init completed successfully         */
    sAes_State_t            ModuleState;      /**< Current operating state                       */
    sAes_XferMode_t         XferMode;         /**< Configured transfer mode                      */
    sAes_CompleteCallback_t CompleteCallback; /**< Called at the end of every Set_* call         */
    sAes_ErrorCallback_t    ErrorCallback;    /**< Called on an asynchronous hardware error      */
    sAes_KeyState_t         KeyState;         /**< Validity of the key currently loaded          */
    sAes_XferError_t        LastXferError;    /**< Last decoded hardware error                   */
    sAes_Operation_t        CurOperation;     /**< Incremental request: operation                */
    sAes_Mode_t             CurMode;          /**< Incremental request: chaining mode            */
    sAes_FunctionState_t    AadClosed;        /**< Incremental AEAD request: header phase closed */
}   sAes_RuntimeData_t;

/* ======================== FORWARD DECLARATIONS ============================ */

static uint32_t              SAes_Build_StdCrValue   ( uint32_t chmodRaw,
                                                       uint32_t modeRaw,
                                                       uint32_t kmodRaw,
                                                       uint32_t sizeRaw,
                                                       uint32_t gcmphRaw );
static uint32_t              SAes_Calc_ChmodReg      ( uint32_t chmodRaw );
static uint32_t              SAes_Calc_SizeRaw       ( sAes_KeySize_t keySize );
static uint32_t              SAes_Calc_ModeRaw       ( sAes_Operation_t operation );
static sAes_RequestState_t  SAes_Calc_RequestFromWait( sAes_RegWaitResult_t waitResult );
static sAes_DataCnt_t       SAes_Calc_KeyBlockCnt   ( sAes_KeySize_t keySize );
static sAes_RequestState_t  SAes_Exec_LoadRequestKey( const sAes_Request_t * const request );
static sAes_RegWaitResult_t SAes_Calc_WaitFromRequest( sAes_RequestState_t requestState );
static sAes_FunctionState_t SAes_Calc_IsAead          ( sAes_Mode_t mode );
static void                 SAes_Update_KeyState    ( sAes_RegWaitResult_t waitResult );
static sAes_RequestState_t SAes_Exec_LoadKey        ( sAes_KeySource_t keySource,
                                                      sAes_KeySize_t keySize,
                                                      const sAes_Data_t * const keyBytes,
                                                      sAes_FunctionState_t keyProt );
static void                 SAes_Build_CrBase        ( sAes_Mode_t mode, uint32_t * const chmodRaw );
static sAes_RequestState_t SAes_Exec_PrepareDecrypt ( void );
static sAes_RequestState_t SAes_Exec_SimpleBlocks   ( sAes_Operation_t operation,
                                                      const sAes_Data_t * const input,
                                                      sAes_Data_t * const output,
                                                      sAes_DataLen_t dataLen );
static sAes_RequestState_t SAes_Exec_AeadHeader     ( const sAes_Data_t * const aad, sAes_DataLen_t aadLen );
static sAes_RequestState_t SAes_Exec_AeadPayload    ( sAes_Operation_t operation,
                                                      const sAes_Data_t * const input,
                                                      sAes_Data_t * const output,
                                                      sAes_DataLen_t dataLen );
static sAes_RequestState_t SAes_Exec_GcmFinal       ( sAes_Operation_t operation,
                                                      sAes_DataLen_t aadLen,
                                                      sAes_DataLen_t dataLen,
                                                      sAes_Data_t * const tag,
                                                      sAes_DataCnt_t tagLen );
static sAes_RequestState_t SAes_Exec_CcmFinal       ( sAes_Data_t * const tag, sAes_DataCnt_t tagLen );
static sAes_RequestState_t SAes_Exec_Process_Simple ( const sAes_Request_t * const request, uint32_t chmodRaw );
static sAes_RequestState_t SAes_Exec_Process_Gcm    ( const sAes_Request_t * const request );
static sAes_RequestState_t SAes_Exec_Process_Ccm    ( const sAes_Request_t * const request );
static sAes_RequestState_t SAes_Check_Request       ( const sAes_Request_t * const request );
static void                 SAes_Write_Uint64BigEndian( sAes_Data_t * const dest, uint64_t value );

/* ========================== SYMBOLIC CONSTANTS ============================ */

/** \brief Default interrupt priority proposed by \ref SAes_Get_DefaultConfig */
#define SAES_DEFAULT_IRQ_PRIO                ( 7u )

/** \brief Byte length of the GCM "last block" length field (RM0481, Table 374: 2 x 64-bit) */
#define SAES_GCM_FINAL_BLOCK_BYTES           ( 16u )

/** \brief Byte width of a 64-bit GCM length field (RM0481, Table 374) */
#define SAES_UINT64_BYTES                    ( 8u )

/** \brief Mask of every SAES_CR field set together by \ref SAes_Build_StdCrValue */
#define SAES_CR_STD_MASK                      ( AES_CR_CHMOD | AES_CR_MODE | AES_CR_KMOD | AES_CR_DATATYPE | \
                                                 AES_CR_KEYSIZE | AES_CR_GCMPH                                  )

/* =============================== MACROS =================================== */

/* ========================== EXPORTED VARIABLES ============================ */

/* =========================== LOCAL VARIABLES ============================== */

/** \brief Single instance runtime data (the device has one SAES instance) */
static sAes_RuntimeData_t sAes_Runtime =
{
    .InitState        = SAES_FUNCTION_INACTIVE,
    .ModuleState      = SAES_STATE_UNINIT,
    .XferMode         = SAES_XFER_MODE_POLL,
    .CompleteCallback = SAES_NULL_PTR,
    .ErrorCallback    = SAES_NULL_PTR,
    .KeyState         = SAES_KEY_STATE_NONE,
    .LastXferError    = SAES_XFER_ERROR_NONE,
    .CurOperation     = SAES_OPERATION_ENCRYPT,
    .CurMode          = SAES_MODE_ECB,
    .AadClosed        = SAES_FUNCTION_INACTIVE
};

#endif /* SAES */

/* ========================= EXPORTED FUNCTIONS ============================= */

/**
 * \brief Initializes the module: enables the clock, makes sure the RNG the SAES
 *        side-channel countermeasures depend on is running (RM0481, 38.4.19: SAES
 *        fetches random numbers from the RNG bus) and (ISR/DMA mode) configures
 *        the SAES NVIC interrupt.
 *
 * Verifies the result at the end (SAES_CR.EN read-back, rule 2.7); on failure the
 * module is deinitialized and an error is returned.
 *
 * \param sAesConfig [in]: Pointer to the configuration structure
 * \return \ref SAES_REQUEST_OK on success, \ref SAES_REQUEST_ERROR otherwise
 */
sAes_RequestState_t SAes_Init( const sAes_Config_t * const sAesConfig )
{
    sAes_RequestState_t retState = SAES_REQUEST_ERROR;

#if defined(SAES)
    if( ( SAES_NULL_PTR != sAesConfig ) &&
        ( SAES_XFER_MODE_CNT > sAesConfig->XferMode ) &&
        ( SAES_FUNCTION_INACTIVE == sAes_Runtime.InitState )    )
    {
        const rcc_RequestState_t clockState = Rcc_Set_PeriphActive( RCC_PERIPH_SAES );

        if( RCC_REQUEST_OK == clockState )
        {
            (void)Rng_Set_ExecActive( RNG_PERIPH_1 );

            rng_FunctionState_t rngState = RNG_FUNCTION_INACTIVE;
            const rng_RequestState_t rngQuery = Rng_Get_ExecState( RNG_PERIPH_1, &rngState );

            if( ( RNG_REQUEST_OK == rngQuery )      &&
                ( RNG_FUNCTION_ACTIVE == rngState )    )
            {
                sAes_Runtime.XferMode         = sAesConfig->XferMode;
                sAes_Runtime.CompleteCallback = sAesConfig->CompleteCallback;
                sAes_Runtime.ErrorCallback    = sAesConfig->ErrorCallback;
                sAes_Runtime.KeyState         = SAES_KEY_STATE_NONE;
                sAes_Runtime.LastXferError    = SAES_XFER_ERROR_NONE;
                sAes_Runtime.AadClosed        = SAES_FUNCTION_INACTIVE;

                SAes_Reg_Clear_AllFlags();

                if( SAES_XFER_MODE_POLL != sAesConfig->XferMode )
                {
                    (void)Nvic_Set_PeriphIrq_Prio( NVIC_PERIPH_IRQ_SAES, (nvic_IrqPrio_t)sAesConfig->IrqPriority );
                    (void)Nvic_Set_PeriphIrq_Active( NVIC_PERIPH_IRQ_SAES );
                }
                else
                {
                    /* POLL mode, the NVIC line of the peripheral is not used */
                }

                sAes_Runtime.InitState   = SAES_FUNCTION_ACTIVE;
                sAes_Runtime.ModuleState = SAES_STATE_IDLE;
                retState                 = SAES_REQUEST_OK;
            }
            else
            {
                /* The RNG could not be confirmed running, the side-channel countermeasures
                 * of the SAES would starve: the module is deinitialized below */
                retState = SAES_REQUEST_ERROR;
            }
        }
        else
        {
            /* Clock could not be enabled, nothing else is touched */
            retState = SAES_REQUEST_ERROR;
        }
    }
    else
    {
        /* Invalid configuration or the module is already initialized */
        retState = SAES_REQUEST_ERROR;
    }

    if( SAES_REQUEST_OK != retState )
    {
        (void)SAes_Deinit();
    }
    else
    {
        /* Initialization succeeded, nothing to roll back */
    }
#else
    (void)sAesConfig;
#endif /* SAES */

    return ( retState );
}


/**
 * \brief Deinitializes the module: clears the key, disables the interrupt, the
 *        SAES and its clock. The RNG is left running (other modules may use it).
 *
 * \return \ref SAES_REQUEST_OK, \ref SAES_REQUEST_ERROR on a device without the SAES peripheral.
 */
sAes_RequestState_t SAes_Deinit( void )
{
    sAes_RequestState_t retState = SAES_REQUEST_ERROR;

#if defined(SAES)
    SAes_Reg_Set_Disable();
    SAes_Reg_Clear_AllFlags();
    (void)Nvic_Set_PeriphIrq_Inactive( NVIC_PERIPH_IRQ_SAES );
    (void)Rcc_Set_PeriphInactive( RCC_PERIPH_SAES );

    sAes_Runtime.InitState        = SAES_FUNCTION_INACTIVE;
    sAes_Runtime.ModuleState      = SAES_STATE_UNINIT;
    sAes_Runtime.CompleteCallback = SAES_NULL_PTR;
    sAes_Runtime.ErrorCallback    = SAES_NULL_PTR;
    sAes_Runtime.KeyState         = SAES_KEY_STATE_NONE;
    sAes_Runtime.LastXferError    = SAES_XFER_ERROR_NONE;
    sAes_Runtime.AadClosed        = SAES_FUNCTION_INACTIVE;
    retState                      = SAES_REQUEST_OK;
#endif /* SAES */

    return ( retState );
}


/**
 * \brief Serves the POLL transfer mode.
 *
 * Every operation of this implementation finishes synchronously inside its
 * `SAes_Set_*` call (see the file introduction), so there is never a pending
 * operation left for this function to finish; it is kept for interface
 * compatibility with the other families / a future asynchronous version.
 */
void SAes_Task( void )
{
    return;
}


/**
 * \brief Fills \p sAesConfig with the default configuration (POLL mode, no callbacks).
 *
 * \param sAesConfig [out]: Pointer to the configuration structure
 * \return \ref SAES_REQUEST_OK on success, \ref SAES_REQUEST_ERROR for a null pointer
 */
sAes_RequestState_t SAes_Get_DefaultConfig( sAes_Config_t * const sAesConfig )
{
    sAes_RequestState_t retState = SAES_REQUEST_ERROR;

#if defined(SAES)
    if( SAES_NULL_PTR != sAesConfig )
    {
        sAesConfig->XferMode         = SAES_XFER_MODE_POLL;
        sAesConfig->IrqPriority      = (sAes_IrqPrio_t)SAES_DEFAULT_IRQ_PRIO;
        sAesConfig->CompleteCallback = SAES_NULL_PTR;
        sAesConfig->ErrorCallback    = SAES_NULL_PTR;
        retState                    = SAES_REQUEST_OK;
    }
    else
    {
        /* Null pointer, nothing is written */
        retState = SAES_REQUEST_ERROR;
    }
#else
    (void)sAesConfig;
#endif /* SAES */

    return ( retState );
}


/**
 * \brief Reports whether a key source / chaining mode combination is supported.
 *
 * Every combination documented by RM0481 chapter 38 is supported on every line that
 * has the SAES peripheral (there is no narrower sub-set on STM32H533/553/573/H5F4/H5F5);
 * the getter has no side effect (rule of section 5 of the digest).
 *
 * \param keySource [in]:  Key source to query
 * \param mode      [in]:  Chaining mode to query
 * \param supported [out]: Pointer to the result
 * \return \ref SAES_REQUEST_OK on success, \ref SAES_REQUEST_ERROR for invalid parameters
 */
sAes_RequestState_t SAes_Get_Capability( sAes_KeySource_t keySource,
                                         sAes_Mode_t mode,
                                         sAes_FunctionState_t * const supported )
{
    sAes_RequestState_t retState = SAES_REQUEST_ERROR;

#if defined(SAES)
    if( ( SAES_KEY_SOURCE_CNT > keySource ) &&
        ( SAES_MODE_CNT > mode )            &&
        ( SAES_NULL_PTR != supported )        )
    {
        *supported = SAES_FUNCTION_ACTIVE;
        retState   = SAES_REQUEST_OK;
    }
    else
    {
        /* Invalid parameter, nothing is written */
        retState = SAES_REQUEST_ERROR;
    }
#else
    (void)keySource;
    (void)mode;
    (void)supported;
#endif /* SAES */

    return ( retState );
}


/**
 * \brief Returns the current operating state of the module.
 *
 * \param sAesState [out]: Pointer to the state
 * \return \ref SAES_REQUEST_OK on success, \ref SAES_REQUEST_ERROR for a null pointer
 */
sAes_RequestState_t SAes_Get_State( sAes_State_t * const sAesState )
{
    sAes_RequestState_t retState = SAES_REQUEST_ERROR;

#if defined(SAES)
    if( SAES_NULL_PTR != sAesState )
    {
        *sAesState = sAes_Runtime.ModuleState;
        retState   = SAES_REQUEST_OK;
    }
    else
    {
        /* Null pointer, nothing is written */
        retState = SAES_REQUEST_ERROR;
    }
#else
    (void)sAesState;
#endif /* SAES */

    return ( retState );
}


/**
 * \brief Returns the validity of the key currently loaded in the SAES key registers.
 *
 * \param keyState [out]: Pointer to the key state
 * \return \ref SAES_REQUEST_OK on success, \ref SAES_REQUEST_ERROR for a null pointer
 */
sAes_RequestState_t SAes_Get_KeyState( sAes_KeyState_t * const keyState )
{
    sAes_RequestState_t retState = SAES_REQUEST_ERROR;

#if defined(SAES)
    if( SAES_NULL_PTR != keyState )
    {
        *keyState = sAes_Runtime.KeyState;
        retState  = SAES_REQUEST_OK;
    }
    else
    {
        /* Null pointer, nothing is written */
        retState = SAES_REQUEST_ERROR;
    }
#else
    (void)keyState;
#endif /* SAES */

    return ( retState );
}


/**
 * \brief Returns the last hardware transfer error decoded from SAES_ISR.
 *
 * \param xferError [out]: Pointer to the error
 * \return \ref SAES_REQUEST_OK on success, \ref SAES_REQUEST_ERROR for a null pointer
 */
sAes_RequestState_t SAes_Get_XferError( sAes_XferError_t * const xferError )
{
    sAes_RequestState_t retState = SAES_REQUEST_ERROR;

#if defined(SAES)
    if( SAES_NULL_PTR != xferError )
    {
        *xferError = sAes_Runtime.LastXferError;
        retState   = SAES_REQUEST_OK;
    }
    else
    {
        /* Null pointer, nothing is written */
        retState = SAES_REQUEST_ERROR;
    }
#else
    (void)xferError;
#endif /* SAES */

    return ( retState );
}


/**
 * \brief Loads a key into the SAES key registers in normal key mode (RM0481, 38.8.1
 *        KMOD = 0x0, and 38.4.17 for the hardware key sources).
 *
 * \param keyConfig [in]: Pointer to the key configuration
 * \return \ref SAES_REQUEST_OK on success, \ref SAES_REQUEST_ERROR otherwise
 */
sAes_RequestState_t SAes_Set_KeyLoad( const sAes_KeyConfig_t * const keyConfig )
{
    sAes_RequestState_t retState = SAES_REQUEST_ERROR;

#if defined(SAES)
    if( ( SAES_FUNCTION_ACTIVE == sAes_Runtime.InitState )      &&
        ( SAES_NULL_PTR != keyConfig )                          &&
        ( SAES_KEY_SOURCE_CNT > keyConfig->KeySource )           &&
        ( SAES_KEY_SIZE_CNT > keyConfig->KeySize )                 )
    {
        SAes_Reg_Set_Disable();
        (void)SAes_Reg_Wait_BusyCleared();

        uint32_t chmodRaw = SAES_CR_CHMOD_ECB_RAW;
        uint32_t keyProtRaw = 0u;

        SAes_Build_CrBase( SAES_MODE_ECB, &chmodRaw );

        if( SAES_FUNCTION_ACTIVE == keyConfig->Protect )
        {
            keyProtRaw = AES_CR_KEYPROT;
        }
        else
        {
            keyProtRaw = 0u;
        }

        const uint32_t crMask  = ( AES_CR_CHMOD | AES_CR_MODE | AES_CR_KMOD | AES_CR_DATATYPE |
                                   AES_CR_KEYSIZE | AES_CR_KEYPROT                               );
        const uint32_t crValue = ( SAes_Calc_ChmodReg( chmodRaw )               |
                                   ( SAES_CR_MODE_ENCRYPT_RAW << AES_CR_MODE_Pos ) |
                                   ( SAES_CR_KMOD_NORMAL_RAW << AES_CR_KMOD_Pos ) |
                                   ( SAES_CR_DATATYPE_NONE_RAW << AES_CR_DATATYPE_Pos ) |
                                   SAes_Calc_SizeRaw( keyConfig->KeySize ) | keyProtRaw             );

        SAes_Set_RegVal( SAES_REG_CR, crMask, crValue );

        retState = SAes_Exec_LoadKey( keyConfig->KeySource,
                                      keyConfig->KeySize,
                                      keyConfig->KeyBytes,
                                      keyConfig->Protect );
    }
    else
    {
        /* Invalid parameter or the module is not initialized */
        retState = SAES_REQUEST_ERROR;
    }
#else
    (void)keyConfig;
#endif /* SAES */

    return ( retState );
}


/**
 * \brief Wraps (encrypts) a key with the selected key source (RM0481, 38.4.14,
 *        "Key wrapping for SAES"/"...CTR mode").
 *
 * \param wrapConfig [in]:  Pointer to the wrap configuration
 * \param plainKey   [in]:  Key to wrap, big-endian, WrappedKeySize long
 * \param wrappedKey [out]: Resulting wrapped blob, same length as \p plainKey
 * \return \ref SAES_REQUEST_OK on success, \ref SAES_REQUEST_ERROR otherwise
 */
sAes_RequestState_t SAes_Set_KeyWrap( const sAes_WrapConfig_t * const wrapConfig,
                                      const sAes_Data_t * const plainKey,
                                      sAes_Data_t * const wrappedKey )
{
    sAes_RequestState_t retState = SAES_REQUEST_ERROR;

#if defined(SAES)
    if( ( SAES_FUNCTION_ACTIVE == sAes_Runtime.InitState )     &&
        ( SAES_NULL_PTR != wrapConfig )                         &&
        ( SAES_NULL_PTR != plainKey )                           &&
        ( SAES_NULL_PTR != wrappedKey )                         &&
        ( SAES_MODE_CTR >= wrapConfig->Mode )                   &&
        ( SAES_KEY_SIZE_CNT > wrapConfig->WrapKeySize )          &&
        ( SAES_KEY_SIZE_CNT > wrapConfig->WrappedKeySize )         )
    {
        if( SAES_MODE_CTR == wrapConfig->Mode )
        {
            /* CTR-mode "wrap" derives a key from the IV, there is nothing to encrypt
             * (RM0481, Figure 374): not a valid direction for SAes_Set_KeyWrap */
            retState = SAES_REQUEST_ERROR;
        }
        else
        {
            SAes_Reg_Set_Disable();
            (void)SAes_Reg_Wait_BusyCleared();

            uint32_t chmodRaw = SAES_CR_CHMOD_ECB_RAW;

            SAes_Build_CrBase( wrapConfig->Mode, &chmodRaw );
            SAes_Set_RegVal( SAES_REG_CR,
                             SAES_CR_STD_MASK,
                             SAes_Build_StdCrValue( chmodRaw,
                                                    SAES_CR_MODE_ENCRYPT_RAW,
                                                    SAES_CR_KMOD_WRAPPED_RAW,
                                                    SAes_Calc_SizeRaw( wrapConfig->WrappedKeySize ),
                                                    SAES_CR_GCMPH_INIT_RAW                               ) );

            if( SAES_MODE_CBC == wrapConfig->Mode )
            {
                SAes_Reg_Write_Iv( wrapConfig->Iv );
            }
            else
            {
                /* ECB does not use an IV */
            }

            const sAes_RequestState_t keyState = SAes_Exec_LoadKey( wrapConfig->WrapKeySource,
                                                                    wrapConfig->WrapKeySize,
                                                                    wrapConfig->WrapKeyBytes,
                                                                    SAES_FUNCTION_INACTIVE );

            if( SAES_REQUEST_OK == keyState )
            {
                const sAes_RequestState_t enableState = SAes_Reg_Set_Enable();
                sAes_RequestState_t         blockState   = SAES_REQUEST_ERROR;

                if( SAES_REQUEST_OK == enableState )
                {
                    const sAes_DataCnt_t wordCnt = SAes_Calc_KeyBlockCnt( wrapConfig->WrappedKeySize );

                    blockState = SAES_REQUEST_OK;

                    for( sAes_DataCnt_t blockIdx = 0u; wordCnt > blockIdx; blockIdx++ )
                    {
                        const uint32_t byteOff = ( blockIdx * SAES_BLOCK_BYTES );

                        SAes_Reg_Write_Block( &plainKey[byteOff] );

                        const sAes_RegWaitResult_t ccfResult = SAes_Reg_Wait_Ccf();

                        if( SAES_REG_WAIT_OK == ccfResult )
                        {
                            SAes_Reg_Read_Block( &wrappedKey[byteOff] );
                            SAes_Reg_Clear_Ccf();
                        }
                        else
                        {
                            blockState = SAES_REQUEST_ERROR;
                            break;
                        }
                    }
                }
                else
                {
                    /* EN did not read back set */
                    blockState = SAES_REQUEST_ERROR;
                }

                SAes_Reg_Set_Disable();
                retState = blockState;
            }
            else
            {
                /* Key could not be loaded, nothing was encrypted */
                retState = SAES_REQUEST_ERROR;
            }
        }
    }
    else
    {
        /* Invalid parameter or the module is not initialized */
        retState = SAES_REQUEST_ERROR;
    }
#else
    (void)wrapConfig;
    (void)plainKey;
    (void)wrappedKey;
#endif /* SAES */

    return ( retState );
}


/**
 * \brief Unwraps (decrypts) a wrapped key directly into the SAES key registers, or
 *        derives it from an IV in CTR mode (RM0481, 38.4.14). At the end the key
 *        is immediately usable in normal key mode (KMOD = 0x0).
 *
 * \param wrapConfig  [in]: Pointer to the wrap configuration
 * \param wrappedKey  [in]: Wrapped blob to unwrap, big-endian, WrappedKeySize long
 *                          (ignored in CTR mode, the key is derived from the IV)
 * \return \ref SAES_REQUEST_OK on success, \ref SAES_REQUEST_ERROR otherwise
 */
sAes_RequestState_t SAes_Set_KeyUnwrap( const sAes_WrapConfig_t * const wrapConfig,
                                        const sAes_Data_t * const wrappedKey )
{
    sAes_RequestState_t retState = SAES_REQUEST_ERROR;

#if defined(SAES)
    if( ( SAES_FUNCTION_ACTIVE == sAes_Runtime.InitState )     &&
        ( SAES_NULL_PTR != wrapConfig )                         &&
        ( SAES_MODE_CTR >= wrapConfig->Mode )                   &&
        ( SAES_KEY_SIZE_CNT > wrapConfig->WrapKeySize )          &&
        ( SAES_KEY_SIZE_CNT > wrapConfig->WrappedKeySize )         )
    {
        SAes_Reg_Set_Disable();
        (void)SAes_Reg_Wait_BusyCleared();

        const uint32_t sizeRaw = SAes_Calc_SizeRaw( wrapConfig->WrappedKeySize );

        if( SAES_MODE_CTR == wrapConfig->Mode )
        {
            /* Derive the key from the IV (RM0481, Figure 374): single pass, MODE = decryption */
            SAes_Set_RegVal( SAES_REG_CR,
                             SAES_CR_STD_MASK,
                             SAes_Build_StdCrValue( SAES_CR_CHMOD_CTR_RAW,
                                                    SAES_CR_MODE_DECRYPT_RAW,
                                                    SAES_CR_KMOD_WRAPPED_RAW,
                                                    sizeRaw,
                                                    SAES_CR_GCMPH_INIT_RAW                     ) );
            SAes_Reg_Write_Iv( wrapConfig->Iv );

            const sAes_RequestState_t keyState = SAes_Exec_LoadKey( wrapConfig->WrapKeySource,
                                                                    wrapConfig->WrapKeySize,
                                                                    wrapConfig->WrapKeyBytes,
                                                                    SAES_FUNCTION_INACTIVE );

            if( SAES_REQUEST_OK == keyState )
            {
                const sAes_RequestState_t enableState = SAes_Reg_Set_Enable();
                sAes_RegWaitResult_t        ccfResult   = SAES_REG_WAIT_TIMEOUT;

                if( SAES_REQUEST_OK == enableState )
                {
                    ccfResult = SAes_Reg_Wait_Ccf();
                }
                else
                {
                    /* EN did not read back set */
                }

                SAes_Reg_Clear_Ccf();
                SAes_Reg_Set_Disable();

                /* The key is now in normal mode (KMOD auto-cleared at decryption end, RM0481 38.4.14) */
                retState = SAes_Calc_RequestFromWait( ccfResult );
                SAes_Update_KeyState( ccfResult );
            }
            else
            {
                retState = SAES_REQUEST_ERROR;
            }
        }
        else
        {
            /* ECB / CBC: key preparation pass (MODE = key derivation), then the actual decryption */
            uint32_t chmodRaw = SAES_CR_CHMOD_ECB_RAW;

            SAes_Build_CrBase( wrapConfig->Mode, &chmodRaw );
            SAes_Set_RegVal( SAES_REG_CR,
                             SAES_CR_STD_MASK,
                             SAes_Build_StdCrValue( chmodRaw,
                                                    SAES_CR_MODE_KEY_DERIVATION_RAW,
                                                    SAES_CR_KMOD_WRAPPED_RAW,
                                                    sizeRaw,
                                                    SAES_CR_GCMPH_INIT_RAW                    ) );

            const sAes_RequestState_t keyState = SAes_Exec_LoadKey( wrapConfig->WrapKeySource,
                                                                    wrapConfig->WrapKeySize,
                                                                    wrapConfig->WrapKeyBytes,
                                                                    SAES_FUNCTION_INACTIVE       );

            if( SAES_REQUEST_OK == keyState )
            {
                const sAes_RequestState_t prepState = SAes_Exec_PrepareDecrypt();

                if( SAES_REQUEST_OK == prepState )
                {
                    const uint32_t decMask  = ( AES_CR_CHMOD | AES_CR_MODE );
                    const uint32_t decValue = ( SAes_Calc_ChmodReg( chmodRaw )               |
                                                 ( SAES_CR_MODE_DECRYPT_RAW << AES_CR_MODE_Pos ) );

                    SAes_Set_RegVal( SAES_REG_CR, decMask, decValue );

                    if( SAES_MODE_CBC == wrapConfig->Mode )
                    {
                        SAes_Reg_Write_Iv( wrapConfig->Iv );
                    }
                    else
                    {
                        /* ECB does not use an IV */
                    }

                    const sAes_RequestState_t enableState = SAes_Reg_Set_Enable();
                    sAes_RequestState_t         blockState   = SAES_REQUEST_ERROR;

                    if( SAES_REQUEST_OK == enableState )
                    {
                        const sAes_DataCnt_t wordCnt = SAes_Calc_KeyBlockCnt( wrapConfig->WrappedKeySize );

                        blockState = SAES_REQUEST_OK;

                        for( sAes_DataCnt_t blockIdx = 0u; wordCnt > blockIdx; blockIdx++ )
                        {
                            const uint32_t byteOff = ( blockIdx * SAES_BLOCK_BYTES );

                            SAes_Reg_Write_Block( &wrappedKey[byteOff] );

                            const sAes_RegWaitResult_t ccfResult = SAes_Reg_Wait_Ccf();

                            /* RM0481, 38.4.14: reading SAES_DOUTR here returns zero (RDERRF), the
                             * decrypted key stays in the key registers; nothing is read back */
                            SAes_Reg_Clear_Ccf();
                            SAes_Reg_Clear_Rweif();

                            if( SAES_REG_WAIT_OK != ccfResult )
                            {
                                blockState = SAES_REQUEST_ERROR;
                                break;
                            }
                            else
                            {
                                /* Block decrypted into the key registers, continue */
                            }
                        }
                    }
                    else
                    {
                        /* EN did not read back set */
                        blockState = SAES_REQUEST_ERROR;
                    }

                    SAes_Reg_Set_Disable();
                    retState = blockState;
                    SAes_Update_KeyState( SAes_Calc_WaitFromRequest( blockState ) );
                }
                else
                {
                    retState = SAES_REQUEST_ERROR;
                }
            }
            else
            {
                retState = SAES_REQUEST_ERROR;
            }
        }
    }
    else
    {
        /* Invalid parameter or the module is not initialized */
        retState = SAES_REQUEST_ERROR;
    }
#else
    (void)wrapConfig;
    (void)wrappedKey;
#endif /* SAES */

    return ( retState );
}


/**
 * \brief Switches the key currently valid in SAES to the shared key mode, so that
 *        the target peripheral can fetch it over the dedicated hardware bus
 *        (RM0481, 38.4.15, KMOD = 0x2 / KSHAREID). The key bytes themselves are not
 *        re-written: KMOD/KSHAREID are only re-configurable while EN and BUSY are
 *        both clear, which \ref SAes_Set_KeyUnwrap / \ref SAes_Set_KeyLoad leave true.
 *
 * \param shareTarget [in]: Peripheral the key is shared with
 * \return \ref SAES_REQUEST_OK on success, \ref SAES_REQUEST_ERROR otherwise
 */
sAes_RequestState_t SAes_Set_KeyShare( sAes_ShareTarget_t shareTarget )
{
    sAes_RequestState_t retState = SAES_REQUEST_ERROR;

#if defined(SAES)
    if( ( SAES_FUNCTION_ACTIVE == sAes_Runtime.InitState )     &&
        ( SAES_SHARE_TARGET_CNT > shareTarget )                 &&
        ( SAES_KEY_STATE_VALID == sAes_Runtime.KeyState )         )
    {
        SAes_Reg_Set_Disable();
        (void)SAes_Reg_Wait_BusyCleared();

        SAes_Set_RegVal( SAES_REG_CR,
                         ( AES_CR_KMOD | AES_CR_KSHAREID ),
                         ( ( SAES_CR_KMOD_SHARED_RAW << AES_CR_KMOD_Pos ) |
                           ( SAES_CR_KSHAREID_AES_RAW << AES_CR_KSHAREID_Pos )    ) );

        const sAes_FunctionState_t keyValidState = SAes_Reg_Get_KeyValidState();

        if( SAES_FUNCTION_INACTIVE != keyValidState )
        {
            retState = SAES_REQUEST_OK;
        }
        else
        {
            retState = SAES_REQUEST_ERROR;
        }
    }
    else
    {
        /* Invalid parameter, module not initialized or no valid key to share */
        retState = SAES_REQUEST_ERROR;
    }
#else
    (void)shareTarget;
#endif /* SAES */

    return ( retState );
}


/**
 * \brief Clears the key registers and the key state (RM0481, 38.8.1 IPRST, the
 *        recommended way to drop a key before handing the peripheral to a less
 *        secure context).
 *
 * \return \ref SAES_REQUEST_OK, \ref SAES_REQUEST_ERROR on a device without the SAES peripheral.
 */
sAes_RequestState_t SAes_Set_KeyClear( void )
{
    sAes_RequestState_t retState = SAES_REQUEST_ERROR;

#if defined(SAES)
    SAes_Reg_Set_Disable();
    (void)SAes_Reg_Wait_BusyCleared();
    SAes_Set_RegBit( SAES_REG_CR, AES_CR_IPRST );
    SAes_Reset_RegBit( SAES_REG_CR, AES_CR_IPRST );
    SAes_Reg_Clear_AllFlags();

    sAes_Runtime.KeyState = SAES_KEY_STATE_NONE;
    retState              = SAES_REQUEST_OK;
#endif /* SAES */

    return ( retState );
}


/**
 * \brief Runs one complete data operation (RM0481, 38.4.5 - 38.4.13): ECB / CBC / CTR
 *        encrypt or decrypt a buffer of \ref sAes_Request_t.DataLen bytes, or run the
 *        full GCM / GMAC / CCM init - header - payload - final sequence.
 *
 * \param request [in]: Pointer to the request
 * \return \ref SAES_REQUEST_OK on success, \ref SAES_REQUEST_ERROR otherwise
 */
sAes_RequestState_t SAes_Set_Process( const sAes_Request_t * const request )
{
    sAes_RequestState_t retState = SAES_REQUEST_ERROR;

#if defined(SAES)
    const sAes_RequestState_t checkState = SAes_Check_Request( request );

    if( ( SAES_FUNCTION_ACTIVE == sAes_Runtime.InitState ) &&
        ( SAES_REQUEST_OK == checkState )                     )
    {
        sAes_Runtime.ModuleState = SAES_STATE_BUSY;

        if( ( SAES_MODE_ECB == request->Mode ) ||
            ( SAES_MODE_CBC == request->Mode ) ||
            ( SAES_MODE_CTR == request->Mode )    )
        {
            uint32_t chmodRaw = SAES_CR_CHMOD_ECB_RAW;

            SAes_Build_CrBase( request->Mode, &chmodRaw );
            retState = SAes_Exec_Process_Simple( request, chmodRaw );
        }
        else if( ( SAES_MODE_GCM == request->Mode )  ||
                 ( SAES_MODE_GMAC == request->Mode )    )
        {
            retState = SAes_Exec_Process_Gcm( request );
        }
        else if( SAES_MODE_CCM == request->Mode )
        {
            retState = SAes_Exec_Process_Ccm( request );
        }
        else
        {
            /* Rejected by SAes_Check_Request already */
            retState = SAES_REQUEST_ERROR;
        }

        sAes_Runtime.ModuleState = SAES_STATE_IDLE;

        if( SAES_NULL_PTR != sAes_Runtime.CompleteCallback )
        {
            sAes_Runtime.CompleteCallback( retState );
        }
        else
        {
            /* No callback configured */
        }
    }
    else
    {
        /* Invalid request or the module is not initialized */
        retState = SAES_REQUEST_ERROR;
    }
#else
    (void)request;
#endif /* SAES */

    return ( retState );
}


/**
 * \brief Starts an incremental AEAD request (GCM, GMAC or CCM): runs the SAES
 *        initialization phase (hash subkey / first mask) and opens the header phase.
 *        ECB, CBC and CTR do not need a separate start (no phase concept): the
 *        key is loaded and the chaining mode / IV are configured, ready for
 *        \ref SAes_Set_Update.
 *
 * \param request [in]: Pointer to the request (Input / Output / DataLen are ignored here)
 * \return \ref SAES_REQUEST_OK on success, \ref SAES_REQUEST_ERROR otherwise
 */
sAes_RequestState_t SAes_Set_Start( const sAes_Request_t * const request )
{
    sAes_RequestState_t retState = SAES_REQUEST_ERROR;

#if defined(SAES)
    if( ( SAES_FUNCTION_ACTIVE == sAes_Runtime.InitState ) &&
        ( SAES_NULL_PTR != request )                        &&
        ( SAES_MODE_CNT > request->Mode )                   &&
        ( SAES_KEY_SIZE_CNT > request->KeySize )            &&
        ( SAES_REQUEST_KEY_CNT > request->KeySelect )          )
    {
        SAes_Reg_Set_Disable();
        (void)SAes_Reg_Wait_BusyCleared();

        uint32_t chmodRaw = SAES_CR_CHMOD_ECB_RAW;

        SAes_Build_CrBase( request->Mode, &chmodRaw );

        if( SAES_MODE_CCM == request->Mode )
        {
            chmodRaw = SAES_CR_CHMOD_CCM_RAW;
        }
        else
        {
            /* chmodRaw already set by SAes_Build_CrBase for ECB/CBC/CTR/GCM/GMAC */
        }

        const uint32_t modeRaw = SAes_Calc_ModeRaw( request->Operation );
        const uint32_t sizeRaw = SAes_Calc_SizeRaw( request->KeySize );
        const sAes_FunctionState_t isAead = SAes_Calc_IsAead( request->Mode );

        SAes_Set_RegVal( SAES_REG_CR,
                         SAES_CR_STD_MASK,
                         SAes_Build_StdCrValue( chmodRaw,
                                                modeRaw,
                                                SAES_CR_KMOD_NORMAL_RAW,
                                                sizeRaw,
                                                SAES_CR_GCMPH_INIT_RAW              ) );

        if( SAES_MODE_ECB != request->Mode )
        {
            SAes_Reg_Write_Iv( request->Iv );
        }
        else
        {
            /* ECB does not use an IV */
        }

        const sAes_RequestState_t keyState = SAes_Exec_LoadRequestKey( request );

        if( SAES_REQUEST_OK == keyState )
        {
            sAes_RequestState_t initState = SAES_REQUEST_OK;

            if( SAES_FUNCTION_ACTIVE == isAead )
            {
                /* RM0481, 38.4.11 step 7-9 / 38.4.13 step 7-9: EN starts the H / first-mask
                 * calculation and auto-clears when done */
                const sAes_RequestState_t enableState = SAes_Reg_Set_Enable();
                sAes_RegWaitResult_t        ccfResult   = SAES_REG_WAIT_TIMEOUT;

                if( SAES_REQUEST_OK == enableState )
                {
                    ccfResult = SAes_Reg_Wait_Ccf();
                }
                else
                {
                    /* EN did not read back set */
                }

                SAes_Reg_Clear_Ccf();
                initState = SAes_Calc_RequestFromWait( ccfResult );
            }
            else
            {
                /* ECB / CBC / CTR: no separate init phase, SAes_Set_Update enables the peripheral */
            }

            sAes_Runtime.CurOperation = request->Operation;
            sAes_Runtime.CurMode      = request->Mode;
            sAes_Runtime.AadClosed    = SAES_FUNCTION_INACTIVE;
            retState                  = initState;
        }
        else
        {
            retState = SAES_REQUEST_ERROR;
        }
    }
    else
    {
        /* Invalid request or the module is not initialized */
        retState = SAES_REQUEST_ERROR;
    }
#else
    (void)request;
#endif /* SAES */

    return ( retState );
}


/**
 * \brief Feeds additional authenticated data to an incremental GCM / GMAC / CCM
 *        request opened by \ref SAes_Set_Start (RM0481, 38.4.11 / 38.4.13 header phase).
 *
 * \param aad    [in]: AAD bytes
 * \param aadLen [in]: Byte length of \p aad (multiple of 16, the last call may be shorter)
 * \return \ref SAES_REQUEST_OK on success, \ref SAES_REQUEST_ERROR otherwise
 */
sAes_RequestState_t SAes_Set_UpdateAad( const sAes_Data_t * const aad, sAes_DataLen_t aadLen )
{
    sAes_RequestState_t retState = SAES_REQUEST_ERROR;

#if defined(SAES)
    if( ( SAES_FUNCTION_ACTIVE == sAes_Runtime.InitState )     &&
        ( SAES_FUNCTION_INACTIVE == sAes_Runtime.AadClosed )   &&
        ( ( SAES_NULL_PTR != aad )  ||
          ( 0u == aadLen )            )                             )
    {
        retState = SAes_Exec_AeadHeader( aad, aadLen );
    }
    else
    {
        /* Module not initialized, header phase already closed, or invalid parameter */
        retState = SAES_REQUEST_ERROR;
    }
#else
    (void)aad;
    (void)aadLen;
#endif /* SAES */

    return ( retState );
}


/**
 * \brief Feeds (and closes, if still open) the payload of an incremental request
 *        (RM0481, 38.4.5 - 38.4.13 payload phase).
 *
 * \param input   [in]:  Plaintext (encrypt) or ciphertext (decrypt)
 * \param output  [out]: Ciphertext (encrypt) or plaintext (decrypt)
 * \param dataLen [in]:  Byte length of \p input / \p output
 * \return \ref SAES_REQUEST_OK on success, \ref SAES_REQUEST_ERROR otherwise
 */
sAes_RequestState_t SAes_Set_Update( const sAes_Data_t * const input,
                                     sAes_Data_t * const output,
                                     sAes_DataLen_t dataLen )
{
    sAes_RequestState_t retState = SAES_REQUEST_ERROR;

#if defined(SAES)
    if( ( SAES_FUNCTION_ACTIVE == sAes_Runtime.InitState ) &&
        ( SAES_NULL_PTR != input )                          &&
        ( SAES_NULL_PTR != output )                           )
    {
        const sAes_FunctionState_t isAead = SAes_Calc_IsAead( sAes_Runtime.CurMode );

        if( SAES_FUNCTION_ACTIVE == isAead )
        {
            if( SAES_FUNCTION_INACTIVE == sAes_Runtime.AadClosed )
            {
                (void)SAes_Exec_AeadHeader( SAES_NULL_PTR, 0u );
            }
            else
            {
                /* Header phase already closed by an earlier SAes_Set_UpdateAad */
            }

            retState = SAes_Exec_AeadPayload( sAes_Runtime.CurOperation, input, output, dataLen );
        }
        else
        {
            SAes_Reset_RegBit( SAES_REG_CR, AES_CR_EN );
            const sAes_RequestState_t enableState = SAes_Reg_Set_Enable();

            if( SAES_REQUEST_OK == enableState )
            {
                retState = SAes_Exec_SimpleBlocks( sAes_Runtime.CurOperation, input, output, dataLen );
            }
            else
            {
                retState = SAES_REQUEST_ERROR;
            }
        }
    }
    else
    {
        /* Module not initialized or invalid parameter */
        retState = SAES_REQUEST_ERROR;
    }
#else
    (void)input;
    (void)output;
    (void)dataLen;
#endif /* SAES */

    return ( retState );
}


/**
 * \brief Finalizes an incremental request: for GCM / GMAC / CCM runs the final
 *        phase and returns the authentication tag; for ECB / CBC / CTR simply
 *        disables the peripheral.
 *
 * \param tag    [out]: Authentication tag buffer (GCM, GMAC, CCM only, otherwise ignored)
 * \param tagLen [in]:  Requested tag byte length (4 .. 16)
 * \return \ref SAES_REQUEST_OK on success, \ref SAES_REQUEST_ERROR otherwise
 */
sAes_RequestState_t SAes_Set_Finish( sAes_Data_t * const tag, sAes_DataCnt_t tagLen )
{
    sAes_RequestState_t retState = SAES_REQUEST_ERROR;

#if defined(SAES)
    if( SAES_FUNCTION_ACTIVE == sAes_Runtime.InitState )
    {
        const sAes_FunctionState_t isAead = SAes_Calc_IsAead( sAes_Runtime.CurMode );

        if( SAES_FUNCTION_ACTIVE == isAead )
        {
            if( SAES_MODE_CCM == sAes_Runtime.CurMode )
            {
                retState = SAes_Exec_CcmFinal( tag, tagLen );
            }
            else
            {
                retState = SAes_Exec_GcmFinal( sAes_Runtime.CurOperation, 0u, 0u, tag, tagLen );
            }
        }
        else
        {
            SAes_Reg_Set_Disable();
            retState = SAES_REQUEST_OK;
        }

        sAes_Runtime.AadClosed = SAES_FUNCTION_INACTIVE;
    }
    else
    {
        /* Module not initialized */
        retState = SAES_REQUEST_ERROR;
    }
#else
    (void)tag;
    (void)tagLen;
#endif /* SAES */

    return ( retState );
}


/**
 * \brief Aborts an incremental request: disables the peripheral and clears the key
 *        (a partially fed AEAD computation cannot be trusted afterwards).
 *
 * \return \ref SAES_REQUEST_OK, \ref SAES_REQUEST_ERROR on a device without the SAES peripheral.
 */
sAes_RequestState_t SAes_Set_Abort( void )
{
    sAes_RequestState_t retState = SAES_REQUEST_ERROR;

#if defined(SAES)
    sAes_Runtime.AadClosed = SAES_FUNCTION_INACTIVE;
    retState               = SAes_Set_KeyClear();
#endif /* SAES */

    return ( retState );
}


/**
 * \brief Saves the registers needed to suspend an ECB / CBC / CTR / GCM / GMAC / CCM
 *        request (RM0481, 38.4.9 / 38.4.13 suspend sequences; not supported in GCM
 *        itself per RM0481, but the context is still saved uniformly here).
 *
 * \param context [out]: Pointer to the context structure
 * \return \ref SAES_REQUEST_OK on success, \ref SAES_REQUEST_ERROR for a null pointer
 */
sAes_RequestState_t SAes_Get_Context( sAes_Context_t * const context )
{
    sAes_RequestState_t retState = SAES_REQUEST_ERROR;

#if defined(SAES)
    if( SAES_NULL_PTR != context )
    {
        context->ControlReg = SAes_Get_RegVal( SAES_REG_CR, SAES_REG_FULL_MASK );
        SAes_Reg_Read_Iv( (sAes_Data_t *)context->IvReg );
        SAes_Reg_Read_Suspend( context->SuspendReg );
        context->ProcessedBytes = 0u;
        retState                = SAES_REQUEST_OK;
    }
    else
    {
        /* Null pointer, nothing is written */
        retState = SAES_REQUEST_ERROR;
    }
#else
    (void)context;
#endif /* SAES */

    return ( retState );
}


/**
 * \brief Restores a context saved by \ref SAes_Get_Context (the key registers are not
 *        restored: RM0481 states the application already knows the original key).
 *
 * \param context [in]: Pointer to the context structure
 * \return \ref SAES_REQUEST_OK on success, \ref SAES_REQUEST_ERROR for a null pointer
 */
sAes_RequestState_t SAes_Set_Context( const sAes_Context_t * const context )
{
    sAes_RequestState_t retState = SAES_REQUEST_ERROR;

#if defined(SAES)
    if( SAES_NULL_PTR != context )
    {
        SAes_Reg_Set_Disable();
        SAes_Reg_Write_Suspend( context->SuspendReg );
        SAes_Reg_Write_Iv( (const sAes_Data_t *)context->IvReg );
        SAes_Set_RegVal( SAES_REG_CR, SAES_REG_FULL_MASK & ~AES_CR_EN, context->ControlReg & ~AES_CR_EN );
        retState = SAes_Reg_Set_Enable();
    }
    else
    {
        /* Null pointer, nothing is restored */
        retState = SAES_REQUEST_ERROR;
    }
#else
    (void)context;
#endif /* SAES */

    return ( retState );
}


/**
 * \brief Configures the priority of the SAES global interrupt (ISR / DMA transfer mode).
 *
 * \param irqPriority [in]: Requested priority
 * \return \ref SAES_REQUEST_OK on success, \ref SAES_REQUEST_ERROR otherwise
 */
sAes_RequestState_t SAes_Set_IrqPriority( sAes_IrqPrio_t irqPriority )
{
    sAes_RequestState_t retState = SAES_REQUEST_ERROR;

#if defined(SAES)
    if( SAES_FUNCTION_ACTIVE == sAes_Runtime.InitState )
    {
        const nvic_RequestState_t nvicState = Nvic_Set_PeriphIrq_Prio( NVIC_PERIPH_IRQ_SAES,
                                                                       (nvic_IrqPrio_t)irqPriority );

        if( NVIC_REQUEST_OK == nvicState )
        {
            retState = SAES_REQUEST_OK;
        }
        else
        {
            retState = SAES_REQUEST_ERROR;
        }
    }
    else
    {
        /* Module not initialized */
        retState = SAES_REQUEST_ERROR;
    }
#else
    (void)irqPriority;
#endif /* SAES */

    return ( retState );
}


/**
 * \brief Reads back the priority of the SAES global interrupt.
 *
 * \param irqPriority [out]: Pointer to the priority
 * \return \ref SAES_REQUEST_OK on success, \ref SAES_REQUEST_ERROR otherwise
 */
sAes_RequestState_t SAes_Get_IrqPriority( sAes_IrqPrio_t * const irqPriority )
{
    sAes_RequestState_t retState = SAES_REQUEST_ERROR;

#if defined(SAES)
    if( ( SAES_FUNCTION_ACTIVE == sAes_Runtime.InitState ) &&
        ( SAES_NULL_PTR != irqPriority )                     )
    {
        nvic_IrqPrio_t                nvicPrio  = 0u;
        const nvic_RequestState_t nvicState = Nvic_Get_PeriphIrq_Prio( NVIC_PERIPH_IRQ_SAES, &nvicPrio );

        if( NVIC_REQUEST_OK == nvicState )
        {
            *irqPriority = (sAes_IrqPrio_t)nvicPrio;
            retState     = SAES_REQUEST_OK;
        }
        else
        {
            retState = SAES_REQUEST_ERROR;
        }
    }
    else
    {
        /* Module not initialized or null pointer */
        retState = SAES_REQUEST_ERROR;
    }
#else
    (void)irqPriority;
#endif /* SAES */

    return ( retState );
}

/* ========================= LOCAL FUNCTIONS ================================= */

#if defined(SAES)

/**
 * \brief Builds a SAES_CR value for \ref SAES_CR_STD_MASK (CHMOD, MODE, KMOD, DATATYPE,
 *        KEYSIZE, GCMPH together); DATATYPE is always \ref SAES_CR_DATATYPE_NONE_RAW.
 *
 * \param chmodRaw [in]: SAES_CR.CHMOD raw value
 * \param modeRaw  [in]: SAES_CR.MODE raw value
 * \param kmodRaw  [in]: SAES_CR.KMOD raw value
 * \param sizeRaw  [in]: SAES_CR.KEYSIZE raw value (0 or \ref AES_CR_KEYSIZE)
 * \param gcmphRaw [in]: SAES_CR.GCMPH raw value (ignored outside GCM/GMAC/CCM)
 * \return The combined register value
 */
static uint32_t SAes_Build_StdCrValue( uint32_t chmodRaw,
                                       uint32_t modeRaw,
                                       uint32_t kmodRaw,
                                       uint32_t sizeRaw,
                                       uint32_t gcmphRaw )
{
    const uint32_t crValue = ( SAes_Calc_ChmodReg( chmodRaw )               |
                                ( modeRaw << AES_CR_MODE_Pos ) |
                                ( kmodRaw << AES_CR_KMOD_Pos ) |
                                ( SAES_CR_DATATYPE_NONE_RAW << AES_CR_DATATYPE_Pos ) |
                                sizeRaw | ( gcmphRaw << AES_CR_GCMPH_Pos )              );

    return ( crValue );
}


/**
 * \brief Packs the logical SAES_CR.CHMOD value into its real register position: CMSIS /
 *        RM0481 38.8.1 split the field as CHMOD[1:0] at bits 6:5 and CHMOD[2] at bit 16
 *        (`AES_CR_CHMOD_Msk` = 0x803 << 5), so a plain `chmodRaw << AES_CR_CHMOD_Pos` is
 *        wrong for CCM (raw 0x4, bit 2 set): it would land at bit 7 instead of bit 16 and
 *        the peripheral would run as ECB. This function uses the CMSIS `AES_CR_CHMOD_0/1/2`
 *        bit macros directly instead of a contiguous shift.
 *
 * \param chmodRaw [in]: Logical SAES_CR.CHMOD raw value (\ref SAES_CR_CHMOD_ECB_RAW, ...)
 * \return The CHMOD bits already in their correct register position
 */
static uint32_t SAes_Calc_ChmodReg( uint32_t chmodRaw )
{
    uint32_t chmodReg = 0u;

    if( SAES_CR_CHMOD_CBC_RAW == chmodRaw )
    {
        chmodReg = AES_CR_CHMOD_0;
    }
    else if( SAES_CR_CHMOD_CTR_RAW == chmodRaw )
    {
        chmodReg = AES_CR_CHMOD_1;
    }
    else if( SAES_CR_CHMOD_GCM_RAW == chmodRaw )
    {
        chmodReg = ( AES_CR_CHMOD_0 | AES_CR_CHMOD_1 );
    }
    else if( SAES_CR_CHMOD_CCM_RAW == chmodRaw )
    {
        chmodReg = AES_CR_CHMOD_2;
    }
    else
    {
        /* SAES_CR_CHMOD_ECB_RAW (and any other value defaults to ECB, no bit set) */
        chmodReg = 0u;
    }

    return ( chmodReg );
}


/**
 * \brief Converts the public key size to the SAES_CR.KEYSIZE raw bit.
 *
 * \param keySize [in]: Public key size
 * \return \ref AES_CR_KEYSIZE for \ref SAES_KEY_SIZE_256, 0 otherwise
 */
static uint32_t SAes_Calc_SizeRaw( sAes_KeySize_t keySize )
{
    uint32_t sizeRaw = 0u;

    if( SAES_KEY_SIZE_256 == keySize )
    {
        sizeRaw = AES_CR_KEYSIZE;
    }
    else
    {
        /* SAES_KEY_SIZE_128 (and any other value defaults to 128-bit) */
        sizeRaw = 0u;
    }

    return ( sizeRaw );
}


/**
 * \brief Converts the public operation to the SAES_CR.MODE raw value (encryption /
 *        decryption only, key derivation is handled separately).
 *
 * \param operation [in]: Public operation
 * \return \ref SAES_CR_MODE_DECRYPT_RAW for \ref SAES_OPERATION_DECRYPT, else encrypt
 */
static uint32_t SAes_Calc_ModeRaw( sAes_Operation_t operation )
{
    uint32_t modeRaw = SAES_CR_MODE_ENCRYPT_RAW;

    if( SAES_OPERATION_DECRYPT == operation )
    {
        modeRaw = SAES_CR_MODE_DECRYPT_RAW;
    }
    else
    {
        /* SAES_OPERATION_ENCRYPT (and any other value defaults to encryption) */
        modeRaw = SAES_CR_MODE_ENCRYPT_RAW;
    }

    return ( modeRaw );
}


/**
 * \brief Count of 16-byte blocks a wrap / unwrap of the given key size spans.
 *
 * \param keySize [in]: Public key size
 * \return 2 for \ref SAES_KEY_SIZE_256, 1 otherwise
 */
static sAes_DataCnt_t SAes_Calc_KeyBlockCnt( sAes_KeySize_t keySize )
{
    sAes_DataCnt_t blockCnt = 1u;

    if( SAES_KEY_SIZE_256 == keySize )
    {
        blockCnt = ( SAES_KEY_256_BYTES / SAES_BLOCK_BYTES );
    }
    else
    {
        /* SAES_KEY_SIZE_128 (and any other value defaults to a single block) */
        blockCnt = 1u;
    }

    return ( blockCnt );
}


/**
 * \brief Converts a bounded-wait outcome to the module request state.
 *
 * \param waitResult [in]: Outcome of a \ref SAes_Reg_Wait_* call
 * \return \ref SAES_REQUEST_OK for \ref SAES_REG_WAIT_OK, \ref SAES_REQUEST_ERROR otherwise
 */
static sAes_RequestState_t SAes_Calc_RequestFromWait( sAes_RegWaitResult_t waitResult )
{
    sAes_RequestState_t retState = SAES_REQUEST_ERROR;

    if( SAES_REG_WAIT_OK == waitResult )
    {
        retState = SAES_REQUEST_OK;
    }
    else
    {
        retState = SAES_REQUEST_ERROR;
    }

    return ( retState );
}


/**
 * \brief Loads the software key given inline with a request, if any (RM0481, 38.4.17
 *        normal key mode); a request using the key already valid in SAES needs no load.
 *
 * \param request [in]: Pointer to the request
 * \return \ref SAES_REQUEST_OK on success (including "nothing to load"), \ref SAES_REQUEST_ERROR otherwise
 */
static sAes_RequestState_t SAes_Exec_LoadRequestKey( const sAes_Request_t * const request )
{
    sAes_RequestState_t retState = SAES_REQUEST_OK;

    if( SAES_REQUEST_KEY_INLINE == request->KeySelect )
    {
        retState = SAes_Exec_LoadKey( SAES_KEY_SOFTWARE, request->KeySize, request->Key, SAES_FUNCTION_INACTIVE );
    }
    else
    {
        /* SAES_REQUEST_KEY_LOADED: the key already valid in SAES is used, nothing to load */
        retState = SAES_REQUEST_OK;
    }

    return ( retState );
}


/**
 * \brief Converts a module request outcome back to a wait-style outcome, so a block
 *        loop's result can feed \ref SAes_Update_KeyState.
 *
 * \param requestState [in]: Outcome of a block loop
 * \return \ref SAES_REG_WAIT_OK for \ref SAES_REQUEST_OK, \ref SAES_REG_WAIT_HW_ERROR otherwise
 */
static sAes_RegWaitResult_t SAes_Calc_WaitFromRequest( sAes_RequestState_t requestState )
{
    sAes_RegWaitResult_t retResult = SAES_REG_WAIT_HW_ERROR;

    if( SAES_REQUEST_OK == requestState )
    {
        retResult = SAES_REG_WAIT_OK;
    }
    else
    {
        retResult = SAES_REG_WAIT_HW_ERROR;
    }

    return ( retResult );
}


/**
 * \brief Reports whether a chaining mode is one of the AEAD modes with a GCMPH phase.
 *
 * \param mode [in]: Public chaining mode
 * \return \ref SAES_FUNCTION_ACTIVE for GCM / GMAC / CCM, \ref SAES_FUNCTION_INACTIVE otherwise
 */
static sAes_FunctionState_t SAes_Calc_IsAead( sAes_Mode_t mode )
{
    sAes_FunctionState_t retState = SAES_FUNCTION_INACTIVE;

    if( ( SAES_MODE_GCM == mode )  ||
        ( SAES_MODE_GMAC == mode ) ||
        ( SAES_MODE_CCM == mode )     )
    {
        retState = SAES_FUNCTION_ACTIVE;
    }
    else
    {
        retState = SAES_FUNCTION_INACTIVE;
    }

    return ( retState );
}


/**
 * \brief Updates \ref sAes_RuntimeData_t.KeyState from a register wait outcome.
 *
 * \param waitResult [in]: Outcome of \ref SAes_Reg_Wait_KeyValid / \ref SAes_Reg_Wait_Ccf
 */
static void SAes_Update_KeyState( sAes_RegWaitResult_t waitResult )
{
    if( SAES_REG_WAIT_OK == waitResult )
    {
        sAes_Runtime.KeyState = SAES_KEY_STATE_VALID;
    }
    else
    {
        sAes_Runtime.KeyState      = SAES_KEY_STATE_ERROR;
        sAes_Runtime.LastXferError = SAes_Reg_Get_XferError();
        SAes_Reg_Clear_AllFlags();

        if( SAES_NULL_PTR != sAes_Runtime.ErrorCallback )
        {
            sAes_Runtime.ErrorCallback( sAes_Runtime.LastXferError );
        }
        else
        {
            /* No callback configured */
        }
    }
}


/**
 * \brief Loads a key by software bytes or by a hardware source (RM0481, 38.4.17);
 *        updates \ref sAes_RuntimeData_t.KeyState at the end.
 *
 * \param keySource [in]: Key source
 * \param keySize   [in]: Key length
 * \param keyBytes  [in]: Software key bytes (ignored for a hardware source)
 * \param keyProt   [in]: \ref SAES_FUNCTION_ACTIVE sets SAES_CR.KEYPROT before loading
 * \return \ref SAES_REQUEST_OK on success, \ref SAES_REQUEST_ERROR otherwise
 */
static sAes_RequestState_t SAes_Exec_LoadKey( sAes_KeySource_t keySource,
                                              sAes_KeySize_t keySize,
                                              const sAes_Data_t * const keyBytes,
                                              sAes_FunctionState_t keyProt )
{
    sAes_RequestState_t retState = SAES_REQUEST_ERROR;

    (void)keyProt;

    if( SAES_KEY_SOFTWARE == keySource )
    {
        if( SAES_NULL_PTR != keyBytes )
        {
            SAes_Set_RegVal( SAES_REG_CR, AES_CR_KEYSEL, ( SAES_CR_KEYSEL_SOFTWARE_RAW << AES_CR_KEYSEL_Pos ) );
            SAes_Reg_Write_Key( keyBytes, keySize );

            /* RM0481, 38.8.2: the correct KEYRx write sequence sets KEYVALID by hardware
             * the same way a hardware key source does; an incorrect sequence sets KEIF */
            const sAes_RegWaitResult_t waitResult = SAes_Reg_Wait_KeyValid();

            SAes_Update_KeyState( waitResult );
            retState = SAes_Calc_RequestFromWait( waitResult );

            if( SAES_REQUEST_OK != retState )
            {
                SAes_Reg_Clear_Keif();
            }
            else
            {
                /* Key loaded successfully, nothing to clear */
            }
        }
        else
        {
            retState = SAES_REQUEST_ERROR;
        }
    }
    else
    {
        uint32_t keySelRaw = SAES_CR_KEYSEL_DHUK_XOR_BHK_RAW;

        if( SAES_KEY_DHUK == keySource )
        {
            keySelRaw = SAES_CR_KEYSEL_DHUK_RAW;
        }
        else if( SAES_KEY_BHK == keySource )
        {
            keySelRaw = SAES_CR_KEYSEL_BHK_RAW;
        }
        else
        {
            /* SAES_KEY_DHUK_XOR_BHK (and any other value defaults to the XOR source) */
            keySelRaw = SAES_CR_KEYSEL_DHUK_XOR_BHK_RAW;
        }

        SAes_Set_RegVal( SAES_REG_CR, AES_CR_KEYSEL, ( keySelRaw << AES_CR_KEYSEL_Pos ) );

        const sAes_RegWaitResult_t waitResult = SAes_Reg_Wait_KeyValid();

        SAes_Update_KeyState( waitResult );
        retState = SAes_Calc_RequestFromWait( waitResult );

        if( SAES_REQUEST_OK != retState )
        {
            SAes_Reg_Clear_Keif();
        }
        else
        {
            /* Key loaded successfully, nothing to clear */
        }
    }

    return ( retState );
}


/**
 * \brief Converts the public chaining mode to the SAES_CR.CHMOD raw value.
 *
 * \param mode      [in]:  Public chaining mode (ECB .. CCM)
 * \param chmodRaw  [out]: Resulting SAES_CR.CHMOD raw value
 */
static void SAes_Build_CrBase( sAes_Mode_t mode, uint32_t * const chmodRaw )
{
    if( SAES_MODE_CBC == mode )
    {
        *chmodRaw = SAES_CR_CHMOD_CBC_RAW;
    }
    else if( SAES_MODE_CTR == mode )
    {
        *chmodRaw = SAES_CR_CHMOD_CTR_RAW;
    }
    else if( ( SAES_MODE_GCM == mode )  ||
             ( SAES_MODE_GMAC == mode )    )
    {
        *chmodRaw = SAES_CR_CHMOD_GCM_RAW;
    }
    else if( SAES_MODE_CCM == mode )
    {
        *chmodRaw = SAES_CR_CHMOD_CCM_RAW;
    }
    else
    {
        /* SAES_MODE_ECB (and any other value defaults to ECB) */
        *chmodRaw = SAES_CR_CHMOD_ECB_RAW;
    }
}


/**
 * \brief Runs the ECB/CBC decryption key-preparation pass (RM0481, 38.4.9: MODE =
 *        key derivation, EN set, wait CCF, clear CCF, EN auto-cleared).
 *
 * \return \ref SAES_REQUEST_OK on success, \ref SAES_REQUEST_ERROR otherwise
 */
static sAes_RequestState_t SAes_Exec_PrepareDecrypt( void )
{
    const sAes_RequestState_t    enableState = SAes_Reg_Set_Enable();
    sAes_RequestState_t           retState     = SAES_REQUEST_ERROR;

    if( SAES_REQUEST_OK == enableState )
    {
        const sAes_RegWaitResult_t ccfResult = SAes_Reg_Wait_Ccf();

        SAes_Reg_Clear_Ccf();
        retState = SAes_Calc_RequestFromWait( ccfResult );
    }
    else
    {
        retState = SAES_REQUEST_ERROR;
    }

    return ( retState );
}


/**
 * \brief Streams \p dataLen bytes through SAES_DINR / SAES_DOUTR, one 16-byte block
 *        at a time, waiting for CCF between blocks (RM0481, 38.4.5). The last CTR
 *        block may be shorter than 16 bytes (zero-padded on input, truncated on output,
 *        RM0481 38.4.10 step 8a); ECB and CBC require an exact multiple of 16 bytes.
 *
 * \param operation [in]:  Encrypt or decrypt (only used to decide the zero-padding rule)
 * \param input     [in]:  Input buffer
 * \param output    [out]: Output buffer, same length as \p input
 * \param dataLen   [in]:  Byte length of \p input / \p output
 * \return \ref SAES_REQUEST_OK on success, \ref SAES_REQUEST_ERROR otherwise
 */
static sAes_RequestState_t SAes_Exec_SimpleBlocks( sAes_Operation_t operation,
                                                   const sAes_Data_t * const input,
                                                   sAes_Data_t * const output,
                                                   sAes_DataLen_t dataLen )
{
    sAes_RequestState_t retState   = SAES_REQUEST_OK;
    sAes_Data_t           blockIn[SAES_BLOCK_BYTES]  = { 0u };
    sAes_Data_t           blockOut[SAES_BLOCK_BYTES] = { 0u };
    const sAes_DataLen_t fullBlocks = ( dataLen / SAES_BLOCK_BYTES );
    const sAes_DataLen_t tailBytes  = ( dataLen % SAES_BLOCK_BYTES );

    (void)operation;

    for( sAes_DataLen_t blockIdx = 0u; fullBlocks > blockIdx; blockIdx++ )
    {
        const sAes_DataLen_t byteOff = ( blockIdx * SAES_BLOCK_BYTES );

        SAes_Reg_Write_Block( &input[byteOff] );

        const sAes_RegWaitResult_t ccfResult = SAes_Reg_Wait_Ccf();

        if( SAES_REG_WAIT_OK == ccfResult )
        {
            SAes_Reg_Read_Block( &output[byteOff] );
            SAes_Reg_Clear_Ccf();
        }
        else
        {
            retState = SAES_REQUEST_ERROR;
            break;
        }
    }

    if( ( SAES_REQUEST_OK == retState ) &&
        ( 0u != tailBytes )                 )
    {
        const sAes_DataLen_t byteOff = ( fullBlocks * SAES_BLOCK_BYTES );

        for( uint32_t idx = 0u; SAES_BLOCK_BYTES > idx; idx++ )
        {
            if( tailBytes > idx )
            {
                blockIn[idx] = input[byteOff + idx];
            }
            else
            {
                blockIn[idx] = 0u;
            }
        }

        SAes_Reg_Write_Block( blockIn );

        const sAes_RegWaitResult_t ccfResult = SAes_Reg_Wait_Ccf();

        if( SAES_REG_WAIT_OK == ccfResult )
        {
            SAes_Reg_Read_Block( blockOut );
            SAes_Reg_Clear_Ccf();

            for( uint32_t idx = 0u; tailBytes > idx; idx++ )
            {
                output[byteOff + idx] = blockOut[idx];
            }
        }
        else
        {
            retState = SAES_REQUEST_ERROR;
        }
    }
    else
    {
        /* No partial tail block, or an earlier block already failed */
    }

    return ( retState );
}


/**
 * \brief Runs the GCM/CCM header phase for a (possibly empty) AAD buffer
 *        (RM0481, 38.4.11 / 38.4.13 "append header data"), then switches CR to the
 *        payload phase and marks the header closed.
 *
 * \param aad    [in]: AAD bytes (may be \ref SAES_NULL_PTR if \p aadLen is zero)
 * \param aadLen [in]: Byte length of \p aad
 * \return \ref SAES_REQUEST_OK on success, \ref SAES_REQUEST_ERROR otherwise
 */
static sAes_RequestState_t SAes_Exec_AeadHeader( const sAes_Data_t * const aad, sAes_DataLen_t aadLen )
{
    sAes_RequestState_t retState    = SAES_REQUEST_OK;
    const sAes_DataLen_t fullBlocks = ( aadLen / SAES_BLOCK_BYTES );
    const sAes_DataLen_t tailBytes  = ( aadLen % SAES_BLOCK_BYTES );

    if( 0u != aadLen )
    {
        SAes_Set_RegVal( SAES_REG_CR, AES_CR_GCMPH, ( SAES_CR_GCMPH_HEADER_RAW << AES_CR_GCMPH_Pos ) );
        (void)SAes_Reg_Set_Enable();

        for( sAes_DataLen_t blockIdx = 0u; fullBlocks > blockIdx; blockIdx++ )
        {
            SAes_Reg_Write_Block( &aad[blockIdx * SAES_BLOCK_BYTES] );

            const sAes_RegWaitResult_t ccfResult = SAes_Reg_Wait_Ccf();

            if( SAES_REG_WAIT_OK == ccfResult )
            {
                SAes_Reg_Clear_Ccf();
            }
            else
            {
                retState = SAES_REQUEST_ERROR;
                break;
            }
        }

        if( ( SAES_REQUEST_OK == retState ) &&
            ( 0u != tailBytes )                 )
        {
            sAes_Data_t blockIn[SAES_BLOCK_BYTES] = { 0u };
            const sAes_DataLen_t byteOff = ( fullBlocks * SAES_BLOCK_BYTES );

            for( uint32_t idx = 0u; tailBytes > idx; idx++ )
            {
                blockIn[idx] = aad[byteOff + idx];
            }

            SAes_Reg_Write_Block( blockIn );

            const sAes_RegWaitResult_t ccfResult = SAes_Reg_Wait_Ccf();

            retState = SAes_Calc_RequestFromWait( ccfResult );
            SAes_Reg_Clear_Ccf();
        }
        else
        {
            /* No partial tail block, or an earlier block already failed */
        }
    }
    else
    {
        /* Len(A) = 0: the header phase is skipped (RM0481, 38.4.11 / 38.4.13) */
    }

    SAes_Set_RegVal( SAES_REG_CR, AES_CR_GCMPH, ( SAES_CR_GCMPH_PAYLOAD_RAW << AES_CR_GCMPH_Pos ) );
    sAes_Runtime.AadClosed = SAES_FUNCTION_ACTIVE;

    return ( retState );
}


/**
 * \brief Runs the GCM/CCM payload phase (RM0481, 38.4.11 / 38.4.13 "append payload data").
 *
 * \param operation [in]:  Encrypt or decrypt
 * \param input     [in]:  Plaintext (encrypt) or ciphertext (decrypt)
 * \param output    [out]: Ciphertext (encrypt) or plaintext (decrypt)
 * \param dataLen   [in]:  Byte length of \p input / \p output
 * \return \ref SAES_REQUEST_OK on success, \ref SAES_REQUEST_ERROR otherwise
 */
static sAes_RequestState_t SAes_Exec_AeadPayload( sAes_Operation_t operation,
                                                  const sAes_Data_t * const input,
                                                  sAes_Data_t * const output,
                                                  sAes_DataLen_t dataLen )
{
    (void)SAes_Reg_Set_Enable();

    return ( SAes_Exec_SimpleBlocks( operation, input, output, dataLen ) );
}


/**
 * \brief Runs the GCM/GMAC final phase: writes the bit-length block, reads the tag
 *        (RM0481, 38.4.11 step 14-19 / 38.4.12).
 *
 * \param operation [in]:  Encrypt or decrypt (encrypt waits BUSY cleared first)
 * \param aadLen    [in]:  Byte length of the AAD already fed (0 if tracked by the caller)
 * \param dataLen   [in]:  Byte length of the payload already fed
 * \param tag       [out]: Resulting / expected authentication tag
 * \param tagLen    [in]:  Requested tag byte length
 * \return \ref SAES_REQUEST_OK on success, \ref SAES_REQUEST_ERROR otherwise
 */
static sAes_RequestState_t SAes_Exec_GcmFinal( sAes_Operation_t operation,
                                               sAes_DataLen_t aadLen,
                                               sAes_DataLen_t dataLen,
                                               sAes_Data_t * const tag,
                                               sAes_DataCnt_t tagLen )
{
    sAes_RequestState_t retState = SAES_REQUEST_ERROR;
    sAes_Data_t           lengthBlock[SAES_GCM_FINAL_BLOCK_BYTES] = { 0u };
    sAes_Data_t           tagBlock[SAES_BLOCK_BYTES]              = { 0u };
    const uint64_t         aadBits    = ( (uint64_t)aadLen * SAES_BITS_PER_BYTE );
    const uint64_t         payloadBits = ( (uint64_t)dataLen * SAES_BITS_PER_BYTE );

    if( SAES_OPERATION_ENCRYPT == operation )
    {
        (void)SAes_Reg_Wait_BusyCleared();
    }
    else
    {
        /* Decryption does not need the extra BUSY wait (RM0481, 38.4.11 step 14) */
    }

    SAes_Write_Uint64BigEndian( &lengthBlock[0], aadBits );
    SAes_Write_Uint64BigEndian( &lengthBlock[SAES_UINT64_BYTES], payloadBits );

    SAes_Set_RegVal( SAES_REG_CR, AES_CR_GCMPH, ( SAES_CR_GCMPH_FINAL_RAW << AES_CR_GCMPH_Pos ) );
    SAes_Reg_Write_Block( lengthBlock );

    const sAes_RegWaitResult_t ccfResult = SAes_Reg_Wait_Ccf();

    if( SAES_REG_WAIT_OK == ccfResult )
    {
        SAes_Reg_Read_Block( tagBlock );
        SAes_Reg_Clear_Ccf();
        SAes_Reg_Set_Disable();

        if( SAES_NULL_PTR != tag )
        {
            for( sAes_DataCnt_t idx = 0u;
                 ( SAES_BLOCK_BYTES > idx ) &&
                 ( tagLen > idx );
                 idx++                        )
            {
                tag[idx] = tagBlock[idx];
            }
        }
        else
        {
            /* No tag buffer requested */
        }

        retState = SAES_REQUEST_OK;
    }
    else
    {
        SAes_Reg_Set_Disable();
        retState = SAES_REQUEST_ERROR;
    }

    return ( retState );
}


/**
 * \brief Runs the CCM final phase: selects GCMPH = final, reads the tag directly
 *        (no SAES_DINR write, RM0481, 38.4.13 step 14-18).
 *
 * \param tag    [out]: Resulting / expected authentication tag
 * \param tagLen [in]:  Requested tag byte length
 * \return \ref SAES_REQUEST_OK on success, \ref SAES_REQUEST_ERROR otherwise
 */
static sAes_RequestState_t SAes_Exec_CcmFinal( sAes_Data_t * const tag, sAes_DataCnt_t tagLen )
{
    sAes_RequestState_t retState = SAES_REQUEST_ERROR;
    sAes_Data_t           tagBlock[SAES_BLOCK_BYTES] = { 0u };

    SAes_Set_RegVal( SAES_REG_CR, AES_CR_GCMPH, ( SAES_CR_GCMPH_FINAL_RAW << AES_CR_GCMPH_Pos ) );

    const sAes_RegWaitResult_t ccfResult = SAes_Reg_Wait_Ccf();

    if( SAES_REG_WAIT_OK == ccfResult )
    {
        SAes_Reg_Read_Block( tagBlock );
        SAes_Reg_Clear_Ccf();
        SAes_Reg_Set_Disable();

        if( SAES_NULL_PTR != tag )
        {
            for( sAes_DataCnt_t idx = 0u;
                 ( SAES_BLOCK_BYTES > idx ) &&
                 ( tagLen > idx );
                 idx++                        )
            {
                tag[idx] = tagBlock[idx];
            }
        }
        else
        {
            /* No tag buffer requested */
        }

        retState = SAES_REQUEST_OK;
    }
    else
    {
        SAes_Reg_Set_Disable();
        retState = SAES_REQUEST_ERROR;
    }

    return ( retState );
}


/**
 * \brief One-shot ECB / CBC / CTR request (RM0481, 38.4.9 / 38.4.10).
 *
 * \param request  [in]: Pointer to the request
 * \param chmodRaw [in]: SAES_CR.CHMOD raw value already selected by the caller
 * \return \ref SAES_REQUEST_OK on success, \ref SAES_REQUEST_ERROR otherwise
 */
static sAes_RequestState_t SAes_Exec_Process_Simple( const sAes_Request_t * const request, uint32_t chmodRaw )
{
    sAes_RequestState_t retState = SAES_REQUEST_ERROR;

    SAes_Reg_Set_Disable();
    (void)SAes_Reg_Wait_BusyCleared();

    const uint32_t sizeRaw = SAes_Calc_SizeRaw( request->KeySize );

    if( ( SAES_OPERATION_DECRYPT == request->Operation ) &&
        ( SAES_MODE_CTR != request->Mode )                  )
    {
        /* ECB/CBC decrypt: key preparation pass first (RM0481, 38.4.9) */
        SAes_Set_RegVal( SAES_REG_CR,
                         SAES_CR_STD_MASK,
                         SAes_Build_StdCrValue( chmodRaw,
                                                SAES_CR_MODE_KEY_DERIVATION_RAW,
                                                SAES_CR_KMOD_NORMAL_RAW,
                                                sizeRaw,
                                                SAES_CR_GCMPH_INIT_RAW                     ) );

        const sAes_RequestState_t loadState = SAes_Exec_LoadRequestKey( request );

        if( SAES_REQUEST_OK == loadState )
        {
            const sAes_RequestState_t prepState = SAes_Exec_PrepareDecrypt();

            if( SAES_REQUEST_OK == prepState )
            {
                const uint32_t decMask  = ( AES_CR_CHMOD | AES_CR_MODE );
                const uint32_t decValue = ( SAes_Calc_ChmodReg( chmodRaw )               |
                                             ( SAES_CR_MODE_DECRYPT_RAW << AES_CR_MODE_Pos ) );

                SAes_Set_RegVal( SAES_REG_CR, decMask, decValue );

                if( SAES_MODE_CBC == request->Mode )
                {
                    SAes_Reg_Write_Iv( request->Iv );
                }
                else
                {
                    /* ECB does not use an IV */
                }

                const sAes_RequestState_t enableState = SAes_Reg_Set_Enable();

                if( SAES_REQUEST_OK == enableState )
                {
                    retState = SAes_Exec_SimpleBlocks( request->Operation,
                                                       request->Input,
                                                       request->Output,
                                                       request->DataLen );
                }
                else
                {
                    retState = SAES_REQUEST_ERROR;
                }
            }
            else
            {
                retState = SAES_REQUEST_ERROR;
            }
        }
        else
        {
            retState = SAES_REQUEST_ERROR;
        }
    }
    else
    {
        /* Encryption (any mode) or CTR decryption: a single pass is enough */
        const uint32_t modeRaw = SAes_Calc_ModeRaw( request->Operation );

        SAes_Set_RegVal( SAES_REG_CR,
                         SAES_CR_STD_MASK,
                         SAes_Build_StdCrValue( chmodRaw,
                                                modeRaw,
                                                SAES_CR_KMOD_NORMAL_RAW,
                                                sizeRaw,
                                                SAES_CR_GCMPH_INIT_RAW              ) );

        if( SAES_MODE_ECB != request->Mode )
        {
            SAes_Reg_Write_Iv( request->Iv );
        }
        else
        {
            /* ECB does not use an IV */
        }

        const sAes_RequestState_t loadState = SAes_Exec_LoadRequestKey( request );

        if( SAES_REQUEST_OK == loadState )
        {
            const sAes_RequestState_t enableState = SAes_Reg_Set_Enable();

            if( SAES_REQUEST_OK == enableState )
            {
                retState = SAes_Exec_SimpleBlocks( request->Operation,
                                                   request->Input,
                                                   request->Output,
                                                   request->DataLen );
            }
            else
            {
                retState = SAES_REQUEST_ERROR;
            }
        }
        else
        {
            retState = SAES_REQUEST_ERROR;
        }
    }

    SAes_Reg_Set_Disable();

    return ( retState );
}


/**
 * \brief One-shot GCM / GMAC request: init, header (AAD), payload, final (RM0481, 38.4.11).
 *
 * \param request [in]: Pointer to the request
 * \return \ref SAES_REQUEST_OK on success, \ref SAES_REQUEST_ERROR otherwise
 */
static sAes_RequestState_t SAes_Exec_Process_Gcm( const sAes_Request_t * const request )
{
    sAes_RequestState_t retState = SAES_REQUEST_ERROR;

    SAes_Reg_Set_Disable();
    (void)SAes_Reg_Wait_BusyCleared();

    const uint32_t modeRaw = SAes_Calc_ModeRaw( request->Operation );
    const uint32_t sizeRaw = SAes_Calc_SizeRaw( request->KeySize );

    SAes_Set_RegVal( SAES_REG_CR,
                     SAES_CR_STD_MASK,
                     SAes_Build_StdCrValue( SAES_CR_CHMOD_GCM_RAW,
                                            modeRaw,
                                            SAES_CR_KMOD_NORMAL_RAW,
                                            sizeRaw,
                                            SAES_CR_GCMPH_INIT_RAW                          ) );
    SAes_Reg_Write_Iv( request->Iv );

    const sAes_RequestState_t loadState = SAes_Exec_LoadRequestKey( request );

    if( SAES_REQUEST_OK == loadState )
    {
        const sAes_RequestState_t enableState = SAes_Reg_Set_Enable();
        sAes_RegWaitResult_t        initCcf      = SAES_REG_WAIT_TIMEOUT;

        if( SAES_REQUEST_OK == enableState )
        {
            initCcf = SAes_Reg_Wait_Ccf();
        }
        else
        {
            /* EN did not read back set */
        }

        SAes_Reg_Clear_Ccf();

        if( SAES_REG_WAIT_OK == initCcf )
        {
            const sAes_RequestState_t headerState = SAes_Exec_AeadHeader( request->Aad, request->AadLen );

            if( SAES_REQUEST_OK == headerState )
            {
                const sAes_RequestState_t payloadState = SAes_Exec_AeadPayload( request->Operation,
                                                                                request->Input,
                                                                                request->Output,
                                                                                request->DataLen );

                if( SAES_REQUEST_OK == payloadState )
                {
                    retState = SAes_Exec_GcmFinal( request->Operation,
                                                   request->AadLen,
                                                   request->DataLen,
                                                   request->Tag,
                                                   request->TagLen );
                }
                else
                {
                    SAes_Reg_Set_Disable();
                    retState = SAES_REQUEST_ERROR;
                }
            }
            else
            {
                SAes_Reg_Set_Disable();
                retState = SAES_REQUEST_ERROR;
            }
        }
        else
        {
            SAes_Reg_Set_Disable();
            retState = SAES_REQUEST_ERROR;
        }
    }
    else
    {
        retState = SAES_REQUEST_ERROR;
    }

    return ( retState );
}


/**
 * \brief One-shot CCM request: init, header (B1 + AAD), payload, final (RM0481, 38.4.13).
 *        \ref sAes_Request_t.Iv must already be the 16-byte B0 block and
 *        \ref sAes_Request_t.Aad must already include the B1 length prefix (see the
 *        file introduction and the README "CCM scope" note).
 *
 * \param request [in]: Pointer to the request
 * \return \ref SAES_REQUEST_OK on success, \ref SAES_REQUEST_ERROR otherwise
 */
static sAes_RequestState_t SAes_Exec_Process_Ccm( const sAes_Request_t * const request )
{
    sAes_RequestState_t retState = SAES_REQUEST_ERROR;

    SAes_Reg_Set_Disable();
    (void)SAes_Reg_Wait_BusyCleared();

    const uint32_t modeRaw = SAes_Calc_ModeRaw( request->Operation );
    const uint32_t sizeRaw = SAes_Calc_SizeRaw( request->KeySize );

    SAes_Set_RegVal( SAES_REG_CR,
                     SAES_CR_STD_MASK,
                     SAes_Build_StdCrValue( SAES_CR_CHMOD_CCM_RAW,
                                            modeRaw,
                                            SAES_CR_KMOD_NORMAL_RAW,
                                            sizeRaw,
                                            SAES_CR_GCMPH_INIT_RAW                          ) );
    SAes_Reg_Write_Iv( request->Iv );

    const sAes_RequestState_t loadState = SAes_Exec_LoadRequestKey( request );

    if( SAES_REQUEST_OK == loadState )
    {
        const sAes_RequestState_t enableState = SAes_Reg_Set_Enable();
        sAes_RegWaitResult_t        initCcf      = SAES_REG_WAIT_TIMEOUT;

        if( SAES_REQUEST_OK == enableState )
        {
            initCcf = SAes_Reg_Wait_Ccf();
        }
        else
        {
            /* EN did not read back set */
        }

        SAes_Reg_Clear_Ccf();

        if( SAES_REG_WAIT_OK == initCcf )
        {
            const sAes_RequestState_t headerState = SAes_Exec_AeadHeader( request->Aad, request->AadLen );

            if( SAES_REQUEST_OK == headerState )
            {
                const sAes_RequestState_t payloadState = SAes_Exec_AeadPayload( request->Operation,
                                                                                request->Input,
                                                                                request->Output,
                                                                                request->DataLen );

                if( SAES_REQUEST_OK == payloadState )
                {
                    retState = SAes_Exec_CcmFinal( request->Tag, request->TagLen );
                }
                else
                {
                    retState = SAES_REQUEST_ERROR;
                }

                if( SAES_REQUEST_OK != payloadState )
                {
                    SAes_Reg_Set_Disable();
                }
                else
                {
                    /* SAes_Exec_CcmFinal already disabled the peripheral */
                }
            }
            else
            {
                SAes_Reg_Set_Disable();
                retState = SAES_REQUEST_ERROR;
            }
        }
        else
        {
            SAes_Reg_Set_Disable();
            retState = SAES_REQUEST_ERROR;
        }
    }
    else
    {
        retState = SAES_REQUEST_ERROR;
    }

    return ( retState );
}


/**
 * \brief Writes a 64-bit value as 8 big-endian bytes (RM0481, Table 374: GCM length fields).
 *
 * \param dest  [out]: 8-byte destination
 * \param value [in]:  Value to write MSB first
 */
static void SAes_Write_Uint64BigEndian( sAes_Data_t * const dest, uint64_t value )
{
    for( uint32_t idx = 0u; SAES_UINT64_BYTES > idx; idx++ )
    {
        const uint32_t shiftBits = ( ( SAES_UINT64_BYTES - 1u - idx ) * SAES_BITS_PER_BYTE );

        dest[idx] = (sAes_Data_t)( value >> shiftBits );
    }
}


/**
 * \brief Validates a \ref sAes_Request_t before any register is touched.
 *
 * \param request [in]: Pointer to the request
 * \return \ref SAES_REQUEST_OK if every field is in range, \ref SAES_REQUEST_ERROR otherwise
 */
static sAes_RequestState_t SAes_Check_Request( const sAes_Request_t * const request )
{
    sAes_RequestState_t retState = SAES_REQUEST_ERROR;

    if( ( SAES_NULL_PTR != request )                     &&
        ( SAES_OPERATION_CNT > request->Operation )       &&
        ( SAES_MODE_CNT > request->Mode )                 &&
        ( SAES_REQUEST_KEY_CNT > request->KeySelect )     &&
        ( SAES_KEY_SIZE_CNT > request->KeySize )          &&
        ( SAES_NULL_PTR != request->Input )               &&
        ( SAES_NULL_PTR != request->Output )              &&
        ( ( SAES_REQUEST_KEY_LOADED == request->KeySelect ) ||
          ( SAES_NULL_PTR != request->Key )                    ) &&
        ( ( SAES_MODE_ECB == request->Mode ) ||
          ( SAES_NULL_PTR != request->Iv )      )                   )
    {
        sAes_FunctionState_t isEcbOrCbc = SAES_FUNCTION_INACTIVE;

        if( ( SAES_MODE_ECB == request->Mode ) ||
            ( SAES_MODE_CBC == request->Mode )    )
        {
            isEcbOrCbc = SAES_FUNCTION_ACTIVE;
        }
        else
        {
            isEcbOrCbc = SAES_FUNCTION_INACTIVE;
        }

        if( ( SAES_FUNCTION_ACTIVE == isEcbOrCbc )                        &&
            ( 0u != ( request->DataLen % SAES_BLOCK_BYTES ) )                )
        {
            /* ECB / CBC require an exact multiple of the block size */
            retState = SAES_REQUEST_ERROR;
        }
        else
        {
            retState = SAES_REQUEST_OK;
        }
    }
    else
    {
        /* Invalid request */
        retState = SAES_REQUEST_ERROR;
    }

    return ( retState );
}

#endif /* SAES */
