/**
 * \author Mr.Nobody
 * \file SAes.c
 * \ingroup SAes
 * \brief SAes module common functionality
 *
 * # Introduction #
 * The secure AES coprocessor of the STM32H7S lines (RM0477, chapter 36 "Secure AES
 * coprocessor (SAES)"; CMSIS type `SAES_TypeDef` with the `SAES_CR` / `SAES_SR` /
 * `SAES_ISR` bit names of the STM32H7RS device headers). Every data, key, IV and tag register is written / read four
 * 32-bit words at a time, MSB first (\ref SAes_Reg.c); the chaining mode and the
 * key handling mode are selected with `SAES_CR.CHMOD` / `SAES_CR.KMOD` /
 * `SAES_CR.GCMPH` (\ref SAes.h, values taken from RM0477 section 36.8.1 and
 * cross-checked against the CMSIS bit positions).
 *
 * # Devices without the SAES peripheral #
 * The SAES exists on the STM32H7S3 / STM32H7S7 lines, whose CMSIS device header defines \c SAES; the classic
 * STM32H7 lines and STM32H7R3 / STM32H7R7 have none. Every public function checks it (\c defined(SAES)):
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
 * contract keeps working.
 *
 * # DMA transfer mode #
 * With \ref SAES_XFER_MODE_DMA, \ref SAes_Init initializes two Gpdma channels of \ref sAes_Config_t: the input
 * channel (memory -> SAES_DINR, request SAES_IN) and the output channel (SAES_DOUTR -> memory, request SAES_OUT),
 * 32-bit words with the bytes of every word exchanged by the Gpdma (the module keeps its big-endian byte order,
 * SAES_CR.DATATYPE stays "no swapping"). The full 16-byte blocks of the payload (ECB, CBC, CTR, GCM, CCM) and of
 * the header (GCM, GMAC, CCM: input channel only) are moved by the DMA in chunks of at most
 * \ref SAES_DMA_CHUNK_MAX bytes (RM0477 36.4.5 "Appending data using DMA", 36.6): the channels are started, then
 * SAES_CR.DMAINEN / DMAOUTEN are set, the call waits (bounded) for the transfer complete interrupt of the channel
 * which ends the chunk. The partial last block is a CPU step (zero padding, SAES_CR.NPBLB), as RM0477 requires
 * for the GCM payload encryption and the CCM payload decryption. The buffers of a request with a full block must
 * be 32-bit aligned (\ref SAES_REQUEST_ERROR otherwise, before a register is touched); the suspend / resume of
 * RM0477 is not available in the DMA mode (the call returns only at the end of the data). The channels are GPDMA1
 * channels (the requests SAES_IN / SAES_OUT of the Gpdma module; HPDMA1 has no SAES request). Note: RM0477 Table
 * 90 lists the GPDMA1 request 4 as saes_out_dma and 5 as saes_in_dma, the LL header of the STM32H7RS (used by the
 * Gpdma module) defines SAES_IN = 4 and SAES_OUT = 5 - the integration tests in the DMA mode on a board with the
 * SAES decide (a swapped request ends a chunk by the timeout).
 *
 * # CCM scope #
 * The CCM chaining mode drives `SAES_CR.GCMPH` exactly as RM0477 section 36.4.13
 * documents (register sequencing only). Building the RFC 3610 / NIST SP800-38C
 * `B0` first block and the `B1` associated-data length prefix is left to the
 * caller: \ref sAes_Request_t.Iv must already be the 16-byte B0 block (RM0477
 * Table 330) and \ref sAes_Request_t.Aad must already include the B1 length
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
#include "Gpdma_Port.h"                      /* DMA mode channels              */
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
    gpdma_PeriphId_t        DmaPeriphId;      /**< Gpdma controller of the DMA mode              */
    gpdma_ChannelId_t       DmaInChannelId;   /**< Gpdma channel memory -> SAES_DINR             */
    gpdma_ChannelId_t       DmaOutChannelId;  /**< Gpdma channel SAES_DOUTR -> memory            */
    sAes_FunctionState_t    DmaInit;          /**< Both Gpdma channels are initialized           */
    volatile sAes_FunctionState_t DmaInDone;  /**< Transfer complete of the input channel        */
    volatile sAes_FunctionState_t DmaOutDone; /**< Transfer complete of the output channel       */
    volatile sAes_FunctionState_t DmaError;   /**< Gpdma error of one of the channels            */
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
static sAes_RequestState_t SAes_Exec_SimpleBlocks   ( sAes_Operation_t     operation,
                                                      const sAes_Data_t *  const input,
                                                      sAes_Data_t *        const output,
                                                      sAes_DataLen_t       dataLen,
                                                      sAes_FunctionState_t npblbUsed );
static sAes_RequestState_t SAes_Exec_AeadHeader     ( const sAes_Data_t * const aad, sAes_DataLen_t aadLen );
static sAes_RequestState_t SAes_Exec_AeadPayload    ( sAes_Mode_t         mode,
                                                      sAes_Operation_t    operation,
                                                      const sAes_Data_t * const input,
                                                      sAes_Data_t *       const output,
                                                      sAes_DataLen_t      dataLen );
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
static sAes_RequestState_t  SAes_Check_DmaBuffers   ( const sAes_Data_t * const input,
                                                      const sAes_Data_t * const output,
                                                      sAes_DataLen_t      dataLen,
                                                      const sAes_Data_t * const aad,
                                                      sAes_DataLen_t      aadLen );
static sAes_RequestState_t  SAes_Init_Dma           ( const sAes_Config_t * const sAesConfig );
static gpdma_RequestState_t SAes_Init_DmaChannel    ( const sAes_Config_t * const sAesConfig,
                                                      sAes_FunctionState_t       inputChannel );
static void                 SAes_Deinit_Dma         ( void );
static sAes_RequestState_t  SAes_Exec_DmaBlocks     ( const sAes_Data_t * const input,
                                                      sAes_Data_t *       const output,
                                                      sAes_DataLen_t      byteCnt );
static sAes_RequestState_t  SAes_Exec_DmaChunk      ( const sAes_Data_t * const input,
                                                      sAes_Data_t *       const output,
                                                      sAes_DataLen_t      byteOff,
                                                      sAes_DataLen_t      chunkSize );
static gpdma_RequestState_t SAes_Start_DmaChannel   ( gpdma_ChannelId_t channelId,
                                                      uint32_t          srcAddr,
                                                      uint32_t          dstAddr,
                                                      sAes_DataLen_t    chunkSize );
static sAes_RequestState_t  SAes_Wait_Dma           ( sAes_FunctionState_t outUsed, sAes_DataLen_t chunkSize );
static void                 SAes_DmaInCompleteIsr   ( void );
static void                 SAes_DmaOutCompleteIsr  ( void );
static void                 SAes_DmaErrorIsr        ( gpdma_ErrorMaskId_t errMask );

/* ========================== SYMBOLIC CONSTANTS ============================ */

/** \brief Default interrupt priority proposed by \ref SAes_Get_DefaultConfig */
#define SAES_DEFAULT_IRQ_PRIO                ( 7u )

/** \brief Default Gpdma channels and priority of the DMA mode proposed by \ref SAes_Get_DefaultConfig (channel 0 is
 *         the default of the Hash module) */
#define SAES_DEFAULT_DMA_IN_CHANNEL          ( GPDMA_CHANNEL_2 )
#define SAES_DEFAULT_DMA_OUT_CHANNEL         ( GPDMA_CHANNEL_3 )
#define SAES_DEFAULT_DMA_PRIO                ( GPDMA_PRIORITY_LOW )

/** \brief Largest DMA chunk: the biggest multiple of the block size within the 16-bit Gpdma block size */
#define SAES_DMA_CHUNK_MAX                   ( 65520u )

/** \brief Mask of the address bits that must be zero for a 32-bit DMA access */
#define SAES_WORD_ALIGN_MASK                 ( 3u )

/** \brief Bounded wait for the end of a DMA chunk: iterations per 16-byte block (RM0477 SAES processing latency:
 *         at most a few hundred SAES clock cycles per block, large margin) */
#define SAES_DMA_WAIT_PER_BLOCK_RAW          ( 0x4000u )

/** \brief Gpdma errors reported by the DMA mode */
#define SAES_DMA_ERROR_MASK                  ( GPDMA_ERROR_TRANSFER      | \
                                               GPDMA_ERROR_CONFIG_UPDATE | \
                                               GPDMA_ERROR_CONFIG_ERROR  | \
                                               GPDMA_ERROR_TRIG_OVERRUN )

/** \brief Byte length of the GCM "last block" length field (RM0477, Table 329: 2 x 64-bit) */
#define SAES_GCM_FINAL_BLOCK_BYTES           ( 16u )

/** \brief Byte width of a 64-bit GCM length field (RM0477, Table 329) */
#define SAES_UINT64_BYTES                    ( 8u )

/** \brief Mask of every SAES_CR field set together by \ref SAes_Build_StdCrValue; NPBLB is cleared with them (it is
 *         set only before the partial last block of a GCM payload encryption / CCM payload decryption) */
#define SAES_CR_STD_MASK                      ( SAES_CR_CHMOD | SAES_CR_MODE | SAES_CR_KMOD | SAES_CR_DATATYPE | \
                                                 SAES_CR_KEYSIZE | SAES_CR_GCMPH | SAES_CR_NPBLB                   )

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
    .AadClosed        = SAES_FUNCTION_INACTIVE,
    .DmaPeriphId      = GPDMA_PERIPH_1,
    .DmaInChannelId   = SAES_DEFAULT_DMA_IN_CHANNEL,
    .DmaOutChannelId  = SAES_DEFAULT_DMA_OUT_CHANNEL,
    .DmaInit          = SAES_FUNCTION_INACTIVE,
    .DmaInDone        = SAES_FUNCTION_INACTIVE,
    .DmaOutDone       = SAES_FUNCTION_INACTIVE,
    .DmaError         = SAES_FUNCTION_INACTIVE
};

/** \brief Transfer lists of the Gpdma channels of the DMA mode (used by the Gpdma module) */
static volatile gpdma_XferList_t sAes_DmaInXferList[ 1 ];
static volatile gpdma_XferList_t sAes_DmaOutXferList[ 1 ];

#endif /* SAES */

/* ========================= EXPORTED FUNCTIONS ============================= */

/**
 * \brief Initializes the module: enables the clock, makes sure the RNG the SAES
 *        side-channel countermeasures depend on is running (RM0477, 36.4.19: SAES
 *        fetches random numbers from the RNG bus), (ISR/DMA mode) configures
 *        the SAES NVIC interrupt and (DMA mode) initializes the input and the output Gpdma channel.
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
    if( ( SAES_NULL_PTR          != sAesConfig             ) &&
        ( SAES_XFER_MODE_CNT     >  sAesConfig->XferMode   ) &&
        ( SAES_FUNCTION_INACTIVE == sAes_Runtime.InitState )    )
    {
        const rcc_RequestState_t clockState = Rcc_Set_PeriphActive( RCC_PERIPH_SAES );

        if( RCC_REQUEST_OK == clockState )
        {
            (void)Rng_Set_ExecActive( RNG_PERIPH_1 );

            rng_FunctionState_t rngState = RNG_FUNCTION_INACTIVE;
            const rng_RequestState_t rngQuery = Rng_Get_ExecState( RNG_PERIPH_1, &rngState );

            if( ( RNG_REQUEST_OK      == rngQuery ) &&
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

                if( SAES_XFER_MODE_DMA == sAesConfig->XferMode )
                {
                    retState = SAes_Init_Dma( sAesConfig );
                }
                else
                {
                    retState = SAES_REQUEST_OK;
                }

                if( SAES_REQUEST_OK == retState )
                {
                    sAes_Runtime.InitState   = SAES_FUNCTION_ACTIVE;
                    sAes_Runtime.ModuleState = SAES_STATE_IDLE;
                }
                else
                {
                    /* A Gpdma channel of the DMA mode could not be initialized: the module is deinitialized below */
                }
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
 * \brief Deinitializes the module: clears the key, releases the Gpdma channels of the DMA mode, disables the
 *        interrupt, the SAES and its clock. The RNG is left running (other modules may use it).
 *
 * \return \ref SAES_REQUEST_OK, \ref SAES_REQUEST_ERROR on a device without the SAES peripheral.
 */
sAes_RequestState_t SAes_Deinit( void )
{
    sAes_RequestState_t retState = SAES_REQUEST_ERROR;

#if defined(SAES)
    SAes_Reg_Set_Disable();
    SAes_Reg_Clear_AllFlags();
    SAes_Deinit_Dma();
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
 * \brief Fills \p sAesConfig with the default configuration (POLL mode, no callbacks; for the DMA mode GPDMA1 with
 *        the input channel 2 and the output channel 3 at the low priority).
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
        sAesConfig->DmaPeriphId      = GPDMA_PERIPH_1;
        sAesConfig->DmaInChannelId   = SAES_DEFAULT_DMA_IN_CHANNEL;
        sAesConfig->DmaOutChannelId  = SAES_DEFAULT_DMA_OUT_CHANNEL;
        sAesConfig->DmaChannelPrio   = SAES_DEFAULT_DMA_PRIO;
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
 * Every combination documented by RM0477 chapter 36 is supported on every line that
 * has the SAES peripheral (there is no narrower sub-set on STM32H7S3 / STM32H7S7);
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
    if( ( SAES_KEY_SOURCE_CNT >  keySource ) &&
        ( SAES_MODE_CNT       >  mode      ) &&
        ( SAES_NULL_PTR       != supported )    )
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
 * \brief Loads a key into the SAES key registers in normal key mode (RM0477, 36.8.1
 *        KMOD = 0x0, and 36.4.17 for the hardware key sources).
 *
 * \param keyConfig [in]: Pointer to the key configuration
 * \return \ref SAES_REQUEST_OK on success, \ref SAES_REQUEST_ERROR otherwise
 */
sAes_RequestState_t SAes_Set_KeyLoad( const sAes_KeyConfig_t * const keyConfig )
{
    sAes_RequestState_t retState = SAES_REQUEST_ERROR;

#if defined(SAES)
    if( ( SAES_FUNCTION_ACTIVE   == sAes_Runtime.InitState ) &&
        ( SAES_NULL_PTR          != keyConfig              ) &&
        ( SAES_KEY_SOURCE_CNT    >  keyConfig->KeySource   ) &&
        ( SAES_KEY_SIZE_CNT      >  keyConfig->KeySize     ) &&
        ( SAES_FUNCTION_INACTIVE == keyConfig->Protect     )    )
    {
        /* The STM32H7S lines have no SAES_CR.KEYPROT (RM0477 36.8.1): a protection request is rejected above */
        SAes_Reg_Set_Disable();
        (void)SAes_Reg_Wait_BusyCleared();

        uint32_t chmodRaw = SAES_CR_CHMOD_ECB_RAW;

        SAes_Build_CrBase( SAES_MODE_ECB, &chmodRaw );

        const uint32_t crMask  = ( SAES_CR_CHMOD | SAES_CR_MODE | SAES_CR_KMOD | SAES_CR_DATATYPE |
                                   SAES_CR_KEYSIZE                                                );
        const uint32_t crValue = ( SAes_Calc_ChmodReg( chmodRaw )               |
                                   ( SAES_CR_MODE_ENCRYPT_RAW << SAES_CR_MODE_Pos ) |
                                   ( SAES_CR_KMOD_NORMAL_RAW << SAES_CR_KMOD_Pos ) |
                                   ( SAES_CR_DATATYPE_NONE_RAW << SAES_CR_DATATYPE_Pos ) |
                                   SAes_Calc_SizeRaw( keyConfig->KeySize )                          );

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
 * \brief Wraps (encrypts) a key with the selected key source (RM0477, 36.4.14,
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
    if( ( SAES_FUNCTION_ACTIVE == sAes_Runtime.InitState     ) &&
        ( SAES_NULL_PTR        != wrapConfig                 ) &&
        ( SAES_NULL_PTR        != plainKey                   ) &&
        ( SAES_NULL_PTR        != wrappedKey                 ) &&
        ( SAES_MODE_CTR        >= wrapConfig->Mode           ) &&
        ( SAES_KEY_SIZE_CNT    >  wrapConfig->WrapKeySize    ) &&
        ( SAES_KEY_SIZE_CNT    >  wrapConfig->WrappedKeySize )    )
    {
        if( SAES_MODE_CTR == wrapConfig->Mode )
        {
            /* CTR-mode "wrap" derives a key from the IV, there is nothing to encrypt
             * (RM0477, Figure 370): not a valid direction for SAes_Set_KeyWrap */
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
 *        derives it from an IV in CTR mode (RM0477, 36.4.14). At the end the key
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
    if( ( SAES_FUNCTION_ACTIVE == sAes_Runtime.InitState     ) &&
        ( SAES_NULL_PTR        != wrapConfig                 ) &&
        ( SAES_MODE_CTR        >= wrapConfig->Mode           ) &&
        ( SAES_KEY_SIZE_CNT    >  wrapConfig->WrapKeySize    ) &&
        ( SAES_KEY_SIZE_CNT    >  wrapConfig->WrappedKeySize )    )
    {
        SAes_Reg_Set_Disable();
        (void)SAes_Reg_Wait_BusyCleared();

        const uint32_t sizeRaw = SAes_Calc_SizeRaw( wrapConfig->WrappedKeySize );

        if( SAES_MODE_CTR == wrapConfig->Mode )
        {
            /* Derive the key from the IV (RM0477, Figure 370): single pass, MODE = decryption */
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

                /* The key is now in normal mode (KMOD auto-cleared at decryption end, RM0477 36.4.14) */
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
                    const uint32_t decMask  = ( SAES_CR_CHMOD | SAES_CR_MODE );
                    const uint32_t decValue = ( SAes_Calc_ChmodReg( chmodRaw )               |
                                                 ( SAES_CR_MODE_DECRYPT_RAW << SAES_CR_MODE_Pos ) );

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

                            /* RM0477, 36.4.14: reading SAES_DOUTR here returns zero (RDERRF), the
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
 *        (RM0477, 36.4.15, KMOD = 0x2 / KSHAREID). The key bytes themselves are not
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
    if( ( SAES_FUNCTION_ACTIVE  == sAes_Runtime.InitState ) &&
        ( SAES_SHARE_TARGET_CNT >  shareTarget            ) &&
        ( SAES_KEY_STATE_VALID  == sAes_Runtime.KeyState  )    )
    {
        SAes_Reg_Set_Disable();
        (void)SAes_Reg_Wait_BusyCleared();

        SAes_Set_RegVal( SAES_REG_CR,
                         ( SAES_CR_KMOD | SAES_CR_KSHAREID ),
                         ( ( SAES_CR_KMOD_SHARED_RAW << SAES_CR_KMOD_Pos ) |
                           ( SAES_CR_KSHAREID_CRYP_RAW << SAES_CR_KSHAREID_Pos )    ) );

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
 * \brief Clears the key registers and the key state (RM0477, 36.8.1 IPRST, the
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
    SAes_Set_RegBit( SAES_REG_CR, SAES_CR_IPRST );
    SAes_Reset_RegBit( SAES_REG_CR, SAES_CR_IPRST );
    SAes_Reg_Clear_AllFlags();

    sAes_Runtime.KeyState = SAES_KEY_STATE_NONE;
    retState              = SAES_REQUEST_OK;
#endif /* SAES */

    return ( retState );
}


/**
 * \brief Runs one complete data operation (RM0477, 36.4.5 - 36.4.13): ECB / CBC / CTR
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
        ( SAES_REQUEST_OK      == checkState             )    )
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
        else if( ( SAES_MODE_GCM  == request->Mode ) ||
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
        ( SAES_NULL_PTR        != request                ) &&
        ( SAES_MODE_CNT        >  request->Mode          ) &&
        ( SAES_KEY_SIZE_CNT    >  request->KeySize       ) &&
        ( SAES_REQUEST_KEY_CNT >  request->KeySelect     )    )
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
                /* RM0477, 36.4.11 step 7-9 / 36.4.13 step 7-9: EN starts the H / first-mask
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
 *        request opened by \ref SAes_Set_Start (RM0477, 36.4.11 / 36.4.13 header phase).
 *
 * \param aad    [in]: AAD bytes
 * \param aadLen [in]: Byte length of \p aad (multiple of 16, the last call may be shorter)
 * \return \ref SAES_REQUEST_OK on success, \ref SAES_REQUEST_ERROR otherwise
 */
sAes_RequestState_t SAes_Set_UpdateAad( const sAes_Data_t * const aad, sAes_DataLen_t aadLen )
{
    sAes_RequestState_t retState = SAES_REQUEST_ERROR;

#if defined(SAES)
    if( ( SAES_FUNCTION_ACTIVE   == sAes_Runtime.InitState ) &&
        ( SAES_FUNCTION_INACTIVE == sAes_Runtime.AadClosed ) &&
        ( ( SAES_NULL_PTR        != aad               ) ||
          ( 0u                   == aadLen            )    )    )
    {
        retState = SAes_Check_DmaBuffers( SAES_NULL_PTR, SAES_NULL_PTR, 0u, aad, aadLen );

        if( SAES_REQUEST_OK == retState )
        {
            retState = SAes_Exec_AeadHeader( aad, aadLen );
        }
        else
        {
            /* A buffer of the DMA mode is not word aligned, nothing is written */
        }
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
 *        (RM0477, 36.4.5 - 36.4.13 payload phase).
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
        ( SAES_NULL_PTR        != input                  ) &&
        ( SAES_NULL_PTR        != output                 )    )
    {
        const sAes_FunctionState_t isAead     = SAes_Calc_IsAead( sAes_Runtime.CurMode );
        const sAes_RequestState_t  alignState = SAes_Check_DmaBuffers( input, output, dataLen, SAES_NULL_PTR, 0u );

        if( SAES_REQUEST_OK != alignState )
        {
            /* A buffer of the DMA mode is not word aligned, nothing is written */
            retState = SAES_REQUEST_ERROR;
        }
        else if( SAES_FUNCTION_ACTIVE == isAead )
        {
            if( SAES_FUNCTION_INACTIVE == sAes_Runtime.AadClosed )
            {
                (void)SAes_Exec_AeadHeader( SAES_NULL_PTR, 0u );
            }
            else
            {
                /* Header phase already closed by an earlier SAes_Set_UpdateAad */
            }

            retState = SAes_Exec_AeadPayload( sAes_Runtime.CurMode,
                                              sAes_Runtime.CurOperation,
                                              input,
                                              output,
                                              dataLen );
        }
        else
        {
            SAes_Reset_RegBit( SAES_REG_CR, SAES_CR_EN );
            const sAes_RequestState_t enableState = SAes_Reg_Set_Enable();

            if( SAES_REQUEST_OK == enableState )
            {
                retState = SAes_Exec_SimpleBlocks( sAes_Runtime.CurOperation,
                                                   input,
                                                   output,
                                                   dataLen,
                                                   SAES_FUNCTION_INACTIVE );
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
 *        request (RM0477, 36.4.9 / 36.4.13 suspend sequences; not supported in GCM
 *        itself per RM0477, but the context is still saved uniformly here).
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
 *        restored: RM0477 states the application already knows the original key).
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
        SAes_Set_RegVal( SAES_REG_CR, SAES_REG_FULL_MASK & ~SAES_CR_EN, context->ControlReg & ~SAES_CR_EN );
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
        ( SAES_NULL_PTR        != irqPriority            )    )
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
 * \param sizeRaw  [in]: SAES_CR.KEYSIZE raw value (0 or \ref SAES_CR_KEYSIZE)
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
                                ( modeRaw << SAES_CR_MODE_Pos ) |
                                ( kmodRaw << SAES_CR_KMOD_Pos ) |
                                ( SAES_CR_DATATYPE_NONE_RAW << SAES_CR_DATATYPE_Pos ) |
                                sizeRaw | ( gcmphRaw << SAES_CR_GCMPH_Pos )              );

    return ( crValue );
}


/**
 * \brief Packs the logical SAES_CR.CHMOD value into its real register position: CMSIS /
 *        RM0477 36.8.1 split the field as CHMOD[1:0] at bits 6:5 and CHMOD[2] at bit 16
 *        (`SAES_CR_CHMOD_Msk` = 0x803 << 5), so a plain `chmodRaw << SAES_CR_CHMOD_Pos` is
 *        wrong for CCM (raw 0x4, bit 2 set): it would land at bit 7 instead of bit 16 and
 *        the peripheral would run as ECB. This function uses the CMSIS `SAES_CR_CHMOD_0/1/2`
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
        chmodReg = SAES_CR_CHMOD_0;
    }
    else if( SAES_CR_CHMOD_CTR_RAW == chmodRaw )
    {
        chmodReg = SAES_CR_CHMOD_1;
    }
    else if( SAES_CR_CHMOD_GCM_RAW == chmodRaw )
    {
        chmodReg = ( SAES_CR_CHMOD_0 | SAES_CR_CHMOD_1 );
    }
    else if( SAES_CR_CHMOD_CCM_RAW == chmodRaw )
    {
        chmodReg = SAES_CR_CHMOD_2;
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
 * \return \ref SAES_CR_KEYSIZE for \ref SAES_KEY_SIZE_256, 0 otherwise
 */
static uint32_t SAes_Calc_SizeRaw( sAes_KeySize_t keySize )
{
    uint32_t sizeRaw = 0u;

    if( SAES_KEY_SIZE_256 == keySize )
    {
        sizeRaw = SAES_CR_KEYSIZE;
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
 * \brief Loads the software key given inline with a request, if any (RM0477, 36.4.17
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

    if( ( SAES_MODE_GCM  == mode ) ||
        ( SAES_MODE_GMAC == mode ) ||
        ( SAES_MODE_CCM  == mode )    )
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
 * \brief Loads a key by software bytes or by a hardware source (RM0477, 36.4.17);
 *        updates \ref sAes_RuntimeData_t.KeyState at the end.
 *
 * \param keySource [in]: Key source
 * \param keySize   [in]: Key length
 * \param keyBytes  [in]: Software key bytes (ignored for a hardware source)
 * \param keyProt   [in]: Not used (the STM32H7S lines have no SAES_CR.KEYPROT)
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
            SAes_Set_RegVal( SAES_REG_CR, SAES_CR_KEYSEL, ( SAES_CR_KEYSEL_SOFTWARE_RAW << SAES_CR_KEYSEL_Pos ) );
            SAes_Reg_Write_Key( keyBytes, keySize );

            /* RM0477, 36.8.2: the correct KEYRx write sequence sets KEYVALID by hardware
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

        SAes_Set_RegVal( SAES_REG_CR, SAES_CR_KEYSEL, ( keySelRaw << SAES_CR_KEYSEL_Pos ) );

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
    else if( ( SAES_MODE_GCM  == mode ) ||
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
 * \brief Runs the ECB/CBC decryption key-preparation pass (RM0477, 36.4.9: MODE =
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
 *        at a time, waiting for CCF between blocks (RM0477, 36.4.5). The last CTR
 *        block may be shorter than 16 bytes (zero-padded on input, truncated on output,
 *        RM0477 36.4.10 step 8a); ECB and CBC require an exact multiple of 16 bytes.
 *
 * \param operation [in]:  Encrypt or decrypt (only used to decide the zero-padding rule)
 * \param input     [in]:  Input buffer
 * \param output    [out]: Output buffer, same length as \p input
 * \param dataLen   [in]:  Byte length of \p input / \p output
 * \param npblbUsed [in]:  \ref SAES_FUNCTION_ACTIVE: the count of the padding bytes of a partial last block is
 *                         written to SAES_CR.NPBLB before the block (GCM payload encryption, CCM payload
 *                         decryption: the tag is wrong otherwise, RM0477 SAES_CR.NPBLB)
 * \return \ref SAES_REQUEST_OK on success, \ref SAES_REQUEST_ERROR otherwise
 */
static sAes_RequestState_t SAes_Exec_SimpleBlocks( sAes_Operation_t     operation,
                                                   const sAes_Data_t *  const input,
                                                   sAes_Data_t *        const output,
                                                   sAes_DataLen_t       dataLen,
                                                   sAes_FunctionState_t npblbUsed )
{
    sAes_RequestState_t retState   = SAES_REQUEST_OK;
    sAes_Data_t           blockIn[SAES_BLOCK_BYTES]  = { 0u };
    sAes_Data_t           blockOut[SAES_BLOCK_BYTES] = { 0u };
    const sAes_DataLen_t fullBlocks = ( dataLen / SAES_BLOCK_BYTES );
    const sAes_DataLen_t tailBytes  = ( dataLen % SAES_BLOCK_BYTES );

    (void)operation;

    if( ( SAES_XFER_MODE_DMA == sAes_Runtime.XferMode ) &&
        ( 0u                 <  fullBlocks            )    )
    {
        retState = SAes_Exec_DmaBlocks( input, output, ( fullBlocks * SAES_BLOCK_BYTES ) );
    }
    else
    {
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
    }

    if( ( SAES_REQUEST_OK == retState  ) &&
        ( 0u              != tailBytes )    )
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

        if( SAES_FUNCTION_ACTIVE == npblbUsed )
        {
            SAes_Set_RegVal( SAES_REG_CR,
                             SAES_CR_NPBLB,
                             ( (uint32_t)( SAES_BLOCK_BYTES - tailBytes ) << SAES_CR_NPBLB_Pos ) );
        }
        else
        {
            /* The padding bytes do not enter a tag */
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
 *        (RM0477, 36.4.11 / 36.4.13 "append header data"), then switches CR to the
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
        SAes_Set_RegVal( SAES_REG_CR, SAES_CR_GCMPH, ( SAES_CR_GCMPH_HEADER_RAW << SAES_CR_GCMPH_Pos ) );
        (void)SAes_Reg_Set_Enable();

        if( ( SAES_XFER_MODE_DMA == sAes_Runtime.XferMode ) &&
            ( 0u                 <  fullBlocks            )    )
        {
            /* The header phase has no output: only the input channel runs (RM0477 36.4.11, DMAINEN) */
            retState = SAes_Exec_DmaBlocks( aad, SAES_NULL_PTR, ( fullBlocks * SAES_BLOCK_BYTES ) );
        }
        else
        {
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
        }

        if( ( SAES_REQUEST_OK == retState  ) &&
            ( 0u              != tailBytes )    )
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
        /* Len(A) = 0: the header phase is skipped (RM0477, 36.4.11 / 36.4.13) */
    }

    SAes_Set_RegVal( SAES_REG_CR, SAES_CR_GCMPH, ( SAES_CR_GCMPH_PAYLOAD_RAW << SAES_CR_GCMPH_Pos ) );
    sAes_Runtime.AadClosed = SAES_FUNCTION_ACTIVE;

    return ( retState );
}


/**
 * \brief Runs the GCM/CCM payload phase (RM0477, 36.4.11 / 36.4.13 "append payload data"). The partial last block
 *        of a GCM encryption or of a CCM decryption needs SAES_CR.NPBLB (RM0477 SAES_CR.NPBLB).
 *
 * \param mode      [in]:  Chaining mode (GCM, GMAC or CCM)
 * \param operation [in]:  Encrypt or decrypt
 * \param input     [in]:  Plaintext (encrypt) or ciphertext (decrypt)
 * \param output    [out]: Ciphertext (encrypt) or plaintext (decrypt)
 * \param dataLen   [in]:  Byte length of \p input / \p output
 * \return \ref SAES_REQUEST_OK on success, \ref SAES_REQUEST_ERROR otherwise
 */
static sAes_RequestState_t SAes_Exec_AeadPayload( sAes_Mode_t         mode,
                                                  sAes_Operation_t    operation,
                                                  const sAes_Data_t * const input,
                                                  sAes_Data_t *       const output,
                                                  sAes_DataLen_t      dataLen )
{
    sAes_FunctionState_t npblbUsed = SAES_FUNCTION_INACTIVE;

    if( ( ( SAES_MODE_GCM          == mode      ) &&
          ( SAES_OPERATION_ENCRYPT == operation )    ) ||
        ( ( SAES_MODE_CCM          == mode      ) &&
          ( SAES_OPERATION_DECRYPT == operation )    )    )
    {
        npblbUsed = SAES_FUNCTION_ACTIVE;
    }
    else
    {
        /* GCM decryption, CCM encryption: the tag is computed over the zero-padded input block */
    }

    (void)SAes_Reg_Set_Enable();

    return ( SAes_Exec_SimpleBlocks( operation, input, output, dataLen, npblbUsed ) );
}


/**
 * \brief Runs the GCM/GMAC final phase: writes the bit-length block, reads the tag
 *        (RM0477, 36.4.11 step 14-19 / 36.4.12).
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
        /* Decryption does not need the extra BUSY wait (RM0477, 36.4.11 step 14) */
    }

    SAes_Write_Uint64BigEndian( &lengthBlock[0], aadBits );
    SAes_Write_Uint64BigEndian( &lengthBlock[SAES_UINT64_BYTES], payloadBits );

    SAes_Set_RegVal( SAES_REG_CR, SAES_CR_GCMPH, ( SAES_CR_GCMPH_FINAL_RAW << SAES_CR_GCMPH_Pos ) );
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
 *        (no SAES_DINR write, RM0477, 36.4.13 step 14-18).
 *
 * \param tag    [out]: Resulting / expected authentication tag
 * \param tagLen [in]:  Requested tag byte length
 * \return \ref SAES_REQUEST_OK on success, \ref SAES_REQUEST_ERROR otherwise
 */
static sAes_RequestState_t SAes_Exec_CcmFinal( sAes_Data_t * const tag, sAes_DataCnt_t tagLen )
{
    sAes_RequestState_t retState = SAES_REQUEST_ERROR;
    sAes_Data_t           tagBlock[SAES_BLOCK_BYTES] = { 0u };

    SAes_Set_RegVal( SAES_REG_CR, SAES_CR_GCMPH, ( SAES_CR_GCMPH_FINAL_RAW << SAES_CR_GCMPH_Pos ) );

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
 * \brief One-shot ECB / CBC / CTR request (RM0477, 36.4.9 / 36.4.10).
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
        ( SAES_MODE_CTR          != request->Mode      )    )
    {
        /* ECB/CBC decrypt: key preparation pass first (RM0477, 36.4.9) */
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
                const uint32_t decMask  = ( SAES_CR_CHMOD | SAES_CR_MODE );
                const uint32_t decValue = ( SAes_Calc_ChmodReg( chmodRaw )               |
                                             ( SAES_CR_MODE_DECRYPT_RAW << SAES_CR_MODE_Pos ) );

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
                                                       request->DataLen ,
                                                       SAES_FUNCTION_INACTIVE );
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
                                                   request->DataLen ,
                                                   SAES_FUNCTION_INACTIVE );
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
 * \brief One-shot GCM / GMAC request: init, header (AAD), payload, final (RM0477, 36.4.11).
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
                const sAes_RequestState_t payloadState = SAes_Exec_AeadPayload( request->Mode,
                                                                                request->Operation,
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
 * \brief One-shot CCM request: init, header (B1 + AAD), payload, final (RM0477, 36.4.13).
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
                const sAes_RequestState_t payloadState = SAes_Exec_AeadPayload( request->Mode,
                                                                                request->Operation,
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
 * \brief Writes a 64-bit value as 8 big-endian bytes (RM0477, Table 329: GCM length fields).
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

    if( ( SAES_NULL_PTR             != request                 ) &&
        ( SAES_OPERATION_CNT        >  request->Operation      ) &&
        ( SAES_MODE_CNT             >  request->Mode           ) &&
        ( SAES_REQUEST_KEY_CNT      >  request->KeySelect      ) &&
        ( SAES_KEY_SIZE_CNT         >  request->KeySize        ) &&
        ( SAES_NULL_PTR             != request->Input          ) &&
        ( SAES_NULL_PTR             != request->Output         ) &&
        ( ( SAES_REQUEST_KEY_LOADED == request->KeySelect ) ||
          ( SAES_NULL_PTR           != request->Key       )    ) &&
        ( ( SAES_MODE_ECB           == request->Mode      ) ||
          ( SAES_NULL_PTR           != request->Iv        )    )    )
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

        if( ( SAES_FUNCTION_ACTIVE == isEcbOrCbc                              ) &&
            ( 0u                   != ( request->DataLen % SAES_BLOCK_BYTES ) )    )
        {
            /* ECB / CBC require an exact multiple of the block size */
            retState = SAES_REQUEST_ERROR;
        }
        else
        {
            retState = SAes_Check_DmaBuffers( request->Input,
                                              request->Output,
                                              request->DataLen,
                                              request->Aad,
                                              request->AadLen );
        }
    }
    else
    {
        /* Invalid request */
        retState = SAES_REQUEST_ERROR;
    }

    return ( retState );
}


/**
 * \brief Checks the buffers of a request for the DMA mode: the DMA moves 32-bit words, so a buffer which holds a
 *        full block (moved by the DMA) must be word aligned. Other transfer modes accept every buffer.
 *
 * \param input   [in]: Payload input (\ref SAES_NULL_PTR without a payload)
 * \param output  [in]: Payload output (\ref SAES_NULL_PTR without a payload)
 * \param dataLen [in]: Byte length of the payload
 * \param aad     [in]: Additional authenticated data (\ref SAES_NULL_PTR without AAD)
 * \param aadLen  [in]: Byte length of \p aad
 * \return \ref SAES_REQUEST_OK when the DMA can move the buffers, \ref SAES_REQUEST_ERROR otherwise
 */
static sAes_RequestState_t SAes_Check_DmaBuffers( const sAes_Data_t * const input,
                                                  const sAes_Data_t * const output,
                                                  sAes_DataLen_t      dataLen,
                                                  const sAes_Data_t * const aad,
                                                  sAes_DataLen_t      aadLen )
{
    sAes_RequestState_t retState = SAES_REQUEST_OK;

    if( SAES_XFER_MODE_DMA == sAes_Runtime.XferMode )
    {
        const uint32_t dataAlign = ( ( (uint32_t)(uintptr_t)input | (uint32_t)(uintptr_t)output ) &
                                     SAES_WORD_ALIGN_MASK );
        const uint32_t aadAlign  = ( (uint32_t)(uintptr_t)aad & SAES_WORD_ALIGN_MASK );

        if( ( ( SAES_BLOCK_BYTES <= dataLen   ) &&
              ( 0u               != dataAlign )    ) ||
            ( ( SAES_BLOCK_BYTES <= aadLen    ) &&
              ( 0u               != aadAlign  )    )    )
        {
            /* A full block of a buffer which is not word aligned cannot be moved by the DMA */
            retState = SAES_REQUEST_ERROR;
        }
        else
        {
            /* Word aligned buffers, or no full block for the DMA */
            retState = SAES_REQUEST_OK;
        }
    }
    else
    {
        /* POLL / ISR mode: the CPU moves the bytes */
        retState = SAES_REQUEST_OK;
    }

    return ( retState );
}


/**
 * \brief Initializes the input and the output Gpdma channel of the DMA mode and activates their interrupts.
 *
 * \param sAesConfig [in]: Configuration of the module (Gpdma controller, channels, priority)
 * \return \ref SAES_REQUEST_OK when both channels are ready, \ref SAES_REQUEST_ERROR otherwise
 */
static sAes_RequestState_t SAes_Init_Dma( const sAes_Config_t * const sAesConfig )
{
    sAes_RequestState_t  retState = SAES_REQUEST_ERROR;
    gpdma_RequestState_t dmaState = GPDMA_REQUEST_ERROR;

    sAes_Runtime.DmaPeriphId     = sAesConfig->DmaPeriphId;
    sAes_Runtime.DmaInChannelId  = sAesConfig->DmaInChannelId;
    sAes_Runtime.DmaOutChannelId = sAesConfig->DmaOutChannelId;

    if( ( GPDMA_PERIPH_1             == sAesConfig->DmaPeriphId     ) &&
        ( sAesConfig->DmaInChannelId != sAesConfig->DmaOutChannelId )    )
    {
        dmaState = SAes_Init_DmaChannel( sAesConfig, SAES_FUNCTION_ACTIVE );
    }
    else
    {
        /* Only GPDMA1 has the SAES requests (RM0477 Table 90, HPDMA1 has none), one channel cannot serve both
           directions */
        dmaState = GPDMA_REQUEST_ERROR;
    }

    if( GPDMA_REQUEST_OK == dmaState )
    {
        dmaState = SAes_Init_DmaChannel( sAesConfig, SAES_FUNCTION_INACTIVE );
    }
    else
    {
        /* The input channel failed */
    }

    if( GPDMA_REQUEST_OK == dmaState )
    {
        sAes_Runtime.DmaInit = SAES_FUNCTION_ACTIVE;

        dmaState = Gpdma_Set_InterruptActive( sAesConfig->DmaPeriphId, sAesConfig->DmaInChannelId );
    }
    else
    {
        /* The output channel failed */
    }

    if( GPDMA_REQUEST_OK == dmaState )
    {
        dmaState = Gpdma_Set_InterruptActive( sAesConfig->DmaPeriphId, sAesConfig->DmaOutChannelId );
    }
    else
    {
        /* The interrupt of the input channel failed */
    }

    if( GPDMA_REQUEST_OK == dmaState )
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
 * \brief Initializes one Gpdma channel of the DMA mode: single requests of the SAES, 32-bit words, the bytes of
 *        every word exchanged on the destination side (the SAES data registers hold the block MSB first, the
 *        memory holds it as a byte array). The block size and the memory address are set per chunk.
 *
 * \param sAesConfig   [in]: Configuration of the module
 * \param inputChannel [in]: \ref SAES_FUNCTION_ACTIVE: input channel (memory -> SAES_DINR, request SAES_IN),
 *                           otherwise the output channel (SAES_DOUTR -> memory, request SAES_OUT)
 * \return Result of \ref Gpdma_Init
 */
static gpdma_RequestState_t SAes_Init_DmaChannel( const sAes_Config_t * const sAesConfig,
                                                  sAes_FunctionState_t       inputChannel )
{
    gpdma_ConfigStruct_t   dmaConfig  = { 0 };
    gpdma_TransferConfig_t xferConfig = { 0 };
    gpdma_RequestState_t   dmaState   = Gpdma_Get_DefaultConfig( &dmaConfig );

    xferConfig.XferListExecMode            = GPDMA_XFER_LIST_EXEC_ONCE;
    xferConfig.EventMode                   = GPDMA_TRANSFER_EVENT_BLOCK;
    xferConfig.TriggerType                 = GPDMA_TRG_NOT_USED;
    xferConfig.TriggerSource               = GPDMA_TRG_EXTIT0_SYNC; /* Not used (GPDMA_TRG_NOT_USED) */
    xferConfig.TriggerMode                 = GPDMA_TRIGGER_BLOCK;
    xferConfig.RequestMode                 = GPDMA_PERIPH_REQ_SINGLE;
    xferConfig.BlockSize                   = 0u; /* Set per chunk by SAes_Start_DmaChannel */
    xferConfig.BlockRepetitionCount        = 0u;
    xferConfig.SourceDataSize              = GPDMA_DATA_SIZE_32BITS;
    xferConfig.SourceBurstLength           = 1u;
    xferConfig.SourcePortId                = GPDMA_PORT_DEFAULT;
    xferConfig.SourceDataOp                = GPDMA_SRC_DATA_PRESERVE;
    xferConfig.SourceBlockOffset2D         = 0u;
    xferConfig.SourceRepBlockOffset2D      = 0u;
    xferConfig.DestinationDataSize         = GPDMA_DATA_SIZE_32BITS;
    xferConfig.DestinationBurstLength      = 1u;
    xferConfig.DestinationPortId           = GPDMA_PORT_DEFAULT;
    xferConfig.DestinationDataOp           = GPDMA_DEST_DATA_BYTE_2BYTES_SWAP;
    xferConfig.DestinationBlockOffset2D    = 0u;
    xferConfig.DestinationRepBlockOffset2D = 0u;

    dmaConfig.PeriphId           = sAesConfig->DmaPeriphId;
    dmaConfig.ChannelPrio        = sAesConfig->DmaChannelPrio;
    dmaConfig.TransferExecMode   = GPDMA_XFER_EXEC_BLOCKING;
    dmaConfig.TransferConfig     = &xferConfig;
    dmaConfig.TransfersCount     = 1u;
    dmaConfig.XferListAccessMode = GPDMA_TRANSFER_LIST_ACCESS_SINGLE;
    dmaConfig.TransferLockState  = GPDMA_TRANSFER_LIST_LOCKED;
    dmaConfig.HalfTransferIsr    = SAES_NULL_PTR;
    dmaConfig.ErrorIsr           = SAes_DmaErrorIsr;
    dmaConfig.ErrorMask          = SAES_DMA_ERROR_MASK;

    if( SAES_FUNCTION_ACTIVE == inputChannel )
    {
        xferConfig.Direction           = GPDMA_DIR_MEMORY_TO_PERIPH;
        xferConfig.RequestSource       = GPDMA_REQ_SAES_IN;
        xferConfig.SourceAddr          = 0u; /* Set per chunk by SAes_Start_DmaChannel */
        xferConfig.SourceAddrMode      = GPDMA_ADDR_INCREMENT;
        xferConfig.DestinationAddr     = (gpdma_DstAddr_t)SAes_Reg_Get_DinAddr();
        xferConfig.DestinationAddrMode = GPDMA_ADDR_STATIC;
        dmaConfig.ChannelId            = sAesConfig->DmaInChannelId;
        dmaConfig.XferList             = &sAes_DmaInXferList[ 0 ];
        dmaConfig.TransferCompleteIsr  = SAes_DmaInCompleteIsr;
    }
    else
    {
        xferConfig.Direction           = GPDMA_DIR_PERIPH_TO_MEMORY;
        xferConfig.RequestSource       = GPDMA_REQ_SAES_OUT;
        xferConfig.SourceAddr          = (gpdma_SrcAddr_t)SAes_Reg_Get_DoutAddr();
        xferConfig.SourceAddrMode      = GPDMA_ADDR_STATIC;
        xferConfig.DestinationAddr     = 0u; /* Set per chunk by SAes_Start_DmaChannel */
        xferConfig.DestinationAddrMode = GPDMA_ADDR_INCREMENT;
        dmaConfig.ChannelId            = sAesConfig->DmaOutChannelId;
        dmaConfig.XferList             = &sAes_DmaOutXferList[ 0 ];
        dmaConfig.TransferCompleteIsr  = SAes_DmaOutCompleteIsr;
    }

    if( GPDMA_REQUEST_OK == dmaState )
    {
        dmaState = Gpdma_Init( &dmaConfig );
    }
    else
    {
        /* The default configuration is not available */
    }

    return ( dmaState );
}


/**
 * \brief Releases the Gpdma channels of the DMA mode (\ref Gpdma_Deinit stops a running transfer), if initialized.
 */
static void SAes_Deinit_Dma( void )
{
    if( SAES_FUNCTION_ACTIVE == sAes_Runtime.DmaInit )
    {
        (void)Gpdma_Set_InterruptInactive( sAes_Runtime.DmaPeriphId, sAes_Runtime.DmaInChannelId );
        (void)Gpdma_Set_InterruptInactive( sAes_Runtime.DmaPeriphId, sAes_Runtime.DmaOutChannelId );
        (void)Gpdma_Deinit( sAes_Runtime.DmaPeriphId, sAes_Runtime.DmaInChannelId );
        (void)Gpdma_Deinit( sAes_Runtime.DmaPeriphId, sAes_Runtime.DmaOutChannelId );
    }
    else
    {
        /* No channel of the DMA mode */
    }

    sAes_Runtime.DmaInit = SAES_FUNCTION_INACTIVE;
}


/**
 * \brief Moves \p byteCnt bytes (full blocks) through the SAES by the DMA, in chunks of at most
 *        \ref SAES_DMA_CHUNK_MAX bytes.
 *
 * \param input   [in]:  Word aligned input buffer
 * \param output  [out]: Word aligned output buffer, \ref SAES_NULL_PTR in the header phase (no output)
 * \param byteCnt [in]:  Byte count, a multiple of \ref SAES_BLOCK_BYTES
 * \return \ref SAES_REQUEST_OK when every chunk was moved, \ref SAES_REQUEST_ERROR otherwise
 */
static sAes_RequestState_t SAes_Exec_DmaBlocks( const sAes_Data_t * const input,
                                                sAes_Data_t *       const output,
                                                sAes_DataLen_t      byteCnt )
{
    sAes_RequestState_t retState = SAES_REQUEST_OK;

    for( sAes_DataLen_t byteOff = 0u;
         ( byteCnt         >  byteOff  ) &&
         ( SAES_REQUEST_OK == retState )    ;
         byteOff += SAES_DMA_CHUNK_MAX )
    {
        sAes_DataLen_t chunkSize = ( byteCnt - byteOff );

        if( SAES_DMA_CHUNK_MAX < chunkSize )
        {
            chunkSize = SAES_DMA_CHUNK_MAX;
        }
        else
        {
            /* The rest fits one chunk */
        }

        retState = SAes_Exec_DmaChunk( input, output, byteOff, chunkSize );
    }

    return ( retState );
}


/**
 * \brief Moves one chunk by the DMA (RM0477 36.4.5 "Appending data using DMA"): starts the output channel (if any)
 *        and the input channel, sets SAES_CR.DMAINEN / DMAOUTEN, waits for the end of the chunk and clears the DMA
 *        requests and SAES_ISR.CCF (back to the software control). On an error both channels are stopped.
 *
 * \param input     [in]:  Word aligned input buffer
 * \param output    [out]: Word aligned output buffer, \ref SAES_NULL_PTR in the header phase
 * \param byteOff   [in]:  Byte offset of the chunk in the buffers
 * \param chunkSize [in]:  Byte count of the chunk (multiple of \ref SAES_BLOCK_BYTES, at most
 *                         \ref SAES_DMA_CHUNK_MAX)
 * \return \ref SAES_REQUEST_OK when the chunk was moved, \ref SAES_REQUEST_ERROR otherwise
 */
static sAes_RequestState_t SAes_Exec_DmaChunk( const sAes_Data_t * const input,
                                               sAes_Data_t *       const output,
                                               sAes_DataLen_t      byteOff,
                                               sAes_DataLen_t      chunkSize )
{
    sAes_RequestState_t  retState = SAES_REQUEST_ERROR;
    gpdma_RequestState_t dmaState = GPDMA_REQUEST_OK;
    sAes_FunctionState_t outUsed  = SAES_FUNCTION_INACTIVE;

    sAes_Runtime.DmaInDone  = SAES_FUNCTION_INACTIVE;
    sAes_Runtime.DmaOutDone = SAES_FUNCTION_INACTIVE;
    sAes_Runtime.DmaError   = SAES_FUNCTION_INACTIVE;

    if( SAES_NULL_PTR != output )
    {
        outUsed  = SAES_FUNCTION_ACTIVE;
        dmaState = SAes_Start_DmaChannel( sAes_Runtime.DmaOutChannelId,
                                          SAes_Reg_Get_DoutAddr(),
                                          (uint32_t)(uintptr_t)&output[ byteOff ],
                                          chunkSize );
    }
    else
    {
        /* Header phase: the SAES has no output */
    }

    if( GPDMA_REQUEST_OK == dmaState )
    {
        dmaState = SAes_Start_DmaChannel( sAes_Runtime.DmaInChannelId,
                                          (uint32_t)(uintptr_t)&input[ byteOff ],
                                          SAes_Reg_Get_DinAddr(),
                                          chunkSize );
    }
    else
    {
        /* The output channel could not be started */
    }

    if( GPDMA_REQUEST_OK == dmaState )
    {
        SAes_Reg_Set_DmaRequests( SAES_FUNCTION_ACTIVE, outUsed );
        retState = SAes_Wait_Dma( outUsed, chunkSize );
        SAes_Reg_Set_DmaRequests( SAES_FUNCTION_INACTIVE, SAES_FUNCTION_INACTIVE );
    }
    else
    {
        retState = SAES_REQUEST_ERROR;
    }

    if( SAES_REQUEST_OK != retState )
    {
        (void)Gpdma_Set_ChannelInactive( sAes_Runtime.DmaPeriphId, sAes_Runtime.DmaInChannelId );
        (void)Gpdma_Set_ChannelInactive( sAes_Runtime.DmaPeriphId, sAes_Runtime.DmaOutChannelId );
    }
    else
    {
        /* Both channels ended their block */
    }

    SAes_Reg_Clear_Ccf();

    return ( retState );
}


/**
 * \brief Sets the block size and the addresses of a Gpdma channel of the DMA mode and starts it. The addresses
 *        of the register side are written again: a channel stopped after an error was reset.
 *
 * \param channelId [in]: Gpdma channel
 * \param srcAddr   [in]: Source address
 * \param dstAddr   [in]: Destination address
 * \param chunkSize [in]: Byte count of the chunk
 * \return \ref GPDMA_REQUEST_OK when the channel runs, otherwise the first error of the Gpdma module
 */
static gpdma_RequestState_t SAes_Start_DmaChannel( gpdma_ChannelId_t channelId,
                                                   uint32_t          srcAddr,
                                                   uint32_t          dstAddr,
                                                   sAes_DataLen_t    chunkSize )
{
    gpdma_RequestState_t dmaState = Gpdma_Set_BlockSize( sAes_Runtime.DmaPeriphId,
                                                         channelId,
                                                         (gpdma_BlockSize_t)chunkSize );

    if( GPDMA_REQUEST_OK == dmaState )
    {
        dmaState = Gpdma_Set_SourceAddr( sAes_Runtime.DmaPeriphId, channelId, (gpdma_SrcAddr_t)srcAddr );
    }
    else
    {
        /* The block size was not accepted */
    }

    if( GPDMA_REQUEST_OK == dmaState )
    {
        dmaState = Gpdma_Set_DestinationAddr( sAes_Runtime.DmaPeriphId, channelId, (gpdma_DstAddr_t)dstAddr );
    }
    else
    {
        /* The source address was not accepted */
    }

    if( GPDMA_REQUEST_OK == dmaState )
    {
        dmaState = Gpdma_Set_ChannelActive( sAes_Runtime.DmaPeriphId, channelId );
    }
    else
    {
        /* The destination address was not accepted */
    }

    return ( dmaState );
}


/**
 * \brief Waits (bounded) for the end of a DMA chunk: the transfer complete of the output channel (payload) or of
 *        the input channel and the end of the processing of the last block (header, SAES_SR.BUSY cleared).
 *
 * \param outUsed   [in]: \ref SAES_FUNCTION_ACTIVE when the output channel runs
 * \param chunkSize [in]: Byte count of the chunk (scales the bound of the wait)
 * \return \ref SAES_REQUEST_OK at the end of the chunk without an error, \ref SAES_REQUEST_ERROR on a Gpdma error,
 *         an error flag of the SAES or the timeout
 */
static sAes_RequestState_t SAes_Wait_Dma( sAes_FunctionState_t outUsed, sAes_DataLen_t chunkSize )
{
    sAes_RequestState_t retState = SAES_REQUEST_ERROR;
    const uint32_t      waitCnt  = ( ( chunkSize / SAES_BLOCK_BYTES ) * SAES_DMA_WAIT_PER_BLOCK_RAW );

    for( uint32_t iterationCnt = 0u; waitCnt > iterationCnt; iterationCnt++ )
    {
        sAes_FunctionState_t doneState = sAes_Runtime.DmaInDone;

        if( SAES_FUNCTION_ACTIVE == outUsed )
        {
            doneState = sAes_Runtime.DmaOutDone;
        }
        else
        {
            /* Header phase: the input channel ends the chunk */
        }

        if( SAES_FUNCTION_ACTIVE == sAes_Runtime.DmaError )
        {
            retState = SAES_REQUEST_ERROR;
            break;
        }
        else if( SAES_FUNCTION_ACTIVE == doneState )
        {
            retState = SAES_REQUEST_OK;
            break;
        }
        else
        {
            /* The chunk is still being moved */
        }
    }

    if( ( SAES_REQUEST_OK        == retState ) &&
        ( SAES_FUNCTION_INACTIVE == outUsed  )    )
    {
        const sAes_RegWaitResult_t busyResult = SAes_Reg_Wait_BusyCleared();

        retState = SAes_Calc_RequestFromWait( busyResult );
    }
    else
    {
        /* Payload: the output channel read the last block, its processing is over */
    }

    if( SAES_REQUEST_OK == retState )
    {
        const sAes_XferError_t xferError = SAes_Reg_Get_XferError();

        if( SAES_XFER_ERROR_NONE != xferError )
        {
            sAes_Runtime.LastXferError = xferError;
            retState                   = SAES_REQUEST_ERROR;
        }
        else
        {
            /* No key / read-write / RNG error of the SAES */
        }
    }
    else
    {
        /* The chunk already failed */
    }

    return ( retState );
}


/**
 * \brief Transfer complete interrupt of the input channel of the DMA mode.
 */
static void SAes_DmaInCompleteIsr( void )
{
    sAes_Runtime.DmaInDone = SAES_FUNCTION_ACTIVE;
}


/**
 * \brief Transfer complete interrupt of the output channel of the DMA mode.
 */
static void SAes_DmaOutCompleteIsr( void )
{
    sAes_Runtime.DmaOutDone = SAES_FUNCTION_ACTIVE;
}


/**
 * \brief Error interrupt of both channels of the DMA mode: the running chunk fails.
 *
 * \param errMask [in]: Gpdma errors (not distinguished)
 */
static void SAes_DmaErrorIsr( gpdma_ErrorMaskId_t errMask )
{
    (void)errMask;

    sAes_Runtime.DmaError = SAES_FUNCTION_ACTIVE;
}

#endif /* SAES */
