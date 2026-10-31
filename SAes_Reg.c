/**
 * \author Mr.Nobody
 * \file SAes_Reg.c
 * \ingroup SAes
 * \brief SAes module Reg component functionality.
 *
 * Register access of the module. The registers (SAES_CR, SAES_SR, SAES_DINR, SAES_DOUTR,
 * SAES_KEYRx, SAES_IVRx, SAES_SUSPxR, SAES_IER, SAES_ISR, SAES_ICR) are written only here,
 * the masks come from the CMSIS device header (`AES_CR_...`, `AES_SR_...`, `AES_ISR_...`,
 * the CMSIS struct shared by AES and SAES, \ref SAes.h). Every multi-byte field (key, IV,
 * data block) is written / read MSB first, four 32-bit accesses per 16-byte block
 * (RM0481, section 38.8.3 - 38.8.16): this component converts the byte array given by the
 * caller to that register order and back, nothing else.
 *
 */
/* ============================== INCLUDES ================================== */
#include "SAes_Reg.h"                        /* Self include                   */
#include "SAes_Types.h"                      /* Module types definitions       */
#include "SAes.h"                            /* Register field raw values      */
#include "Stm32.h"                           /* SAES registers definition      */
/* ============================== TYPEDEFS ================================== */

#if defined(SAES)

/** \brief Structure type used to store physical address of SAES registers. */
typedef struct
{
    sAes_RegId_t        RegId;   /**< Peripheral register ID      */
    volatile uint32_t * RegAddr; /**< Peripheral register address */
}   sAes_RegList_t;

/* ======================== FORWARD DECLARATIONS ============================ */

static void SAes_Reg_Write_Word32Array( const sAes_RegId_t * const regIds,
                                        const uint8_t * const bytes,
                                        uint32_t wordCount );
static void SAes_Reg_Read_Word32Array ( const sAes_RegId_t * const regIds,
                                        uint8_t * const bytes,
                                        uint32_t wordCount );
static uint32_t SAes_Reg_Pack_Word32BigEndian  ( const uint8_t * const bytes );
static void     SAes_Reg_Unpack_Word32BigEndian( uint32_t word, uint8_t * const bytes );

/* ========================== SYMBOLIC CONSTANTS ============================ */

/** \brief Register value without any bit set (masked register value of an inactive bit field) */
#define SAES_REG_BITS_CLEAR              ( 0u )

/** \brief Byte width of one register word used for the key / IV / data accesses */
#define SAES_REG_BYTES_PER_WORD32        ( 4u )

/** \brief Word count of one 128-bit IV / 16-byte data block */
#define SAES_REG_IV_WORD_CNT             ( 4u )

/** \brief Word count of a 128-bit key */
#define SAES_REG_KEY128_WORD_CNT         ( 4u )

/** \brief Word count of a 256-bit key */
#define SAES_REG_KEY256_WORD_CNT         ( 8u )

/** \brief Word count of the full suspend register set */
#define SAES_REG_SUSPEND_WORD_CNT        ( 8u )

/* =============================== MACROS =================================== */

/* ========================== EXPORTED VARIABLES ============================ */

/* =========================== LOCAL VARIABLES ============================== */

/** \brief SAES registers configuration structure (reduces code size while referring to the registers) */
static const sAes_RegList_t sAes_RegList[] =
{
    { .RegId = SAES_REG_CR     , .RegAddr = &(SAES->CR     ) },
    { .RegId = SAES_REG_SR     , .RegAddr = &(SAES->SR     ) },
    { .RegId = SAES_REG_DINR   , .RegAddr = &(SAES->DINR   ) },
    { .RegId = SAES_REG_DOUTR  , .RegAddr = &(SAES->DOUTR  ) },
    { .RegId = SAES_REG_KEYR0  , .RegAddr = &(SAES->KEYR0  ) },
    { .RegId = SAES_REG_KEYR1  , .RegAddr = &(SAES->KEYR1  ) },
    { .RegId = SAES_REG_KEYR2  , .RegAddr = &(SAES->KEYR2  ) },
    { .RegId = SAES_REG_KEYR3  , .RegAddr = &(SAES->KEYR3  ) },
    { .RegId = SAES_REG_IVR0   , .RegAddr = &(SAES->IVR0   ) },
    { .RegId = SAES_REG_IVR1   , .RegAddr = &(SAES->IVR1   ) },
    { .RegId = SAES_REG_IVR2   , .RegAddr = &(SAES->IVR2   ) },
    { .RegId = SAES_REG_IVR3   , .RegAddr = &(SAES->IVR3   ) },
    { .RegId = SAES_REG_KEYR4  , .RegAddr = &(SAES->KEYR4  ) },
    { .RegId = SAES_REG_KEYR5  , .RegAddr = &(SAES->KEYR5  ) },
    { .RegId = SAES_REG_KEYR6  , .RegAddr = &(SAES->KEYR6  ) },
    { .RegId = SAES_REG_KEYR7  , .RegAddr = &(SAES->KEYR7  ) },
    { .RegId = SAES_REG_SUSP0R , .RegAddr = &(SAES->SUSP0R ) },
    { .RegId = SAES_REG_SUSP1R , .RegAddr = &(SAES->SUSP1R ) },
    { .RegId = SAES_REG_SUSP2R , .RegAddr = &(SAES->SUSP2R ) },
    { .RegId = SAES_REG_SUSP3R , .RegAddr = &(SAES->SUSP3R ) },
    { .RegId = SAES_REG_SUSP4R , .RegAddr = &(SAES->SUSP4R ) },
    { .RegId = SAES_REG_SUSP5R , .RegAddr = &(SAES->SUSP5R ) },
    { .RegId = SAES_REG_SUSP6R , .RegAddr = &(SAES->SUSP6R ) },
    { .RegId = SAES_REG_SUSP7R , .RegAddr = &(SAES->SUSP7R ) },
    { .RegId = SAES_REG_IER    , .RegAddr = &(SAES->IER    ) },
    { .RegId = SAES_REG_ISR    , .RegAddr = &(SAES->ISR    ) },
    { .RegId = SAES_REG_ICR    , .RegAddr = &(SAES->ICR    ) },
};

_Static_assert( (sizeof(sAes_RegList) / sizeof(sAes_RegList_t)) == SAES_REG_CNT,
                "SAes_Reg: sAes_RegList has incorrect size." );

/** \brief Key registers in the order the big-endian key bytes are written: the first 4 bytes (KEY[255:224], or
 *         KEY[127:96] of a 128-bit key, which starts at index 4) go to the highest register, the registers are
 *         written in descending order (RM0481 SAES key registers, Table 377) */
static const sAes_RegId_t saes_KeyRegsMsw[ SAES_REG_KEY256_WORD_CNT ] =
{
    SAES_REG_KEYR7, SAES_REG_KEYR6, SAES_REG_KEYR5, SAES_REG_KEYR4,
    SAES_REG_KEYR3, SAES_REG_KEYR2, SAES_REG_KEYR1, SAES_REG_KEYR0
};

/** \brief IV registers in the order the big-endian IV bytes are written: IVI[127:96] goes to SAES_IVR3
 *         (RM0481 SAES initialization vector registers, Table 378) */
static const sAes_RegId_t saes_IvRegsMsw[ SAES_REG_IV_WORD_CNT ] =
{
    SAES_REG_IVR3, SAES_REG_IVR2, SAES_REG_IVR1, SAES_REG_IVR0
};

/* ========================= EXPORTED FUNCTIONS ============================= */

/**
 * \brief Sets the register bit with given mask.
 *
 * \param regId   [in]: SAES register ID
 * \param bitMask [in]: Mask to apply to the register
 */
void SAes_Set_RegBit( sAes_RegId_t regId, uint32_t bitMask )
{
    if( SAES_REG_CNT > regId )
    {
        *sAes_RegList[regId].RegAddr |= bitMask;
    }
    else
    {
        /* Invalid register ID, no action required */
    }
}


/**
 * \brief Resets the register bit with given mask.
 *
 * \param regId   [in]: SAES register ID
 * \param bitMask [in]: Mask to apply to the register
 */
void SAes_Reset_RegBit( sAes_RegId_t regId, uint32_t bitMask )
{
    if( SAES_REG_CNT > regId )
    {
        *sAes_RegList[regId].RegAddr &= ~bitMask;
    }
    else
    {
        /* Invalid register ID, no action required */
    }
}


/**
 * \brief Gets the register bit value with given mask.
 *
 * \param regId   [in]: SAES register ID
 * \param bitMask [in]: Mask to apply to the register
 * \return Register bit value with applied mask, no bit set for invalid register ID
 */
uint32_t SAes_Get_RegBit( sAes_RegId_t regId, uint32_t bitMask )
{
    uint32_t retValue = SAES_REG_BITS_CLEAR;

    if( SAES_REG_CNT > regId )
    {
        retValue = ( *sAes_RegList[regId].RegAddr & bitMask );
    }
    else
    {
        /* Invalid register ID, no bit is set */
        retValue = SAES_REG_BITS_CLEAR;
    }

    return ( retValue );
}


/**
 * \brief Updates the register value with given mask and value.
 *
 * \param regId    [in]: SAES register ID
 * \param regMask  [in]: Mask to apply to the register
 * \param regValue [in]: Value to set in the register
 */
void SAes_Set_RegVal( sAes_RegId_t regId, uint32_t regMask, uint32_t regValue )
{
    if( SAES_REG_CNT > regId )
    {
        const uint32_t currentValue = *sAes_RegList[regId].RegAddr;
        const uint32_t updatedValue = ( ( currentValue & ~regMask ) | ( regValue & regMask ) );

        *sAes_RegList[regId].RegAddr = updatedValue;
    }
    else
    {
        /* Invalid register ID, no action required */
    }
}


/**
 * \brief Gets the register value with given mask.
 *
 * \param regId   [in]: SAES register ID
 * \param regMask [in]: Mask to apply to the register
 * \return Register value with applied mask, zero for invalid register ID
 */
uint32_t SAes_Get_RegVal( sAes_RegId_t regId, uint32_t regMask )
{
    uint32_t retValue = SAES_REG_BITS_CLEAR;

    if( SAES_REG_CNT > regId )
    {
        retValue = ( *sAes_RegList[regId].RegAddr & regMask );
    }
    else
    {
        /* Invalid register ID, no value is read */
        retValue = SAES_REG_BITS_CLEAR;
    }

    return ( retValue );
}


/**
 * \brief Enables the SAES peripheral and reads SAES_CR.EN back (rule 2.7 read-back).
 *
 * \return \ref SAES_REQUEST_OK if EN reads back set, \ref SAES_REQUEST_ERROR otherwise.
 */
sAes_RequestState_t SAes_Reg_Set_Enable( void )
{
    sAes_RequestState_t retState = SAES_REQUEST_ERROR;

    SAes_Set_RegBit( SAES_REG_CR, AES_CR_EN );

    const uint32_t enBit = SAes_Get_RegBit( SAES_REG_CR, AES_CR_EN );

    if( SAES_REG_BITS_CLEAR != enBit )
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
 * \brief Disables the SAES peripheral (SAES_CR.EN cleared).
 */
void SAes_Reg_Set_Disable( void )
{
    SAes_Reset_RegBit( SAES_REG_CR, AES_CR_EN );
}


/**
 * \brief Returns whether the SAES peripheral is currently enabled.
 *
 * \return \ref SAES_FUNCTION_ACTIVE if SAES_CR.EN is set, otherwise \ref SAES_FUNCTION_INACTIVE.
 */
sAes_FunctionState_t SAes_Reg_Get_EnableState( void )
{
    sAes_FunctionState_t retState = SAES_FUNCTION_INACTIVE;
    const uint32_t         enBit    = SAes_Get_RegBit( SAES_REG_CR, AES_CR_EN );

    if( SAES_REG_BITS_CLEAR != enBit )
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
 * \brief Returns the SAES_SR.BUSY flag.
 *
 * \return \ref SAES_FUNCTION_ACTIVE if BUSY is set, otherwise \ref SAES_FUNCTION_INACTIVE.
 */
sAes_FunctionState_t SAes_Reg_Get_BusyState( void )
{
    sAes_FunctionState_t retState = SAES_FUNCTION_INACTIVE;
    const uint32_t         busyBit  = SAes_Get_RegBit( SAES_REG_SR, AES_SR_BUSY );

    if( SAES_REG_BITS_CLEAR != busyBit )
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
 * \brief Returns the SAES_SR.KEYVALID flag.
 *
 * \return \ref SAES_FUNCTION_ACTIVE if KEYVALID is set, otherwise \ref SAES_FUNCTION_INACTIVE.
 */
sAes_FunctionState_t SAes_Reg_Get_KeyValidState( void )
{
    sAes_FunctionState_t retState = SAES_FUNCTION_INACTIVE;
    const uint32_t         validBit = SAes_Get_RegBit( SAES_REG_SR, AES_SR_KEYVALID );

    if( SAES_REG_BITS_CLEAR != validBit )
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
 * \brief Waits (bounded) until SAES_SR.KEYVALID is set or SAES_ISR.KEIF reports an error
 *        (RM0481, 38.8.2: hardware key loading sets BUSY then KEYVALID or KEIF).
 *
 * \return \ref SAES_REG_WAIT_OK, \ref SAES_REG_WAIT_HW_ERROR or \ref SAES_REG_WAIT_TIMEOUT.
 */
sAes_RegWaitResult_t SAes_Reg_Wait_KeyValid( void )
{
    sAes_RegWaitResult_t retResult = SAES_REG_WAIT_TIMEOUT;

    for( uint32_t iterationCnt = 0u; SAES_REG_TIMEOUT_RAW > iterationCnt; iterationCnt++ )
    {
        const uint32_t keifFlag     = SAes_Get_RegBit( SAES_REG_ISR, AES_ISR_KEIF    );
        const uint32_t keyValidFlag = SAes_Get_RegBit( SAES_REG_SR , AES_SR_KEYVALID );

        if( SAES_REG_BITS_CLEAR != keifFlag )
        {
            retResult = SAES_REG_WAIT_HW_ERROR;
            break;
        }
        else if( SAES_REG_BITS_CLEAR != keyValidFlag )
        {
            retResult = SAES_REG_WAIT_OK;
            break;
        }
        else
        {
            /* Still waiting for the key to be loaded */
            retResult = SAES_REG_WAIT_TIMEOUT;
        }
    }

    return ( retResult );
}


/**
 * \brief Waits (bounded) until SAES_ISR.CCF is set or a HW error flag is reported
 *        (RM0481, 38.8.19).
 *
 * \return \ref SAES_REG_WAIT_OK, \ref SAES_REG_WAIT_HW_ERROR or \ref SAES_REG_WAIT_TIMEOUT.
 */
sAes_RegWaitResult_t SAes_Reg_Wait_Ccf( void )
{
    sAes_RegWaitResult_t retResult = SAES_REG_WAIT_TIMEOUT;
    const uint32_t         errorMask = ( AES_ISR_KEIF | AES_ISR_RWEIF | AES_ISR_RNGEIF );

    for( uint32_t iterationCnt = 0u; SAES_REG_TIMEOUT_RAW > iterationCnt; iterationCnt++ )
    {
        const uint32_t isrReg = SAes_Get_RegVal( SAES_REG_ISR, ( AES_ISR_CCF | errorMask ) );

        if( SAES_REG_BITS_CLEAR != ( isrReg & errorMask ) )
        {
            retResult = SAES_REG_WAIT_HW_ERROR;
            break;
        }
        else if( AES_ISR_CCF == ( isrReg & AES_ISR_CCF ) )
        {
            retResult = SAES_REG_WAIT_OK;
            break;
        }
        else
        {
            /* Still waiting for the computation to complete */
            retResult = SAES_REG_WAIT_TIMEOUT;
        }
    }

    return ( retResult );
}


/**
 * \brief Waits (bounded) until SAES_SR.BUSY is cleared (RM0481, every sequence step 2:
 *        "wait until BUSY is cleared, no RNG random number fetch in progress").
 *
 * \return \ref SAES_REG_WAIT_OK or \ref SAES_REG_WAIT_TIMEOUT (no error flag applies here).
 */
sAes_RegWaitResult_t SAes_Reg_Wait_BusyCleared( void )
{
    sAes_RegWaitResult_t retResult = SAES_REG_WAIT_TIMEOUT;

    for( uint32_t iterationCnt = 0u; SAES_REG_TIMEOUT_RAW > iterationCnt; iterationCnt++ )
    {
        const sAes_FunctionState_t busyState = SAes_Reg_Get_BusyState();

        if( SAES_FUNCTION_INACTIVE == busyState )
        {
            retResult = SAES_REG_WAIT_OK;
            break;
        }
        else
        {
            /* Still busy (e.g. fetching a random number from the RNG) */
            retResult = SAES_REG_WAIT_TIMEOUT;
        }
    }

    return ( retResult );
}


/**
 * \brief Clears SAES_ISR.CCF (RM0481, 38.8.20).
 */
void SAes_Reg_Clear_Ccf( void )
{
    SAes_Set_RegBit( SAES_REG_ICR, AES_ICR_CCF );
}


/**
 * \brief Clears SAES_ISR.KEIF (RM0481, 38.8.20).
 */
void SAes_Reg_Clear_Keif( void )
{
    SAes_Set_RegBit( SAES_REG_ICR, AES_ICR_KEIF );
}


/**
 * \brief Clears SAES_ISR.RWEIF, also clears SAES_SR.RDERR / WRERR (RM0481, 38.8.20).
 */
void SAes_Reg_Clear_Rweif( void )
{
    SAes_Set_RegBit( SAES_REG_ICR, AES_ICR_RWEIF );
}


/**
 * \brief Clears SAES_ISR.RNGEIF (RM0481, 38.8.20).
 */
void SAes_Reg_Clear_Rngeif( void )
{
    SAes_Set_RegBit( SAES_REG_ICR, AES_ICR_RNGEIF );
}


/**
 * \brief Clears every SAES_ISR flag (CCF, KEIF, RWEIF, RNGEIF).
 */
void SAes_Reg_Clear_AllFlags( void )
{
    SAes_Reg_Clear_Ccf();
    SAes_Reg_Clear_Keif();
    SAes_Reg_Clear_Rweif();
    SAes_Reg_Clear_Rngeif();
}


/**
 * \brief Decodes the pending SAES_ISR error flags into one \ref sAes_XferError_t
 *        (priority: key error, then read/write error, then RNG error).
 *
 * \return The first pending error, \ref SAES_XFER_ERROR_NONE if none is pending.
 */
sAes_XferError_t SAes_Reg_Get_XferError( void )
{
    sAes_XferError_t retError = SAES_XFER_ERROR_NONE;
    const uint32_t     isrReg   = SAes_Get_RegVal( SAES_REG_ISR, ( AES_ISR_KEIF | AES_ISR_RWEIF | AES_ISR_RNGEIF ) );

    if( SAES_REG_BITS_CLEAR != ( isrReg & AES_ISR_KEIF ) )
    {
        retError = SAES_XFER_ERROR_KEY;
    }
    else if( SAES_REG_BITS_CLEAR != ( isrReg & AES_ISR_RWEIF ) )
    {
        retError = SAES_XFER_ERROR_RW;
    }
    else if( SAES_REG_BITS_CLEAR != ( isrReg & AES_ISR_RNGEIF ) )
    {
        retError = SAES_XFER_ERROR_RNG;
    }
    else
    {
        retError = SAES_XFER_ERROR_NONE;
    }

    return ( retError );
}


/**
 * \brief Writes a software key into SAES_KEYRx, MSB first (RM0481, 38.8.5 - 38.8.16).
 *
 * \param keyBytes [in]: Big-endian key bytes, 16 or 32 long
 * \param keySize  [in]: Selects whether 4 or 8 registers are written
 */
void SAes_Reg_Write_Key( const sAes_Data_t * const keyBytes, sAes_KeySize_t keySize )
{
    if( SAES_KEY_SIZE_256 == keySize )
    {
        SAes_Reg_Write_Word32Array( saes_KeyRegsMsw, keyBytes, SAES_REG_KEY256_WORD_CNT );
    }
    else
    {
        /* SAES_KEY_SIZE_128 (and any other value defaults to the 128-bit sequence) */
        SAes_Reg_Write_Word32Array( &saes_KeyRegsMsw[ SAES_REG_KEY256_WORD_CNT - SAES_REG_KEY128_WORD_CNT ],
                                    keyBytes,
                                    SAES_REG_KEY128_WORD_CNT );
    }
}


/**
 * \brief Writes the initialization vector into SAES_IVRx, MSB first (RM0481, 38.8.9 - 38.8.12).
 *
 * \param ivBytes [in]: 16-byte big-endian IV / counter block
 */
void SAes_Reg_Write_Iv( const sAes_Data_t * const ivBytes )
{
    SAes_Reg_Write_Word32Array( saes_IvRegsMsw, ivBytes, SAES_REG_IV_WORD_CNT );
}


/**
 * \brief Reads the current initialization vector back from SAES_IVRx, MSB first.
 *
 * \param ivBytes [out]: 16-byte big-endian IV / counter block
 */
void SAes_Reg_Read_Iv( sAes_Data_t * const ivBytes )
{
    SAes_Reg_Read_Word32Array( saes_IvRegsMsw, ivBytes, SAES_REG_IV_WORD_CNT );
}


/**
 * \brief Writes one 16-byte data block into SAES_DINR, MSB first (RM0481, 38.8.3).
 *
 * \param inBytes [in]: 16-byte big-endian input block
 */
void SAes_Reg_Write_Block( const sAes_Data_t * const inBytes )
{
    for( uint32_t wordIdx = 0u; SAES_BLOCK_WORDS > wordIdx; wordIdx++ )
    {
        const uint32_t byteOff = ( wordIdx * SAES_REG_BYTES_PER_WORD32 );
        const uint32_t word    = SAes_Reg_Pack_Word32BigEndian( &inBytes[byteOff] );

        SAes_Set_RegVal( SAES_REG_DINR, SAES_REG_FULL_MASK, word );
    }
}


/**
 * \brief Reads one 16-byte data block back from SAES_DOUTR, MSB first (RM0481, 38.8.4).
 *
 * \param outBytes [out]: 16-byte big-endian output block
 */
void SAes_Reg_Read_Block( sAes_Data_t * const outBytes )
{
    for( uint32_t wordIdx = 0u; SAES_BLOCK_WORDS > wordIdx; wordIdx++ )
    {
        const uint32_t byteOff = ( wordIdx * SAES_REG_BYTES_PER_WORD32 );
        const uint32_t word    = SAes_Get_RegVal( SAES_REG_DOUTR, SAES_REG_FULL_MASK );

        SAes_Reg_Unpack_Word32BigEndian( word, &outBytes[byteOff] );
    }
}


/**
 * \brief Saves the 8 SAES_SUSPxR registers (RM0481, 38.8.17, GCM/GMAC/CCM suspend/resume).
 *
 * \param suspendWords [out]: 8 raw register words, SUSP0R first
 */
void SAes_Reg_Read_Suspend( uint32_t * const suspendWords )
{
    for( uint32_t idx = 0u; SAES_REG_SUSPEND_WORD_CNT > idx; idx++ )
    {
        suspendWords[idx] = SAes_Get_RegVal( (sAes_RegId_t)( SAES_REG_SUSP0R + idx ), SAES_REG_FULL_MASK );
    }
}


/**
 * \brief Restores the 8 SAES_SUSPxR registers (RM0481, 38.8.17, GCM/GMAC/CCM suspend/resume).
 *
 * \param suspendWords [in]: 8 raw register words, SUSP0R first
 */
void SAes_Reg_Write_Suspend( const uint32_t * const suspendWords )
{
    for( uint32_t idx = 0u; SAES_REG_SUSPEND_WORD_CNT > idx; idx++ )
    {
        SAes_Set_RegVal( (sAes_RegId_t)( SAES_REG_SUSP0R + idx ), SAES_REG_FULL_MASK, suspendWords[idx] );
    }
}

/* ========================= LOCAL FUNCTIONS ================================= */

/**
 * \brief Writes a big-endian byte array as 32-bit registers, the first word to the first listed register.
 *
 * \param regIds    [in]: Registers in the order of the words (the most significant word first)
 * \param bytes     [in]: Big-endian byte array, wordCount * 4 bytes long
 * \param wordCount [in]: Count of 32-bit registers to write
 */
static void SAes_Reg_Write_Word32Array( const sAes_RegId_t * const regIds,
                                        const uint8_t * const bytes,
                                        uint32_t wordCount )
{
    for( uint32_t wordIdx = 0u; wordCount > wordIdx; wordIdx++ )
    {
        const uint32_t byteOff = ( wordIdx * SAES_REG_BYTES_PER_WORD32 );
        const uint32_t word    = SAes_Reg_Pack_Word32BigEndian( &bytes[byteOff] );

        SAes_Set_RegVal( regIds[ wordIdx ], SAES_REG_FULL_MASK, word );
    }
}


/**
 * \brief Reads 32-bit registers back as a big-endian byte array, the first listed register gives the first word.
 *
 * \param regIds    [in]:  Registers in the order of the words (the most significant word first)
 * \param bytes     [out]: Big-endian byte array, wordCount * 4 bytes long
 * \param wordCount [in]:  Count of 32-bit registers to read
 */
static void SAes_Reg_Read_Word32Array( const sAes_RegId_t * const regIds,
                                       uint8_t * const bytes,
                                       uint32_t wordCount )
{
    for( uint32_t wordIdx = 0u; wordCount > wordIdx; wordIdx++ )
    {
        const uint32_t byteOff = ( wordIdx * SAES_REG_BYTES_PER_WORD32 );
        const uint32_t word    = SAes_Get_RegVal( regIds[ wordIdx ], SAES_REG_FULL_MASK );

        SAes_Reg_Unpack_Word32BigEndian( word, &bytes[byteOff] );
    }
}


/**
 * \brief Packs 4 big-endian bytes into one 32-bit word, MSB first.
 *
 * \param bytes [in]: 4-byte big-endian array
 * \return The packed 32-bit word
 */
static uint32_t SAes_Reg_Pack_Word32BigEndian( const uint8_t * const bytes )
{
    uint32_t word = 0u;

    for( uint32_t byteIdx = 0u; SAES_REG_BYTES_PER_WORD32 > byteIdx; byteIdx++ )
    {
        const uint32_t shiftBits = ( ( SAES_REG_BYTES_PER_WORD32 - 1u - byteIdx ) * SAES_BITS_PER_BYTE );

        word |= ( (uint32_t)bytes[byteIdx] << shiftBits );
    }

    return ( word );
}


/**
 * \brief Unpacks one 32-bit word into 4 big-endian bytes, MSB first.
 *
 * \param word  [in]:  32-bit word to unpack
 * \param bytes [out]: 4-byte big-endian array
 */
static void SAes_Reg_Unpack_Word32BigEndian( uint32_t word, uint8_t * const bytes )
{
    for( uint32_t byteIdx = 0u; SAES_REG_BYTES_PER_WORD32 > byteIdx; byteIdx++ )
    {
        const uint32_t shiftBits = ( ( SAES_REG_BYTES_PER_WORD32 - 1u - byteIdx ) * SAES_BITS_PER_BYTE );

        bytes[byteIdx] = (uint8_t)( word >> shiftBits );
    }
}

#endif /* SAES */
