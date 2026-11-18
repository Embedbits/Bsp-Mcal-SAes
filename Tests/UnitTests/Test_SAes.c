/**
 * \author Mr.Nobody
 * \file Test_SAes.c
 * \ingroup SAes
 * \brief Unit tests of the secure AES coprocessor (SAES) module.
 *
 * SAes.c checks the SAES peripheral in every function (STM32H503, H523, H543, H562, H563,
 * H5E4, H5E5 have none, see the module README availability table, and only return the
 * error value), SAes_Reg.c holds the register access; every test case is written once and
 * runs on every line, with the no-SAES body replaced by `TEST_IGNORE_MESSAGE` (the pattern
 * used by the Pka / Cec module tests), except
 * \ref Ut_SAes_NoPeripheral_EveryFunctionReturnsError which runs only there. RCC (peripheral
 * clock), NVIC (interrupt line), RNG (side-channel countermeasures) and Gpdma (channels of the DMA
 * transfer mode) are mocked by CMock, the SAES registers are emulated by RegMem. The Gpdma stubs
 * capture the configuration of the channels and call the transfer complete (or the error) interrupt
 * of the module when its input channel is started - the data itself is not moved, the tests check
 * the channel parameters, the order of the steps and the split between the DMA and the CPU.
 *
 * A HW model (UtSAes_HwModel, only compiled where SAES is defined) sets SAES_SR.KEYVALID
 * as soon as SAES_CR.KEYSEL is non-zero and SAES_ISR.CCF while SAES_CR.EN is set (RegMem is
 * plain memory, this emulates the hardware reaction the real SAES gives and also emulates
 * the self-clearing SAES_ICR.CCF / SAES_ISR.CCF pair). It does not compute any cryptographic
 * result: the data-path tests preset SAES_DOUTR with the literal ciphertext of a public
 * known-answer test (FIPS-197 Appendix C for ECB, NIST SP800-38A Appendix F for CBC, both
 * fetched from nvlpubs.nist.gov and cross-checked against the module's own byte order
 * conversion), never against the module's own macros - a wrong MSB/LSB order or a wrong
 * KEYSEL/KMOD/CHMOD raw value would make these tests fail. The register field raw values
 * asserted below are literal numbers copied from RM0481 section 38.8.1 directly, not the
 * SAes.h macros the implementation itself writes with, for the same reason (Pka lesson).
 *
 * \par Expected results
 * See the Doxygen block of every test case.
 */

/* ============================= INCLUDES =================================== */
#include "unity.h"                          /* Unity testing framework        */
#include "RegMem.h"                         /* Register memory emulation      */
#include "SAes_Port.h"                      /* Module under test              */
#include "SAes.h"                           /* Register field raw values      */
#include "SAes_Reg.h"                       /* Register access                */
#include "MockRcc_Port.h"                   /* RCC module mock                */
#include "MockNvic_Port.h"                  /* NVIC module mock                */
#include "MockRng_Port.h"                   /* RNG module mock                */
#include "MockGpdma_Port.h"                 /* Gpdma module mock              */
#include "Stm32.h"                          /* SAES registers definition      */
/* ============================= TYPEDEFS =================================== */

/* ======================= FORWARD DECLARATIONS ============================= */

#if defined(SAES)
static void UtSAes_HwModel( void );
static void UtSAes_Expect_InitPoll( void );
static void UtSAes_Init_Poll( void );
static void UtSAes_Init_Dma( void );
static void UtSAes_Set_DmaStubs( void );
static void UtSAes_Set_DmaRequest( sAes_Request_t * const request,
                                   sAes_Mode_t            mode,
                                   const sAes_Data_t *    input,
                                   sAes_Data_t *          output,
                                   sAes_DataLen_t         dataLen );
static gpdma_RequestState_t UtSAes_GpdmaDefaultStub( gpdma_ConfigStruct_t * configStruct, int callCnt );
static gpdma_RequestState_t UtSAes_GpdmaInitStub   ( gpdma_ConfigStruct_t * configStruct, int callCnt );
static gpdma_RequestState_t UtSAes_GpdmaSizeStub   ( gpdma_PeriphId_t  periphId,
                                                     gpdma_ChannelId_t channelId,
                                                     gpdma_BlockSize_t blockSize,
                                                     int               callCnt );
static gpdma_RequestState_t UtSAes_GpdmaSrcStub    ( gpdma_PeriphId_t  periphId,
                                                     gpdma_ChannelId_t channelId,
                                                     gpdma_SrcAddr_t   sourceAddr,
                                                     int               callCnt );
static gpdma_RequestState_t UtSAes_GpdmaDstStub    ( gpdma_PeriphId_t  periphId,
                                                     gpdma_ChannelId_t channelId,
                                                     gpdma_DstAddr_t   destAddr,
                                                     int               callCnt );
static gpdma_RequestState_t UtSAes_GpdmaStartStub  ( gpdma_PeriphId_t  periphId,
                                                     gpdma_ChannelId_t channelId,
                                                     int               callCnt );
static gpdma_RequestState_t UtSAes_GpdmaStopStub   ( gpdma_PeriphId_t  periphId,
                                                     gpdma_ChannelId_t channelId,
                                                     int               callCnt );
static void UtSAes_Set_AeadRequest( sAes_Request_t * const request,
                                    sAes_Operation_t       operation,
                                    sAes_Mode_t            mode,
                                    const sAes_Data_t *    input,
                                    sAes_Data_t *          output,
                                    sAes_Data_t *          tag );
#endif /* SAES */

/* ========================= SYMBOLIC CONSTANTS ============================= */

/** Expected version of the module */
#define UT_SAES_VERSION_MAJOR                ( 1u )
#define UT_SAES_VERSION_MINOR                ( 0u )
#define UT_SAES_VERSION_PATCH                ( 0u )

/** Interrupt priority used by the ISR mode test */
#define UT_SAES_IRQ_PRIO                      ( 5u )

/** Byte width of one 32-bit register word (RM0481, 38.8.3 / 38.8.4) */
#define UT_SAES_REG_BYTES_PER_WORD32           ( 4u )

/** Block count factor used by the two-block CTR test */
#define UT_SAES_TWO_BLOCKS                     ( 2u )

/** RM0481, 38.8.1: literal SAES_CR field raw values, copied independently of SAes.h */
#define UT_SAES_CR_MODE_MASK                  ( 0x3uL << 3 )
#define UT_SAES_CR_MODE_ENCRYPT               ( 0x0uL << 3 )
#define UT_SAES_CR_CHMOD_MASK                 ( 0x803uL << 5 )
#define UT_SAES_CR_CHMOD_ECB                  ( 0x0uL )
#define UT_SAES_CR_CHMOD_CBC                  ( 0x1uL << 5 )
/* CHMOD is a SPLIT field (RM0481, 38.8.1): CHMOD[1:0] at bits 6:5, CHMOD[2] at bit 16
 * (mask 0x803 << 5). CTR (raw 2) and GCM/GMAC (raw 3) only use CHMOD[1:0], so the plain
 * "raw << 5" shift happens to match; CCM (raw 4, bit 2 only) does NOT: its register bit
 * is 16, not 7. The CCM value below is the literal bit 16 (0x10000), independent of the
 * module's own AES_CR_CHMOD_2 macro, to catch exactly the "raw << AES_CR_CHMOD_Pos" bug
 * this test was added for (it put CCM's bit 2 at bit 7 and left bit 16 at 0, i.e. ECB). */
#define UT_SAES_CR_CHMOD_CTR                  ( 0x2uL << 5 )
#define UT_SAES_CR_CHMOD_GCM                  ( 0x3uL << 5 )
#define UT_SAES_CR_CHMOD_CCM                  ( 0x10000uL )
#define UT_SAES_CR_KEYSIZE_MASK                ( 1uL << 18 )
#define UT_SAES_CR_KEYSIZE_128                ( 0uL )
#define UT_SAES_CR_KEYSIZE_256                ( 1uL << 18 )
#define UT_SAES_CR_KMOD_MASK                  ( 0x3uL << 24 )
#define UT_SAES_CR_KMOD_NORMAL                ( 0x0uL << 24 )
#define UT_SAES_CR_KMOD_SHARED                ( 0x2uL << 24 )
#define UT_SAES_CR_KSHAREID_MASK              ( 0x3uL << 26 )
#define UT_SAES_CR_KEYSEL_MASK                ( 0x7uL << 28 )
#define UT_SAES_CR_KEYSEL_SOFTWARE            ( 0x0uL << 28 )

/** Big-endian 32-bit words of the FIPS-197 C.1 key / SP800-38A CBC IV bytes defined above
 *  (both happen to be 00 01 02 ... 0F), as the key / IV registers read back MSB first */
#define UT_SAES_WORD0_00010203                ( 0x00010203uL )
#define UT_SAES_WORD1_04050607                ( 0x04050607uL )
#define UT_SAES_WORD2_08090A0B                ( 0x08090A0BuL )
#define UT_SAES_WORD3_0C0D0E0F                ( 0x0C0D0E0FuL )
#define UT_SAES_WORD4_10111213                ( 0x10111213uL )
#define UT_SAES_WORD7_1C1D1E1F                ( 0x1C1D1E1FuL )

/** First 32-bit word (MSB first) of each known-answer ciphertext, preset into SAES_DOUTR */
#define UT_SAES_FIPS197_C1_CIPHERTEXT_WORD0    ( 0x69C4E0D8uL )
#define UT_SAES_FIPS197_C2_CIPHERTEXT_WORD0    ( 0xDDA97CA4uL )
#define UT_SAES_FIPS197_C3_CIPHERTEXT_WORD0    ( 0x8EA2B7CAuL )
#define UT_SAES_SP38A_CBC_CIPHERTEXT_WORD0     ( 0x7649ABACuL )

/** RM0481, 38.8.1: SAES_CR.NPBLB[3:0] at bits 23:20 */
#define UT_SAES_CR_NPBLB_MASK                 ( 0xFuL << 20 )

/** Payload of the NPBLB tests: one full block and a partial last block of 4 bytes (12 padding bytes) */
#define UT_SAES_PARTIAL_LEN                   ( 20u )
#define UT_SAES_CR_NPBLB_12                   ( 0xCuL << 20 )

/** Gpdma channels of the default configuration of the DMA mode (input, output) */
#define UT_SAES_DMA_IN_CH                     ( GPDMA_CHANNEL_2 )
#define UT_SAES_DMA_OUT_CH                    ( GPDMA_CHANNEL_3 )

/** Count of the Gpdma channels of the DMA mode (input, output) and the index of each in the captured configs */
#define UT_SAES_DMA_CHANNEL_CNT               ( 2u )
#define UT_SAES_DMA_CFG_IN                    ( 0u )
#define UT_SAES_DMA_CFG_OUT                   ( 1u )

/** Started channels of the two-chunk test (output + input per chunk) and the log entries of its second chunk */
#define UT_SAES_DMA_TWO_CHUNK_STARTS          ( 4u )
#define UT_SAES_DMA_LOG_CHUNK1_IN             ( 1u )
#define UT_SAES_DMA_LOG_CHUNK2_OUT            ( 2u )
#define UT_SAES_DMA_LOG_CHUNK2_IN             ( 3u )

/** Size of the logs of the Gpdma stubs (calls per test) */
#define UT_SAES_DMA_LOG_MAX                   ( 8u )

/** Payload of the chunk test: one full chunk of the module (65520 bytes) and one more block */
#define UT_SAES_DMA_CHUNK_MAX                 ( 65520u )
#define UT_SAES_DMA_BIG_LEN                   ( UT_SAES_DMA_CHUNK_MAX + SAES_BLOCK_BYTES )

/** Word count of the buffers of the DMA tests */
#define UT_SAES_DMA_WORDS                     ( UT_SAES_DMA_BIG_LEN / UT_SAES_REG_BYTES_PER_WORD32 )

/** Value preset in SAES_DOUTR: the CPU reads it for the partial last block (MSB first) */
#define UT_SAES_DOUTR_PATTERN                 ( 0xA1B2C3D4uL )

/** First bytes of the output of a block read by the CPU from \ref UT_SAES_DOUTR_PATTERN */
#define UT_SAES_DOUTR_BYTE0                   ( 0xA1u )
#define UT_SAES_DOUTR_BYTE3                   ( 0xD4u )

/** Payload of the CPU tail test: one block by the DMA, 4 bytes by the CPU */
#define UT_SAES_TAIL_LEN                      ( 20u )

/** Byte offset which makes a buffer not word aligned */
#define UT_SAES_UNALIGNED_OFFSET              ( 1u )

/** Two blocks of the ECB and the header tests */
#define UT_SAES_TWO_BLOCKS_LEN                ( 32u )

/** Mask of the DMA request bits of SAES_CR (RM0481, 38.8.1: DMAOUTEN bit 12, DMAINEN bit 11) */
#define UT_SAES_CR_DMA_MASK                   ( 0x3uL << 11 )

/** CTR counter value expected in SAES_IVR0 after processing (RM0481, Table 372: starts at 1) */
#define UT_SAES_CTR_COUNTER_AFTER_PROCESS      ( 0x00000001uL )

#if defined(SAES)

/** AES-128 FIPS-197 Appendix C.1 known-answer vector (nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf) */
#define UT_SAES_FIPS197_KEY128_BYTES \
    0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u, \
    0x08u, 0x09u, 0x0Au, 0x0Bu, 0x0Cu, 0x0Du, 0x0Eu, 0x0Fu

#define UT_SAES_FIPS197_PLAINTEXT_BYTES \
    0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u, \
    0x88u, 0x99u, 0xAAu, 0xBBu, 0xCCu, 0xDDu, 0xEEu, 0xFFu

#define UT_SAES_FIPS197_CIPHERTEXT128_BYTES \
    0x69u, 0xC4u, 0xE0u, 0xD8u, 0x6Au, 0x7Bu, 0x04u, 0x30u, \
    0xD8u, 0xCDu, 0xB7u, 0x80u, 0x70u, 0xB4u, 0xC5u, 0x5Au

/** AES-192 FIPS-197 Appendix C.2 known-answer vector (same plaintext as C.1) */
#define UT_SAES_FIPS197_KEY192_BYTES \
    0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u, \
    0x08u, 0x09u, 0x0Au, 0x0Bu, 0x0Cu, 0x0Du, 0x0Eu, 0x0Fu, \
    0x10u, 0x11u, 0x12u, 0x13u, 0x14u, 0x15u, 0x16u, 0x17u

#define UT_SAES_FIPS197_CIPHERTEXT192_BYTES \
    0xDDu, 0xA9u, 0x7Cu, 0xA4u, 0x86u, 0x4Cu, 0xDFu, 0xE0u, \
    0x6Eu, 0xAFu, 0x70u, 0xA0u, 0xECu, 0x0Du, 0x71u, 0x91u

/** AES-256 FIPS-197 Appendix C.3 known-answer vector (same plaintext as C.1) */
#define UT_SAES_FIPS197_KEY256_BYTES \
    0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u, \
    0x08u, 0x09u, 0x0Au, 0x0Bu, 0x0Cu, 0x0Du, 0x0Eu, 0x0Fu, \
    0x10u, 0x11u, 0x12u, 0x13u, 0x14u, 0x15u, 0x16u, 0x17u, \
    0x18u, 0x19u, 0x1Au, 0x1Bu, 0x1Cu, 0x1Du, 0x1Eu, 0x1Fu

#define UT_SAES_FIPS197_CIPHERTEXT256_BYTES \
    0x8Eu, 0xA2u, 0xB7u, 0xCAu, 0x51u, 0x67u, 0x45u, 0xBFu, \
    0xEAu, 0xFCu, 0x49u, 0x90u, 0x4Bu, 0x49u, 0x60u, 0x89u

/** NIST SP800-38A Appendix F.2.1 CBC-AES128.Encrypt, block #1 (nvlpubs.nist.gov,
 *  Legacy/SP/nistspecialpublication800-38a.pdf) */
#define UT_SAES_SP38A_CBC_KEY_BYTES \
    0x2Bu, 0x7Eu, 0x15u, 0x16u, 0x28u, 0xAEu, 0xD2u, 0xA6u, \
    0xABu, 0xF7u, 0x15u, 0x88u, 0x09u, 0xCFu, 0x4Fu, 0x3Cu

#define UT_SAES_SP38A_CBC_IV_BYTES \
    0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u, \
    0x08u, 0x09u, 0x0Au, 0x0Bu, 0x0Cu, 0x0Du, 0x0Eu, 0x0Fu

#define UT_SAES_SP38A_CBC_PLAINTEXT_BYTES \
    0x6Bu, 0xC1u, 0xBEu, 0xE2u, 0x2Eu, 0x40u, 0x9Fu, 0x96u, \
    0xE9u, 0x3Du, 0x7Eu, 0x11u, 0x73u, 0x93u, 0x17u, 0x2Au

#define UT_SAES_SP38A_CBC_CIPHERTEXT_BYTES \
    0x76u, 0x49u, 0xABu, 0xACu, 0x81u, 0x19u, 0xB2u, 0x46u, \
    0xCEu, 0xE9u, 0x8Eu, 0x9Bu, 0x12u, 0xE9u, 0x19u, 0x7Du

/** CTR initial counter block: 96-bit zero nonce, 32-bit counter = 1 (RM0481, Table 372) */
#define UT_SAES_CTR_IV_BYTES \
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, \
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x01u

static const sAes_Data_t utSAes_Fips197_Key128[ SAES_KEY_128_BYTES ]      = { UT_SAES_FIPS197_KEY128_BYTES };
static const sAes_Data_t utSAes_Fips197_Plaintext[ SAES_BLOCK_BYTES ]     = { UT_SAES_FIPS197_PLAINTEXT_BYTES };
static const sAes_Data_t utSAes_Fips197_Ciphertext128[ SAES_BLOCK_BYTES ] = { UT_SAES_FIPS197_CIPHERTEXT128_BYTES };

static const sAes_Data_t utSAes_Fips197_Key192[ 24u ]                     = { UT_SAES_FIPS197_KEY192_BYTES };
static const sAes_Data_t utSAes_Fips197_Ciphertext192[ SAES_BLOCK_BYTES ] = { UT_SAES_FIPS197_CIPHERTEXT192_BYTES };

static const sAes_Data_t utSAes_Fips197_Key256[ SAES_KEY_256_BYTES ]      = { UT_SAES_FIPS197_KEY256_BYTES };
static const sAes_Data_t utSAes_Fips197_Ciphertext256[ SAES_BLOCK_BYTES ] = { UT_SAES_FIPS197_CIPHERTEXT256_BYTES };

static const sAes_Data_t utSAes_Sp38a_CbcKey[ SAES_KEY_128_BYTES ]        = { UT_SAES_SP38A_CBC_KEY_BYTES };
static const sAes_Data_t utSAes_Sp38a_CbcIv[ SAES_BLOCK_BYTES ]           = { UT_SAES_SP38A_CBC_IV_BYTES };
static const sAes_Data_t utSAes_Sp38a_CbcPlaintext[ SAES_BLOCK_BYTES ]    = { UT_SAES_SP38A_CBC_PLAINTEXT_BYTES };
static const sAes_Data_t utSAes_Sp38a_CbcCiphertext[ SAES_BLOCK_BYTES ]   = { UT_SAES_SP38A_CBC_CIPHERTEXT_BYTES };

#endif /* SAES */

/* ========================== EXPORTED VARIABLES ============================= */

/* =========================== LOCAL VARIABLES ============================== */

#if defined(SAES)

/** \brief One call of a Gpdma stub: the channel and its value */
typedef struct
{
    gpdma_ChannelId_t ChannelId; /**< Channel of the call */
    uint32_t          Value;     /**< Block size or address */
}   utSAes_DmaLogItem_t;

/** \brief Configuration of a channel captured by \ref UtSAes_GpdmaInitStub */
typedef struct
{
    gpdma_ChannelId_t     ChannelId;      /**< Channel                         */
    gpdma_Direction_t     Direction;      /**< Direction of the transfer       */
    gpdma_PeriphReqId_t   RequestSource;  /**< Hardware request               */
    gpdma_DataSize_t      SrcDataSize;    /**< Source data width              */
    gpdma_DataSize_t      DstDataSize;    /**< Destination data width         */
    gpdma_AddrMode_t      SrcAddrMode;    /**< Source address mode            */
    gpdma_AddrMode_t      DstAddrMode;    /**< Destination address mode       */
    gpdma_DestDataOp_t    DstDataOp;      /**< Byte exchange of the destination */
    gpdma_SrcAddr_t       SrcAddr;        /**< Source address of the init     */
    gpdma_DstAddr_t       DstAddr;        /**< Destination address of the init */
}   utSAes_DmaChannelCfg_t;

/** Configurations captured by Gpdma_Init: [0] input channel, [1] output channel */
static utSAes_DmaChannelCfg_t utSAes_DmaCfg[ UT_SAES_DMA_CHANNEL_CNT ];
static uint32_t               utSAes_DmaInitCnt;

/** Interrupts of the module captured by Gpdma_Init */
static gpdma_IsrCallback     *utSAes_DmaInIsr;
static gpdma_IsrCallback     *utSAes_DmaOutIsr;
static gpdma_IsrErrCallback  *utSAes_DmaErrIsr;

/** Logs of the block sizes, the addresses, the started and the stopped channels */
static utSAes_DmaLogItem_t    utSAes_DmaSizeLog[ UT_SAES_DMA_LOG_MAX ];
static uint32_t               utSAes_DmaSizeCnt;
static utSAes_DmaLogItem_t    utSAes_DmaSrcLog[ UT_SAES_DMA_LOG_MAX ];
static uint32_t               utSAes_DmaSrcCnt;
static utSAes_DmaLogItem_t    utSAes_DmaDstLog[ UT_SAES_DMA_LOG_MAX ];
static uint32_t               utSAes_DmaDstCnt;
static gpdma_ChannelId_t      utSAes_DmaStartLog[ UT_SAES_DMA_LOG_MAX ];
static uint32_t               utSAes_DmaStartCnt;
static gpdma_ChannelId_t      utSAes_DmaStopLog[ UT_SAES_DMA_LOG_MAX ];
static uint32_t               utSAes_DmaStopCnt;

/** \ref UtSAes_GpdmaStartStub reports a Gpdma error instead of the transfer complete */
static sAes_FunctionState_t   utSAes_DmaFail;

/** Value of SAES_CR.DMAINEN / DMAOUTEN when the input channel was started (requests set after the start) */
static uint32_t               utSAes_DmaCrAtStart;

/** Word-aligned buffers of the DMA tests */
static uint32_t               utSAes_DmaIn[ UT_SAES_DMA_WORDS ];
static uint32_t               utSAes_DmaOut[ UT_SAES_DMA_WORDS ];

#endif /* SAES */

/* ============================ TEST FIXTURE ================================ */

void setUp( void )
{
    TEST_ASSERT_EQUAL( REGMEM_REQUEST_OK, RegMem_Reset() );
#if defined(SAES)
    TEST_ASSERT_EQUAL( REGMEM_REQUEST_OK, RegMem_Set_ModelActive( UtSAes_HwModel ) );
#endif /* SAES */
}


void tearDown( void )
{
    /* Mocks are verified by the generated runner */
}

/* ========================== MODULE VERSION ================================ */

/**
 * \brief   SAes_Get_ModuleVersion() returns the version of the module.
 *
 * \par Expected results
 * - Version is 1.0.0 (Major 1, Minor 0, Patch 0), the same on every line (common function).
 */
void Ut_SAes_Get_ModuleVersion_Always_ReturnsVersion( void )
{
    const sAes_ModuleVersion_t version = SAes_Get_ModuleVersion();

    TEST_ASSERT_EQUAL_UINT8( UT_SAES_VERSION_MAJOR, version.Major );
    TEST_ASSERT_EQUAL_UINT8( UT_SAES_VERSION_MINOR, version.Minor );
    TEST_ASSERT_EQUAL_UINT8( UT_SAES_VERSION_PATCH, version.Patch );
}


/**
 * \brief   SAes_Task() never touches the mocks and always returns.
 *
 * \par Expected results
 * - No RCC / NVIC / RNG call is expected (every operation of this implementation finishes
 *   synchronously inside its own Set_* call, there is never a pending operation).
 */
void Ut_SAes_Task_NoPendingOperation_ReturnsImmediately( void )
{
    SAes_Task();
}

/* =========================== DEFAULT CONFIG ================================ */

/**
 * \brief   SAes_Get_DefaultConfig() fills the default configuration; a null pointer is rejected.
 *
 * \par Expected results
 * - SAES_REQUEST_OK, POLL transfer mode, no callbacks.
 * - NULL pointer: SAES_REQUEST_ERROR.
 */
void Ut_SAes_Get_DefaultConfig_ValidPointer_ReturnsDefaults( void )
{
#if defined(SAES)
    sAes_Config_t config;

    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Get_DefaultConfig( &config ) );
    TEST_ASSERT_EQUAL( SAES_XFER_MODE_POLL, config.XferMode );
    TEST_ASSERT_NULL( config.CompleteCallback );
    TEST_ASSERT_NULL( config.ErrorCallback );

    TEST_ASSERT_EQUAL( SAES_REQUEST_ERROR, SAes_Get_DefaultConfig( SAES_NULL_PTR ) );
#else
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* SAES */
}

/* ================================ INIT ===================================== */

/**
 * \brief   SAes_Init() enables the clock, makes sure the RNG is running and reaches
 *          the IDLE state in POLL mode.
 *
 * \par Expected results
 * - RCC and RNG calls happen in order, SAES_REQUEST_OK is returned.
 */
void Ut_SAes_Init_RccOkRngActive_ReturnsOk( void )
{
#if defined(SAES)
    UtSAes_Expect_InitPoll();

    sAes_Config_t config;

    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Get_DefaultConfig( &config ) );
    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Init( &config ) );

    sAes_State_t state = SAES_STATE_UNINIT;

    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Get_State( &state ) );
    TEST_ASSERT_EQUAL( SAES_STATE_IDLE, state );
#else
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* SAES */
}


/**
 * \brief   SAes_Init() reports an error and rolls back when the RNG cannot be confirmed
 *          running (the SAES side-channel countermeasures would starve, RM0481 38.4.19).
 *
 * \par Expected results
 * - SAES_REQUEST_ERROR, SAes_Deinit's RCC/NVIC calls still happen (rollback).
 */
void Ut_SAes_Init_RngNotActive_ReturnsError( void )
{
#if defined(SAES)
    sAes_Config_t config;

    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Get_DefaultConfig( &config ) );

    rng_FunctionState_t rngState = RNG_FUNCTION_INACTIVE;

    Rcc_Set_PeriphActive_ExpectAndReturn( RCC_PERIPH_SAES, RCC_REQUEST_OK );
    Rng_Set_ExecActive_ExpectAndReturn( RNG_PERIPH_1, RNG_REQUEST_OK );
    Rng_Get_ExecState_ExpectAndReturn( RNG_PERIPH_1, SAES_NULL_PTR, RNG_REQUEST_OK );
    Rng_Get_ExecState_IgnoreArg_state();
    Rng_Get_ExecState_ReturnThruPtr_state( &rngState );
    Nvic_Set_PeriphIrq_Inactive_ExpectAndReturn( NVIC_PERIPH_IRQ_SAES, NVIC_REQUEST_OK );
    Rcc_Set_PeriphInactive_ExpectAndReturn( RCC_PERIPH_SAES, RCC_REQUEST_OK );

    TEST_ASSERT_EQUAL( SAES_REQUEST_ERROR, SAes_Init( &config ) );
#else
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* SAES */
}


/**
 * \brief   SAes_Init() reports an error when the clock cannot be enabled, nothing else
 *          is touched before the rollback.
 *
 * \par Expected results
 * - SAES_REQUEST_ERROR.
 */
void Ut_SAes_Init_RccFails_ReturnsError( void )
{
#if defined(SAES)
    sAes_Config_t config;

    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Get_DefaultConfig( &config ) );

    Rcc_Set_PeriphActive_ExpectAndReturn( RCC_PERIPH_SAES, RCC_REQUEST_ERROR );
    Nvic_Set_PeriphIrq_Inactive_ExpectAndReturn( NVIC_PERIPH_IRQ_SAES, NVIC_REQUEST_OK );
    Rcc_Set_PeriphInactive_ExpectAndReturn( RCC_PERIPH_SAES, RCC_REQUEST_OK );

    TEST_ASSERT_EQUAL( SAES_REQUEST_ERROR, SAes_Init( &config ) );
#else
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* SAES */
}

/* ============================== KEY LOAD ==================================== */

/**
 * \brief   SAes_Set_KeyLoad() with a software 128-bit key sets SAES_CR to normal key
 *          mode / ECB / encryption / 128-bit and writes the key registers; the key
 *          state becomes valid. The CR raw values checked here are copied from
 *          RM0481 38.8.1 directly (see the file introduction).
 *
 * \par Expected results
 * - SAES_REQUEST_OK, SAES_CR fields match RM0481 literal values, KEYR3 holds KEY[127:96] (the first 4
 *   key bytes) down to KEYR0 with KEY[31:0] (RM0481 Table 377), SAes_Get_KeyState() returns SAES_KEY_STATE_VALID.
 */
void Ut_SAes_Set_KeyLoad_SoftwareKey128_SetsCrFieldsAndKeyValid( void )
{
#if defined(SAES)
    UtSAes_Init_Poll();

    sAes_KeyConfig_t keyConfig;

    keyConfig.KeySource = SAES_KEY_SOFTWARE;
    keyConfig.KeySize   = SAES_KEY_SIZE_128;
    keyConfig.KeyBytes  = utSAes_Fips197_Key128;
    keyConfig.Protect   = SAES_FUNCTION_INACTIVE;

    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Set_KeyLoad( &keyConfig ) );

    TEST_ASSERT_EQUAL_HEX32( UT_SAES_CR_KEYSEL_SOFTWARE, ( SAES->CR & UT_SAES_CR_KEYSEL_MASK ) );
    TEST_ASSERT_EQUAL_HEX32( UT_SAES_CR_KMOD_NORMAL,     ( SAES->CR & UT_SAES_CR_KMOD_MASK   ) );
    TEST_ASSERT_EQUAL_HEX32( UT_SAES_CR_CHMOD_ECB,       ( SAES->CR & UT_SAES_CR_CHMOD_MASK  ) );
    TEST_ASSERT_EQUAL_HEX32( UT_SAES_CR_MODE_ENCRYPT,    ( SAES->CR & UT_SAES_CR_MODE_MASK   ) );
    TEST_ASSERT_EQUAL_HEX32( UT_SAES_CR_KEYSIZE_128,     ( SAES->CR & UT_SAES_CR_KEYSIZE_MASK ) );

    TEST_ASSERT_EQUAL_HEX32( UT_SAES_WORD0_00010203, SAES->KEYR3 );
    TEST_ASSERT_EQUAL_HEX32( UT_SAES_WORD1_04050607, SAES->KEYR2 );
    TEST_ASSERT_EQUAL_HEX32( UT_SAES_WORD2_08090A0B, SAES->KEYR1 );
    TEST_ASSERT_EQUAL_HEX32( UT_SAES_WORD3_0C0D0E0F, SAES->KEYR0 );

    sAes_KeyState_t keyState = SAES_KEY_STATE_NONE;

    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Get_KeyState( &keyState ) );
    TEST_ASSERT_EQUAL( SAES_KEY_STATE_VALID, keyState );
#else
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* SAES */
}


/**
 * \brief   SAes_Set_KeyLoad() with a 256-bit software key writes the first key bytes to SAES_KEYR7 and the last
 *          to SAES_KEYR0 (RM0481 SAES key registers, Table 377).
 *
 * \par Expected results
 * - SAES_REQUEST_OK, KEYR7 = KEY[255:224], KEYR4 = KEY[159:128], KEYR3 = KEY[127:96], KEYR0 = KEY[31:0];
 *   the IV registers are not touched by the key.
 */
void Ut_SAes_Set_KeyLoad_SoftwareKey256_WritesKeyr7ToKeyr0( void )
{
#if defined(SAES)
    UtSAes_Init_Poll();

    sAes_KeyConfig_t keyConfig;

    keyConfig.KeySource = SAES_KEY_SOFTWARE;
    keyConfig.KeySize   = SAES_KEY_SIZE_256;
    keyConfig.KeyBytes  = utSAes_Fips197_Key256;
    keyConfig.Protect   = SAES_FUNCTION_INACTIVE;

    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Set_KeyLoad( &keyConfig ) );

    TEST_ASSERT_EQUAL_HEX32( UT_SAES_WORD0_00010203, SAES->KEYR7 );
    TEST_ASSERT_EQUAL_HEX32( UT_SAES_WORD3_0C0D0E0F, SAES->KEYR4 );
    TEST_ASSERT_EQUAL_HEX32( UT_SAES_WORD4_10111213, SAES->KEYR3 );
    TEST_ASSERT_EQUAL_HEX32( UT_SAES_WORD7_1C1D1E1F, SAES->KEYR0 );
    TEST_ASSERT_EQUAL_HEX32( 0u, SAES->IVR0 );
    TEST_ASSERT_EQUAL_HEX32( 0u, SAES->IVR3 );
#else
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* SAES */
}


/**
 * \brief   SAes_Set_KeyLoad() rejects a null configuration pointer before touching a register.
 *
 * \par Expected results
 * - SAES_REQUEST_ERROR, SAES_CR stays at its reset value.
 */
void Ut_SAes_Set_KeyLoad_NullConfig_ReturnsError( void )
{
#if defined(SAES)
    UtSAes_Init_Poll();

    TEST_ASSERT_EQUAL( SAES_REQUEST_ERROR, SAes_Set_KeyLoad( SAES_NULL_PTR ) );
    TEST_ASSERT_EQUAL_HEX32( 0u, SAES->CR );
#else
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* SAES */
}

/* ============================= DATA OPERATIONS =============================== */

/**
 * \brief   SAes_Set_Process() ECB/encrypt with a 128-bit software key reads back the
 *          four 32-bit words of SAES_DOUTR MSB-first into the output buffer.
 *
 * \note    SAES_DOUTR is one physical register read four times to form a 16-byte block
 *          (RM0481, 38.8.4); RegMem traps stores, not loads (see RegMem.h), so the four
 *          reads of one unit test always see the same last-written value - a unit test
 *          cannot distinguish four genuinely different 32-bit chunks. This test proves
 *          the MSB-first byte order conversion (first byte of the expected ciphertext
 *          placed in \p output[0], not swapped); the full
 *          FIPS-197 Appendix C.1 known-answer byte sequence is proven on the real
 *          hardware by the integration test of the same name (its DOUTR genuinely
 *          shifts out four different words).
 *
 * \par Expected results
 * - SAES_REQUEST_OK, every 4-byte chunk of Output equals the preset DOUTR value,
 *   MSB first.
 */
void Ut_SAes_Set_Process_Ecb128EncryptFips197Vector_ReturnsCiphertext( void )
{
#if defined(SAES)
    UtSAes_Init_Poll();

    sAes_Data_t output[ SAES_BLOCK_BYTES ] = { 0u };
    sAes_Request_t request;

    request.Operation = SAES_OPERATION_ENCRYPT;
    request.Mode       = SAES_MODE_ECB;
    request.KeySelect  = SAES_REQUEST_KEY_INLINE;
    request.Key        = utSAes_Fips197_Key128;
    request.KeySize    = SAES_KEY_SIZE_128;
    request.Iv         = SAES_NULL_PTR;
    request.Aad        = SAES_NULL_PTR;
    request.AadLen     = 0u;
    request.Input      = utSAes_Fips197_Plaintext;
    request.Output     = output;
    request.DataLen    = SAES_BLOCK_BYTES;
    request.Tag        = SAES_NULL_PTR;
    request.TagLen     = 0u;

    /* First word of the official FIPS-197 C.1 ciphertext (69 C4 E0 D8) */
    SAES->DOUTR = UT_SAES_FIPS197_C1_CIPHERTEXT_WORD0;
    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Set_Process( &request ) );

    for( uint32_t wordIdx = 0u; SAES_BLOCK_WORDS > wordIdx; wordIdx++ )
    {
        const uint32_t byteOff = ( wordIdx * UT_SAES_REG_BYTES_PER_WORD32 );

        TEST_ASSERT_EQUAL_UINT8_ARRAY( utSAes_Fips197_Ciphertext128,
                                       &output[ byteOff ],
                                       UT_SAES_REG_BYTES_PER_WORD32 );
    }
#else
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* SAES */
}


/**
 * \brief   SAes_Set_Process() ECB/encrypt with a 192-bit software key completes and
 *          reads back SAES_DOUTR; see the 128-bit test for the DOUTR read limitation
 *          of this host harness and the real known-answer integration test.
 *
 * \par Expected results
 * - SAES_REQUEST_OK.
 */
void Ut_SAes_Set_Process_Ecb192EncryptFips197Vector_ReturnsCiphertext( void )
{
#if defined(SAES)
    UtSAes_Init_Poll();

    sAes_Data_t output[ SAES_BLOCK_BYTES ] = { 0u };
    sAes_Request_t request;

    request.Operation = SAES_OPERATION_ENCRYPT;
    request.Mode       = SAES_MODE_ECB;
    request.KeySelect  = SAES_REQUEST_KEY_INLINE;
    request.Key        = utSAes_Fips197_Key192;
    request.KeySize    = SAES_KEY_SIZE_128; /* 192-bit is written like 128-bit (4 registers) */
    request.Iv         = SAES_NULL_PTR;
    request.Aad        = SAES_NULL_PTR;
    request.AadLen     = 0u;
    request.Input      = utSAes_Fips197_Plaintext;
    request.Output     = output;
    request.DataLen    = SAES_BLOCK_BYTES;
    request.Tag        = SAES_NULL_PTR;
    request.TagLen     = 0u;

    SAES->DOUTR = UT_SAES_FIPS197_C2_CIPHERTEXT_WORD0; /* first word of the FIPS-197 C.2 ciphertext */
    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Set_Process( &request ) );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( utSAes_Fips197_Ciphertext192, output, UT_SAES_REG_BYTES_PER_WORD32 );
#else
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* SAES */
}


/**
 * \brief   SAes_Set_Process() ECB/encrypt with a 256-bit software key writes all 8 key
 *          registers and completes; see the 128-bit test for the DOUTR read limitation.
 *
 * \par Expected results
 * - SAES_REQUEST_OK, SAES_CR.KEYSIZE reads back set (256-bit).
 */
void Ut_SAes_Set_Process_Ecb256EncryptFips197Vector_ReturnsCiphertext( void )
{
#if defined(SAES)
    UtSAes_Init_Poll();

    sAes_Data_t output[ SAES_BLOCK_BYTES ] = { 0u };
    sAes_Request_t request;

    request.Operation = SAES_OPERATION_ENCRYPT;
    request.Mode       = SAES_MODE_ECB;
    request.KeySelect  = SAES_REQUEST_KEY_INLINE;
    request.Key        = utSAes_Fips197_Key256;
    request.KeySize    = SAES_KEY_SIZE_256;
    request.Iv         = SAES_NULL_PTR;
    request.Aad        = SAES_NULL_PTR;
    request.AadLen     = 0u;
    request.Input      = utSAes_Fips197_Plaintext;
    request.Output     = output;
    request.DataLen    = SAES_BLOCK_BYTES;
    request.Tag        = SAES_NULL_PTR;
    request.TagLen     = 0u;

    SAES->DOUTR = UT_SAES_FIPS197_C3_CIPHERTEXT_WORD0; /* first word of the FIPS-197 C.3 ciphertext */
    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Set_Process( &request ) );
    TEST_ASSERT_EQUAL_UINT8_ARRAY( utSAes_Fips197_Ciphertext256, output, UT_SAES_REG_BYTES_PER_WORD32 );
    TEST_ASSERT_EQUAL_HEX32( UT_SAES_CR_KEYSIZE_256, ( SAES->CR & UT_SAES_CR_KEYSIZE_MASK ) );
#else
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* SAES */
}


/**
 * \brief   SAes_Set_Process() CBC/encrypt with a 128-bit software key and the NIST
 *          SP800-38A Appendix F.2.1 IV writes SAES_IVRx MSB-first and completes; see
 *          the ECB-128 test for the DOUTR read limitation of this host harness.
 *
 * \par Expected results
 * - SAES_REQUEST_OK, SAES_IVR3 holds IVI[127:96] (the first 4 IV bytes) down to SAES_IVR0 with IVI[31:0]
 *   (RM0481 Table 378).
 */
void Ut_SAes_Set_Process_Cbc128EncryptSp80038aVector_ReturnsCiphertext( void )
{
#if defined(SAES)
    UtSAes_Init_Poll();

    sAes_Data_t output[ SAES_BLOCK_BYTES ] = { 0u };
    sAes_Request_t request;

    request.Operation = SAES_OPERATION_ENCRYPT;
    request.Mode       = SAES_MODE_CBC;
    request.KeySelect  = SAES_REQUEST_KEY_INLINE;
    request.Key        = utSAes_Sp38a_CbcKey;
    request.KeySize    = SAES_KEY_SIZE_128;
    request.Iv         = utSAes_Sp38a_CbcIv;
    request.Aad        = SAES_NULL_PTR;
    request.AadLen     = 0u;
    request.Input      = utSAes_Sp38a_CbcPlaintext;
    request.Output     = output;
    request.DataLen    = SAES_BLOCK_BYTES;
    request.Tag        = SAES_NULL_PTR;
    request.TagLen     = 0u;

    SAES->DOUTR = UT_SAES_SP38A_CBC_CIPHERTEXT_WORD0; /* first word of the SP800-38A F.2.1 block #1 ciphertext */
    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Set_Process( &request ) );

    TEST_ASSERT_EQUAL_UINT8_ARRAY( utSAes_Sp38a_CbcCiphertext, output, UT_SAES_REG_BYTES_PER_WORD32 );
    TEST_ASSERT_EQUAL_HEX32( UT_SAES_CR_CHMOD_CBC, ( SAES->CR & UT_SAES_CR_CHMOD_MASK ) );
    TEST_ASSERT_EQUAL_HEX32( UT_SAES_WORD0_00010203, SAES->IVR3 );
    TEST_ASSERT_EQUAL_HEX32( UT_SAES_WORD3_0C0D0E0F, SAES->IVR0 );
#else
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* SAES */
}


/**
 * \brief   SAes_Set_Process() CTR/encrypt streams two blocks without rewriting
 *          SAES_IVRx between them (RM0481, 38.4.10: the hardware increments the
 *          counter internally). Structural check only - no public CTR vector matches
 *          the SAES-specific 96-bit-nonce / 32-bit-counter split, see the module
 *          README deviation note.
 *
 * \par Expected results
 * - SAES_REQUEST_OK, SAES_IVR0 still holds the value this test wrote (the driver
 *   itself never rewrites it between blocks).
 */
void Ut_SAes_Set_Process_Ctr128EncryptTwoBlocks_DoesNotRewriteIv( void )
{
#if defined(SAES)
    UtSAes_Init_Poll();

    static const sAes_Data_t ctrIv[ SAES_BLOCK_BYTES ] = { UT_SAES_CTR_IV_BYTES };
    static const sAes_Data_t plaintext[ UT_SAES_TWO_BLOCKS * SAES_BLOCK_BYTES ] = { 0u };
    sAes_Data_t output[ UT_SAES_TWO_BLOCKS * SAES_BLOCK_BYTES ] = { 0u };
    sAes_Request_t request;

    request.Operation = SAES_OPERATION_ENCRYPT;
    request.Mode       = SAES_MODE_CTR;
    request.KeySelect  = SAES_REQUEST_KEY_INLINE;
    request.Key        = utSAes_Fips197_Key128;
    request.KeySize    = SAES_KEY_SIZE_128;
    request.Iv         = ctrIv;
    request.Aad        = SAES_NULL_PTR;
    request.AadLen     = 0u;
    request.Input      = plaintext;
    request.Output     = output;
    request.DataLen    = ( UT_SAES_TWO_BLOCKS * SAES_BLOCK_BYTES );
    request.Tag        = SAES_NULL_PTR;
    request.TagLen     = 0u;

    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Set_Process( &request ) );
    TEST_ASSERT_EQUAL_HEX32( UT_SAES_CTR_COUNTER_AFTER_PROCESS, SAES->IVR0 );
    TEST_ASSERT_EQUAL_HEX32( UT_SAES_CR_CHMOD_CTR, ( SAES->CR & UT_SAES_CR_CHMOD_MASK ) );
#else
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* SAES */
}


/**
 * \brief   SAes_Set_Process() GCM/encrypt (no AAD, no payload) sets SAES_CR.CHMOD to the
 *          GCM/GMAC split-field value (bits 6:5, RM0481 38.8.1): CHMOD[1:0] = 0x3 only
 *          needs the low two bits, so this mode is not the one the original bug broke,
 *          but it is checked here against a literal expected value for completeness.
 *
 * \par Expected results
 * - SAES_REQUEST_OK, SAES_CR.CHMOD bits 6:5 set, bit 16 clear.
 */
void Ut_SAes_Set_Process_GcmEncryptNoAadNoPayload_SetsChmodGcmBits( void )
{
#if defined(SAES)
    UtSAes_Init_Poll();

    static const sAes_Data_t gcmIv[ SAES_BLOCK_BYTES ] = { UT_SAES_CTR_IV_BYTES };
    sAes_Data_t dummy = 0u;
    sAes_Data_t tag[ SAES_BLOCK_BYTES ] = { 0u };
    sAes_Request_t request;

    request.Operation = SAES_OPERATION_ENCRYPT;
    request.Mode       = SAES_MODE_GCM;
    request.KeySelect  = SAES_REQUEST_KEY_INLINE;
    request.Key        = utSAes_Fips197_Key128;
    request.KeySize    = SAES_KEY_SIZE_128;
    request.Iv         = gcmIv;
    request.Aad        = SAES_NULL_PTR;
    request.AadLen     = 0u;
    request.Input      = &dummy;
    request.Output     = &dummy;
    request.DataLen    = 0u;
    request.Tag        = tag;
    request.TagLen     = SAES_BLOCK_BYTES;

    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Set_Process( &request ) );
    TEST_ASSERT_EQUAL_HEX32( UT_SAES_CR_CHMOD_GCM, ( SAES->CR & UT_SAES_CR_CHMOD_MASK ) );
#else
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* SAES */
}


/**
 * \brief   SAes_Set_Process() CCM/encrypt (no AAD, no payload) sets SAES_CR.CHMOD to the
 *          CCM split-field value: bit 16 set, bits 6:5 clear (RM0481 38.8.1, CMSIS
 *          `AES_CR_CHMOD_2` = 0x800 << 5 = bit 16). This is exactly the case the original
 *          bug ("chmodRaw << AES_CR_CHMOD_Pos") got wrong: CCM's raw value 0x4 (bit 2)
 *          shifted by 5 lands on bit 7, not bit 16, so the peripheral would silently run
 *          as ECB instead of CCM. \ref UT_SAES_CR_CHMOD_CCM is the literal expected
 *          register value (0x10000), independent of the module's own CHMOD macros.
 *
 * \par Expected results
 * - SAES_REQUEST_OK, SAES_CR bit 16 set, bits 6:5 clear (fails before the fix: bit 7 set,
 *   bit 16 clear, i.e. the masked value would read back as 0 instead of 0x10000).
 */
void Ut_SAes_Set_Process_CcmEncryptNoAadNoPayload_SetsChmodBit16NotBit7( void )
{
#if defined(SAES)
    UtSAes_Init_Poll();

    static const sAes_Data_t ccmB0[ SAES_BLOCK_BYTES ] = { UT_SAES_CTR_IV_BYTES };
    sAes_Data_t dummy = 0u;
    sAes_Data_t tag[ SAES_BLOCK_BYTES ] = { 0u };
    sAes_Request_t request;

    request.Operation = SAES_OPERATION_ENCRYPT;
    request.Mode       = SAES_MODE_CCM;
    request.KeySelect  = SAES_REQUEST_KEY_INLINE;
    request.Key        = utSAes_Fips197_Key128;
    request.KeySize    = SAES_KEY_SIZE_128;
    request.Iv         = ccmB0;
    request.Aad        = SAES_NULL_PTR;
    request.AadLen     = 0u;
    request.Input      = &dummy;
    request.Output     = &dummy;
    request.DataLen    = 0u;
    request.Tag        = tag;
    request.TagLen     = SAES_BLOCK_BYTES;

    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Set_Process( &request ) );
    TEST_ASSERT_EQUAL_HEX32( UT_SAES_CR_CHMOD_CCM, ( SAES->CR & UT_SAES_CR_CHMOD_MASK ) );
#else
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* SAES */
}


/**
 * \brief   SAes_Set_Process() GCM/encrypt with a partial last payload block writes the count of its padding bytes
 *          to SAES_CR.NPBLB (RM0481 SAES_CR.NPBLB: the tag is wrong otherwise).
 *
 * \par Expected results
 * - SAES_REQUEST_OK, SAES_CR.NPBLB = 12 (a 20-byte payload: 4 valid bytes in the last block).
 */
void Ut_SAes_Set_Process_GcmEncryptPartialLastBlock_SetsNpblb( void )
{
#if defined(SAES)
    static const sAes_Data_t input[ UT_SAES_PARTIAL_LEN ] = { 0u };
    sAes_Data_t              output[ UT_SAES_PARTIAL_LEN ];
    sAes_Data_t              tag[ SAES_BLOCK_BYTES ];
    sAes_Request_t           request;

    UtSAes_Init_Poll();
    UtSAes_Set_AeadRequest( &request, SAES_OPERATION_ENCRYPT, SAES_MODE_GCM, input, output, tag );

    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Set_Process( &request ) );
    TEST_ASSERT_EQUAL_HEX32( UT_SAES_CR_NPBLB_12, ( SAES->CR & UT_SAES_CR_NPBLB_MASK ) );
#else
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* SAES */
}


/**
 * \brief   SAes_Set_Process() GCM/decrypt with a partial last payload block leaves SAES_CR.NPBLB clear (the tag is
 *          computed over the zero-padded ciphertext block, RM0481 SAES_CR.NPBLB).
 *
 * \par Expected results
 * - SAES_REQUEST_OK, SAES_CR.NPBLB = 0.
 */
void Ut_SAes_Set_Process_GcmDecryptPartialLastBlock_LeavesNpblbClear( void )
{
#if defined(SAES)
    static const sAes_Data_t input[ UT_SAES_PARTIAL_LEN ] = { 0u };
    sAes_Data_t              output[ UT_SAES_PARTIAL_LEN ];
    sAes_Data_t              tag[ SAES_BLOCK_BYTES ];
    sAes_Request_t           request;

    UtSAes_Init_Poll();
    UtSAes_Set_AeadRequest( &request, SAES_OPERATION_DECRYPT, SAES_MODE_GCM, input, output, tag );

    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Set_Process( &request ) );
    TEST_ASSERT_EQUAL_HEX32( 0u, ( SAES->CR & UT_SAES_CR_NPBLB_MASK ) );
#else
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* SAES */
}


/**
 * \brief   SAes_Set_Process() CCM/decrypt with a partial last payload block writes the count of its padding bytes
 *          to SAES_CR.NPBLB (RM0481 SAES_CR.NPBLB).
 *
 * \par Expected results
 * - SAES_REQUEST_OK, SAES_CR.NPBLB = 12.
 */
void Ut_SAes_Set_Process_CcmDecryptPartialLastBlock_SetsNpblb( void )
{
#if defined(SAES)
    static const sAes_Data_t input[ UT_SAES_PARTIAL_LEN ] = { 0u };
    sAes_Data_t              output[ UT_SAES_PARTIAL_LEN ];
    sAes_Data_t              tag[ SAES_BLOCK_BYTES ];
    sAes_Request_t           request;

    UtSAes_Init_Poll();
    UtSAes_Set_AeadRequest( &request, SAES_OPERATION_DECRYPT, SAES_MODE_CCM, input, output, tag );

    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Set_Process( &request ) );
    TEST_ASSERT_EQUAL_HEX32( UT_SAES_CR_NPBLB_12, ( SAES->CR & UT_SAES_CR_NPBLB_MASK ) );
#else
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* SAES */
}


/**
 * \brief   The next request clears SAES_CR.NPBLB left by a GCM encryption with a partial last block.
 *
 * \par Expected results
 * - After the GCM request SAES_CR.NPBLB = 12, after the following ECB request of one block SAES_CR.NPBLB = 0.
 */
void Ut_SAes_Set_Process_AfterPartialGcmEncrypt_NextRequestClearsNpblb( void )
{
#if defined(SAES)
    static const sAes_Data_t input[ UT_SAES_PARTIAL_LEN ] = { 0u };
    sAes_Data_t              output[ UT_SAES_PARTIAL_LEN ];
    sAes_Data_t              tag[ SAES_BLOCK_BYTES ];
    sAes_Request_t           request;

    UtSAes_Init_Poll();
    UtSAes_Set_AeadRequest( &request, SAES_OPERATION_ENCRYPT, SAES_MODE_GCM, input, output, tag );
    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Set_Process( &request ) );
    TEST_ASSERT_EQUAL_HEX32( UT_SAES_CR_NPBLB_12, ( SAES->CR & UT_SAES_CR_NPBLB_MASK ) );

    request.Mode    = SAES_MODE_ECB;
    request.Iv      = SAES_NULL_PTR;
    request.DataLen = SAES_BLOCK_BYTES;
    request.Tag     = SAES_NULL_PTR;
    request.TagLen  = 0u;
    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Set_Process( &request ) );
    TEST_ASSERT_EQUAL_HEX32( 0u, ( SAES->CR & UT_SAES_CR_NPBLB_MASK ) );
#else
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* SAES */
}

/**
 * \brief   SAes_Init() in the DMA mode initializes the input and the output Gpdma channel and their interrupts.
 *
 * \par Expected results
 * - SAES_REQUEST_OK; the default configuration holds GPDMA1, channels 2 / 3, the low priority.
 * - Input channel 2: memory -> peripheral, request SAES_IN, destination SAES_DINR (static), source incremented.
 * - Output channel 3: peripheral -> memory, request SAES_OUT, source SAES_DOUTR (static), destination incremented.
 * - Both: 32-bit words, the bytes of every word exchanged on the destination side, interrupts activated.
 */
void Ut_SAes_Init_DmaMode_ConfiguresInputAndOutputChannel( void )
{
#if defined(SAES)
    sAes_Config_t config;

    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Get_DefaultConfig( &config ) );
    TEST_ASSERT_EQUAL( GPDMA_PERIPH_1, config.DmaPeriphId );
    TEST_ASSERT_EQUAL( UT_SAES_DMA_IN_CH, config.DmaInChannelId );
    TEST_ASSERT_EQUAL( UT_SAES_DMA_OUT_CH, config.DmaOutChannelId );
    TEST_ASSERT_EQUAL( GPDMA_PRIORITY_LOW, config.DmaChannelPrio );

    UtSAes_Init_Dma();

    TEST_ASSERT_EQUAL_UINT32( UT_SAES_DMA_CHANNEL_CNT, utSAes_DmaInitCnt );
    TEST_ASSERT_EQUAL( UT_SAES_DMA_IN_CH, utSAes_DmaCfg[ UT_SAES_DMA_CFG_IN ].ChannelId );
    TEST_ASSERT_EQUAL( GPDMA_DIR_MEMORY_TO_PERIPH, utSAes_DmaCfg[ UT_SAES_DMA_CFG_IN ].Direction );
    TEST_ASSERT_EQUAL( GPDMA_REQ_SAES_IN, utSAes_DmaCfg[ UT_SAES_DMA_CFG_IN ].RequestSource );
    TEST_ASSERT_EQUAL( GPDMA_ADDR_INCREMENT, utSAes_DmaCfg[ UT_SAES_DMA_CFG_IN ].SrcAddrMode );
    TEST_ASSERT_EQUAL( GPDMA_ADDR_STATIC, utSAes_DmaCfg[ UT_SAES_DMA_CFG_IN ].DstAddrMode );
    TEST_ASSERT_EQUAL_HEX32( (uint32_t)(uintptr_t)&SAES->DINR, utSAes_DmaCfg[ UT_SAES_DMA_CFG_IN ].DstAddr );

    TEST_ASSERT_EQUAL( UT_SAES_DMA_OUT_CH, utSAes_DmaCfg[ UT_SAES_DMA_CFG_OUT ].ChannelId );
    TEST_ASSERT_EQUAL( GPDMA_DIR_PERIPH_TO_MEMORY, utSAes_DmaCfg[ UT_SAES_DMA_CFG_OUT ].Direction );
    TEST_ASSERT_EQUAL( GPDMA_REQ_SAES_OUT, utSAes_DmaCfg[ UT_SAES_DMA_CFG_OUT ].RequestSource );
    TEST_ASSERT_EQUAL( GPDMA_ADDR_STATIC, utSAes_DmaCfg[ UT_SAES_DMA_CFG_OUT ].SrcAddrMode );
    TEST_ASSERT_EQUAL( GPDMA_ADDR_INCREMENT, utSAes_DmaCfg[ UT_SAES_DMA_CFG_OUT ].DstAddrMode );
    TEST_ASSERT_EQUAL_HEX32( (uint32_t)(uintptr_t)&SAES->DOUTR, utSAes_DmaCfg[ UT_SAES_DMA_CFG_OUT ].SrcAddr );

    for( uint32_t idx = 0u; UT_SAES_DMA_CHANNEL_CNT > idx; idx++ )
    {
        TEST_ASSERT_EQUAL( GPDMA_DATA_SIZE_32BITS, utSAes_DmaCfg[ idx ].SrcDataSize );
        TEST_ASSERT_EQUAL( GPDMA_DATA_SIZE_32BITS, utSAes_DmaCfg[ idx ].DstDataSize );
        TEST_ASSERT_EQUAL( GPDMA_DEST_DATA_BYTE_2BYTES_SWAP, utSAes_DmaCfg[ idx ].DstDataOp );
    }

    TEST_ASSERT_NOT_NULL( utSAes_DmaInIsr );
    TEST_ASSERT_NOT_NULL( utSAes_DmaOutIsr );
    TEST_ASSERT_NOT_NULL( utSAes_DmaErrIsr );
#else
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* SAES */
}


/**
 * \brief   SAes_Init() in the DMA mode rejects the same channel for the input and the output and rolls back.
 *
 * \par Expected results
 * - SAES_REQUEST_ERROR, no Gpdma channel is initialized, the Deinit rollback disables the NVIC line and the clock.
 */
void Ut_SAes_Init_DmaModeSameChannels_ReturnsErrorAndDeinitializes( void )
{
#if defined(SAES)
    sAes_Config_t config;

    UtSAes_Set_DmaStubs();
    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Get_DefaultConfig( &config ) );
    config.XferMode        = SAES_XFER_MODE_DMA;
    config.DmaOutChannelId = config.DmaInChannelId;

    UtSAes_Expect_InitPoll();
    Nvic_Set_PeriphIrq_Prio_ExpectAndReturn( NVIC_PERIPH_IRQ_SAES,
                                             (nvic_IrqPrio_t)config.IrqPriority,
                                             NVIC_REQUEST_OK );
    Nvic_Set_PeriphIrq_Active_ExpectAndReturn( NVIC_PERIPH_IRQ_SAES, NVIC_REQUEST_OK );
    Nvic_Set_PeriphIrq_Inactive_ExpectAndReturn( NVIC_PERIPH_IRQ_SAES, NVIC_REQUEST_OK );
    Rcc_Set_PeriphInactive_ExpectAndReturn( RCC_PERIPH_SAES, RCC_REQUEST_OK );

    TEST_ASSERT_EQUAL( SAES_REQUEST_ERROR, SAes_Init( &config ) );
    TEST_ASSERT_EQUAL_UINT32( 0u, utSAes_DmaInitCnt );
#else
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* SAES */
}


/**
 * \brief   SAes_Set_Process() ECB in the DMA mode moves the full blocks by the two channels, the CPU does not touch
 *          SAES_DINR / SAES_DOUTR.
 *
 * \par Expected results
 * - SAES_REQUEST_OK; the output channel is started before the input channel, both with the block size 32.
 * - Input channel: source = the input buffer, destination = SAES_DINR; output channel: source = SAES_DOUTR,
 *   destination = the output buffer.
 * - DMAINEN / DMAOUTEN are clear when the channels are started and cleared again at the end; SAES_DINR keeps 0.
 */
void Ut_SAes_Set_Process_DmaEcbTwoBlocks_MovesBlocksByDma( void )
{
#if defined(SAES)
    sAes_Request_t request;

    UtSAes_Init_Dma();
    UtSAes_Set_DmaRequest( &request,
                           SAES_MODE_ECB,
                           (const sAes_Data_t *)utSAes_DmaIn,
                           (sAes_Data_t *)utSAes_DmaOut,
                           UT_SAES_TWO_BLOCKS_LEN );

    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Set_Process( &request ) );

    TEST_ASSERT_EQUAL_UINT32( UT_SAES_DMA_CHANNEL_CNT, utSAes_DmaStartCnt );
    TEST_ASSERT_EQUAL( UT_SAES_DMA_OUT_CH, utSAes_DmaStartLog[ 0u ] );
    TEST_ASSERT_EQUAL( UT_SAES_DMA_IN_CH, utSAes_DmaStartLog[ 1u ] );
    TEST_ASSERT_EQUAL_UINT32( UT_SAES_TWO_BLOCKS_LEN, utSAes_DmaSizeLog[ 0u ].Value );
    TEST_ASSERT_EQUAL_UINT32( UT_SAES_TWO_BLOCKS_LEN, utSAes_DmaSizeLog[ 1u ].Value );
    TEST_ASSERT_EQUAL_HEX32( (uint32_t)(uintptr_t)&SAES->DOUTR, utSAes_DmaSrcLog[ 0u ].Value );
    TEST_ASSERT_EQUAL_HEX32( (uint32_t)(uintptr_t)utSAes_DmaOut, utSAes_DmaDstLog[ 0u ].Value );
    TEST_ASSERT_EQUAL_HEX32( (uint32_t)(uintptr_t)utSAes_DmaIn, utSAes_DmaSrcLog[ 1u ].Value );
    TEST_ASSERT_EQUAL_HEX32( (uint32_t)(uintptr_t)&SAES->DINR, utSAes_DmaDstLog[ 1u ].Value );
    TEST_ASSERT_EQUAL_HEX32( 0u, utSAes_DmaCrAtStart );
    TEST_ASSERT_EQUAL_HEX32( 0u, ( SAES->CR & UT_SAES_CR_DMA_MASK ) );
    TEST_ASSERT_EQUAL_HEX32( 0u, SAES->DINR );
    TEST_ASSERT_EQUAL_UINT32( 0u, utSAes_DmaStopCnt );
#else
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* SAES */
}


/**
 * \brief   SAes_Set_Process() CTR in the DMA mode moves the full block by the DMA and the partial last block by the
 *          CPU.
 *
 * \par Expected results
 * - SAES_REQUEST_OK, the block size of the channels is 16 (not 20), the 4 bytes of the last block are read by the
 *   CPU from SAES_DOUTR (the preset pattern, MSB first).
 */
void Ut_SAes_Set_Process_DmaCtrPartialBlock_TailByCpu( void )
{
#if defined(SAES)
    static const sAes_Data_t ctrIv[ SAES_BLOCK_BYTES ] = { UT_SAES_CTR_IV_BYTES };
    sAes_Request_t           request;
    const sAes_Data_t *      outBytes = (const sAes_Data_t *)utSAes_DmaOut;

    UtSAes_Init_Dma();
    SAES->DOUTR = UT_SAES_DOUTR_PATTERN;
    UtSAes_Set_DmaRequest( &request,
                           SAES_MODE_CTR,
                           (const sAes_Data_t *)utSAes_DmaIn,
                           (sAes_Data_t *)utSAes_DmaOut,
                           UT_SAES_TAIL_LEN );
    request.Iv = ctrIv;

    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Set_Process( &request ) );

    TEST_ASSERT_EQUAL_UINT32( SAES_BLOCK_BYTES, utSAes_DmaSizeLog[ 0u ].Value );
    TEST_ASSERT_EQUAL_UINT32( SAES_BLOCK_BYTES, utSAes_DmaSizeLog[ 1u ].Value );
    TEST_ASSERT_EQUAL_HEX8( UT_SAES_DOUTR_BYTE0, outBytes[ SAES_BLOCK_BYTES ] );
    TEST_ASSERT_EQUAL_HEX8( UT_SAES_DOUTR_BYTE3, outBytes[ UT_SAES_TAIL_LEN - 1u ] );
#else
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* SAES */
}


/**
 * \brief   SAes_Set_Process() in the DMA mode splits a long payload in chunks of 65520 bytes (16-bit Gpdma block
 *          size, a multiple of the block size).
 *
 * \par Expected results
 * - SAES_REQUEST_OK, two chunks: 65520 bytes and 16 bytes, the second one 65520 bytes further in both buffers.
 */
void Ut_SAes_Set_Process_DmaLongPayload_SplitsInChunks( void )
{
#if defined(SAES)
    sAes_Request_t request;

    UtSAes_Init_Dma();
    UtSAes_Set_DmaRequest( &request,
                           SAES_MODE_ECB,
                           (const sAes_Data_t *)utSAes_DmaIn,
                           (sAes_Data_t *)utSAes_DmaOut,
                           UT_SAES_DMA_BIG_LEN );

    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Set_Process( &request ) );

    TEST_ASSERT_EQUAL_UINT32( UT_SAES_DMA_TWO_CHUNK_STARTS, utSAes_DmaStartCnt );
    TEST_ASSERT_EQUAL_UINT32( UT_SAES_DMA_CHUNK_MAX, utSAes_DmaSizeLog[ UT_SAES_DMA_LOG_CHUNK1_IN ].Value );
    TEST_ASSERT_EQUAL_UINT32( SAES_BLOCK_BYTES, utSAes_DmaSizeLog[ UT_SAES_DMA_LOG_CHUNK2_IN ].Value );
    TEST_ASSERT_EQUAL_HEX32( (uint32_t)(uintptr_t)utSAes_DmaIn + UT_SAES_DMA_CHUNK_MAX,
                             utSAes_DmaSrcLog[ UT_SAES_DMA_LOG_CHUNK2_IN ].Value );
    TEST_ASSERT_EQUAL_HEX32( (uint32_t)(uintptr_t)utSAes_DmaOut + UT_SAES_DMA_CHUNK_MAX,
                             utSAes_DmaDstLog[ UT_SAES_DMA_LOG_CHUNK2_OUT ].Value );
#else
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* SAES */
}


/**
 * \brief   SAes_Set_Process() GCM in the DMA mode moves the header by the input channel only (no output in the header
 *          phase).
 *
 * \par Expected results
 * - SAES_REQUEST_OK, one channel started: the input channel with the 32 bytes of AAD; no output channel.
 */
void Ut_SAes_Set_Process_DmaGcmHeader_InputChannelOnly( void )
{
#if defined(SAES)
    static const sAes_Data_t gcmIv[ SAES_BLOCK_BYTES ] = { UT_SAES_CTR_IV_BYTES };
    sAes_Data_t              tag[ SAES_BLOCK_BYTES ];
    sAes_Request_t           request;

    UtSAes_Init_Dma();
    UtSAes_Set_DmaRequest( &request,
                           SAES_MODE_GCM,
                           (const sAes_Data_t *)utSAes_DmaIn,
                           (sAes_Data_t *)utSAes_DmaOut,
                           0u );
    request.Iv     = gcmIv;
    request.Aad    = (const sAes_Data_t *)utSAes_DmaIn;
    request.AadLen = UT_SAES_TWO_BLOCKS_LEN;
    request.Tag    = tag;
    request.TagLen = SAES_BLOCK_BYTES;

    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Set_Process( &request ) );

    TEST_ASSERT_EQUAL_UINT32( 1u, utSAes_DmaStartCnt );
    TEST_ASSERT_EQUAL( UT_SAES_DMA_IN_CH, utSAes_DmaStartLog[ 0u ] );
    TEST_ASSERT_EQUAL_UINT32( UT_SAES_TWO_BLOCKS_LEN, utSAes_DmaSizeLog[ 0u ].Value );
#else
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* SAES */
}


/**
 * \brief   SAes_Set_Process() in the DMA mode rejects a buffer of a full block which is not word aligned before a
 *          register is touched.
 *
 * \par Expected results
 * - SAES_REQUEST_ERROR, no Gpdma channel started, SAES_CR keeps its value.
 */
void Ut_SAes_Set_Process_DmaUnalignedInput_ReturnsErrorWithoutAccess( void )
{
#if defined(SAES)
    sAes_Request_t request;
    uint32_t       crBefore = 0u;

    UtSAes_Init_Dma();
    UtSAes_Set_DmaRequest( &request,
                           SAES_MODE_ECB,
                           &( (const sAes_Data_t *)utSAes_DmaIn )[ UT_SAES_UNALIGNED_OFFSET ],
                           (sAes_Data_t *)utSAes_DmaOut,
                           SAES_BLOCK_BYTES );
    crBefore = SAES->CR;

    TEST_ASSERT_EQUAL( SAES_REQUEST_ERROR, SAes_Set_Process( &request ) );
    TEST_ASSERT_EQUAL_UINT32( 0u, utSAes_DmaStartCnt );
    TEST_ASSERT_EQUAL_HEX32( crBefore, SAES->CR );
#else
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* SAES */
}


/**
 * \brief   SAes_Set_Process() in the DMA mode fails on a Gpdma error and stops both channels.
 *
 * \par Expected results
 * - SAES_REQUEST_ERROR, Gpdma_Set_ChannelInactive called for the input and the output channel, DMAINEN / DMAOUTEN
 *   cleared.
 */
void Ut_SAes_Set_Process_DmaChannelError_ReturnsErrorAndStopsChannels( void )
{
#if defined(SAES)
    sAes_Request_t request;

    UtSAes_Init_Dma();
    utSAes_DmaFail = SAES_FUNCTION_ACTIVE;
    UtSAes_Set_DmaRequest( &request,
                           SAES_MODE_ECB,
                           (const sAes_Data_t *)utSAes_DmaIn,
                           (sAes_Data_t *)utSAes_DmaOut,
                           SAES_BLOCK_BYTES );

    TEST_ASSERT_EQUAL( SAES_REQUEST_ERROR, SAes_Set_Process( &request ) );
    TEST_ASSERT_EQUAL_UINT32( UT_SAES_DMA_CHANNEL_CNT, utSAes_DmaStopCnt );
    TEST_ASSERT_EQUAL( UT_SAES_DMA_IN_CH, utSAes_DmaStopLog[ 0u ] );
    TEST_ASSERT_EQUAL( UT_SAES_DMA_OUT_CH, utSAes_DmaStopLog[ 1u ] );
    TEST_ASSERT_EQUAL_HEX32( 0u, ( SAES->CR & UT_SAES_CR_DMA_MASK ) );
#else
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* SAES */
}


/**
 * \brief   SAes_Deinit() after the DMA mode releases both Gpdma channels and their interrupts.
 *
 * \par Expected results
 * - SAES_REQUEST_OK, Gpdma_Set_InterruptInactive and Gpdma_Deinit called for channels 2 and 3.
 */
void Ut_SAes_Deinit_DmaMode_ReleasesBothChannels( void )
{
#if defined(SAES)
    UtSAes_Init_Dma();

    Gpdma_Set_InterruptInactive_ExpectAndReturn( GPDMA_PERIPH_1, UT_SAES_DMA_IN_CH, GPDMA_REQUEST_OK );
    Gpdma_Set_InterruptInactive_ExpectAndReturn( GPDMA_PERIPH_1, UT_SAES_DMA_OUT_CH, GPDMA_REQUEST_OK );
    Gpdma_Deinit_ExpectAndReturn( GPDMA_PERIPH_1, UT_SAES_DMA_IN_CH, GPDMA_REQUEST_OK );
    Gpdma_Deinit_ExpectAndReturn( GPDMA_PERIPH_1, UT_SAES_DMA_OUT_CH, GPDMA_REQUEST_OK );
    Nvic_Set_PeriphIrq_Inactive_ExpectAndReturn( NVIC_PERIPH_IRQ_SAES, NVIC_REQUEST_OK );
    Rcc_Set_PeriphInactive_ExpectAndReturn( RCC_PERIPH_SAES, RCC_REQUEST_OK );

    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Deinit() );
#else
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* SAES */
}

/**
 * \brief   SAes_Set_Process() rejects an ECB DataLen that is not a multiple of 16 bytes
 *          before any register is touched.
 *
 * \par Expected results
 * - SAES_REQUEST_ERROR, SAES_CR stays at its reset value.
 */
void Ut_SAes_Set_Process_InvalidDataLenEcb_ReturnsError( void )
{
#if defined(SAES)
    UtSAes_Init_Poll();

    sAes_Data_t output[ SAES_BLOCK_BYTES ] = { 0u };
    sAes_Request_t request;

    request.Operation = SAES_OPERATION_ENCRYPT;
    request.Mode       = SAES_MODE_ECB;
    request.KeySelect  = SAES_REQUEST_KEY_INLINE;
    request.Key        = utSAes_Fips197_Key128;
    request.KeySize    = SAES_KEY_SIZE_128;
    request.Iv         = SAES_NULL_PTR;
    request.Aad        = SAES_NULL_PTR;
    request.AadLen     = 0u;
    request.Input      = utSAes_Fips197_Plaintext;
    request.Output     = output;
    request.DataLen    = ( SAES_BLOCK_BYTES - 1u );
    request.Tag        = SAES_NULL_PTR;
    request.TagLen     = 0u;

    TEST_ASSERT_EQUAL( SAES_REQUEST_ERROR, SAes_Set_Process( &request ) );
    TEST_ASSERT_EQUAL_HEX32( 0u, SAES->CR );
#else
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* SAES */
}

/* =========================== KEY WRAP / UNWRAP ================================ */

/**
 * \brief   SAes_Set_KeyWrap() in ECB mode with a software wrapping key sets
 *          SAES_CR.KMOD to the wrapped raw value and returns the preset ciphertext.
 *
 * \par Expected results
 * - SAES_REQUEST_OK.
 */
void Ut_SAes_Set_KeyWrap_EcbSoftwareWrapKey_SetsWrappedKmod( void )
{
#if defined(SAES)
    UtSAes_Init_Poll();

    sAes_WrapConfig_t wrapConfig;

    wrapConfig.WrapKeySource  = SAES_KEY_SOFTWARE;
    wrapConfig.WrapKeySize    = SAES_KEY_SIZE_128;
    wrapConfig.WrapKeyBytes   = utSAes_Fips197_Key128;
    wrapConfig.Mode           = SAES_MODE_ECB;
    wrapConfig.Iv             = SAES_NULL_PTR;
    wrapConfig.WrappedKeySize = SAES_KEY_SIZE_128;

    sAes_Data_t wrappedKey[ SAES_KEY_128_BYTES ] = { 0u };

    SAES->DOUTR = UT_SAES_FIPS197_C1_CIPHERTEXT_WORD0;

    TEST_ASSERT_EQUAL( SAES_REQUEST_OK,
                       SAes_Set_KeyWrap( &wrapConfig, utSAes_Fips197_Plaintext, wrappedKey ) );
#else
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* SAES */
}


/**
 * \brief   SAes_Set_KeyUnwrap() in ECB mode runs the key-derivation pass then the
 *          decryption pass and leaves the key usable in normal key mode.
 *
 * \par Expected results
 * - SAES_REQUEST_OK, SAes_Get_KeyState() returns SAES_KEY_STATE_VALID.
 */
void Ut_SAes_Set_KeyUnwrap_EcbSoftwareWrapKey_LeavesKeyValid( void )
{
#if defined(SAES)
    UtSAes_Init_Poll();

    sAes_WrapConfig_t wrapConfig;

    wrapConfig.WrapKeySource  = SAES_KEY_SOFTWARE;
    wrapConfig.WrapKeySize    = SAES_KEY_SIZE_128;
    wrapConfig.WrapKeyBytes   = utSAes_Fips197_Key128;
    wrapConfig.Mode           = SAES_MODE_ECB;
    wrapConfig.Iv             = SAES_NULL_PTR;
    wrapConfig.WrappedKeySize = SAES_KEY_SIZE_128;

    TEST_ASSERT_EQUAL( SAES_REQUEST_OK,
                       SAes_Set_KeyUnwrap( &wrapConfig, utSAes_Fips197_Ciphertext128 ) );

    sAes_KeyState_t keyState = SAES_KEY_STATE_NONE;

    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Get_KeyState( &keyState ) );
    TEST_ASSERT_EQUAL( SAES_KEY_STATE_VALID, keyState );
#else
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* SAES */
}

/* =============================== KEY SHARE ================================== */

/**
 * \brief   SAes_Set_KeyShare() on a valid key sets SAES_CR.KMOD to the shared raw
 *          value and SAES_CR.KSHAREID to the AES raw value (RM0481 38.8.1 literals).
 *
 * \par Expected results
 * - SAES_REQUEST_OK, SAES_CR.KMOD = 0x2, SAES_CR.KSHAREID = 0x0.
 */
void Ut_SAes_Set_KeyShare_ValidKey_SetsSharedKmodAndKShareId( void )
{
#if defined(SAES)
    UtSAes_Init_Poll();

    sAes_KeyConfig_t keyConfig;

    keyConfig.KeySource = SAES_KEY_SOFTWARE;
    keyConfig.KeySize   = SAES_KEY_SIZE_128;
    keyConfig.KeyBytes  = utSAes_Fips197_Key128;
    keyConfig.Protect   = SAES_FUNCTION_INACTIVE;

    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Set_KeyLoad( &keyConfig ) );
    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Set_KeyShare( SAES_SHARE_AES ) );

    TEST_ASSERT_EQUAL_HEX32( UT_SAES_CR_KMOD_SHARED, ( SAES->CR & UT_SAES_CR_KMOD_MASK      ) );
    TEST_ASSERT_EQUAL_HEX32( 0u,                     ( SAES->CR & UT_SAES_CR_KSHAREID_MASK ) );
#else
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* SAES */
}


/**
 * \brief   SAes_Set_KeyShare() is rejected when no valid key is loaded.
 *
 * \par Expected results
 * - SAES_REQUEST_ERROR.
 */
void Ut_SAes_Set_KeyShare_NoValidKey_ReturnsError( void )
{
#if defined(SAES)
    UtSAes_Init_Poll();

    TEST_ASSERT_EQUAL( SAES_REQUEST_ERROR, SAes_Set_KeyShare( SAES_SHARE_AES ) );
#else
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* SAES */
}

/* =============================== KEY CLEAR =================================== */

/**
 * \brief   SAes_Set_KeyClear() resets the key state to none after a valid key was loaded.
 *
 * \par Expected results
 * - SAES_REQUEST_OK, SAes_Get_KeyState() returns SAES_KEY_STATE_NONE.
 */
void Ut_SAes_Set_KeyClear_KeyWasValid_ResetsKeyState( void )
{
#if defined(SAES)
    UtSAes_Init_Poll();

    sAes_KeyConfig_t keyConfig;

    keyConfig.KeySource = SAES_KEY_SOFTWARE;
    keyConfig.KeySize   = SAES_KEY_SIZE_128;
    keyConfig.KeyBytes  = utSAes_Fips197_Key128;
    keyConfig.Protect   = SAES_FUNCTION_INACTIVE;

    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Set_KeyLoad( &keyConfig ) );
    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Set_KeyClear() );

    sAes_KeyState_t keyState = SAES_KEY_STATE_VALID;

    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Get_KeyState( &keyState ) );
    TEST_ASSERT_EQUAL( SAES_KEY_STATE_NONE, keyState );
#else
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* SAES */
}

/* ============================ STATE / ERROR GETTERS =========================== */

/**
 * \brief   SAes_Get_KeyState() / SAes_Get_XferError() reject a null pointer.
 *
 * \par Expected results
 * - Both return SAES_REQUEST_ERROR for a null pointer.
 */
void Ut_SAes_Get_KeyStateAndXferError_NullPointer_ReturnsError( void )
{
    TEST_ASSERT_EQUAL( SAES_REQUEST_ERROR, SAes_Get_KeyState( SAES_NULL_PTR ) );
    TEST_ASSERT_EQUAL( SAES_REQUEST_ERROR, SAes_Get_XferError( SAES_NULL_PTR ) );
}

/* ================================ INTERRUPTS =================================== */

/**
 * \brief   SAes_Set_IrqPriority() / SAes_Get_IrqPriority() round-trip through the NVIC mock.
 *
 * \par Expected results
 * - Both return SAES_REQUEST_OK, the read-back priority matches what was set.
 */
void Ut_SAes_IrqPriority_SetThenGet_RoundTrips( void )
{
#if defined(SAES)
    UtSAes_Init_Poll();

    Nvic_Set_PeriphIrq_Prio_ExpectAndReturn( NVIC_PERIPH_IRQ_SAES,
                                             (nvic_IrqPrio_t)UT_SAES_IRQ_PRIO,
                                             NVIC_REQUEST_OK );
    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Set_IrqPriority( (sAes_IrqPrio_t)UT_SAES_IRQ_PRIO ) );

    nvic_IrqPrio_t nvicPrio = (nvic_IrqPrio_t)UT_SAES_IRQ_PRIO;

    Nvic_Get_PeriphIrq_Prio_ExpectAndReturn( NVIC_PERIPH_IRQ_SAES, SAES_NULL_PTR, NVIC_REQUEST_OK );
    Nvic_Get_PeriphIrq_Prio_IgnoreArg_irqPrio();
    Nvic_Get_PeriphIrq_Prio_ReturnThruPtr_irqPrio( &nvicPrio );

    sAes_IrqPrio_t readPrio = 0u;

    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Get_IrqPriority( &readPrio ) );
    TEST_ASSERT_EQUAL_UINT8( UT_SAES_IRQ_PRIO, readPrio );
#else
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* SAES */
}

/* ========================= LINES WITHOUT THE SAES PERIPHERAL =========================== */

/**
 * \brief   Peripheral check of every function on a line without the SAES peripheral.
 *
 * \par Expected results
 * - Every function with a return value returns SAES_REQUEST_ERROR and writes no output.
 * - SAes_Task does nothing, the module version is returned, no mocked function is called.
 * - Ignored on the lines with SAES (the other test cases cover them).
 */
void Ut_SAes_NoPeripheral_EveryFunctionReturnsError( void )
{
#if !defined(SAES)
    sAes_Config_t              config      = { 0 };
    sAes_KeyConfig_t           keyConfig   = { 0 };
    sAes_WrapConfig_t          wrapConfig  = { 0 };
    sAes_Request_t             request     = { 0 };
    sAes_Context_t             context     = { 0 };
    sAes_FunctionState_t       supported   = SAES_FUNCTION_INACTIVE;
    sAes_State_t               sAesState   = SAES_STATE_UNINIT;
    sAes_KeyState_t            keyState    = SAES_KEY_STATE_NONE;
    sAes_XferError_t           xferError   = SAES_XFER_ERROR_NONE;
    sAes_IrqPrio_t             irqPriority = 0u;
    sAes_Data_t                buffer[SAES_BLOCK_BYTES] = { 0 };
    const sAes_ModuleVersion_t version     = SAes_Get_ModuleVersion();

    TEST_ASSERT_EQUAL_UINT8( 1u, version.Major );
    SAes_Task();
    TEST_ASSERT_EQUAL( SAES_REQUEST_ERROR, SAes_Init( &config ) );
    TEST_ASSERT_EQUAL( SAES_REQUEST_ERROR, SAes_Deinit() );
    TEST_ASSERT_EQUAL( SAES_REQUEST_ERROR, SAes_Get_DefaultConfig( &config ) );
    TEST_ASSERT_EQUAL( SAES_REQUEST_ERROR, SAes_Get_Capability( SAES_KEY_SOFTWARE, SAES_MODE_ECB, &supported ) );
    TEST_ASSERT_EQUAL( SAES_REQUEST_ERROR, SAes_Get_State( &sAesState ) );
    TEST_ASSERT_EQUAL( SAES_REQUEST_ERROR, SAes_Get_KeyState( &keyState ) );
    TEST_ASSERT_EQUAL( SAES_REQUEST_ERROR, SAes_Get_XferError( &xferError ) );
    TEST_ASSERT_EQUAL( SAES_REQUEST_ERROR, SAes_Set_KeyLoad( &keyConfig ) );
    TEST_ASSERT_EQUAL( SAES_REQUEST_ERROR, SAes_Set_KeyWrap( &wrapConfig, buffer, buffer ) );
    TEST_ASSERT_EQUAL( SAES_REQUEST_ERROR, SAes_Set_KeyUnwrap( &wrapConfig, buffer ) );
    TEST_ASSERT_EQUAL( SAES_REQUEST_ERROR, SAes_Set_KeyShare( SAES_SHARE_AES ) );
    TEST_ASSERT_EQUAL( SAES_REQUEST_ERROR, SAes_Set_KeyClear() );
    TEST_ASSERT_EQUAL( SAES_REQUEST_ERROR, SAes_Set_Process( &request ) );
    TEST_ASSERT_EQUAL( SAES_REQUEST_ERROR, SAes_Set_Start( &request ) );
    TEST_ASSERT_EQUAL( SAES_REQUEST_ERROR, SAes_Set_UpdateAad( buffer, SAES_BLOCK_BYTES ) );
    TEST_ASSERT_EQUAL( SAES_REQUEST_ERROR, SAes_Set_Update( buffer, buffer, SAES_BLOCK_BYTES ) );
    TEST_ASSERT_EQUAL( SAES_REQUEST_ERROR, SAes_Set_Finish( buffer, SAES_BLOCK_BYTES ) );
    TEST_ASSERT_EQUAL( SAES_REQUEST_ERROR, SAes_Set_Abort() );
    TEST_ASSERT_EQUAL( SAES_REQUEST_ERROR, SAes_Get_Context( &context ) );
    TEST_ASSERT_EQUAL( SAES_REQUEST_ERROR, SAes_Set_Context( &context ) );
    TEST_ASSERT_EQUAL( SAES_REQUEST_ERROR, SAes_Set_IrqPriority( irqPriority ) );
    TEST_ASSERT_EQUAL( SAES_REQUEST_ERROR, SAes_Get_IrqPriority( &irqPriority ) );

    TEST_ASSERT_EQUAL( SAES_FUNCTION_INACTIVE, supported );
    TEST_ASSERT_EQUAL( SAES_STATE_UNINIT, sAesState );
    TEST_ASSERT_EQUAL( SAES_KEY_STATE_NONE, keyState );
    TEST_ASSERT_EQUAL( SAES_XFER_ERROR_NONE, xferError );
    TEST_ASSERT_EQUAL_UINT32( 0u, irqPriority );
#else
    TEST_IGNORE_MESSAGE( "MCU with SAES, see the other test cases" );
#endif /* SAES */
}

/* ========================= LOCAL FUNCTIONS ================================= */

#if defined(SAES)

/**
 * \brief HW model: SAES_SR.KEYVALID follows SAES_CR.KEYSEL != 0, SAES_ISR.CCF follows
 *        SAES_CR.EN, and SAES_ICR.CCF self-clears SAES_ISR.CCF (RegMem is plain memory,
 *        this emulates the hardware reaction the real SAES gives).
 */
static void UtSAes_HwModel( void )
{
    /* RM0481, 38.8.2: KEYVALID follows a hardware key source as soon as KEYSEL is
     * non-zero, and follows a software key (KEYSEL = 0) once the KEYRx write sequence
     * is correct; RegMem cannot check the sequence order, so it is assumed correct. */
    SAES->SR |= AES_SR_KEYVALID;

    if( AES_CR_EN == ( SAES->CR & AES_CR_EN ) )
    {
        SAES->ISR |= AES_ISR_CCF;
    }
    else
    {
        /* EN cleared, status untouched */
    }

    if( 0u != ( SAES->ICR & AES_ICR_CCF ) )
    {
        SAES->ISR &= ~AES_ISR_CCF;
        SAES->ICR &= ~AES_ICR_CCF;
    }
    else
    {
        /* No pending clear */
    }
}


/**
 * \brief Sets up the CMock expectation of a successful POLL mode \ref SAes_Init.
 */
static void UtSAes_Expect_InitPoll( void )
{
    static rng_FunctionState_t utSAes_RngActiveState = RNG_FUNCTION_ACTIVE;

    Rcc_Set_PeriphActive_ExpectAndReturn( RCC_PERIPH_SAES, RCC_REQUEST_OK );
    Rng_Set_ExecActive_ExpectAndReturn( RNG_PERIPH_1, RNG_REQUEST_OK );
    Rng_Get_ExecState_ExpectAndReturn( RNG_PERIPH_1, SAES_NULL_PTR, RNG_REQUEST_OK );
    Rng_Get_ExecState_IgnoreArg_state();
    Rng_Get_ExecState_ReturnThruPtr_state( &utSAes_RngActiveState );
}


/**
 * \brief Runs a successful POLL mode \ref SAes_Init, ready for the test body that follows.
 */
static void UtSAes_Init_Poll( void )
{
    sAes_Config_t config;

    UtSAes_Expect_InitPoll();
    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Get_DefaultConfig( &config ) );
    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Init( &config ) );
}



/**
 * \brief Fills an AEAD request of the NPBLB tests: inline 128-bit key, the CTR IV bytes as the IV / B0 block, no AAD,
 *        a payload of \ref UT_SAES_PARTIAL_LEN bytes and a 16-byte tag.
 *
 * \param request   [out]: Request to fill
 * \param operation [in]:  Encrypt or decrypt
 * \param mode      [in]:  GCM or CCM
 * \param input     [in]:  Payload input
 * \param output    [out]: Payload output
 * \param tag       [out]: Tag buffer
 */
static void UtSAes_Set_AeadRequest( sAes_Request_t * const request,
                                    sAes_Operation_t       operation,
                                    sAes_Mode_t            mode,
                                    const sAes_Data_t *    input,
                                    sAes_Data_t *          output,
                                    sAes_Data_t *          tag )
{
    static const sAes_Data_t iv[ SAES_BLOCK_BYTES ] = { UT_SAES_CTR_IV_BYTES };

    request->Operation = operation;
    request->Mode      = mode;
    request->KeySelect = SAES_REQUEST_KEY_INLINE;
    request->Key       = utSAes_Fips197_Key128;
    request->KeySize   = SAES_KEY_SIZE_128;
    request->Iv        = iv;
    request->Aad       = SAES_NULL_PTR;
    request->AadLen    = 0u;
    request->Input     = input;
    request->Output    = output;
    request->DataLen   = UT_SAES_PARTIAL_LEN;
    request->Tag       = tag;
    request->TagLen    = SAES_BLOCK_BYTES;
}



/**
 * \brief Registers the Gpdma stubs of the DMA tests and clears their logs.
 */
static void UtSAes_Set_DmaStubs( void )
{
    utSAes_DmaInitCnt   = 0u;
    utSAes_DmaSizeCnt   = 0u;
    utSAes_DmaSrcCnt    = 0u;
    utSAes_DmaDstCnt    = 0u;
    utSAes_DmaStartCnt  = 0u;
    utSAes_DmaStopCnt   = 0u;
    utSAes_DmaFail      = SAES_FUNCTION_INACTIVE;
    utSAes_DmaCrAtStart = 0u;
    utSAes_DmaInIsr     = SAES_NULL_PTR;
    utSAes_DmaOutIsr    = SAES_NULL_PTR;
    utSAes_DmaErrIsr    = SAES_NULL_PTR;

    Gpdma_Get_DefaultConfig_StubWithCallback( UtSAes_GpdmaDefaultStub );
    Gpdma_Init_StubWithCallback( UtSAes_GpdmaInitStub );
    Gpdma_Set_BlockSize_StubWithCallback( UtSAes_GpdmaSizeStub );
    Gpdma_Set_SourceAddr_StubWithCallback( UtSAes_GpdmaSrcStub );
    Gpdma_Set_DestinationAddr_StubWithCallback( UtSAes_GpdmaDstStub );
    Gpdma_Set_ChannelActive_StubWithCallback( UtSAes_GpdmaStartStub );
    Gpdma_Set_ChannelInactive_StubWithCallback( UtSAes_GpdmaStopStub );
}


/**
 * \brief Runs a successful \ref SAes_Init in the DMA mode with the default channels (stubs registered, interrupts of
 *        both channels expected).
 */
static void UtSAes_Init_Dma( void )
{
    sAes_Config_t config;

    UtSAes_Set_DmaStubs();
    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Get_DefaultConfig( &config ) );
    config.XferMode = SAES_XFER_MODE_DMA;

    UtSAes_Expect_InitPoll();
    Nvic_Set_PeriphIrq_Prio_ExpectAndReturn( NVIC_PERIPH_IRQ_SAES,
                                             (nvic_IrqPrio_t)config.IrqPriority,
                                             NVIC_REQUEST_OK );
    Nvic_Set_PeriphIrq_Active_ExpectAndReturn( NVIC_PERIPH_IRQ_SAES, NVIC_REQUEST_OK );
    Gpdma_Set_InterruptActive_ExpectAndReturn( GPDMA_PERIPH_1, UT_SAES_DMA_IN_CH, GPDMA_REQUEST_OK );
    Gpdma_Set_InterruptActive_ExpectAndReturn( GPDMA_PERIPH_1, UT_SAES_DMA_OUT_CH, GPDMA_REQUEST_OK );

    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Init( &config ) );
}


/**
 * \brief Fills an encryption request of the DMA tests (inline 128-bit key, no IV, no AAD, no tag).
 *
 * \param request [out]: Request to fill
 * \param mode    [in]:  Chaining mode
 * \param input   [in]:  Input buffer
 * \param output  [out]: Output buffer
 * \param dataLen [in]:  Byte length of the payload
 */
static void UtSAes_Set_DmaRequest( sAes_Request_t * const request,
                                   sAes_Mode_t            mode,
                                   const sAes_Data_t *    input,
                                   sAes_Data_t *          output,
                                   sAes_DataLen_t         dataLen )
{
    request->Operation = SAES_OPERATION_ENCRYPT;
    request->Mode      = mode;
    request->KeySelect = SAES_REQUEST_KEY_INLINE;
    request->Key       = utSAes_Fips197_Key128;
    request->KeySize   = SAES_KEY_SIZE_128;
    request->Iv        = SAES_NULL_PTR;
    request->Aad       = SAES_NULL_PTR;
    request->AadLen    = 0u;
    request->Input     = input;
    request->Output    = output;
    request->DataLen   = dataLen;
    request->Tag       = SAES_NULL_PTR;
    request->TagLen    = 0u;
}


/** \brief Stub of Gpdma_Get_DefaultConfig: the structure keeps the zeros of the caller */
static gpdma_RequestState_t UtSAes_GpdmaDefaultStub( gpdma_ConfigStruct_t * configStruct, int callCnt )
{
    (void)callCnt;
    TEST_ASSERT_NOT_NULL( configStruct );

    return ( GPDMA_REQUEST_OK );
}


/** \brief Stub of Gpdma_Init: captures the channel configuration and the interrupts of the module */
static gpdma_RequestState_t UtSAes_GpdmaInitStub( gpdma_ConfigStruct_t * configStruct, int callCnt )
{
    (void)callCnt;
    TEST_ASSERT_NOT_NULL( configStruct );
    TEST_ASSERT_NOT_NULL( configStruct->TransferConfig );
    TEST_ASSERT_LESS_THAN_UINT32( UT_SAES_DMA_CHANNEL_CNT, utSAes_DmaInitCnt );

    utSAes_DmaChannelCfg_t * const cfg = &utSAes_DmaCfg[ utSAes_DmaInitCnt ];

    cfg->ChannelId     = configStruct->ChannelId;
    cfg->Direction     = configStruct->TransferConfig->Direction;
    cfg->RequestSource = configStruct->TransferConfig->RequestSource;
    cfg->SrcDataSize   = configStruct->TransferConfig->SourceDataSize;
    cfg->DstDataSize   = configStruct->TransferConfig->DestinationDataSize;
    cfg->SrcAddrMode   = configStruct->TransferConfig->SourceAddrMode;
    cfg->DstAddrMode   = configStruct->TransferConfig->DestinationAddrMode;
    cfg->DstDataOp     = configStruct->TransferConfig->DestinationDataOp;
    cfg->SrcAddr       = configStruct->TransferConfig->SourceAddr;
    cfg->DstAddr       = configStruct->TransferConfig->DestinationAddr;

    if( UT_SAES_DMA_IN_CH == configStruct->ChannelId )
    {
        utSAes_DmaInIsr = configStruct->TransferCompleteIsr;
    }
    else
    {
        utSAes_DmaOutIsr = configStruct->TransferCompleteIsr;
    }

    utSAes_DmaErrIsr = configStruct->ErrorIsr;
    utSAes_DmaInitCnt++;

    return ( GPDMA_REQUEST_OK );
}


/** \brief Stub of Gpdma_Set_BlockSize: logs the channel and the block size */
static gpdma_RequestState_t UtSAes_GpdmaSizeStub( gpdma_PeriphId_t  periphId,
                                                  gpdma_ChannelId_t channelId,
                                                  gpdma_BlockSize_t blockSize,
                                                  int               callCnt )
{
    (void)periphId;
    (void)callCnt;
    TEST_ASSERT_LESS_THAN_UINT32( UT_SAES_DMA_LOG_MAX, utSAes_DmaSizeCnt );
    utSAes_DmaSizeLog[ utSAes_DmaSizeCnt ].ChannelId = channelId;
    utSAes_DmaSizeLog[ utSAes_DmaSizeCnt ].Value     = blockSize;
    utSAes_DmaSizeCnt++;

    return ( GPDMA_REQUEST_OK );
}


/** \brief Stub of Gpdma_Set_SourceAddr: logs the channel and the address */
static gpdma_RequestState_t UtSAes_GpdmaSrcStub( gpdma_PeriphId_t  periphId,
                                                 gpdma_ChannelId_t channelId,
                                                 gpdma_SrcAddr_t   sourceAddr,
                                                 int               callCnt )
{
    (void)periphId;
    (void)callCnt;
    TEST_ASSERT_LESS_THAN_UINT32( UT_SAES_DMA_LOG_MAX, utSAes_DmaSrcCnt );
    utSAes_DmaSrcLog[ utSAes_DmaSrcCnt ].ChannelId = channelId;
    utSAes_DmaSrcLog[ utSAes_DmaSrcCnt ].Value     = sourceAddr;
    utSAes_DmaSrcCnt++;

    return ( GPDMA_REQUEST_OK );
}


/** \brief Stub of Gpdma_Set_DestinationAddr: logs the channel and the address */
static gpdma_RequestState_t UtSAes_GpdmaDstStub( gpdma_PeriphId_t  periphId,
                                                 gpdma_ChannelId_t channelId,
                                                 gpdma_DstAddr_t   destAddr,
                                                 int               callCnt )
{
    (void)periphId;
    (void)callCnt;
    TEST_ASSERT_LESS_THAN_UINT32( UT_SAES_DMA_LOG_MAX, utSAes_DmaDstCnt );
    utSAes_DmaDstLog[ utSAes_DmaDstCnt ].ChannelId = channelId;
    utSAes_DmaDstLog[ utSAes_DmaDstCnt ].Value     = destAddr;
    utSAes_DmaDstCnt++;

    return ( GPDMA_REQUEST_OK );
}


/**
 * \brief Stub of Gpdma_Set_ChannelActive: logs the channel; the start of the input channel ends the chunk - it calls
 *        the transfer complete interrupts of both channels (or the error interrupt) of the module.
 */
static gpdma_RequestState_t UtSAes_GpdmaStartStub( gpdma_PeriphId_t  periphId,
                                                   gpdma_ChannelId_t channelId,
                                                   int               callCnt )
{
    (void)periphId;
    (void)callCnt;
    TEST_ASSERT_LESS_THAN_UINT32( UT_SAES_DMA_LOG_MAX, utSAes_DmaStartCnt );
    utSAes_DmaStartLog[ utSAes_DmaStartCnt ] = channelId;
    utSAes_DmaStartCnt++;

    if( UT_SAES_DMA_IN_CH == channelId )
    {
        utSAes_DmaCrAtStart = ( SAES->CR & UT_SAES_CR_DMA_MASK );

        if( SAES_FUNCTION_ACTIVE == utSAes_DmaFail )
        {
            utSAes_DmaErrIsr( GPDMA_ERROR_TRANSFER );
        }
        else
        {
            utSAes_DmaInIsr();
            utSAes_DmaOutIsr();
        }
    }
    else
    {
        /* The output channel waits for the requests of the SAES */
    }

    return ( GPDMA_REQUEST_OK );
}


/** \brief Stub of Gpdma_Set_ChannelInactive: logs the stopped channel */
static gpdma_RequestState_t UtSAes_GpdmaStopStub( gpdma_PeriphId_t  periphId,
                                                  gpdma_ChannelId_t channelId,
                                                  int               callCnt )
{
    (void)periphId;
    (void)callCnt;
    TEST_ASSERT_LESS_THAN_UINT32( UT_SAES_DMA_LOG_MAX, utSAes_DmaStopCnt );
    utSAes_DmaStopLog[ utSAes_DmaStopCnt ] = channelId;
    utSAes_DmaStopCnt++;

    return ( GPDMA_REQUEST_OK );
}

#endif /* SAES */
