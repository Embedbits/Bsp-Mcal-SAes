/**
 * \author Mr.Nobody
 * \file ItTest_SAes.c
 * \ingroup SAes
 * \brief Integration tests of the secure AES coprocessor (SAES) module on target.
 *
 * SAes module runs on the MCU together with the real SAES hardware (register
 * protocol of RM0481 chapter 38), RCC, NVIC and RNG. Tests verify what the unit
 * tests (RegMem, no real AES core) cannot: the known-answer correctness of the
 * data path and the wrap / unwrap round trip with a real hardware-held key.
 *
 * Known-answer vectors:
 * - ECB AES-128 / AES-256: FIPS-197 Appendix C.1 / C.3 (nvlpubs.nist.gov,
 *   NIST.FIPS.197.pdf), fetched and cross-checked against the module's own byte
 *   order conversion (see the unit test file introduction for the same vectors).
 * - CBC AES-128: NIST SP800-38A Appendix F.2.1 (nvlpubs.nist.gov,
 *   nistspecialpublication800-38a.pdf), block #1 and all 4 blocks.
 * - CTR AES-128: NIST SP800-38A Appendix F.5.1, the first 60 bytes (a partial last block).
 * - GCM AES-128: test cases 3 and 4 of "The Galois/Counter Mode of Operation (GCM)" (McGrew / Viega): 64-byte
 *   payload without AAD, 60-byte payload with 20 bytes of AAD (partial last blocks of both phases).
 *   The vectors of the arrays were computed by a pure Python AES / GCM reference (self-checked against FIPS-197
 *   C.1 / C.3 and GCM test case 2), the published ciphertexts and tags of the documents are reproduced.
 * - Key wrap / unwrap: no public vector exists for a device-specific DHUK, so this
 *   test proves the round trip with a software wrapping key instead (wrap then
 *   unwrap must reproduce a key that encrypts the FIPS-197 plaintext to the
 *   FIPS-197 ciphertext) - the actual DHUK / BHK sources need the real device
 *   life-cycle state and are not exercised here (see the module README deviation).
 *
 * DMA transfer mode: the same vectors run with \ref SAES_XFER_MODE_DMA (GPDMA1, input channel 2, output channel 3 of
 * the default configuration); the buffers are word-aligned copies, the full blocks are moved by the DMA, the partial
 * last blocks by the CPU.
 *
 * Used resources:
 * - SAES (control, status, data, key and IV registers)
 * - GPDMA1 channels 2 and 3 (DMA transfer mode)
 * - RNG (SAES side-channel countermeasures, initialized by the test, started by SAes_Init)
 * - no external wiring
 * - lines without SAES (H503, H563): every test is ignored
 *
 * \note Waiting is bounded by number of loop iterations (no reference timer),
 *       limits are set with large margin for the default system clock.
 */

/* ============================= INCLUDES =================================== */
#include "unity.h"                          /* Unity testing framework        */
#include "IntegrationTesting.h"             /* Integration testing on target  */
#include "SAes_Port.h"                      /* Module under test              */
#include "Rng_Port.h"                       /* Random number source of the SAES */
#include "Stm32.h"                          /* Presence of SAES               */
#include "string.h"                         /* memcpy of the aligned buffers  */
/* ============================= TYPEDEFS =================================== */

/* ======================= FORWARD DECLARATIONS ============================= */

static void ItSAes_Init_Module( void );
static void ItSAes_Init_ModuleDma( void );
static void ItSAes_Set_Request ( sAes_Request_t * const request,
                                 sAes_Operation_t       operation,
                                 sAes_Mode_t            mode,
                                 const sAes_Data_t *    key,
                                 const sAes_Data_t *    iv,
                                 const sAes_Data_t *    aad,
                                 sAes_DataLen_t         aadLen,
                                 const sAes_Data_t *    input,
                                 sAes_Data_t *          output,
                                 sAes_DataLen_t         dataLen,
                                 sAes_Data_t *          tag );

/* ========================= SYMBOLIC CONSTANTS ============================= */

/** AES-128 FIPS-197 Appendix C.1 known-answer vector */
#define IT_SAES_FIPS197_KEY128_BYTES \
    0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u, \
    0x08u, 0x09u, 0x0Au, 0x0Bu, 0x0Cu, 0x0Du, 0x0Eu, 0x0Fu

#define IT_SAES_FIPS197_PLAINTEXT_BYTES \
    0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u, \
    0x88u, 0x99u, 0xAAu, 0xBBu, 0xCCu, 0xDDu, 0xEEu, 0xFFu

#define IT_SAES_FIPS197_CIPHERTEXT128_BYTES \
    0x69u, 0xC4u, 0xE0u, 0xD8u, 0x6Au, 0x7Bu, 0x04u, 0x30u, \
    0xD8u, 0xCDu, 0xB7u, 0x80u, 0x70u, 0xB4u, 0xC5u, 0x5Au

/** AES-256 FIPS-197 Appendix C.3 known-answer vector (same plaintext as C.1) */
#define IT_SAES_FIPS197_KEY256_BYTES \
    0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u, \
    0x08u, 0x09u, 0x0Au, 0x0Bu, 0x0Cu, 0x0Du, 0x0Eu, 0x0Fu, \
    0x10u, 0x11u, 0x12u, 0x13u, 0x14u, 0x15u, 0x16u, 0x17u, \
    0x18u, 0x19u, 0x1Au, 0x1Bu, 0x1Cu, 0x1Du, 0x1Eu, 0x1Fu

#define IT_SAES_FIPS197_CIPHERTEXT256_BYTES \
    0x8Eu, 0xA2u, 0xB7u, 0xCAu, 0x51u, 0x67u, 0x45u, 0xBFu, \
    0xEAu, 0xFCu, 0x49u, 0x90u, 0x4Bu, 0x49u, 0x60u, 0x89u

/** NIST SP800-38A Appendix F.2.1 CBC-AES128.Encrypt, block #1 */
#define IT_SAES_SP38A_CBC_KEY_BYTES \
    0x2Bu, 0x7Eu, 0x15u, 0x16u, 0x28u, 0xAEu, 0xD2u, 0xA6u, \
    0xABu, 0xF7u, 0x15u, 0x88u, 0x09u, 0xCFu, 0x4Fu, 0x3Cu

#define IT_SAES_SP38A_CBC_IV_BYTES \
    0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u, \
    0x08u, 0x09u, 0x0Au, 0x0Bu, 0x0Cu, 0x0Du, 0x0Eu, 0x0Fu

#define IT_SAES_SP38A_CBC_PLAINTEXT_BYTES \
    0x6Bu, 0xC1u, 0xBEu, 0xE2u, 0x2Eu, 0x40u, 0x9Fu, 0x96u, \
    0xE9u, 0x3Du, 0x7Eu, 0x11u, 0x73u, 0x93u, 0x17u, 0x2Au

#define IT_SAES_SP38A_CBC_CIPHERTEXT_BYTES \
    0x76u, 0x49u, 0xABu, 0xACu, 0x81u, 0x19u, 0xB2u, 0x46u, \
    0xCEu, 0xE9u, 0x8Eu, 0x9Bu, 0x12u, 0xE9u, 0x19u, 0x7Du

/** Byte lengths of the multi-block vectors */
#define IT_SAES_LEN_64                      ( 64u )
#define IT_SAES_LEN_60                      ( 60u )
#define IT_SAES_GCM_AAD_LEN                 ( 20u )

/** Byte length of a GCM tag */
#define IT_SAES_TAG_LEN                     ( 16u )

/** Word count of the word-aligned buffers of the DMA mode (64 bytes) */
#define IT_SAES_DMA_WORDS                   ( IT_SAES_LEN_64 / 4u )

/** Byte offset which makes a buffer not word aligned */
#define IT_SAES_UNALIGNED_OFFSET            ( 1u )

/** Software wrapping key used by the wrap / unwrap round trip (no device secret involved) */
#define IT_SAES_WRAP_KEY_BYTES \
    0xFEu, 0xDCu, 0xBAu, 0x98u, 0x76u, 0x54u, 0x32u, 0x10u, \
    0x01u, 0x23u, 0x45u, 0x67u, 0x89u, 0xABu, 0xCDu, 0xEFu

/** NIST SP800-38A F.2.1 / F.5.1 plaintext, 4 blocks (64 bytes) */
#define IT_SAES_SP38A_PLAINTEXT64_BYTES \
    0x6Bu, 0xC1u, 0xBEu, 0xE2u, 0x2Eu, 0x40u, 0x9Fu, 0x96u, \
    0xE9u, 0x3Du, 0x7Eu, 0x11u, 0x73u, 0x93u, 0x17u, 0x2Au, \
    0xAEu, 0x2Du, 0x8Au, 0x57u, 0x1Eu, 0x03u, 0xACu, 0x9Cu, \
    0x9Eu, 0xB7u, 0x6Fu, 0xACu, 0x45u, 0xAFu, 0x8Eu, 0x51u, \
    0x30u, 0xC8u, 0x1Cu, 0x46u, 0xA3u, 0x5Cu, 0xE4u, 0x11u, \
    0xE5u, 0xFBu, 0xC1u, 0x19u, 0x1Au, 0x0Au, 0x52u, 0xEFu, \
    0xF6u, 0x9Fu, 0x24u, 0x45u, 0xDFu, 0x4Fu, 0x9Bu, 0x17u, \
    0xADu, 0x2Bu, 0x41u, 0x7Bu, 0xE6u, 0x6Cu, 0x37u, 0x10u

/** NIST SP800-38A F.2.1 CBC-AES128.Encrypt ciphertext, 4 blocks */
#define IT_SAES_SP38A_CBC_CIPHERTEXT64_BYTES \
    0x76u, 0x49u, 0xABu, 0xACu, 0x81u, 0x19u, 0xB2u, 0x46u, \
    0xCEu, 0xE9u, 0x8Eu, 0x9Bu, 0x12u, 0xE9u, 0x19u, 0x7Du, \
    0x50u, 0x86u, 0xCBu, 0x9Bu, 0x50u, 0x72u, 0x19u, 0xEEu, \
    0x95u, 0xDBu, 0x11u, 0x3Au, 0x91u, 0x76u, 0x78u, 0xB2u, \
    0x73u, 0xBEu, 0xD6u, 0xB8u, 0xE3u, 0xC1u, 0x74u, 0x3Bu, \
    0x71u, 0x16u, 0xE6u, 0x9Eu, 0x22u, 0x22u, 0x95u, 0x16u, \
    0x3Fu, 0xF1u, 0xCAu, 0xA1u, 0x68u, 0x1Fu, 0xACu, 0x09u, \
    0x12u, 0x0Eu, 0xCAu, 0x30u, 0x75u, 0x86u, 0xE1u, 0xA7u

/** NIST SP800-38A F.5.1 CTR-AES128 initial counter block */
#define IT_SAES_SP38A_CTR_COUNTER_BYTES \
    0xF0u, 0xF1u, 0xF2u, 0xF3u, 0xF4u, 0xF5u, 0xF6u, 0xF7u, \
    0xF8u, 0xF9u, 0xFAu, 0xFBu, 0xFCu, 0xFDu, 0xFEu, 0xFFu

/** NIST SP800-38A F.5.1 CTR-AES128.Encrypt ciphertext of the first 60 bytes (partial last block) */
#define IT_SAES_SP38A_CTR_CIPHERTEXT60_BYTES \
    0x87u, 0x4Du, 0x61u, 0x91u, 0xB6u, 0x20u, 0xE3u, 0x26u, \
    0x1Bu, 0xEFu, 0x68u, 0x64u, 0x99u, 0x0Du, 0xB6u, 0xCEu, \
    0x98u, 0x06u, 0xF6u, 0x6Bu, 0x79u, 0x70u, 0xFDu, 0xFFu, \
    0x86u, 0x17u, 0x18u, 0x7Bu, 0xB9u, 0xFFu, 0xFDu, 0xFFu, \
    0x5Au, 0xE4u, 0xDFu, 0x3Eu, 0xDBu, 0xD5u, 0xD3u, 0x5Eu, \
    0x5Bu, 0x4Fu, 0x09u, 0x02u, 0x0Du, 0xB0u, 0x3Eu, 0xABu, \
    0x1Eu, 0x03u, 0x1Du, 0xDAu, 0x2Fu, 0xBEu, 0x03u, 0xD1u, \
    0x79u, 0x21u, 0x70u, 0xA0u

/** GCM test cases 3 / 4 (McGrew / Viega): key */
#define IT_SAES_GCM_KEY_BYTES \
    0xFEu, 0xFFu, 0xE9u, 0x92u, 0x86u, 0x65u, 0x73u, 0x1Cu, \
    0x6Du, 0x6Au, 0x8Fu, 0x94u, 0x67u, 0x30u, 0x83u, 0x08u

/** GCM test cases 3 / 4: IV (96 bits) followed by the counter value 2 (SAES_IVRx in the init phase) */
#define IT_SAES_GCM_IV_COUNTER_BYTES \
    0xCAu, 0xFEu, 0xBAu, 0xBEu, 0xFAu, 0xCEu, 0xDBu, 0xADu, \
    0xDEu, 0xCAu, 0xF8u, 0x88u, 0x00u, 0x00u, 0x00u, 0x02u

/** GCM test case 4: additional authenticated data (20 bytes) */
#define IT_SAES_GCM_AAD_BYTES \
    0xFEu, 0xEDu, 0xFAu, 0xCEu, 0xDEu, 0xADu, 0xBEu, 0xEFu, \
    0xFEu, 0xEDu, 0xFAu, 0xCEu, 0xDEu, 0xADu, 0xBEu, 0xEFu, \
    0xABu, 0xADu, 0xDAu, 0xD2u

/** GCM test case 3: plaintext (64 bytes, test case 4 uses the first 60) */
#define IT_SAES_GCM_PLAINTEXT64_BYTES \
    0xD9u, 0x31u, 0x32u, 0x25u, 0xF8u, 0x84u, 0x06u, 0xE5u, \
    0xA5u, 0x59u, 0x09u, 0xC5u, 0xAFu, 0xF5u, 0x26u, 0x9Au, \
    0x86u, 0xA7u, 0xA9u, 0x53u, 0x15u, 0x34u, 0xF7u, 0xDAu, \
    0x2Eu, 0x4Cu, 0x30u, 0x3Du, 0x8Au, 0x31u, 0x8Au, 0x72u, \
    0x1Cu, 0x3Cu, 0x0Cu, 0x95u, 0x95u, 0x68u, 0x09u, 0x53u, \
    0x2Fu, 0xCFu, 0x0Eu, 0x24u, 0x49u, 0xA6u, 0xB5u, 0x25u, \
    0xB1u, 0x6Au, 0xEDu, 0xF5u, 0xAAu, 0x0Du, 0xE6u, 0x57u, \
    0xBAu, 0x63u, 0x7Bu, 0x39u, 0x1Au, 0xAFu, 0xD2u, 0x55u

/** GCM test case 3: ciphertext (test case 4: the first 60 bytes) */
#define IT_SAES_GCM_CIPHERTEXT64_BYTES \
    0x42u, 0x83u, 0x1Eu, 0xC2u, 0x21u, 0x77u, 0x74u, 0x24u, \
    0x4Bu, 0x72u, 0x21u, 0xB7u, 0x84u, 0xD0u, 0xD4u, 0x9Cu, \
    0xE3u, 0xAAu, 0x21u, 0x2Fu, 0x2Cu, 0x02u, 0xA4u, 0xE0u, \
    0x35u, 0xC1u, 0x7Eu, 0x23u, 0x29u, 0xACu, 0xA1u, 0x2Eu, \
    0x21u, 0xD5u, 0x14u, 0xB2u, 0x54u, 0x66u, 0x93u, 0x1Cu, \
    0x7Du, 0x8Fu, 0x6Au, 0x5Au, 0xACu, 0x84u, 0xAAu, 0x05u, \
    0x1Bu, 0xA3u, 0x0Bu, 0x39u, 0x6Au, 0x0Au, 0xACu, 0x97u, \
    0x3Du, 0x58u, 0xE0u, 0x91u, 0x47u, 0x3Fu, 0x59u, 0x85u

/** GCM test case 3: tag (no AAD, 64-byte payload) */
#define IT_SAES_GCM_TAG3_BYTES \
    0x4Du, 0x5Cu, 0x2Au, 0xF3u, 0x27u, 0xCDu, 0x64u, 0xA6u, \
    0x2Cu, 0xF3u, 0x5Au, 0xBDu, 0x2Bu, 0xA6u, 0xFAu, 0xB4u

/** GCM test case 4: tag (20-byte AAD, 60-byte payload) */
#define IT_SAES_GCM_TAG4_BYTES \
    0x5Bu, 0xC9u, 0x4Fu, 0xBCu, 0x32u, 0x21u, 0xA5u, 0xDBu, \
    0x94u, 0xFAu, 0xE9u, 0x5Au, 0xE7u, 0x12u, 0x1Au, 0x47u

/* ========================== LOCAL VARIABLES =============================== */

static const sAes_Data_t itSAes_Fips197_Key128[ SAES_KEY_128_BYTES ]           = { IT_SAES_FIPS197_KEY128_BYTES };
static const sAes_Data_t itSAes_Fips197_Key256[ SAES_KEY_256_BYTES ]           = { IT_SAES_FIPS197_KEY256_BYTES };
static const sAes_Data_t itSAes_Fips197_Plaintext[ SAES_BLOCK_BYTES ]          = { IT_SAES_FIPS197_PLAINTEXT_BYTES };
static const sAes_Data_t itSAes_Fips197_Ciphertext128[ SAES_BLOCK_BYTES ] =
    { IT_SAES_FIPS197_CIPHERTEXT128_BYTES };
static const sAes_Data_t itSAes_Fips197_Ciphertext256[ SAES_BLOCK_BYTES ] =
    { IT_SAES_FIPS197_CIPHERTEXT256_BYTES };

static const sAes_Data_t itSAes_Sp38a_CbcKey[ SAES_KEY_128_BYTES ]             = { IT_SAES_SP38A_CBC_KEY_BYTES };
static const sAes_Data_t itSAes_Sp38a_CbcIv[ SAES_BLOCK_BYTES ]                = { IT_SAES_SP38A_CBC_IV_BYTES };
static const sAes_Data_t itSAes_Sp38a_CbcPlaintext[ SAES_BLOCK_BYTES ]         = { IT_SAES_SP38A_CBC_PLAINTEXT_BYTES };
static const sAes_Data_t itSAes_Sp38a_CbcCiphertext[ SAES_BLOCK_BYTES ]        = { IT_SAES_SP38A_CBC_CIPHERTEXT_BYTES };

static const sAes_Data_t itSAes_WrapKey[ SAES_KEY_128_BYTES ]                  = { IT_SAES_WRAP_KEY_BYTES };

/** Known-answer vectors: SP800-38A CBC / CTR, GCM test cases 3 and 4 (see the file introduction) */
static const sAes_Data_t itSAes_Sp38a_Plaintext64[ IT_SAES_LEN_64 ]     = { IT_SAES_SP38A_PLAINTEXT64_BYTES };
static const sAes_Data_t itSAes_Sp38a_CbcCiphertext64[ IT_SAES_LEN_64 ] = { IT_SAES_SP38A_CBC_CIPHERTEXT64_BYTES };
static const sAes_Data_t itSAes_Sp38a_CtrCounter[ SAES_BLOCK_BYTES ]    = { IT_SAES_SP38A_CTR_COUNTER_BYTES };
static const sAes_Data_t itSAes_Sp38a_CtrCiphertext60[ IT_SAES_LEN_60 ] = { IT_SAES_SP38A_CTR_CIPHERTEXT60_BYTES };
static const sAes_Data_t itSAes_Gcm_Key[ SAES_BLOCK_BYTES ]             = { IT_SAES_GCM_KEY_BYTES };
static const sAes_Data_t itSAes_Gcm_IvCounter[ SAES_BLOCK_BYTES ]       = { IT_SAES_GCM_IV_COUNTER_BYTES };
static const sAes_Data_t itSAes_Gcm_Aad[ IT_SAES_GCM_AAD_LEN ]          = { IT_SAES_GCM_AAD_BYTES };
static const sAes_Data_t itSAes_Gcm_Plaintext64[ IT_SAES_LEN_64 ]       = { IT_SAES_GCM_PLAINTEXT64_BYTES };
static const sAes_Data_t itSAes_Gcm_Ciphertext64[ IT_SAES_LEN_64 ]      = { IT_SAES_GCM_CIPHERTEXT64_BYTES };
static const sAes_Data_t itSAes_Gcm_Tag3[ SAES_BLOCK_BYTES ]            = { IT_SAES_GCM_TAG3_BYTES };
static const sAes_Data_t itSAes_Gcm_Tag4[ SAES_BLOCK_BYTES ]            = { IT_SAES_GCM_TAG4_BYTES };

/** Word-aligned buffers of the DMA mode: input, output and AAD (the DMA moves 32-bit words) */
static uint32_t itSAes_DmaIn[ IT_SAES_DMA_WORDS ];
static uint32_t itSAes_DmaOut[ IT_SAES_DMA_WORDS ];
static uint32_t itSAes_DmaAad[ IT_SAES_DMA_WORDS ];

/* ============================= TEST SETUP ================================= */

void setUp( void )
{
    /* Nothing to reset between the test cases (fresh boot, system reset) */
}


void tearDown( void )
{
    /* Peripheral state is cleared by system reset after the test case */
}

/* =============================== TESTS ==================================== */

/**
 * \brief   ECB AES-128 encryption of the FIPS-197 Appendix C.1 plaintext matches the
 *          official ciphertext on the real SAES hardware.
 *
 * \par Expected results
 * - SAes_Set_Process() returns SAES_REQUEST_OK, Output equals the FIPS-197 ciphertext.
 */
void It_SAes_Set_Process_Ecb128EncryptFips197Vector_MatchesKnownAnswer( void )
{
    sAes_Data_t output[ SAES_BLOCK_BYTES ];
    sAes_Request_t request;

#if !defined(SAES)
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* !SAES */

    ItSAes_Init_Module();

    request.Operation = SAES_OPERATION_ENCRYPT;
    request.Mode       = SAES_MODE_ECB;
    request.KeySelect  = SAES_REQUEST_KEY_INLINE;
    request.Key        = itSAes_Fips197_Key128;
    request.KeySize    = SAES_KEY_SIZE_128;
    request.Iv         = SAES_NULL_PTR;
    request.Aad        = SAES_NULL_PTR;
    request.AadLen     = 0u;
    request.Input      = itSAes_Fips197_Plaintext;
    request.Output     = output;
    request.DataLen    = SAES_BLOCK_BYTES;
    request.Tag        = SAES_NULL_PTR;
    request.TagLen     = 0u;

    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Set_Process( &request ) );
    TEST_ASSERT_EQUAL_MEMORY( itSAes_Fips197_Ciphertext128, output, SAES_BLOCK_BYTES );
}


/**
 * \brief   ECB AES-256 encryption of the FIPS-197 Appendix C.3 plaintext matches the
 *          official ciphertext on the real SAES hardware.
 *
 * \par Expected results
 * - SAes_Set_Process() returns SAES_REQUEST_OK, Output equals the FIPS-197 ciphertext.
 */
void It_SAes_Set_Process_Ecb256EncryptFips197Vector_MatchesKnownAnswer( void )
{
    sAes_Data_t output[ SAES_BLOCK_BYTES ];
    sAes_Request_t request;

#if !defined(SAES)
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* !SAES */

    ItSAes_Init_Module();

    request.Operation = SAES_OPERATION_ENCRYPT;
    request.Mode       = SAES_MODE_ECB;
    request.KeySelect  = SAES_REQUEST_KEY_INLINE;
    request.Key        = itSAes_Fips197_Key256;
    request.KeySize    = SAES_KEY_SIZE_256;
    request.Iv         = SAES_NULL_PTR;
    request.Aad        = SAES_NULL_PTR;
    request.AadLen     = 0u;
    request.Input      = itSAes_Fips197_Plaintext;
    request.Output     = output;
    request.DataLen    = SAES_BLOCK_BYTES;
    request.Tag        = SAES_NULL_PTR;
    request.TagLen     = 0u;

    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Set_Process( &request ) );
    TEST_ASSERT_EQUAL_MEMORY( itSAes_Fips197_Ciphertext256, output, SAES_BLOCK_BYTES );
}


/**
 * \brief   ECB AES-128 decryption of the FIPS-197 ciphertext reproduces the plaintext
 *          (round trip of the encryption test above, exercises the key-preparation pass).
 *
 * \par Expected results
 * - SAes_Set_Process() returns SAES_REQUEST_OK, Output equals the FIPS-197 plaintext.
 */
void It_SAes_Set_Process_Ecb128DecryptFips197Vector_ReproducesPlaintext( void )
{
    sAes_Data_t output[ SAES_BLOCK_BYTES ];
    sAes_Request_t request;

#if !defined(SAES)
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* !SAES */

    ItSAes_Init_Module();

    request.Operation = SAES_OPERATION_DECRYPT;
    request.Mode       = SAES_MODE_ECB;
    request.KeySelect  = SAES_REQUEST_KEY_INLINE;
    request.Key        = itSAes_Fips197_Key128;
    request.KeySize    = SAES_KEY_SIZE_128;
    request.Iv         = SAES_NULL_PTR;
    request.Aad        = SAES_NULL_PTR;
    request.AadLen     = 0u;
    request.Input      = itSAes_Fips197_Ciphertext128;
    request.Output     = output;
    request.DataLen    = SAES_BLOCK_BYTES;
    request.Tag        = SAES_NULL_PTR;
    request.TagLen     = 0u;

    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Set_Process( &request ) );
    TEST_ASSERT_EQUAL_MEMORY( itSAes_Fips197_Plaintext, output, SAES_BLOCK_BYTES );
}


/**
 * \brief   CBC AES-128 encryption of the NIST SP800-38A Appendix F.2.1 block #1
 *          matches the official ciphertext on the real SAES hardware.
 *
 * \par Expected results
 * - SAes_Set_Process() returns SAES_REQUEST_OK, Output equals the SP800-38A ciphertext.
 */
void It_SAes_Set_Process_Cbc128EncryptSp80038aVector_MatchesKnownAnswer( void )
{
    sAes_Data_t output[ SAES_BLOCK_BYTES ];
    sAes_Request_t request;

#if !defined(SAES)
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* !SAES */

    ItSAes_Init_Module();

    request.Operation = SAES_OPERATION_ENCRYPT;
    request.Mode       = SAES_MODE_CBC;
    request.KeySelect  = SAES_REQUEST_KEY_INLINE;
    request.Key        = itSAes_Sp38a_CbcKey;
    request.KeySize    = SAES_KEY_SIZE_128;
    request.Iv         = itSAes_Sp38a_CbcIv;
    request.Aad        = SAES_NULL_PTR;
    request.AadLen     = 0u;
    request.Input      = itSAes_Sp38a_CbcPlaintext;
    request.Output     = output;
    request.DataLen    = SAES_BLOCK_BYTES;
    request.Tag        = SAES_NULL_PTR;
    request.TagLen     = 0u;

    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Set_Process( &request ) );
    TEST_ASSERT_EQUAL_MEMORY( itSAes_Sp38a_CbcCiphertext, output, SAES_BLOCK_BYTES );
}


/**
 * \brief   A key wrapped then unwrapped with the same software wrapping key (ECB mode,
 *          RM0481 38.4.14) encrypts the FIPS-197 plaintext to the FIPS-197 ciphertext,
 *          proving the wrap / unwrap round trip on real hardware without depending on
 *          the device-specific DHUK / BHK (see the file introduction).
 *
 * \par Expected results
 * - SAes_Set_KeyWrap() and SAes_Set_KeyUnwrap() both return SAES_REQUEST_OK.
 * - SAes_Get_KeyState() reports SAES_KEY_STATE_VALID after the unwrap.
 * - SAes_Set_Process() with \ref SAES_REQUEST_KEY_LOADED encrypts \ref itSAes_Fips197_Plaintext
 *   to \ref itSAes_Fips197_Ciphertext128 using the unwrapped key.
 */
void It_SAes_KeyWrapThenUnwrap_SoftwareWrapKey_RoundTripsToOriginalKey( void )
{
    sAes_WrapConfig_t wrapConfig;
    sAes_Data_t         wrappedKey[ SAES_KEY_128_BYTES ];
    sAes_Data_t         output[ SAES_BLOCK_BYTES ];
    sAes_Request_t     request;
    sAes_KeyState_t     keyState = SAES_KEY_STATE_NONE;

#if !defined(SAES)
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* !SAES */

    ItSAes_Init_Module();

    wrapConfig.WrapKeySource  = SAES_KEY_SOFTWARE;
    wrapConfig.WrapKeySize    = SAES_KEY_SIZE_128;
    wrapConfig.WrapKeyBytes   = itSAes_WrapKey;
    wrapConfig.Mode           = SAES_MODE_ECB;
    wrapConfig.Iv             = SAES_NULL_PTR;
    wrapConfig.WrappedKeySize = SAES_KEY_SIZE_128;

    TEST_ASSERT_EQUAL( SAES_REQUEST_OK,
                       SAes_Set_KeyWrap( &wrapConfig, itSAes_Fips197_Key128, wrappedKey ) );
    TEST_ASSERT_EQUAL( SAES_REQUEST_OK,
                       SAes_Set_KeyUnwrap( &wrapConfig, wrappedKey ) );
    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Get_KeyState( &keyState ) );
    TEST_ASSERT_EQUAL( SAES_KEY_STATE_VALID, keyState );

    request.Operation = SAES_OPERATION_ENCRYPT;
    request.Mode       = SAES_MODE_ECB;
    request.KeySelect  = SAES_REQUEST_KEY_LOADED;
    request.Key        = SAES_NULL_PTR;
    request.KeySize    = SAES_KEY_SIZE_128;
    request.Iv         = SAES_NULL_PTR;
    request.Aad        = SAES_NULL_PTR;
    request.AadLen     = 0u;
    request.Input      = itSAes_Fips197_Plaintext;
    request.Output     = output;
    request.DataLen    = SAES_BLOCK_BYTES;
    request.Tag        = SAES_NULL_PTR;
    request.TagLen     = 0u;

    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Set_Process( &request ) );
    TEST_ASSERT_EQUAL_MEMORY( itSAes_Fips197_Ciphertext128, output, SAES_BLOCK_BYTES );
}


/**
 * \brief   SAes_Set_KeyShare() switches a valid software key to the shared key mode
 *          targeting the AES peripheral. The AES side of the key-sharing demo (reading
 *          the key over the dedicated hardware bus) is the Aes module's own integration
 *          test, not exercised here (Aes was not far enough along when this test was
 *          written, see the module README and the final report).
 *
 * \par Expected results
 * - SAes_Set_KeyLoad() and SAes_Set_KeyShare() both return SAES_REQUEST_OK.
 */
void It_SAes_Set_KeyShare_AfterKeyLoad_ReturnsOk( void )
{
    sAes_KeyConfig_t keyConfig;

#if !defined(SAES)
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* !SAES */

    ItSAes_Init_Module();

    keyConfig.KeySource = SAES_KEY_SOFTWARE;
    keyConfig.KeySize   = SAES_KEY_SIZE_128;
    keyConfig.KeyBytes  = itSAes_Fips197_Key128;
    keyConfig.Protect   = SAES_FUNCTION_INACTIVE;

    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Set_KeyLoad( &keyConfig ) );
    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Set_KeyShare( SAES_SHARE_AES ) );
}


/**
 * \brief   CBC AES-128 encryption of all four blocks of NIST SP800-38A F.2.1 matches the official ciphertext.
 *
 * \par Expected results
 * - SAes_Set_Process() returns SAES_REQUEST_OK, Output equals the four SP800-38A ciphertext blocks.
 */
void It_SAes_Set_Process_Cbc128Sp80038a4Blocks_MatchesKnownAnswer( void )
{
    sAes_Data_t    output[ IT_SAES_LEN_64 ];
    sAes_Request_t request;

#if !defined(SAES)
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* !SAES */

    ItSAes_Init_Module();
    ItSAes_Set_Request( &request,
                        SAES_OPERATION_ENCRYPT,
                        SAES_MODE_CBC,
                        itSAes_Sp38a_CbcKey,
                        itSAes_Sp38a_CbcIv,
                        SAES_NULL_PTR,
                        0u,
                        itSAes_Sp38a_Plaintext64,
                        output,
                        IT_SAES_LEN_64,
                        SAES_NULL_PTR );

    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Set_Process( &request ) );
    TEST_ASSERT_EQUAL_MEMORY( itSAes_Sp38a_CbcCiphertext64, output, IT_SAES_LEN_64 );
}

/**
 * \brief   CTR AES-128 encryption of the first 60 bytes of NIST SP800-38A F.5.1 (three full blocks and a partial
 *          last block) matches the official ciphertext.
 *
 * \par Expected results
 * - SAes_Set_Process() returns SAES_REQUEST_OK, Output equals the first 60 bytes of the SP800-38A ciphertext.
 */
void It_SAes_Set_Process_Ctr128Sp80038a60Bytes_MatchesKnownAnswer( void )
{
    sAes_Data_t    output[ IT_SAES_LEN_60 ];
    sAes_Request_t request;

#if !defined(SAES)
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* !SAES */

    ItSAes_Init_Module();
    ItSAes_Set_Request( &request,
                        SAES_OPERATION_ENCRYPT,
                        SAES_MODE_CTR,
                        itSAes_Sp38a_CbcKey,
                        itSAes_Sp38a_CtrCounter,
                        SAES_NULL_PTR,
                        0u,
                        itSAes_Sp38a_Plaintext64,
                        output,
                        IT_SAES_LEN_60,
                        SAES_NULL_PTR );

    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Set_Process( &request ) );
    TEST_ASSERT_EQUAL_MEMORY( itSAes_Sp38a_CtrCiphertext60, output, IT_SAES_LEN_60 );
}


/**
 * \brief   GCM AES-128 encryption of test case 3 (64-byte payload, no AAD) matches the published ciphertext and tag.
 *
 * \par Expected results
 * - SAes_Set_Process() returns SAES_REQUEST_OK, Output and Tag equal the test case 3 ciphertext and tag.
 */
void It_SAes_Set_Process_Gcm128Tc3Encrypt_MatchesKnownAnswer( void )
{
    sAes_Data_t    output[ IT_SAES_LEN_64 ];
    sAes_Data_t    tag[ IT_SAES_TAG_LEN ];
    sAes_Request_t request;

#if !defined(SAES)
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* !SAES */

    ItSAes_Init_Module();
    ItSAes_Set_Request( &request,
                        SAES_OPERATION_ENCRYPT,
                        SAES_MODE_GCM,
                        itSAes_Gcm_Key,
                        itSAes_Gcm_IvCounter,
                        SAES_NULL_PTR,
                        0u,
                        itSAes_Gcm_Plaintext64,
                        output,
                        IT_SAES_LEN_64,
                        tag );

    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Set_Process( &request ) );
    TEST_ASSERT_EQUAL_MEMORY( itSAes_Gcm_Ciphertext64, output, IT_SAES_LEN_64 );
    TEST_ASSERT_EQUAL_MEMORY( itSAes_Gcm_Tag3, tag, IT_SAES_TAG_LEN );
}


/**
 * \brief   GCM AES-128 encryption of test case 4 (20-byte AAD, 60-byte payload: partial last blocks of the header and
 *          of the payload) matches the published ciphertext and tag.
 *
 * \par Expected results
 * - SAes_Set_Process() returns SAES_REQUEST_OK, Output and Tag equal the test case 4 ciphertext and tag (the tag
 *   needs SAES_CR.NPBLB for the partial last payload block, RM0481 38.4.11).
 */
void It_SAes_Set_Process_Gcm128Tc4Encrypt_MatchesKnownAnswer( void )
{
    sAes_Data_t    output[ IT_SAES_LEN_60 ];
    sAes_Data_t    tag[ IT_SAES_TAG_LEN ];
    sAes_Request_t request;

#if !defined(SAES)
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* !SAES */

    ItSAes_Init_Module();
    ItSAes_Set_Request( &request,
                        SAES_OPERATION_ENCRYPT,
                        SAES_MODE_GCM,
                        itSAes_Gcm_Key,
                        itSAes_Gcm_IvCounter,
                        itSAes_Gcm_Aad,
                        IT_SAES_GCM_AAD_LEN,
                        itSAes_Gcm_Plaintext64,
                        output,
                        IT_SAES_LEN_60,
                        tag );

    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Set_Process( &request ) );
    TEST_ASSERT_EQUAL_MEMORY( itSAes_Gcm_Ciphertext64, output, IT_SAES_LEN_60 );
    TEST_ASSERT_EQUAL_MEMORY( itSAes_Gcm_Tag4, tag, IT_SAES_TAG_LEN );
}


/**
 * \brief   GCM AES-128 decryption of test case 4 reproduces the plaintext and computes the published tag.
 *
 * \par Expected results
 * - SAes_Set_Process() returns SAES_REQUEST_OK, Output equals the first 60 bytes of the plaintext, Tag equals the
 *   test case 4 tag.
 */
void It_SAes_Set_Process_Gcm128Tc4Decrypt_ReproducesPlaintextAndTag( void )
{
    sAes_Data_t    output[ IT_SAES_LEN_60 ];
    sAes_Data_t    tag[ IT_SAES_TAG_LEN ];
    sAes_Request_t request;

#if !defined(SAES)
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* !SAES */

    ItSAes_Init_Module();
    ItSAes_Set_Request( &request,
                        SAES_OPERATION_DECRYPT,
                        SAES_MODE_GCM,
                        itSAes_Gcm_Key,
                        itSAes_Gcm_IvCounter,
                        itSAes_Gcm_Aad,
                        IT_SAES_GCM_AAD_LEN,
                        itSAes_Gcm_Ciphertext64,
                        output,
                        IT_SAES_LEN_60,
                        tag );

    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Set_Process( &request ) );
    TEST_ASSERT_EQUAL_MEMORY( itSAes_Gcm_Plaintext64, output, IT_SAES_LEN_60 );
    TEST_ASSERT_EQUAL_MEMORY( itSAes_Gcm_Tag4, tag, IT_SAES_TAG_LEN );
}


/*------------------------------- DMA transfer mode --------------------------*/

/**
 * \brief   DMA mode: ECB AES-128 encryption and decryption of the FIPS-197 C.1 block (one block moved by the DMA).
 *
 * \par Expected results
 * - SAes_Set_Process() returns SAES_REQUEST_OK, the ciphertext and then the plaintext of FIPS-197 C.1.
 */
void It_SAes_Dma_Ecb128Fips197_EncryptsAndDecrypts( void )
{
    sAes_Request_t request;

#if !defined(SAES)
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* !SAES */

    ItSAes_Init_ModuleDma();
    (void)memcpy( itSAes_DmaIn, itSAes_Fips197_Plaintext, SAES_BLOCK_BYTES );
    ItSAes_Set_Request( &request,
                        SAES_OPERATION_ENCRYPT,
                        SAES_MODE_ECB,
                        itSAes_Fips197_Key128,
                        SAES_NULL_PTR,
                        SAES_NULL_PTR,
                        0u,
                        (const sAes_Data_t *)itSAes_DmaIn,
                        (sAes_Data_t *)itSAes_DmaOut,
                        SAES_BLOCK_BYTES,
                        SAES_NULL_PTR );
    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Set_Process( &request ) );
    TEST_ASSERT_EQUAL_MEMORY( itSAes_Fips197_Ciphertext128, itSAes_DmaOut, SAES_BLOCK_BYTES );

    (void)memcpy( itSAes_DmaIn, itSAes_Fips197_Ciphertext128, SAES_BLOCK_BYTES );
    request.Operation = SAES_OPERATION_DECRYPT;
    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Set_Process( &request ) );
    TEST_ASSERT_EQUAL_MEMORY( itSAes_Fips197_Plaintext, itSAes_DmaOut, SAES_BLOCK_BYTES );
}


/**
 * \brief   DMA mode: CBC AES-128 encryption of the four blocks of NIST SP800-38A F.2.1.
 *
 * \par Expected results
 * - SAes_Set_Process() returns SAES_REQUEST_OK, the four SP800-38A ciphertext blocks.
 */
void It_SAes_Dma_Cbc128Sp80038a4Blocks_MatchesKnownAnswer( void )
{
    sAes_Request_t request;

#if !defined(SAES)
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* !SAES */

    ItSAes_Init_ModuleDma();
    (void)memcpy( itSAes_DmaIn, itSAes_Sp38a_Plaintext64, IT_SAES_LEN_64 );
    ItSAes_Set_Request( &request,
                        SAES_OPERATION_ENCRYPT,
                        SAES_MODE_CBC,
                        itSAes_Sp38a_CbcKey,
                        itSAes_Sp38a_CbcIv,
                        SAES_NULL_PTR,
                        0u,
                        (const sAes_Data_t *)itSAes_DmaIn,
                        (sAes_Data_t *)itSAes_DmaOut,
                        IT_SAES_LEN_64,
                        SAES_NULL_PTR );

    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Set_Process( &request ) );
    TEST_ASSERT_EQUAL_MEMORY( itSAes_Sp38a_CbcCiphertext64, itSAes_DmaOut, IT_SAES_LEN_64 );
}


/**
 * \brief   DMA mode: CTR AES-128 encryption of the first 60 bytes of NIST SP800-38A F.5.1 (48 bytes by the DMA, the
 *          partial last block by the CPU).
 *
 * \par Expected results
 * - SAes_Set_Process() returns SAES_REQUEST_OK, the first 60 bytes of the SP800-38A ciphertext.
 */
void It_SAes_Dma_Ctr128Sp80038a60Bytes_MatchesKnownAnswer( void )
{
    sAes_Request_t request;

#if !defined(SAES)
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* !SAES */

    ItSAes_Init_ModuleDma();
    (void)memcpy( itSAes_DmaIn, itSAes_Sp38a_Plaintext64, IT_SAES_LEN_60 );
    ItSAes_Set_Request( &request,
                        SAES_OPERATION_ENCRYPT,
                        SAES_MODE_CTR,
                        itSAes_Sp38a_CbcKey,
                        itSAes_Sp38a_CtrCounter,
                        SAES_NULL_PTR,
                        0u,
                        (const sAes_Data_t *)itSAes_DmaIn,
                        (sAes_Data_t *)itSAes_DmaOut,
                        IT_SAES_LEN_60,
                        SAES_NULL_PTR );

    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Set_Process( &request ) );
    TEST_ASSERT_EQUAL_MEMORY( itSAes_Sp38a_CtrCiphertext60, itSAes_DmaOut, IT_SAES_LEN_60 );
}


/**
 * \brief   DMA mode: GCM AES-128 encryption of test case 3 (64-byte payload by the DMA, no AAD).
 *
 * \par Expected results
 * - SAes_Set_Process() returns SAES_REQUEST_OK, the test case 3 ciphertext and tag.
 */
void It_SAes_Dma_Gcm128Tc3Encrypt_MatchesKnownAnswer( void )
{
    sAes_Data_t    tag[ IT_SAES_TAG_LEN ];
    sAes_Request_t request;

#if !defined(SAES)
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* !SAES */

    ItSAes_Init_ModuleDma();
    (void)memcpy( itSAes_DmaIn, itSAes_Gcm_Plaintext64, IT_SAES_LEN_64 );
    ItSAes_Set_Request( &request,
                        SAES_OPERATION_ENCRYPT,
                        SAES_MODE_GCM,
                        itSAes_Gcm_Key,
                        itSAes_Gcm_IvCounter,
                        SAES_NULL_PTR,
                        0u,
                        (const sAes_Data_t *)itSAes_DmaIn,
                        (sAes_Data_t *)itSAes_DmaOut,
                        IT_SAES_LEN_64,
                        tag );

    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Set_Process( &request ) );
    TEST_ASSERT_EQUAL_MEMORY( itSAes_Gcm_Ciphertext64, itSAes_DmaOut, IT_SAES_LEN_64 );
    TEST_ASSERT_EQUAL_MEMORY( itSAes_Gcm_Tag3, tag, IT_SAES_TAG_LEN );
}


/**
 * \brief   DMA mode: GCM AES-128 encryption of test case 4 (AAD: 16 bytes by the DMA and 4 by the CPU; payload: 48
 *          bytes by the DMA and the partial last block with SAES_CR.NPBLB by the CPU).
 *
 * \par Expected results
 * - SAes_Set_Process() returns SAES_REQUEST_OK, the test case 4 ciphertext and tag.
 */
void It_SAes_Dma_Gcm128Tc4Encrypt_MatchesKnownAnswer( void )
{
    sAes_Data_t    tag[ IT_SAES_TAG_LEN ];
    sAes_Request_t request;

#if !defined(SAES)
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* !SAES */

    ItSAes_Init_ModuleDma();
    (void)memcpy( itSAes_DmaIn, itSAes_Gcm_Plaintext64, IT_SAES_LEN_60 );
    (void)memcpy( itSAes_DmaAad, itSAes_Gcm_Aad, IT_SAES_GCM_AAD_LEN );
    ItSAes_Set_Request( &request,
                        SAES_OPERATION_ENCRYPT,
                        SAES_MODE_GCM,
                        itSAes_Gcm_Key,
                        itSAes_Gcm_IvCounter,
                        (const sAes_Data_t *)itSAes_DmaAad,
                        IT_SAES_GCM_AAD_LEN,
                        (const sAes_Data_t *)itSAes_DmaIn,
                        (sAes_Data_t *)itSAes_DmaOut,
                        IT_SAES_LEN_60,
                        tag );

    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Set_Process( &request ) );
    TEST_ASSERT_EQUAL_MEMORY( itSAes_Gcm_Ciphertext64, itSAes_DmaOut, IT_SAES_LEN_60 );
    TEST_ASSERT_EQUAL_MEMORY( itSAes_Gcm_Tag4, tag, IT_SAES_TAG_LEN );
}


/**
 * \brief   DMA mode: GCM AES-128 decryption of test case 4 reproduces the plaintext and the published tag.
 *
 * \par Expected results
 * - SAes_Set_Process() returns SAES_REQUEST_OK, the first 60 bytes of the plaintext, the test case 4 tag.
 */
void It_SAes_Dma_Gcm128Tc4Decrypt_ReproducesPlaintextAndTag( void )
{
    sAes_Data_t    tag[ IT_SAES_TAG_LEN ];
    sAes_Request_t request;

#if !defined(SAES)
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* !SAES */

    ItSAes_Init_ModuleDma();
    (void)memcpy( itSAes_DmaIn, itSAes_Gcm_Ciphertext64, IT_SAES_LEN_60 );
    (void)memcpy( itSAes_DmaAad, itSAes_Gcm_Aad, IT_SAES_GCM_AAD_LEN );
    ItSAes_Set_Request( &request,
                        SAES_OPERATION_DECRYPT,
                        SAES_MODE_GCM,
                        itSAes_Gcm_Key,
                        itSAes_Gcm_IvCounter,
                        (const sAes_Data_t *)itSAes_DmaAad,
                        IT_SAES_GCM_AAD_LEN,
                        (const sAes_Data_t *)itSAes_DmaIn,
                        (sAes_Data_t *)itSAes_DmaOut,
                        IT_SAES_LEN_60,
                        tag );

    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Set_Process( &request ) );
    TEST_ASSERT_EQUAL_MEMORY( itSAes_Gcm_Plaintext64, itSAes_DmaOut, IT_SAES_LEN_60 );
    TEST_ASSERT_EQUAL_MEMORY( itSAes_Gcm_Tag4, tag, IT_SAES_TAG_LEN );
}


/**
 * \brief   DMA mode: a request whose buffer of a full block is not word aligned is rejected before a register is
 *          touched; the next aligned request runs.
 *
 * \par Expected results
 * - SAes_Set_Process() returns SAES_REQUEST_ERROR for the input at a byte offset of 1, SAES_REQUEST_OK and the
 *   FIPS-197 C.1 ciphertext for the aligned input afterwards.
 */
void It_SAes_Dma_UnalignedBuffer_RejectedThenAlignedRuns( void )
{
    sAes_Request_t request;

#if !defined(SAES)
    TEST_IGNORE_MESSAGE( "MCU without SAES" );
#endif /* !SAES */

    ItSAes_Init_ModuleDma();
    (void)memcpy( itSAes_DmaIn, itSAes_Fips197_Plaintext, SAES_BLOCK_BYTES );
    ItSAes_Set_Request( &request,
                        SAES_OPERATION_ENCRYPT,
                        SAES_MODE_ECB,
                        itSAes_Fips197_Key128,
                        SAES_NULL_PTR,
                        SAES_NULL_PTR,
                        0u,
                        &( (const sAes_Data_t *)itSAes_DmaIn )[ IT_SAES_UNALIGNED_OFFSET ],
                        (sAes_Data_t *)itSAes_DmaOut,
                        SAES_BLOCK_BYTES,
                        SAES_NULL_PTR );
    TEST_ASSERT_EQUAL( SAES_REQUEST_ERROR, SAes_Set_Process( &request ) );

    request.Input = (const sAes_Data_t *)itSAes_DmaIn;
    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Set_Process( &request ) );
    TEST_ASSERT_EQUAL_MEMORY( itSAes_Fips197_Ciphertext128, itSAes_DmaOut, SAES_BLOCK_BYTES );
}

/* =========================== LOCAL FUNCTIONS ================================ */

/**
 * \brief Initializes the Rng (SAes_Init starts it through Rng_Set_ExecActive, which needs the initialized Rng) and
 *        then the module in POLL mode with the default configuration.
 */
static void ItSAes_Init_Module( void )
{
    sAes_Config_t      config;
    rng_ConfigStruct_t rngConfig;

    TEST_ASSERT_EQUAL( RNG_REQUEST_OK, Rng_Get_DefaultConfig( &rngConfig ) );
    TEST_ASSERT_EQUAL( RNG_REQUEST_OK, Rng_Init( &rngConfig ) );

    (void)SAes_Get_DefaultConfig( &config );
    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Init( &config ) );
}


/**
 * \brief Initializes the Rng and then the module in the DMA transfer mode (default Gpdma controller and channels).
 */
static void ItSAes_Init_ModuleDma( void )
{
    sAes_Config_t      config;
    rng_ConfigStruct_t rngConfig;

    TEST_ASSERT_EQUAL( RNG_REQUEST_OK, Rng_Get_DefaultConfig( &rngConfig ) );
    TEST_ASSERT_EQUAL( RNG_REQUEST_OK, Rng_Init( &rngConfig ) );

    (void)SAes_Get_DefaultConfig( &config );
    config.XferMode = SAES_XFER_MODE_DMA;
    TEST_ASSERT_EQUAL( SAES_REQUEST_OK, SAes_Init( &config ) );
}


/**
 * \brief Fills a data request with an inline key of 128 bits.
 *
 * \param request   [out]: Request to fill
 * \param operation [in]:  Encrypt or decrypt
 * \param mode      [in]:  Chaining mode
 * \param key       [in]:  128-bit software key
 * \param iv        [in]:  16-byte IV / counter block (NULL for ECB)
 * \param aad       [in]:  Additional authenticated data (NULL without AAD)
 * \param aadLen    [in]:  Byte length of \p aad
 * \param input     [in]:  Input data
 * \param output    [out]: Output data
 * \param dataLen   [in]:  Byte length of \p input / \p output
 * \param tag       [out]: 16-byte tag buffer (NULL for the modes without a tag)
 */
static void ItSAes_Set_Request( sAes_Request_t * const request,
                                sAes_Operation_t       operation,
                                sAes_Mode_t            mode,
                                const sAes_Data_t *    key,
                                const sAes_Data_t *    iv,
                                const sAes_Data_t *    aad,
                                sAes_DataLen_t         aadLen,
                                const sAes_Data_t *    input,
                                sAes_Data_t *          output,
                                sAes_DataLen_t         dataLen,
                                sAes_Data_t *          tag )
{
    request->Operation = operation;
    request->Mode      = mode;
    request->KeySelect = SAES_REQUEST_KEY_INLINE;
    request->Key       = key;
    request->KeySize   = SAES_KEY_SIZE_128;
    request->Iv        = iv;
    request->Aad       = aad;
    request->AadLen    = aadLen;
    request->Input     = input;
    request->Output    = output;
    request->DataLen   = dataLen;
    request->Tag       = tag;

    if( SAES_NULL_PTR != tag )
    {
        request->TagLen = IT_SAES_TAG_LEN;
    }
    else
    {
        request->TagLen = 0u;
    }
}
