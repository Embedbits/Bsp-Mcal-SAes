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
 *   nistspecialpublication800-38a.pdf), block #1.
 * - Key wrap / unwrap: no public vector exists for a device-specific DHUK, so this
 *   test proves the round trip with a software wrapping key instead (wrap then
 *   unwrap must reproduce a key that encrypts the FIPS-197 plaintext to the
 *   FIPS-197 ciphertext) - the actual DHUK / BHK sources need the real device
 *   life-cycle state and are not exercised here (see the module README deviation).
 *
 * Used resources:
 * - SAES (control, status, data, key and IV registers)
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
/* ============================= TYPEDEFS =================================== */

/* ======================= FORWARD DECLARATIONS ============================= */

static void ItSAes_Init_Module( void );

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

/** Software wrapping key used by the wrap / unwrap round trip (no device secret involved) */
#define IT_SAES_WRAP_KEY_BYTES \
    0xFEu, 0xDCu, 0xBAu, 0x98u, 0x76u, 0x54u, 0x32u, 0x10u, \
    0x01u, 0x23u, 0x45u, 0x67u, 0x89u, 0xABu, 0xCDu, 0xEFu

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
