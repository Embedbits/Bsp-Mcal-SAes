/**
 * \defgroup SAes SAes
 * \brief SAes module
 *
 * \author Mr.Nobody
 * \file SAes_Types.h
 * \ingroup SAes
 * \brief SAes module global types definition
 *
 * This file contains the types definitions used across the module and are
 * available for other modules through the Port file. The interface is
 * identical for all families (RM0481 chapter 38, "Secure AES coprocessor (SAES)").
 *
 */

#ifndef SAES_SAES_TYPES_H
#define SAES_SAES_TYPES_H
/* ============================== INCLUDES ================================== */
#include "stdint.h"                         /* Standard integer types         */
/* ========================== SYMBOLIC CONSTANTS ============================ */

/** Null pointer definition */
#define SAES_NULL_PTR                       ( ( void* ) 0u )

/** Byte length of an AES block (every chaining mode processes 16-byte blocks) */
#define SAES_BLOCK_BYTES                     ( 16u )

/** Byte length of a 128-bit key */
#define SAES_KEY_128_BYTES                   ( 16u )

/** Byte length of a 256-bit key */
#define SAES_KEY_256_BYTES                   ( 32u )

/** Byte length of the authentication tag of GCM / GMAC / CCM */
#define SAES_TAG_MAX_BYTES                   ( 16u )

/** Count of 32-bit SAES_IVRx registers (RM0481, 38.8.9 - 38.8.12) */
#define SAES_IV_REG_CNT                       ( 4u )

/** Count of 32-bit SAES_SUSPxR registers (RM0481, 38.8.17) */
#define SAES_SUSPEND_REG_CNT                  ( 8u )

/* ========================== EXPORTED MACROS =============================== */

/* ============================== TYPEDEFS ================================== */

/** \brief Type signaling major version of SW module */
typedef uint8_t sAes_MajorVersion_t;

/** \brief Type signaling minor version of SW module */
typedef uint8_t sAes_MinorVersion_t;

/** \brief Type signaling patch version of SW module */
typedef uint8_t sAes_PatchVersion_t;

/** \brief Type signaling actual version of SW module */
typedef struct
{
    sAes_MajorVersion_t Major; /**< Major version */
    sAes_MinorVersion_t Minor; /**< Minor version */
    sAes_PatchVersion_t Patch; /**< Patch version */
}   sAes_ModuleVersion_t;

/** \brief Function status enumeration */
typedef enum
{
    SAES_FUNCTION_INACTIVE = 0u, /**< Function status is inactive */
    SAES_FUNCTION_ACTIVE         /**< Function status is active   */
}   sAes_FunctionState_t;

/** \brief Enumeration used to signal request processing state */
typedef enum
{
    SAES_REQUEST_ERROR = 0u, /**< Processing request failed  */
    SAES_REQUEST_OK          /**< Processing request succeed */
}   sAes_RequestState_t;

/** \brief One byte of a key, IV, AAD, plaintext, ciphertext or tag buffer */
typedef uint8_t sAes_Data_t;

/** \brief Byte count of a key / IV / tag buffer */
typedef uint16_t sAes_DataCnt_t;

/** \brief Byte count of a bulk payload / AAD buffer (GCM/CCM allow long messages) */
typedef uint32_t sAes_DataLen_t;

/** \brief Source of the key used by the AES cryptographic core (RM0481, SAES_CR.KEYSEL) */
typedef enum
{
    SAES_KEY_SOFTWARE = 0u, /**< Software key, written to SAES_KEYRx         */
    SAES_KEY_DHUK,          /**< Derived hardware unique key of the device   */
    SAES_KEY_BHK,           /**< Boot hardware key (loaded by the boot code) */
    SAES_KEY_DHUK_XOR_BHK,  /**< DHUK XOR-ed with BHK                        */
    SAES_KEY_SOURCE_UNUSED, /**< Not a valid key source                      */
    SAES_KEY_SOURCE_CNT     /**< Count of available key sources              */
}   sAes_KeySource_t;

/** \brief Key length used by the AES cryptographic core (RM0481, SAES_CR.KEYSIZE) */
typedef enum
{
    SAES_KEY_SIZE_128 = 0u, /**< 128-bit key                  */
    SAES_KEY_SIZE_256,      /**< 256-bit key                  */
    SAES_KEY_SIZE_UNUSED,   /**< Not a valid key size         */
    SAES_KEY_SIZE_CNT       /**< Count of available key sizes */
}   sAes_KeySize_t;

/** \brief Key handling mode (RM0481, SAES_CR.KMOD) */
typedef enum
{
    SAES_KEY_MODE_NORMAL = 0u, /**< The key is used directly by the data operations     */
    SAES_KEY_MODE_WRAPPED,     /**< The data path encrypts / decrypts an AES key itself */
    SAES_KEY_MODE_SHARED,      /**< The key is handed over to the AES peripheral        */
    SAES_KEY_MODE_UNUSED,      /**< Not a valid key mode                                */
    SAES_KEY_MODE_CNT          /**< Count of available key modes                        */
}   sAes_KeyMode_t;

/** \brief Chaining mode of the AES cryptographic core (RM0481, SAES_CR.CHMOD) */
typedef enum
{
    SAES_MODE_ECB = 0u, /**< Electronic codebook                */
    SAES_MODE_CBC,      /**< Cipher-block chaining              */
    SAES_MODE_CTR,      /**< Counter mode                       */
    SAES_MODE_GCM,      /**< Galois / counter mode              */
    SAES_MODE_GMAC,     /**< Galois message authentication code */
    SAES_MODE_CCM,      /**< Counter with CBC-MAC               */
    SAES_MODE_UNUSED,   /**< Not a valid chaining mode          */
    SAES_MODE_CNT       /**< Count of available chaining modes  */
}   sAes_Mode_t;

/** \brief Requested direction of a data operation (RM0481, SAES_CR.MODE, encryption / decryption) */
typedef enum
{
    SAES_OPERATION_ENCRYPT = 0u, /**< The cryptographic core encrypts */
    SAES_OPERATION_DECRYPT,      /**< The cryptographic core decrypts */
    SAES_OPERATION_UNUSED,       /**< Not a valid operation           */
    SAES_OPERATION_CNT           /**< Count of available operations   */
}   sAes_Operation_t;

/** \brief Selection of the key passed to a data request (\ref sAes_Request_t) */
typedef enum
{
    SAES_REQUEST_KEY_LOADED = 0u, /**< Use the key currently valid in the module (load / unwrap / share) */
    SAES_REQUEST_KEY_INLINE,      /**< Use the software key bytes given with the request                 */
    SAES_REQUEST_KEY_UNUSED,      /**< Not a valid key selection                                         */
    SAES_REQUEST_KEY_CNT          /**< Count of available key selections                                 */
}   sAes_RequestKeySelect_t;

/** \brief Target of \ref SAes_Set_KeyShare (RM0481, SAES_CR.KSHAREID) */
typedef enum
{
    SAES_SHARE_AES = 0u,      /**< The AES peripheral of the device */
    SAES_SHARE_TARGET_UNUSED, /**< Not a valid share target         */
    SAES_SHARE_TARGET_CNT     /**< Count of available share targets */
}   sAes_ShareTarget_t;

/** \brief Validity of the key currently loaded in the SAES key registers */
typedef enum
{
    SAES_KEY_STATE_NONE = 0u, /**< No key is loaded (cleared, deinitialized or never loaded) */
    SAES_KEY_STATE_VALID,     /**< A key is loaded and ready to be used / shared / wrapped   */
    SAES_KEY_STATE_ERROR      /**< The hardware reported a key error (RM0481, SAES_ISR.KEIF) */
}   sAes_KeyState_t;

/** \brief Data transfer mode of the module */
typedef enum
{
    SAES_XFER_MODE_POLL = 0u, /**< Completion is read by \ref SAes_Task            */
    SAES_XFER_MODE_ISR,       /**< Completion is signaled by the SAES interrupt    */
    SAES_XFER_MODE_DMA,       /**< Data is moved by Gpdma, completion by interrupt */
    SAES_XFER_MODE_UNUSED,    /**< Not a valid transfer mode                       */
    SAES_XFER_MODE_CNT        /**< Count of available transfer modes               */
}   sAes_XferMode_t;

/** \brief Module operating state */
typedef enum
{
    SAES_STATE_UNINIT = 0u, /**< \ref SAes_Init was not called (or failed)   */
    SAES_STATE_IDLE,        /**< Module is initialized, no operation running */
    SAES_STATE_BUSY         /**< An operation is running in the accelerator  */
}   sAes_State_t;

/** \brief Hardware transfer error reported through \ref SAes_Get_XferError (RM0481, SAES_ISR) */
typedef enum
{
    SAES_XFER_ERROR_NONE = 0u, /**< No error pending                             */
    SAES_XFER_ERROR_KEY,       /**< Key error (SAES_ISR.KEIF)                    */
    SAES_XFER_ERROR_RW,        /**< Read / write protocol error (SAES_ISR.RWEIF) */
    SAES_XFER_ERROR_RNG        /**< RNG bus error (SAES_ISR.RNGEIF)              */
}   sAes_XferError_t;

/** \brief Interrupt priority of the SAES global interrupt (same range as \ref nvic_IrqPrio_t) */
typedef uint8_t sAes_IrqPrio_t;

/** \brief Callback signature invoked by \ref SAes_Task / the SAES ISR when a request finishes */
typedef void (*sAes_CompleteCallback_t)( sAes_RequestState_t result );

/** \brief Callback signature invoked when the hardware reports an asynchronous error */
typedef void (*sAes_ErrorCallback_t)( sAes_XferError_t error );

/** \brief Module configuration passed to \ref SAes_Init */
typedef struct
{
    sAes_XferMode_t         XferMode;         /**< POLL (served by SAes_Task), ISR or DMA */
    sAes_IrqPrio_t          IrqPriority;      /**< NVIC priority used in ISR / DMA mode   */
    sAes_CompleteCallback_t CompleteCallback; /**< Called when a request finishes         */
    sAes_ErrorCallback_t    ErrorCallback;    /**< Called on an asynchronous HW error     */
}   sAes_Config_t;

/** \brief Key loaded by \ref SAes_Set_KeyLoad */
typedef struct
{
    sAes_KeySource_t     KeySource; /**< Source of the key                                       */
    sAes_KeySize_t       KeySize;   /**< Key length (also used for a hardware key source)        */
    const sAes_Data_t   *KeyBytes;  /**< Key bytes, big-endian, KeySize long (SAES_KEY_SOFTWARE) */
    sAes_FunctionState_t Protect;   /**< \ref SAES_FUNCTION_ACTIVE sets SAES_CR.KEYPROT          */
}   sAes_KeyConfig_t;

/** \brief Configuration of a key wrap / unwrap operation */
typedef struct
{
    sAes_KeySource_t   WrapKeySource;  /**< Source of the key used to wrap / unwrap     */
    sAes_KeySize_t     WrapKeySize;    /**< Length of the wrapping key                  */
    const sAes_Data_t *WrapKeyBytes;   /**< Wrapping key bytes (SAES_KEY_SOFTWARE only) */
    sAes_Mode_t        Mode;           /**< \ref SAES_MODE_ECB or \ref SAES_MODE_CBC    */
    const sAes_Data_t *Iv;             /**< 16-byte initialization vector (CBC only)    */
    sAes_KeySize_t     WrappedKeySize; /**< Length of the key being wrapped / unwrapped */
}   sAes_WrapConfig_t;

/** \brief One-shot / incremental data request (same shape for \ref SAes_Set_Process and the
 *  incremental Start / UpdateAad / Update / Finish group) */
typedef struct
{
    sAes_Operation_t        Operation; /**< Encrypt or decrypt                                      */
    sAes_Mode_t             Mode;      /**< Chaining mode                                           */
    sAes_RequestKeySelect_t KeySelect; /**< Key already loaded, or given inline below               */
    const sAes_Data_t      *Key;       /**< Software key bytes (\ref SAES_REQUEST_KEY_INLINE)       */
    sAes_KeySize_t          KeySize;   /**< Key length                                              */
    const sAes_Data_t      *Iv;        /**< 16-byte IV / counter block (CBC, CTR, GCM, CCM)         */
    const sAes_Data_t      *Aad;       /**< Additional authenticated data (GCM, GMAC, CCM)          */
    sAes_DataLen_t          AadLen;    /**< Byte length of \ref Aad                                 */
    const sAes_Data_t      *Input;     /**< Plaintext (encrypt) or ciphertext (decrypt)             */
    sAes_Data_t            *Output;    /**< Ciphertext (encrypt) or plaintext (decrypt)             */
    sAes_DataLen_t          DataLen;   /**< Byte length of \ref Input / \ref Output                 */
    sAes_Data_t            *Tag;       /**< Authentication tag (GCM, GMAC, CCM), produced / checked */
    sAes_DataCnt_t          TagLen;    /**< Byte length of \ref Tag (4 .. 16)                       */
}   sAes_Request_t;

/** \brief Suspend / resume context of an incremental request (RM0481, 38.4.9 suspend/resume) */
typedef struct
{
    uint32_t       ControlReg;                         /**< Saved SAES_CR                                         */
    uint32_t       IvReg[ SAES_IV_REG_CNT ];           /**< Saved SAES_IVRx (CBC, CTR, GCM, GMAC, CCM)            */
    uint32_t       SuspendReg[ SAES_SUSPEND_REG_CNT ]; /**< Saved SAES_SUSPxR (GCM, GMAC, CCM only)               */
    sAes_DataLen_t ProcessedBytes;                     /**< Bytes already produced, for the caller's book-keeping */
}   sAes_Context_t;

#endif /* SAES_SAES_TYPES_H */
