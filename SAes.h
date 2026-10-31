/**
 * \author Mr.Nobody
 * \file SAes.h
 * \ingroup SAes
 * \brief SAes module common functionality header file.
 *
 * This file contains the register field values used internally by the module, taken
 * from RM0481 Rev 5, chapter 38 "Secure AES coprocessor (SAES)", section 38.8.1
 * "SAES control register (SAES_CR)". The CMSIS device header only gives the position
 * and the mask of every field (`AES_CR_KEYSEL_Msk`, ...), not the meaning of each
 * value inside a field: those sub-values below were read from the RM0481 reference
 * manual text (both a plain and a layout-preserving extraction agree) and cross-checked
 * against the CMSIS bit positions (`AES_CR_KEYSEL_Pos` = 28,
 * `AES_CR_KMOD_Pos` = 24, `AES_CR_KSHAREID_Pos` = 26, `AES_CR_CHMOD_Msk` = 0x803 << 5,
 * i.e. bits 16, 6:5 - matching the RM0481 bit picture exactly).
 *
 */

#ifndef SAES_SAES_H
#define SAES_SAES_H

#ifdef __cplusplus
extern "C" {
#endif

/* ============================= INCLUDES =================================== */
#include "SAes_Types.h"                      /* Module types definitions       */
/* ============================= TYPEDEFS =================================== */

/* ========================= SYMBOLIC CONSTANTS ============================= */

/** \name SAES_CR.KEYSEL[2:0] - key selection (RM0481, 38.8.1) */
/**@{*/
#define SAES_CR_KEYSEL_SOFTWARE_RAW          ( 0x0u ) /**< Software key, loaded in SAES_KEYRx    */
#define SAES_CR_KEYSEL_DHUK_RAW              ( 0x1u ) /**< Derived hardware unique key           */
#define SAES_CR_KEYSEL_BHK_RAW               ( 0x2u ) /**< Boot hardware key                     */
#define SAES_CR_KEYSEL_DHUK_XOR_BHK_RAW      ( 0x4u ) /**< XOR of DHUK and BHK                   */
/**@}*/

/** \name SAES_CR.KSHAREID[1:0] - key share identification (RM0481, 38.8.1) */
/**@{*/
#define SAES_CR_KSHAREID_AES_RAW             ( 0x0u ) /**< AES peripheral */
/**@}*/

/** \name SAES_CR.KMOD[1:0] - key mode selection (RM0481, 38.8.1) */
/**@{*/
#define SAES_CR_KMOD_NORMAL_RAW              ( 0x0u ) /**< Key registers freely usable               */
#define SAES_CR_KMOD_WRAPPED_RAW             ( 0x1u ) /**< Key registers hold a key to wrap / unwrap  */
#define SAES_CR_KMOD_SHARED_RAW              ( 0x2u ) /**< Key is shared with the KSHAREID peripheral */
/**@}*/

/** \name SAES_CR.CHMOD[2:0] - chaining mode (RM0481, 38.8.1) */
/**@{*/
#define SAES_CR_CHMOD_ECB_RAW                ( 0x0u )
#define SAES_CR_CHMOD_CBC_RAW                ( 0x1u )
#define SAES_CR_CHMOD_CTR_RAW                ( 0x2u )
#define SAES_CR_CHMOD_GCM_RAW                ( 0x3u ) /**< Also used for GMAC */
#define SAES_CR_CHMOD_CCM_RAW                ( 0x4u )
/**@}*/

/** \name SAES_CR.MODE[1:0] - operating mode (RM0481, 38.8.1) */
/**@{*/
#define SAES_CR_MODE_ENCRYPT_RAW             ( 0x0u )
#define SAES_CR_MODE_KEY_DERIVATION_RAW      ( 0x1u ) /**< Key preparation before ECB/CBC decryption */
#define SAES_CR_MODE_DECRYPT_RAW             ( 0x2u )
/**@}*/

/** \name SAES_CR.DATATYPE[1:0] - data swapping (RM0481, 38.8.1) */
/**@{*/
#define SAES_CR_DATATYPE_NONE_RAW            ( 0x0u ) /**< No swapping, 32-bit data (used throughout) */
/**@}*/

/** \name SAES_CR.GCMPH[1:0] - GCM / GMAC / CCM phase (RM0481, 38.8.1) */
/**@{*/
#define SAES_CR_GCMPH_INIT_RAW               ( 0x0u )
#define SAES_CR_GCMPH_HEADER_RAW             ( 0x1u )
#define SAES_CR_GCMPH_PAYLOAD_RAW            ( 0x2u )
#define SAES_CR_GCMPH_FINAL_RAW              ( 0x3u )
/**@}*/

/** \brief Initial value of the 32-bit counter field of a CTR mode IV (RM0481, Table 372) */
#define SAES_CTR_INITIAL_COUNTER_RAW         ( 0x00000001u )

/** \brief Bounded iteration count used by every busy/ready/CCF wait loop on SAES_SR / SAES_ISR */
#define SAES_REG_TIMEOUT_RAW                 ( 0x100000u )

/** \brief Count of 32-bit words transferred per AES block (RM0481, 38.8.3: 4 sequential writes) */
#define SAES_BLOCK_WORDS                     ( 4u )

/** \brief Mask covering every bit of a 32-bit register (full-width read / write) */
#define SAES_REG_FULL_MASK                   ( 0xFFFFFFFFu )

/** \brief Bits in one byte, used by every big-endian byte / bit-length conversion */
#define SAES_BITS_PER_BYTE                   ( 8u )

#ifdef __cplusplus
}
#endif

#endif /* SAES_SAES_H */
