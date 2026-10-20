# SAES Peripheral Driver

This module provides an abstraction layer for the **secure AES coprocessor** (`SAES`) of STM32 MCUs: an AES engine
protected against the side-channel attacks that works with **keys the CPU never sees** - the keys derived from the
hardware secrets of the device, the **wrapping and unwrapping** of the keys for the storage outside of the chip and the
**sharing of a key** with the fast AES peripheral. It offers the same encryption and authenticated encryption modes as the
Aes module, the key management on the top of them, and the data transfer in DMA, interrupt or polling mode. It is a
low-level MCAL module: it owns the SAES hardware, the application and the other modules never touch the registers.

The public interface (`SAes_Port.h`, `SAes_Types.h`) is **identical for all supported families**. The implementation
for a family lives in its own branch (`Dev/<Family>` for development, `Releases/<Family>` for the released versions), so
a module or an application written against the interface does not change when the MCU family changes.

This README is the landing page and the **specification of the interface** (master). The family branches contain their
own README with everything that is specific to the family: the instances of the device, their settings and the status of
the implementation.

> **Status: design.** No implementation exists yet, the interface below is a proposal. Stories and branches follow.

---

## Intent and purpose

- The ordinary AES accelerator takes the key from the software: any code that can read the key (a bug, a debugger, a
  power analysis of the accelerator) gets it. The SAES is made for the **root of trust of the product**: the key is
  *inside* the chip. The hardware unique key of the device (DHUK, derived from the secrets of the chip) and the boot hardware
  key (BHK, stored in the protected backup registers by the boot code) can be used as the key of an operation, or XOR-ed
  together, **without any software ever reading them**.
- The typical use is the **key hierarchy**: a product key (of the license, of the update, of the file system) is
  generated outside, **wrapped** by the hardware key and stored in the flash or in a file; at run time the module
  **unwraps** it into the key registers of the SAES (the plain key is never in the memory) and either uses it
  for the secure operation, or **shares** it with the AES peripheral which then runs the bulk data at the full speed while the CPU still does not
  see the key. A copy of the device cannot decrypt the wrapped key of another device (the DHUK is unique).
- The SAES is protected against the differential power analysis (it fits the SESIP / PSA level 3 targets) and it is slower
  than the AES peripheral (hundreds of cycles per block instead of tens): it is the tool for the keys and for the short secret
  operations, not for the bulk data.
- The module hides the differences between the families: the key sources, the registers of the key handling, the security
  context rules and the DMA requests differ, the interface stays the same.

What the module is **not**: it does not generate the keys (the Rng module and the key generation of the product), it does
not store the wrapped keys (the application / the flash module) and it does not decide what is the secure world of the
system (the TrustZone configuration and the access rights belong to the system configuration). It does not replace the
Aes module for the bulk data.

---

## Concept

The SAES has three ways to get a key, `sAes_KeySource_t`:

| Source | Meaning |
|---|---|
| `SAES_KEY_SOFTWARE` | The key bytes given by the software (128 or 256 bits). The CPU knows the key. |
| `SAES_KEY_DHUK` | The derived hardware unique key of the device. Unique per device, never readable. |
| `SAES_KEY_BHK` | The boot hardware key stored in the protected backup registers by the boot code. |
| `SAES_KEY_DHUK_XOR_BHK` | The two hardware keys XOR-ed together. |

And three key handling modes, `sAes_KeyMode_t`:

| Mode | Meaning |
|---|---|
| `SAES_KEY_MODE_NORMAL` | The key is used for the encryption / decryption of the data in the SAES (the data are not keys). |
| `SAES_KEY_MODE_WRAPPED` | The data are keys: a key is **wrapped** (encrypted by the selected key, the result may leave the chip) or **unwrapped** (the wrapped key is decrypted straight **into the key registers**, the plain key never reaches the data path of the CPU). |
| `SAES_KEY_MODE_SHARED` | The key in the SAES is **sent to the AES peripheral** through the dedicated key bus (`Aes` module: `AES_KEY_SHARED`); the AES then works with a key the CPU does not know. |

Rules:

1. A hardware key (DHUK, BHK, their XOR) is selected by `sAes_KeySource_t`; the key size is 128 or 256 bits. The module reports
   an error when the key is not available (the BHK was not loaded by the boot code, the security context does not
   allow it).
2. `SAes_Set_KeyWrap( wrapConfig, plainKey, wrappedKey )` encrypts a key with the selected hardware or software key in the
   selected mode (ECB, CBC, CTR) and returns the wrapped blob. `SAes_Set_KeyUnwrap( wrapConfig, wrappedKey )` loads the
   plain key into the SAES key registers; it can be used by the SAES (`SAES_KEY_MODE_NORMAL`) or shared.
3. `SAes_Set_KeyShare( target )` hands the loaded key over to the AES peripheral. The key stays valid in the AES until the
   AES module clears it at the end of its request or until `SAes_Set_KeyClear`. A key is **bound to the security
   context** (secure / non-secure, privileged) in which it was loaded: another context cannot use it.
4. The operations with the data are the same as in the Aes module (`SAes_Set_Process` for the one-shot, `SAes_Set_Start` -
   `SAes_Set_UpdateAad` - `SAes_Set_Update` - `SAes_Set_Finish` for the incremental use, `SAes_Get_Context` /
   `SAes_Set_Context` for the suspend and resume); the modes ECB, CBC, CTR, GCM, GMAC and CCM with 128-bit and 256-bit keys.
5. A key is **valid** only while the module knows that the hardware accepted it (`SAes_Get_KeyState`); an operation without a
   valid key returns an error; the key registers are cleared by `SAes_Set_KeyClear`, by `SAes_Deinit` and after the
   error that invalidates the key.
6. Requests are accepted when the peripheral is idle; the transfer modes POLL / ISR / DMA and the callbacks are the same as
   in the Aes module. All parameters are checked before a register is written.

---

## Supported families

Every family gets its own story, its own tasks and its own branches `Dev/<Family>` and `Releases/<Family>` cut from this
master.

| Family | Branch | Peripheral | Status |
|---|---|---|---|
| STM32H5 | `Dev/STM32H5` | `SAES` on the lines with the crypto (STM32H533, H553, H573, H5F): 128 / 256-bit keys, ECB, CBC, CTR, GCM, GMAC, CCM, DHUK / BHK / XOR keys, wrapped-key and shared-key mode, protection against the side-channel attacks, security context enforcement | planned (first) |
| STM32U5 | `Dev/STM32U5` | `SAES` on the lines with the crypto | planned |
| STM32U3 | `Dev/STM32U3` | device dependent | planned |
| STM32F4, STM32F7, STM32G4, STM32H7, STM32L4 | `Dev/STM32F4` ... | no secure AES on the device - the module is a stub that returns `SAES_REQUEST_ERROR` | planned |

A function without a meaning in a family stays in the interface, returns `SAES_REQUEST_ERROR` and suppresses the unused
parameters (for example the hardware key sources of a device that has only the software key, the shared mode without the AES
peripheral).

---

## Public interface in short (proposal)

| Group | Functions |
|---|---|
| Module management | `SAes_Get_ModuleVersion`, `SAes_Init`, `SAes_Deinit`, `SAes_Task`, `SAes_Get_DefaultConfig` |
| Capability and state | `SAes_Get_Capability`, `SAes_Get_State`, `SAes_Get_KeyState`, `SAes_Get_XferError` |
| Key management | `SAes_Set_KeyLoad`, `SAes_Set_KeyWrap`, `SAes_Set_KeyUnwrap`, `SAes_Set_KeyShare`, `SAes_Set_KeyClear` |
| One-shot | `SAes_Set_Process` |
| Incremental | `SAes_Set_Start`, `SAes_Set_UpdateAad`, `SAes_Set_Update`, `SAes_Set_Finish`, `SAes_Set_Abort` |
| Suspend and resume | `SAes_Get_Context`, `SAes_Set_Context` |
| Interrupts | `SAes_Set_IrqPriority`, `SAes_Get_IrqPriority` |

```c
sAes_ModuleVersion_t SAes_Get_ModuleVersion  ( void );

sAes_RequestState_t  SAes_Init               ( const sAes_Config_t * const sAesConfig );
sAes_RequestState_t  SAes_Deinit             ( void );
void                 SAes_Task               ( void );
sAes_RequestState_t  SAes_Get_DefaultConfig  ( sAes_Config_t * const sAesConfig );

sAes_RequestState_t  SAes_Get_Capability     ( sAes_KeySource_t keySource, sAes_Mode_t mode, sAes_FunctionState_t * const supported );
sAes_RequestState_t  SAes_Get_KeyState       ( sAes_KeyState_t * const keyState );

sAes_RequestState_t  SAes_Set_KeyLoad        ( const sAes_KeyConfig_t * const keyConfig );
sAes_RequestState_t  SAes_Set_KeyWrap        ( const sAes_WrapConfig_t * const wrapConfig, const sAes_Data_t * const plainKey, sAes_Data_t * const wrappedKey );
sAes_RequestState_t  SAes_Set_KeyUnwrap      ( const sAes_WrapConfig_t * const wrapConfig, const sAes_Data_t * const wrappedKey );
sAes_RequestState_t  SAes_Set_KeyShare       ( sAes_ShareTarget_t shareTarget );
sAes_RequestState_t  SAes_Set_KeyClear       ( void );

sAes_RequestState_t  SAes_Set_Process        ( const sAes_Request_t * const request );
```

The data operation functions (`SAes_Set_Start`, `SAes_Set_Update` ...) have the same parameters as their `Aes_` counterparts.
Every function returns `SAES_REQUEST_OK` / `SAES_REQUEST_ERROR` and checks its parameters and the state of the module
before it touches a register.

| Type | Meaning |
|---|---|
| `sAes_Config_t` | Transfer mode (`SAES_XFER_MODE_POLL` / `ISR` / `DMA`), DMA channels and priorities, interrupt priority, callbacks (complete, error) |
| `sAes_KeyConfig_t` | Key source, key size, the key bytes (software key only) |
| `sAes_WrapConfig_t` | The wrapping key (source, size, software key bytes), the wrapping mode (ECB, CBC, CTR) and its IV |
| `sAes_ShareTarget_t` | `SAES_SHARE_AES` (the AES peripheral of the device) |
| `sAes_KeyState_t` | `SAES_KEY_STATE_NONE`, `SAES_KEY_STATE_VALID`, `SAES_KEY_STATE_ERROR` |
| `sAes_Request_t` | The same items as `aes_Request_t`; the key is the key that is loaded (`SAES_KEY_LOADED`) or given in the request |

---

## Usage

### Provisioning: wrap a product key with the hardware key and store the blob

```c
#include "SAes_Port.h"

const sAes_WrapConfig_t wrapConfig =
{
    .WrapKeySource = SAES_KEY_DHUK_XOR_BHK,               /* unique per device and per boot state */
    .WrapKeySize   = SAES_KEY_SIZE_256,
    .Mode          = SAES_MODE_CBC,
    .Iv            = wrapIv,
};

sAes_Data_t wrappedKey[ 32u ];

(void)SAes_Set_KeyWrap( &wrapConfig, productKey, wrappedKey );    /* wrappedKey is stored in the flash */
```

### Run time: unwrap the key and decrypt the bulk data with the fast AES

```c
(void)SAes_Set_KeyUnwrap( &wrapConfig, wrappedKey );              /* the plain key is only in the key registers */
(void)SAes_Set_KeyShare( SAES_SHARE_AES );                        /* the key goes to the AES peripheral over the key bus */

aesRequest.KeySource = AES_KEY_SHARED;                            /* Aes module: no key in the CPU */
(void)Aes_Set_Process( &aesRequest );

(void)SAes_Set_KeyClear();
```

---

## Behaviour and limits

- **No readback.** Neither the hardware keys nor the keys loaded by the unwrap can be read out by any function of the module.
  `SAes_Set_KeyWrap` returns only the encrypted blob; with a software key the module writes and clears the key registers
  but the software has the plain key by definition.
- **Security context.** A key loaded in the secure and privileged context cannot be used from the non-secure one. The
  module reports the access that the system does not allow as an error and does not retry.
- **Speed.** The SAES needs hundreds of clock cycles per block (against tens for the AES peripheral); use it for the
  keys and short messages, share the key with the AES for the bulk data.
- **Hardware keys and the boot.** The BHK exists only if the boot code loaded it; the DHUK needs the state of the product
  (the lifecycle / the debug protection) that the device requires; the family README lists the conditions.
- **Not part of the first version:** the key generation, the key storage, the derivation of the keys (KDF), the wrapping with
  the key of another device (the key exchange), the usage restrictions of the key beyond the security context, the DES.

---

## Dependencies

- **Rcc** - peripheral clock and reset
- **Nvic** - interrupt of the peripheral
- **Gpdma** - DMA transfers of the input and the output data
- **Aes** - the target of the key sharing
- **Rng** - the SAES is hardware-linked with the random number generator and draws random numbers from it for the side-channel countermeasures, so the RNG has to be running (the module makes sure of it through the API of the Rng module and reports the RNG error of the SAES)
- **RAL (Register Abstraction Layer)** - used internally to access the registers

All mandatory RCC, NVIC and DMA configurations are handled internally.

---

## Testing

- **Unit tests** (host, Unity + CMock + RegMem): the key source and mode rules (accepted / rejected combinations), the sequence
  of the key loading, wrapping, unwrapping and sharing, the key state transitions (valid, error, cleared), the clearing of
  the key registers, the data operations (the same cases as the Aes module), the rejected calls without a valid key.
- **Integration tests** (target, probe-rs): the wrap - unwrap round trip with the hardware key sources of the device, the
  failing unwrap of a blob with a different key, the shared key with the AES (the result compared with a software
  reference with the known key), the operations from the non-secure context against the security rules.

---

## Interface conventions

The module follows the common rules of the MCAL layer, so that it behaves like the other modules:

- **Lists instead of free members.** Everything that the hardware restricts (the pins, the kernel clock sources, the DMA
  channels, the triggers and the other selectable sources) is a `typedef enum` list with exactly the items that are valid
  for the device line; a pin is an item `SAES_<SIGNAL>_PIN_<INSTANCE>_P<port><pin>` and there is an `*_UNUSED` item. A choice
  that is not in the list cannot be written.
- **Own peripheral only.** The module calls only the registers / LL functions of its own peripheral. The clocks, the
  interrupts, the pins, the DMA and the EXTI lines go through the API of the Rcc, Nvic, Gpio, Gpdma and Exti modules; a
  missing function is added to that module, it is not bypassed.
- **Init verifies itself.** `SAes_Init` checks the result at the end; when it is not as required, the module is
  deinitialized and an error is returned. The waiting for the hardware is a loop on the register state with a timeout,
  never a blind delay.
- **Transfer modes.** Where the module moves data, the POLL (served by `SAes_Task`), ISR and DMA modes have the same
  configuration structure, the same request and the same callbacks (error, half transfer, transfer complete).
- **Flags and states are enums of the module** (`sAes_FunctionState_t`, `sAes_FlagState_t`), the limits and the constants are
  named, there are no magic numbers in the interface.
- **Unsupported functions stay.** A function without a meaning in a family keeps its signature, suppresses the unused
  parameters and returns `SAES_REQUEST_ERROR`.
- **Documentation.** Every function and type has a Doxygen description, the main header has the `\defgroup`.

---

## Repository layout and branches

The master holds this README and the license. The family branches (`Dev/<Family>`, `Releases/<Family>`) hold:

| Path | Content |
|---|---|
| `README.md` | README of the family: the instances of the device, specifics, errata, status |
| `SAes_Port.h`, `SAes_Types.h` | Public interface (identical in all families) |
| `SAes*.c`, `SAes.h` | Implementation of the family |
| `CMakeLists.txt` | Library `SAes_Lib` of the EmBi platform |
| `Tests/UnitTests` | Unit tests (Unity + CMock + RegMem) |
| `Tests/IntegrationTests` | Integration tests on the target (probe-rs) |

A change of the public interface is made in all families.

---

## CMake integration

```cmake
target_link_libraries( User_Lib PRIVATE SAes_Lib )
```

1. Link `SAes_Lib` to your CMake library.
2. Include `SAes_Port.h` in your project.
3. Configure the module as needed for your hardware.

---

## License

This project is licensed under the **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**.

You are free to use, modify, and share this work for **non-commercial purposes**, provided appropriate credit is given.

See [LICENSE.md](LICENSE.md) for full terms or visit [creativecommons.org/licenses/by-nc/4.0](https://creativecommons.org/licenses/by-nc/4.0/).

---

## Authors

- **Mr.Nobody** - [embedbits.com](https://embedbits.com)

Contributions are welcome! Please open a pull request.
