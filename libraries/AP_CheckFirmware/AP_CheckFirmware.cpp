/*
  support checking board ID and firmware CRC in the bootloader
 */
#include "AP_CheckFirmware.h"
#include <AP_HAL/HAL.h>
#include <AP_Math/crc.h>

// ajfg
#if defined(HAL_BOOTLOADER_BUILD)
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#endif

#if AP_CHECK_FIRMWARE_ENABLED

#if defined(HAL_BOOTLOADER_BUILD)

#if AP_SIGNED_FIRMWARE
#include "../../Tools/AP_Bootloader/support.h"
#include <string.h>


// Maximum bound on digest algorithm encoding around digest 
#define MAX_ENC_ALG_SZ      32


const struct ap_secure_data public_keys __attribute__((section(".apsec_data")));

/*
  return true if all public keys are zero. We allow boot of an
  unsigned firmware in that case
 */
static bool all_zero_public_keys(void)
{
    /*
      look over all public keys, if one matches then we are OK
     */
    const uint8_t zero_key[AP_PUBLIC_KEY_LEN] {};
    for (const auto &public_key : public_keys.public_key) {
        if (memcmp(public_key.key, zero_key, AP_PUBLIC_KEY_LEN) != 0) {
            return false;
        }
    }
    return true;
}

/*
  check a signature against bootloader keys
 */
// ajfg: This pragma extends the frame so the compiler does not complain about
// the extra size
#pragma GCC diagnostic error "-Wframe-larger-than=5000"
static check_fw_result_t check_firmware_signature(const app_descriptor_signed *ad,
                                                  const uint8_t *flash1, uint32_t len1,
                                                  const uint8_t *flash2, uint32_t len2)
{
    if (all_zero_public_keys()) {
        return check_fw_result_t::CHECK_FW_OK;
    }

    // 8 byte signature version
    static const uint64_t sig_version = 30437LLU;
    // ajfg. Previous  72 = 8 + 64 (sigver, sig)
    //       Now      264 = 8 + 256 (sigver, sig)
    if (ad->signature_length != 264) {
        return check_fw_result_t::FAIL_REASON_BAD_FIRMWARE_SIGNATURE;
    }
    if (memcmp((const uint8_t*)&sig_version, ad->signature, sizeof(sig_version)) != 0) {
        return check_fw_result_t::FAIL_REASON_BAD_FIRMWARE_SIGNATURE;
    }

    if (wolfCrypt_Init() != 0) {
        return check_fw_result_t::FAIL_REASON_WOLF_INIT_FAILED;
    }

    /*
      look over all public keys, if one matches then we are OK
     */
    int             ret = 0;
    wc_Sha256       sha;
    wc_Sha256*      pSha256 = nullptr;
    unsigned char   digest[WC_SHA256_DIGEST_SIZE];

    unsigned char   encSig[WC_SHA256_DIGEST_SIZE + MAX_ENC_ALG_SZ];
    word32          encSigLen = 0;
    unsigned char*  decSig = nullptr;
    word32          decSigLen = 0;

    RsaKey          rsaKey;
    RsaKey*         pRsaKey = nullptr;
    word32          idx = 0;


    // Calculate the digest (sha256) of the flash memory
    ret = wc_InitSha256(&sha);
    if (ret != 0) {
        return check_fw_result_t::FAIL_REASON_HASH_FAILED;
    }
    pSha256 = &sha;

    wc_Sha256Update(&sha, flash1, len1);
    wc_Sha256Update(&sha, flash2, len2);
    ret = wc_Sha256Final(&sha, digest);
    if (ret != 0) {
        return check_fw_result_t::FAIL_REASON_WOLF_INIT_FAILED;
    }
    
    // Encode digest with algorithm information as per PKCS#1.5 
    // Same algorithm as make_secure_fw.py
    encSigLen = wc_EncodeSignature(encSig, digest, sizeof(digest), SHA256h);

    
    // Encoded signature is ok
    if ((int) encSigLen >= 0) {
        for (const auto &public_key : public_keys.public_key) {

            // Try next key
            // Initialize the RSA key and decode the DER encoded public key
            ret = wc_InitRsaKey(&rsaKey, nullptr);
            if (ret != 0) {
                break;
            }
            pRsaKey = &rsaKey;

            // Read the next public key
            idx = 0;
            ret = wc_RsaPublicKeyDecode(public_key.key, &idx, &rsaKey, sizeof(public_key.key));
            if (ret != 0) {
                break;
            }

            // Verify the signature by decrypting the value
            // Skip signature version
            decSigLen = wc_RsaSSL_VerifyInline(const_cast<byte*>(&ad->signature[sizeof(sig_version)]), ad->signature_length,
                                               &decSig, &rsaKey);
            if ((int)decSigLen < 0) {
                ret = -1;
                break;
            }
                
            if (encSigLen != decSigLen) {
                ret = -1;
                break;
            }

            // Compare both signatures
            if (XMEMCMP(encSig, decSig, encSigLen) == 0) {
                // Signature ok
                ret = 0;
                break;
            }

            // Free the data structures
            if (pRsaKey != nullptr) {
                wc_FreeRsaKey(pRsaKey);
                pRsaKey = nullptr;
            }
        }
    }

    // Free the data structures
    if (pRsaKey != nullptr)
        wc_FreeRsaKey(pRsaKey);

    if (pSha256 != nullptr)
        wc_Sha256Free(pSha256);    
        
    wolfCrypt_Cleanup();
    // none of the public keys matched
    if (ret == 0)
        return check_fw_result_t::CHECK_FW_OK;
    else 
        return check_fw_result_t::FAIL_REASON_VERIFICATION;
}
#endif // AP_SIGNED_FIRMWARE

/*
  check firmware CRC and board ID to see if it matches
 */
static check_fw_result_t check_good_firmware_signed(void)
{
    const uint8_t sig[8] = AP_APP_DESCRIPTOR_SIGNATURE_SIGNED;
    const uint8_t *flash1 = (const uint8_t *)(FLASH_LOAD_ADDRESS + (FLASH_BOOTLOADER_LOAD_KB + APP_START_OFFSET_KB)*1024);
    const uint32_t flash_size = (BOARD_FLASH_SIZE - (FLASH_BOOTLOADER_LOAD_KB + APP_START_OFFSET_KB))*1024;
    const app_descriptor_signed *ad = (const app_descriptor_signed *)memmem(flash1, flash_size-sizeof(app_descriptor_signed), sig, sizeof(sig));
    if (ad == nullptr) {
        // no application signature
        return check_fw_result_t::FAIL_REASON_NO_APP_SIG;
    }
    // check length
    if (ad->image_size > flash_size) {
        return check_fw_result_t::FAIL_REASON_BAD_LENGTH_APP;
    }

    bool id_ok = (ad->board_id == APJ_BOARD_ID);
#ifdef ALT_BOARD_ID
    id_ok |= (ad->board_id == ALT_BOARD_ID);
#endif

    if (!id_ok) {
        return check_fw_result_t::FAIL_REASON_BAD_BOARD_ID;
    }

    const uint8_t *flash2 = (const uint8_t *)&ad->version_major;
    const uint32_t desc_len = offsetof(app_descriptor_signed, version_major) - offsetof(app_descriptor_signed, image_crc1);
    const uint32_t len1 = ((const uint8_t *)&ad->image_crc1) - flash1;

    if ((len1 + desc_len) > ad->image_size) {
        return check_fw_result_t::FAIL_REASON_BAD_LENGTH_DESCRIPTOR;
    }

    const uint32_t len2 = ad->image_size - (len1 + desc_len);
    uint32_t crc1 = crc32_small(0, flash1, len1);
    uint32_t crc2 = crc32_small(0, flash2, len2);
    if (crc1 != ad->image_crc1 || crc2 != ad->image_crc2) {
        return check_fw_result_t::FAIL_REASON_BAD_CRC;
    }

    check_fw_result_t ret = check_fw_result_t::CHECK_FW_OK;

#if AP_SIGNED_FIRMWARE
    ret = check_firmware_signature(ad, flash1, len1, flash2, len2);
#endif

    return ret;
}

/*
  check firmware CRC and board ID to see if it matches, using unsigned
  signature
 */
static check_fw_result_t check_good_firmware_unsigned(void)
{
    const uint8_t sig[8] = AP_APP_DESCRIPTOR_SIGNATURE_UNSIGNED;
    const uint8_t *flash1 = (const uint8_t *)(FLASH_LOAD_ADDRESS + (FLASH_BOOTLOADER_LOAD_KB + APP_START_OFFSET_KB)*1024);
    const uint32_t flash_size = (BOARD_FLASH_SIZE - (FLASH_BOOTLOADER_LOAD_KB + APP_START_OFFSET_KB))*1024;
    const app_descriptor_unsigned *ad = (const app_descriptor_unsigned *)memmem(flash1, flash_size-sizeof(app_descriptor_unsigned), sig, sizeof(sig));
    if (ad == nullptr) {
        // no application signature
        return check_fw_result_t::FAIL_REASON_NO_APP_SIG;
    }
    // check length
    if (ad->image_size > flash_size) {
        return check_fw_result_t::FAIL_REASON_BAD_LENGTH_APP;
    }

    bool id_ok = (ad->board_id == APJ_BOARD_ID);
#ifdef ALT_BOARD_ID
    id_ok |= (ad->board_id == ALT_BOARD_ID);
#endif

    if (!id_ok) {
        return check_fw_result_t::FAIL_REASON_BAD_BOARD_ID;
    }

    const uint8_t *flash2 = (const uint8_t *)&ad->version_major;
    const uint8_t desc_len = offsetof(app_descriptor_unsigned, version_major) - offsetof(app_descriptor_unsigned, image_crc1);
    const uint32_t len1 = ((const uint8_t *)&ad->image_crc1) - flash1;

    if ((len1 + desc_len) > ad->image_size) {
        return check_fw_result_t::FAIL_REASON_BAD_LENGTH_DESCRIPTOR;
    }

    const uint32_t len2 = ad->image_size - (len1 + desc_len);
    uint32_t crc1 = crc32_small(0, flash1, len1);
    uint32_t crc2 = crc32_small(0, flash2, len2);
    if (crc1 != ad->image_crc1 || crc2 != ad->image_crc2) {
        return check_fw_result_t::FAIL_REASON_BAD_CRC;
    }

    return check_fw_result_t::CHECK_FW_OK;
}

check_fw_result_t check_good_firmware(void)
{
#if AP_SIGNED_FIRMWARE
    // allow unsigned format if we have no public keys. This allows
    // for use of SECURE_COMMAND to remove all public keys and then
    // load of unsigned firmware
    const auto ret = check_good_firmware_signed();
    if (ret != check_fw_result_t::CHECK_FW_OK &&
        all_zero_public_keys() &&
        check_good_firmware_unsigned() == check_fw_result_t::CHECK_FW_OK) {
        return check_fw_result_t::CHECK_FW_OK;
    }
    return ret;
#else
    const auto ret = check_good_firmware_unsigned();
    if (ret != check_fw_result_t::CHECK_FW_OK) {
        // allow for signed format, not checking public keys. This
        // allows for booting of a signed firmware with an unsigned
        // bootloader, which allows for bootstrapping a system up from
        // unsigned to signed
        const auto ret2 = check_good_firmware_signed();
        if (ret2 == check_fw_result_t::CHECK_FW_OK) {
            return check_fw_result_t::CHECK_FW_OK;
        }
    }
    return ret;
#endif
}




#endif // HAL_BOOTLOADER_BUILD

#if !defined(HAL_BOOTLOADER_BUILD)
extern const AP_HAL::HAL &hal;

/*
  declare constant app_descriptor in flash
 */
extern const app_descriptor_t app_descriptor;
#if CONFIG_HAL_BOARD == HAL_BOARD_CHIBIOS
const app_descriptor_t app_descriptor __attribute__((section(".app_descriptor")));
#else
const app_descriptor_t app_descriptor;
#endif

/*
  this is needed to ensure we don't elide the app_descriptor
 */
void check_firmware_print(void)
{
    hal.console->printf("Booting %u/%u\n",
                        app_descriptor.version_major,
                        app_descriptor.version_minor);
}
#endif

#endif // AP_CHECK_FIRMWARE_ENABLED


// ajfg
#if defined(HAL_BOOTLOADER_BUILD)

#if AP_ADD_CHECKSUMS_ENABLED 
/*
  Verify the checksum of the firmware and the persistent parameters
  If they do not match, boot will fail
*/
uint32_t verify_checksums(void)
{
    const uint8_t *flash_address = (const uint8_t *)(FLASH_LOAD_ADDRESS + (FLASH_BOOTLOADER_LOAD_KB + APP_START_OFFSET_KB)*1024);
    const uint32_t flash_size = (BOARD_FLASH_SIZE - (FLASH_BOOTLOADER_LOAD_KB + APP_START_OFFSET_KB))*1024;

    // Get firmware checksum from ROMFS
    // default params checksum 32 bytes  from the end
    // firmware checksum 32 bytes before params checksum
    unsigned char firmware_checksum[WC_SHA256_DIGEST_SIZE];
    unsigned char params_checksum[WC_SHA256_DIGEST_SIZE];

    memcpy(&firmware_checksum,  (flash_address + flash_size - WC_SHA256_DIGEST_SIZE), WC_SHA256_DIGEST_SIZE);
    memcpy(&params_checksum,    (flash_address + flash_size - WC_SHA256_DIGEST_SIZE), WC_SHA256_DIGEST_SIZE);

    // Calculate checksum sha256 of the firmware
    unsigned char calculated_hash[WC_SHA256_DIGEST_SIZE];

    int ret = -1;
    wc_Sha256 sha256;

    ret = wc_InitSha256(&sha256);
    if (ret != 0) {
        // TODO: Log a message
        // printf("Failed to update the hash\n");
        // Error
        return -1;
    }

    ret = wc_Sha256Update(&sha256, flash_address, flash_size);

    if (ret != 0) {
        // TODO: Log a message
        // printf("Failed to update the hash\n");
        // Error
        return -2;
    }

    ret = wc_Sha256Final(&sha256, calculated_hash);
    if (ret != 0) {
        // TODO: Log a message
        // printf("ERROR: Hash operation failed");
        // Error
        return -3;
    }
        
    wc_Sha256Free(&sha256);

    // Compare checksums
    if (memcmp(&firmware_checksum, calculated_hash, WC_SHA256_DIGEST_SIZE) != 0) {
    // if (memcmp((const uint8_t*)&sig_version, ad->signature, sizeof(sig_version)) != 0) {
        // Error
        return -4;
    }

    return 0;
}
#endif
#endif