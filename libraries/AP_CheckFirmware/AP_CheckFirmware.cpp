/*
  support checking board ID and firmware CRC in the bootloader
 */
#include "AP_CheckFirmware.h"
#include <AP_HAL/HAL.h>
#include <AP_Math/crc.h>


#if AP_CHECK_FIRMWARE_ENABLED


#if defined(HAL_BOOTLOADER_BUILD)

#if AP_SIGNED_FIRMWARE
#include "../../Tools/AP_Bootloader/support.h"
#include <string.h>


// Maximum bound on digest algorithm encoding around digest 
#define MAX_ENC_ALG_SZ      32

// 8 byte signature version
static const uint64_t sig_version = 30437LLU;

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

// ajfg
// Calculates the signature of the input hash and compare against
// the received signature
int int_check_signature(unsigned char *in_signature, int in_signature_length,
    unsigned char *in_digest, int in_digest_length)
{
    // encSign = in_firmware_signature (calculated)
    unsigned char   encSig[WC_SHA256_DIGEST_SIZE + MAX_ENC_ALG_SZ];
    word32          encSigLen = 0;

    // decSign = in_firmware (stored in Firmware)
    unsigned char*  decSig = nullptr;
    word32          decSigLen = 0;

    RsaKey          rsaKey;
    RsaKey*         pRsaKey = nullptr;
    word32          idx = 0;

    int ret = 0;

    // Encode digest with algorithm information as per PKCS#1.5 
    // Same algorithm as make_secure_fw.py
    encSigLen = wc_EncodeSignature(encSig, in_digest, in_digest_length, SHA256h);

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
        decSigLen = wc_RsaSSL_VerifyInline(in_signature, in_signature_length, &decSig, &rsaKey);

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

    // Free the data structures
    if (pRsaKey != nullptr)
        wc_FreeRsaKey(pRsaKey);

    return ret;
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

    // Calculate the digest (sha256) of the flash memory
    ret = wc_InitSha256(&sha);
    if (ret != 0) {
        return check_fw_result_t::FAIL_REASON_HASH_FAILED;
    }
    pSha256 = &sha;

    // The hash is calculated of the two parts of the firmware
    wc_Sha256Update(&sha, flash1, len1);
    wc_Sha256Update(&sha, flash2, len2);

    ret = wc_Sha256Final(&sha, digest);
    if (ret != 0) {
        return check_fw_result_t::FAIL_REASON_WOLF_INIT_FAILED;
    }
       
    ret = int_check_signature(const_cast<unsigned char *>(&ad->signature[sizeof(sig_version)]), 
                                ad->signature_length, digest, sizeof(digest));

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



// ajfg
#if defined(HAL_BOOTLOADER_BUILD)

extern const AP_HAL::HAL &hal;

// ajfg
const char *persistent_header = "{{PERSISTENT_START_V1}}\n";

const char *firmware_checksum_key = "fiw=";
const char *parameters_checksum_key = "def=";

/*
  Verify the checksum of the firmware and the persistent parameters
  If they do not match, boot will fail
*/
int32_t verify_checksums(void)
{
    int output = 0;

    output = verify_checksum_firmware();

    output |= verify_checksum_parameters();

    return output;
}

int32_t verify_checksum_firmware()
{
    const uint8_t *flash_address = (const uint8_t *)(FLASH_LOAD_ADDRESS + (FLASH_BOOTLOADER_LOAD_KB + APP_START_OFFSET_KB)*1024);
    
    uint32_t image_size = 0;
    uint8_t *firmware_checksum = find_firmware(image_size);

    if (firmware_checksum == nullptr) {
        return (static_cast<int32_t>(check_fw_result_t::FAIL_REASON_CHECKSUM_NOT_FOUND) * -1);
    }

    // Calculate checksum sha256 of the firmware   
    unsigned char calculated_hash[WC_SHA256_DIGEST_SIZE];

    calculate_hash(flash_address, image_size, calculated_hash);

    // Compare checksums
    if (memcmp(firmware_checksum, calculated_hash, WC_SHA256_DIGEST_SIZE) != 0) {
        // TODO
        // GCS_SEND_TEXT(MAV_SEVERITY_INFO, "Incorrect firmware checksum");
        return -6;
    }

    return 0;
}

int32_t verify_checksum_parameters()
{
    unsigned char *parameters_address = nullptr;

    uint32_t parameters_size = 0;
    uint8_t *parameters_checksum = find_parameters(parameters_size, &parameters_address);

    if (parameters_checksum == nullptr) {
        return (static_cast<int32_t>(check_fw_result_t::FAIL_REASON_CHECKSUM_NOT_FOUND) * -1);
    }

    // Calculate checksum sha256 of the firmware   
    unsigned char calculated_hash[WC_SHA256_DIGEST_SIZE];

    calculate_hash(parameters_address, parameters_size, calculated_hash);

    // Compare checksums
    if (memcmp(parameters_checksum, calculated_hash, WC_SHA256_DIGEST_SIZE) != 0) {
        // TODO
        // GCS_SEND_TEXT(MAV_SEVERITY_INFO, "Incorrect firmware checksum");
        return -6;
    }

    return 0;
}

int32_t calculate_hash(const unsigned char *in_buffer, uint32_t in_size, unsigned char *out_buffer)
{
    // Calculate checksum sha256 of the firmware   
    int ret = -1;
    wc_Sha256 sha256;

    ret = wc_InitSha256(&sha256);
    if (ret != 0) {
        // TODO
        // GCS_SEND_TEXT(MAV_SEVERITY_INFO, "Unable to initialize SHA256");
        return -3;
    }

    // Calculate the checksum of the whole firmware
    ret = wc_Sha256Update(&sha256, in_buffer, in_size);
    if (ret != 0) {
        // TODO
        // GCS_SEND_TEXT(MAV_SEVERITY_INFO, "Error calculating Sha256");
        return -4;
    }

    // unsigned char calculated_hash[WC_SHA256_DIGEST_SIZE];

    ret = wc_Sha256Final(&sha256, out_buffer);
    if (ret != 0) {
        // TODO
        // GCS_SEND_TEXT(MAV_SEVERITY_INFO, "Error calculating Sha256");
        return -5;
    }
        
    wc_Sha256Free(&sha256);

    return 0;
}

uint8_t *find_firmware(uint32_t &out_image_size)
{
    // Look for the Application Descriptor
#if AP_SIGNED_FIRMWARE
    const uint8_t sig[8] = AP_APP_DESCRIPTOR_SIGNATURE_SIGNED;
#else    
    const uint8_t sig[8] = AP_APP_DESCRIPTOR_SIGNATURE_UNSIGNED;
#endif

    const uint8_t *flash_address = (const uint8_t *)(FLASH_LOAD_ADDRESS + (FLASH_BOOTLOADER_LOAD_KB + APP_START_OFFSET_KB)*1024);
    const uint32_t flash_size = (BOARD_FLASH_SIZE - (FLASH_BOOTLOADER_LOAD_KB + APP_START_OFFSET_KB))*1024;
    const app_descriptor_signed *ad = (const app_descriptor_signed *)memmem(flash_address, flash_size-sizeof(app_descriptor_signed), sig, sizeof(sig));

    if (ad == nullptr) {
        // no application signature
        // return (static_cast<int32_t>(check_fw_result_t::FAIL_REASON_NO_APP_SIG) * -1);
        return nullptr;
    }

    /*
    Alternative:
    const uint32_t page_size = hal.flash->getpagesize(0);
    const uint32_t flash_addr = hal.flash->getpageaddr(0);
    const uint8_t *flash = (const uint8_t *)flash_addr;
    const uint8_t key[] = AP_PUBLIC_KEY_SIGNATURE;
    const struct ap_secure_data *kk = (const struct ap_secure_data *)memmem(flash, page_size, key, sizeof(key));
    */

    // Check firmware size
    if (ad->image_size > flash_size) {
        // return (static_cast<int>(check_fw_result_t::FAIL_REASON_BAD_LENGTH_APP) * -1);
        return nullptr;
    }

    // Read Firmware checksum
    uint8_t *firmware_checksum = (uint8_t *) memmem(ad, flash_size, 
                                firmware_checksum_key, sizeof(firmware_checksum_key)+WC_SHA256_DIGEST_SIZE);

    // Skip the key name; fiw=
    firmware_checksum += sizeof(firmware_checksum_key);

    out_image_size = ad->image_size;

    return firmware_checksum;
}

// It returns the address of the are where the Persistent parameters start
// and the size of the area
uint8_t *find_parameters(uint32_t &out_image_size, unsigned char **out_parameters_address)
{
    // Look for the Persistent Parameters
    const uint8_t *flash_address = (const uint8_t *)(FLASH_LOAD_ADDRESS + (FLASH_BOOTLOADER_LOAD_KB + APP_START_OFFSET_KB)*1024);
    const uint32_t flash_size = (BOARD_FLASH_SIZE - (FLASH_BOOTLOADER_LOAD_KB + APP_START_OFFSET_KB))*1024;

    unsigned char *parameters_address = (unsigned char *)memmem(flash_address, flash_size, persistent_header, sizeof(persistent_header));

    if (parameters_address == nullptr) {
        // no application signature
        // return (static_cast<int32_t>(check_fw_result_t::FAIL_REASON_CHECKSUM_NOT_FOUND) * -1);
        return nullptr;
    }

    // Skip the header
    parameters_address += sizeof(persistent_header);

    // Read Parameters checksum
    uint8_t *parameters_checksum = (uint8_t *) memmem(parameters_address, flash_size, 
                                   parameters_checksum_key, sizeof(parameters_checksum_key) + WC_SHA256_DIGEST_SIZE);

    // Read Firmware checksum
    uint8_t *firmware_checksum = (uint8_t *) memmem(parameters_address, flash_size, 
                                    firmware_checksum_key, sizeof(firmware_checksum_key)+WC_SHA256_DIGEST_SIZE);

    // Calculate the size based on the two pointers
    uint32_t parameters_size = firmware_checksum - parameters_address;

    // Skip the key name; def=
    parameters_checksum += sizeof(parameters_checksum_key);

    *out_parameters_address = parameters_address;
    out_image_size = parameters_size;

    return parameters_checksum;
}

#endif // HAL_BOOTLOADER_BUILD

#endif // AP_CHECK_FIRMWARE_ENABLED