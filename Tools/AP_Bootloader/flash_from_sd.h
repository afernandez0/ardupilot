#pragma once

#include "AP_Bootloader_config.h"

#include <AP_HAL_ChibiOS/sdcard.h>
#include <stdbool.h>

#if AP_BOOTLOADER_FLASH_FROM_SD_ENABLED

bool flash_from_sd();

#endif  // AP_BOOTLOADER_FLASH_FROM_SD_ENABLED

bool log_message_in_bootlog(const char *message);
bool log_message_in_bootlog(const char *message, const uint16_t message_len);

void log_bytes_in_bootlog(const uint8_t *input_hex, const uint16_t input_len);

void convert_hex_to_string(const uint8_t *input_hex, const uint16_t input_len, char *output_string);

