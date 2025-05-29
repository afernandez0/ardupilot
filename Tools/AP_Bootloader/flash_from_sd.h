#pragma once

#include "AP_Bootloader_config.h"

#if AP_BOOTLOADER_FLASH_FROM_SD_ENABLED

#include <AP_HAL_ChibiOS/sdcard.h>
#include <stdbool.h>

bool flash_from_sd();
bool create_bootlog(const char *message);

#endif  // AP_BOOTLOADER_FLASH_FROM_SD_ENABLED
