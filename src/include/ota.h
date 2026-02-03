#pragma once

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FIRMWARE_ENDPOINT_URL "https://firmware.api.koiosdigital.net"

void ota_init(void);
bool ota_has_completed_boot_check(void);
void ota_check_now(void);  // Trigger manual OTA check

#ifdef __cplusplus
}
#endif