#pragma once

#include <stdbool.h>

#define FIRMWARE_ENDPOINT_URL "https://firmware.api.koiosdigital.net"

void ota_init();
bool ota_has_completed_boot_check();
void ota_check_now();  // Trigger manual OTA check