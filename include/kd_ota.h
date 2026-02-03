#pragma once

#include "sdkconfig.h"

#ifdef ENABLE_OTA

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// OTA functions
bool kd_common_ota_has_completed_boot_check(void);
void kd_common_check_ota(void);  // Trigger manual OTA check

#ifdef __cplusplus
}
#endif

#endif // ENABLE_OTA
