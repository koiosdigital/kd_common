#pragma once

#include "sdkconfig.h"
#include <stdlib.h>
#include <stdint.h>

// Sub-headers (all C-compatible)
#include "kd_wifi.h"
#include "kd_provisioning.h"
#include "kd_ntp.h"
#include "kd_mdns.h"

#ifdef CONFIG_KD_COMMON_CRYPTO_ENABLE
#include "kd_crypto.h"
#endif

#ifdef CONFIG_KD_COMMON_CONSOLE_ENABLE
#include "kd_console.h"
#endif

#ifdef CONFIG_KD_COMMON_API_ENABLE
#include "kd_api.h"
#endif

#ifdef ENABLE_OTA
#include "kd_ota.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Core initialization
void kd_common_init(void);

// Utility functions
void kd_common_reverse_bytes(uint8_t* data, size_t len);

// Device identification
char* kd_common_get_device_name(void);

#ifdef __cplusplus
}
#endif
