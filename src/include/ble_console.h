#pragma once

#include "sdkconfig.h"

#include <esp_err.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BLE_CONSOLE_ENDPOINT_NAME "kd_console"

#ifdef CONFIG_KD_COMMON_CONSOLE_ENABLE
esp_err_t ble_console_endpoint(uint32_t session_id, const uint8_t* inbuf, ssize_t inlen, uint8_t** outbuf, ssize_t* outlen, void* priv_data);
#endif // CONFIG_KD_COMMON_CONSOLE_ENABLE

#ifdef __cplusplus
}
#endif