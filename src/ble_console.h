#pragma once

#include <esp_err.h>

#define BLE_CONSOLE_ENDPOINT_NAME "kd_console"

esp_err_t ble_console_endpoint(uint32_t session_id, const uint8_t* inbuf, ssize_t inlen, uint8_t** outbuf, ssize_t* outlen, void* priv_data);