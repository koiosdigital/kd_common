#pragma once

#include <esp_err.h>

#define CUSTOM_PROV_ENDPOINT "certmgr"

esp_err_t custom_prov_endpoint(uint32_t session_id, const uint8_t* inbuf, ssize_t inlen, uint8_t** outbuf, ssize_t* outlen, void* priv_data);