#pragma once

#include "esp_ds.h"
#include "stdlib.h"

typedef struct esp_ds_data_ctx {
    esp_ds_data_t* esp_ds_data;
    uint8_t efuse_key_id;
    uint16_t rsa_length_bits;
} esp_ds_data_ctx_t;

typedef enum CryptoState_t {
    CRYPTO_STATE_UNINITIALIZED,
    CRYPTO_STATE_KEY_GENERATED,
    CRYPTO_STATE_VALID_CSR,
    CRYPTO_STATE_VALID_CERT
} CryptoState_t;

esp_ds_data_ctx_t* kd_common_crypto_get_ctx();
esp_err_t kd_common_get_device_cert(char* buffer, size_t* len);
CryptoState_t kd_common_crypto_get_state();