#include "crypto.h"

#ifndef KD_COMMON_CRYPTO_DISABLE

#include "crypto_internal.h"

#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

#include <esp_log.h>
#include <esp_efuse.h>

static const char* TAG = "kd_crypto";

// Global keygen mutex definition
namespace crypto {
SemaphoreHandle_t keygen_mutex = nullptr;
}

using namespace crypto;

//MARK: Public API

CryptoState_t kd_common_crypto_get_state() {
    CryptoState_t state = CRYPTO_STATE_UNINITIALIZED;

    if (xSemaphoreTake(keygen_mutex, pdMS_TO_TICKS(10)) == pdTRUE) {
        state = CRYPTO_STATE_KEY_GENERATED;
        xSemaphoreGive(keygen_mutex);
    }

    if (crypto_get_csr(nullptr, nullptr) == ESP_OK) {
        state = CRYPTO_STATE_VALID_CSR;
    }

    if (kd_common_get_device_cert(nullptr, nullptr) == ESP_OK) {
        state = CRYPTO_STATE_VALID_CERT;
    }

    bool has_fuses = esp_efuse_get_key_purpose(DS_KEY_BLOCK) ==
                     ESP_EFUSE_KEY_PURPOSE_HMAC_DOWN_DIGITAL_SIGNATURE;

    if (has_fuses) {
        esp_ds_data_ctx_t* ds_data_ctx = kd_common_crypto_get_ctx();
        if (ds_data_ctx == nullptr) {
            state = CRYPTO_STATE_BAD_DS_PARAMS;
        } else {
            free(ds_data_ctx->esp_ds_data);
            free(ds_data_ctx);
        }
    }

    return state;
}

esp_ds_data_ctx_t* kd_common_crypto_get_ctx() {
    return crypto_storage_get_ds_ctx();
}

esp_err_t kd_common_get_device_cert(char* buffer, size_t* len) {
    return crypto_storage_get_device_cert(buffer, len);
}

esp_err_t kd_common_clear_device_cert() {
    return crypto_storage_clear_device_cert();
}

esp_err_t kd_common_get_claim_token(char* buffer, size_t* len) {
    return crypto_storage_get_claim_token(buffer, len);
}

esp_err_t kd_common_clear_claim_token() {
    return crypto_storage_clear_claim_token();
}

//MARK: Internal API (used by console commands)

esp_err_t crypto_get_csr(char* buffer, size_t* len) {
    return crypto_storage_get_csr(buffer, len);
}

esp_err_t crypto_clear_csr() {
    return crypto_storage_clear_csr();
}

esp_err_t crypto_set_device_cert(char* buffer, size_t len) {
    return crypto_storage_set_device_cert(buffer, len);
}

esp_err_t crypto_set_claim_token(char* buffer, size_t len) {
    return crypto_storage_set_claim_token(buffer, len);
}

esp_err_t store_ds_params(uint8_t* c, uint8_t* iv, uint8_t key_id, uint16_t rsa_length) {
    return crypto_storage_store_ds_params(c, iv, key_id, rsa_length);
}

bool crypto_will_generate_key() {
    bool has_fuses = esp_efuse_get_key_purpose(DS_KEY_BLOCK) ==
                     ESP_EFUSE_KEY_PURPOSE_HMAC_DOWN_DIGITAL_SIGNATURE;
    return !has_fuses;
}

esp_err_t crypto_init() {
    return ensure_key_exists();
}

#endif // KD_COMMON_CRYPTO_DISABLE
