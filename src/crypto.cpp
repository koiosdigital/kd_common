#include "crypto.h"

#ifdef CONFIG_KD_COMMON_CRYPTO_ENABLE

#include "crypto_internal.h"
#include "crypto_console.h"

#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

#include <esp_log.h>
#include <esp_efuse.h>
#include <esp_ds.h>
#include <esp_heap_caps.h>
#include <hal/hmac_types.h>


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

    bool has_fuses = esp_efuse_get_key_purpose(get_ds_key_block()) ==
        ESP_EFUSE_KEY_PURPOSE_HMAC_DOWN_DIGITAL_SIGNATURE;

    if (has_fuses) {
        esp_ds_data_ctx_t* ds_data_ctx = kd_common_crypto_get_ctx();
        if (ds_data_ctx == nullptr) {
            state = CRYPTO_STATE_BAD_DS_PARAMS;
        }
        else {
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

esp_err_t kd_common_set_device_cert(const char* cert, size_t len) {
    return crypto_storage_set_device_cert(cert, len);
}

esp_err_t kd_common_get_csr(char* buffer, size_t* len) {
    return crypto_storage_get_csr(buffer, len);
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
    bool has_fuses = esp_efuse_get_key_purpose(get_ds_key_block()) ==
        ESP_EFUSE_KEY_PURPOSE_HMAC_DOWN_DIGITAL_SIGNATURE;
    return !has_fuses;
}

esp_err_t crypto_init() {
#ifdef CONFIG_KD_COMMON_CONSOLE_ENABLE
    crypto_console_init();
#endif
    return ensure_key_exists();
}

esp_err_t kd_common_crypto_test_ds_signing() {
    ESP_LOGI(TAG, "=== DS Signing Test ===");

    // Get DS context - this validates that DS params are stored correctly
    esp_ds_data_ctx_t* ds_ctx = kd_common_crypto_get_ctx();
    if (ds_ctx == nullptr) {
        ESP_LOGE(TAG, "Failed to get DS context");
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "DS context loaded: key_id=%d, rsa_bits=%d",
        ds_ctx->efuse_key_id, ds_ctx->rsa_length_bits);

    size_t rsa_bytes = ds_ctx->rsa_length_bits / 8;

    // Allocate DMA-capable buffers for DS peripheral
    uint8_t* test_msg = static_cast<uint8_t*>(heap_caps_calloc(rsa_bytes, 1, MALLOC_CAP_DMA));
    uint8_t* signature = static_cast<uint8_t*>(heap_caps_calloc(rsa_bytes, 1, MALLOC_CAP_DMA));
    if (test_msg == nullptr || signature == nullptr) {
        ESP_LOGE(TAG, "Failed to allocate buffers");
        heap_caps_free(test_msg);
        heap_caps_free(signature);
        free(ds_ctx->esp_ds_data);
        free(ds_ctx);
        return ESP_ERR_NO_MEM;
    }

    // Fill with test pattern
    memset(test_msg, 0xAA, rsa_bytes);

    // Sign using DS peripheral
    ESP_LOGI(TAG, "Calling esp_ds_sign...");
    esp_ds_context_t* ds_sign_ctx = nullptr;
    hmac_key_id_t hmac_key = static_cast<hmac_key_id_t>(ds_ctx->efuse_key_id);

    esp_err_t ret = esp_ds_start_sign(test_msg, ds_ctx->esp_ds_data, hmac_key, &ds_sign_ctx);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "esp_ds_start_sign failed: %s", esp_err_to_name(ret));
        heap_caps_free(test_msg);
        heap_caps_free(signature);
        free(ds_ctx->esp_ds_data);
        free(ds_ctx);
        return ret;
    }

    ret = esp_ds_finish_sign(signature, ds_sign_ctx);
    heap_caps_free(test_msg);
    free(ds_ctx->esp_ds_data);
    free(ds_ctx);

    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "esp_ds_finish_sign failed: %s", esp_err_to_name(ret));
        heap_caps_free(signature);
        return ret;
    }

    // Log first bytes of signature to confirm output
    ESP_LOGI(TAG, "Signature (first 16 bytes): %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
        signature[0], signature[1], signature[2], signature[3],
        signature[4], signature[5], signature[6], signature[7],
        signature[8], signature[9], signature[10], signature[11],
        signature[12], signature[13], signature[14], signature[15]);

    heap_caps_free(signature);

    ESP_LOGI(TAG, "=== DS SIGNING TEST PASSED ===");
    return ESP_OK;
}

#endif // CONFIG_KD_COMMON_CRYPTO_ENABLE
