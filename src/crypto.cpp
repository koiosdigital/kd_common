#include "crypto.h"

#ifdef CONFIG_KD_COMMON_CRYPTO_ENABLE

#include "crypto_internal.h"

#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

#include <esp_log.h>
#include <esp_efuse.h>
#include <esp_ds.h>
#include <esp_heap_caps.h>
#include <hal/hmac_types.h>

#include <mbedtls/x509_crt.h>
#include <mbedtls/sha256.h>
#include <mbedtls/rsa.h>
#include <mbedtls/pk.h>

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
    return ensure_key_exists();
}

esp_err_t kd_common_crypto_test_ds_signing() {
    ESP_LOGI(TAG, "=== DS Signing Test ===");

    // Get DS context
    esp_ds_data_ctx_t* ds_ctx = kd_common_crypto_get_ctx();
    if (ds_ctx == nullptr) {
        ESP_LOGE(TAG, "Failed to get DS context");
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "DS context loaded: key_id=%d, rsa_bits=%d",
        ds_ctx->efuse_key_id, ds_ctx->rsa_length_bits);

    // Get device certificate
    size_t cert_len = 0;
    esp_err_t ret = kd_common_get_device_cert(nullptr, &cert_len);
    if (ret != ESP_OK || cert_len == 0) {
        ESP_LOGE(TAG, "Failed to get cert length: %s", esp_err_to_name(ret));
        free(ds_ctx->esp_ds_data);
        free(ds_ctx);
        return ESP_FAIL;
    }

    char* cert_pem = static_cast<char*>(calloc(cert_len + 1, 1));
    if (cert_pem == nullptr) {
        ESP_LOGE(TAG, "Failed to allocate cert buffer");
        free(ds_ctx->esp_ds_data);
        free(ds_ctx);
        return ESP_ERR_NO_MEM;
    }

    ret = kd_common_get_device_cert(cert_pem, &cert_len);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to get cert: %s", esp_err_to_name(ret));
        free(cert_pem);
        free(ds_ctx->esp_ds_data);
        free(ds_ctx);
        return ret;
    }
    ESP_LOGI(TAG, "Certificate loaded: %zu bytes", cert_len);

    // Parse certificate to extract public key
    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);

    int mbret = mbedtls_x509_crt_parse(&crt, reinterpret_cast<const unsigned char*>(cert_pem), cert_len + 1);
    free(cert_pem);

    if (mbret != 0) {
        ESP_LOGE(TAG, "Failed to parse certificate: -0x%04X", -mbret);
        mbedtls_x509_crt_free(&crt);
        free(ds_ctx->esp_ds_data);
        free(ds_ctx);
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "Certificate parsed successfully");

    // Verify it's RSA
    if (mbedtls_pk_get_type(&crt.pk) != MBEDTLS_PK_RSA) {
        ESP_LOGE(TAG, "Certificate key is not RSA");
        mbedtls_x509_crt_free(&crt);
        free(ds_ctx->esp_ds_data);
        free(ds_ctx);
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "Public key type: RSA, bits: %zu", mbedtls_pk_get_bitlen(&crt.pk));

    // Create test message and hash it
    const char* test_message = "DS peripheral test message for signature verification";
    unsigned char hash[32];
    mbedtls_sha256(reinterpret_cast<const unsigned char*>(test_message),
        strlen(test_message), hash, 0);
    ESP_LOGI(TAG, "Test message hashed (SHA-256)");

    // Prepare padded message for DS signing (PKCS#1 v1.5 padding)
    // DS peripheral expects the message in a specific format
    size_t rsa_bytes = ds_ctx->rsa_length_bits / 8;
    uint8_t* padded_msg = static_cast<uint8_t*>(heap_caps_calloc(rsa_bytes, 1, MALLOC_CAP_DMA));
    if (padded_msg == nullptr) {
        ESP_LOGE(TAG, "Failed to allocate padded message buffer");
        mbedtls_x509_crt_free(&crt);
        free(ds_ctx->esp_ds_data);
        free(ds_ctx);
        return ESP_ERR_NO_MEM;
    }

    // PKCS#1 v1.5 padding for SHA-256: 0x00 0x01 [0xFF...] 0x00 [DigestInfo] [hash]
    // DigestInfo for SHA-256: 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
    static const uint8_t sha256_digest_info[] = {
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
        0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
    };

    size_t di_len = sizeof(sha256_digest_info);
    size_t hash_len = 32;
    size_t padding_len = rsa_bytes - 3 - di_len - hash_len;

    padded_msg[0] = 0x00;
    padded_msg[1] = 0x01;
    memset(&padded_msg[2], 0xFF, padding_len);
    padded_msg[2 + padding_len] = 0x00;
    memcpy(&padded_msg[3 + padding_len], sha256_digest_info, di_len);
    memcpy(&padded_msg[3 + padding_len + di_len], hash, hash_len);

    // Reverse for DS peripheral (little-endian)
    kd_common_reverse_bytes(padded_msg, rsa_bytes);

    // Allocate signature buffer (DMA capable)
    uint8_t* signature = static_cast<uint8_t*>(heap_caps_calloc(rsa_bytes, 1, MALLOC_CAP_DMA));
    if (signature == nullptr) {
        ESP_LOGE(TAG, "Failed to allocate signature buffer");
        heap_caps_free(padded_msg);
        mbedtls_x509_crt_free(&crt);
        free(ds_ctx->esp_ds_data);
        free(ds_ctx);
        return ESP_ERR_NO_MEM;
    }

    // Sign using DS peripheral
    ESP_LOGI(TAG, "Calling esp_ds_sign...");
    esp_ds_context_t* ds_sign_ctx = nullptr;

    // Convert efuse_key_id to hmac_key_id_t (HMAC_KEY0 = 0, corresponding to EFUSE_BLK_KEY0)
    hmac_key_id_t hmac_key = static_cast<hmac_key_id_t>(ds_ctx->efuse_key_id);
    ESP_LOGI(TAG, "Using HMAC key: %d", hmac_key);

    ret = esp_ds_start_sign(padded_msg, ds_ctx->esp_ds_data, hmac_key, &ds_sign_ctx);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "esp_ds_start_sign failed: %s", esp_err_to_name(ret));
        heap_caps_free(signature);
        heap_caps_free(padded_msg);
        mbedtls_x509_crt_free(&crt);
        free(ds_ctx->esp_ds_data);
        free(ds_ctx);
        return ret;
    }

    ret = esp_ds_finish_sign(signature, ds_sign_ctx);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "esp_ds_finish_sign failed: %s", esp_err_to_name(ret));
        heap_caps_free(signature);
        heap_caps_free(padded_msg);
        mbedtls_x509_crt_free(&crt);
        free(ds_ctx->esp_ds_data);
        free(ds_ctx);
        return ret;
    }
    ESP_LOGI(TAG, "DS signing completed");

    // Reverse signature back to big-endian for verification
    kd_common_reverse_bytes(signature, rsa_bytes);

    // Log first/last bytes of signature
    ESP_LOGI(TAG, "Signature (first 16 bytes): %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
        signature[0], signature[1], signature[2], signature[3],
        signature[4], signature[5], signature[6], signature[7],
        signature[8], signature[9], signature[10], signature[11],
        signature[12], signature[13], signature[14], signature[15]);

    // Verify signature using public key from certificate
    mbedtls_rsa_context* rsa = mbedtls_pk_rsa(crt.pk);

    mbret = mbedtls_rsa_pkcs1_verify(rsa, MBEDTLS_MD_SHA256, 32, hash, signature);

    heap_caps_free(signature);
    heap_caps_free(padded_msg);
    mbedtls_x509_crt_free(&crt);
    free(ds_ctx->esp_ds_data);
    free(ds_ctx);

    if (mbret != 0) {
        ESP_LOGE(TAG, "=== SIGNATURE VERIFICATION FAILED: -0x%04X ===", -mbret);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "=== SIGNATURE VERIFICATION PASSED ===");
    return ESP_OK;
}

#endif // CONFIG_KD_COMMON_CRYPTO_ENABLE
