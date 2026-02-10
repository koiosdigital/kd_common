#include "crypto.h"

#ifdef CONFIG_KD_COMMON_CRYPTO_ENABLE

#include "crypto_internal.h"
#include "crypto_console.h"
#include "kdc_heap_tracing.h"

#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

#include <esp_log.h>
#include <esp_efuse.h>
#include <esp_ds.h>
#include <esp_heap_caps.h>
#include <hal/hmac_types.h>

#include <psa/crypto.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>

#include <string.h>

static const char* TAG = "kd_crypto";

// Global keygen mutex definition
SemaphoreHandle_t g_keygen_mutex = NULL;

//MARK: Public API

CryptoState_t kd_common_crypto_get_state(void) {
    CryptoState_t state = CRYPTO_STATE_UNINITIALIZED;

    if (xSemaphoreTake(g_keygen_mutex, pdMS_TO_TICKS(10)) == pdTRUE) {
        state = CRYPTO_STATE_KEY_GENERATED;
        xSemaphoreGive(g_keygen_mutex);
    }

    if (crypto_get_csr(NULL, NULL) == ESP_OK) {
        state = CRYPTO_STATE_VALID_CSR;
    }

    if (kd_common_get_device_cert(NULL, NULL) == ESP_OK) {
        state = CRYPTO_STATE_VALID_CERT;
    }

    bool has_fuses = esp_efuse_get_key_purpose(crypto_get_ds_key_block_internal()) ==
        ESP_EFUSE_KEY_PURPOSE_HMAC_DOWN_DIGITAL_SIGNATURE;

    if (has_fuses) {
        esp_ds_data_ctx_t* ds_data_ctx = kd_common_crypto_get_ctx();
        if (ds_data_ctx == NULL) {
            state = CRYPTO_STATE_BAD_DS_PARAMS;
        }
        else {
            free(ds_data_ctx->esp_ds_data);
            free(ds_data_ctx);
        }
    }

    return state;
}

esp_ds_data_ctx_t* kd_common_crypto_get_ctx(void) {
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

esp_err_t kd_common_clear_device_cert(void) {
    return crypto_storage_clear_device_cert();
}

esp_err_t kd_common_get_claim_token(char* buffer, size_t* len) {
    return crypto_storage_get_claim_token(buffer, len);
}

esp_err_t kd_common_clear_claim_token(void) {
    return crypto_storage_clear_claim_token();
}

//MARK: Internal API (used by console commands)

esp_err_t crypto_get_csr(char* buffer, size_t* len) {
    return crypto_storage_get_csr(buffer, len);
}

esp_err_t crypto_clear_csr(void) {
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

bool crypto_will_generate_key(void) {
    bool has_fuses = esp_efuse_get_key_purpose(crypto_get_ds_key_block_internal()) ==
        ESP_EFUSE_KEY_PURPOSE_HMAC_DOWN_DIGITAL_SIGNATURE;
    return !has_fuses;
}

static void crypto_log_provisioning_info(void) {
    CryptoState_t state = kd_common_crypto_get_state();

    // Parseable pattern for provisioner script
    printf("\n\n[CRYPTO_STATUS] %d\n\n", state);
    fflush(stdout);

    if (state == CRYPTO_STATE_VALID_CSR) {
        // Get and print CSR if available
        size_t csr_len = 0;
        if (crypto_get_csr(NULL, &csr_len) == ESP_OK && csr_len > 0) {
            // Allocate extra byte for null terminator (CSR stored as blob without null)
            char* csr = (char*)heap_caps_malloc_prefer(csr_len + 1, 2, MALLOC_CAP_SPIRAM, MALLOC_CAP_8BIT);
            if (csr != NULL && crypto_get_csr(csr, &csr_len) == ESP_OK) {
                csr[csr_len] = '\0';  // Ensure null termination
                printf("\n\n[CSR_BEGIN]\n%s[CSR_END]\n\n", csr);
                fflush(stdout);
                heap_caps_free(csr);
            }
        }
    }
}

esp_err_t crypto_init(void) {
#ifdef CONFIG_KD_COMMON_CONSOLE_ENABLE
    crypto_console_init();
#endif
    esp_err_t ret = ensure_key_exists();
    crypto_log_provisioning_info();
    return ret;
}

esp_err_t kd_common_crypto_test_ds_signing(void) {
    ESP_LOGI(TAG, "=== DS Signing Test ===");

    // Get DS context
    esp_ds_data_ctx_t* ds_ctx = kd_common_crypto_get_ctx();
    if (ds_ctx == NULL) {
        ESP_LOGE(TAG, "Failed to get DS context");
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "DS context loaded: key_id=%d, rsa_bits=%d",
        ds_ctx->efuse_key_id, ds_ctx->rsa_length_bits);

    // Get device certificate
    size_t cert_len = 0;
    esp_err_t ret = kd_common_get_device_cert(NULL, &cert_len);
    if (ret != ESP_OK || cert_len == 0) {
        ESP_LOGE(TAG, "Failed to get cert length: %s", esp_err_to_name(ret));
        free(ds_ctx->esp_ds_data);
        free(ds_ctx);
        return ESP_FAIL;
    }

    char* cert_pem = (char*)calloc(cert_len + 1, 1);
    if (cert_pem == NULL) {
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

    // Parse certificate to extract public key (mbedTLS required for X.509 parsing)
    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);

    int mbret = mbedtls_x509_crt_parse(&crt, (const unsigned char*)cert_pem, cert_len + 1);
    free(cert_pem);

    if (mbret != 0) {
        ESP_LOGE(TAG, "Failed to parse certificate: -0x%04X", -mbret);
        mbedtls_x509_crt_free(&crt);
        free(ds_ctx->esp_ds_data);
        free(ds_ctx);
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "Certificate parsed, key bits: %zu", mbedtls_pk_get_bitlen(&crt.pk));

    // Import public key into PSA using mbedTLS 3.x interop
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    mbret = mbedtls_pk_get_psa_attributes(&crt.pk, PSA_KEY_USAGE_VERIFY_HASH, &key_attr);
    if (mbret != 0) {
        ESP_LOGE(TAG, "Failed to get PSA attributes: -0x%04X", -mbret);
        mbedtls_x509_crt_free(&crt);
        free(ds_ctx->esp_ds_data);
        free(ds_ctx);
        return ESP_FAIL;
    }
    psa_set_key_algorithm(&key_attr, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256));

    psa_key_id_t psa_key_id;
    mbret = mbedtls_pk_import_into_psa(&crt.pk, &key_attr, &psa_key_id);
    mbedtls_x509_crt_free(&crt);

    if (mbret != 0) {
        ESP_LOGE(TAG, "Failed to import public key to PSA: -0x%04X", -mbret);
        free(ds_ctx->esp_ds_data);
        free(ds_ctx);
        return ESP_FAIL;
    }

    // Hash test message using PSA
    const char* test_message = "DS peripheral test message for signature verification";
    uint8_t hash[32];
    size_t hash_len;
    psa_status_t status = psa_hash_compute(PSA_ALG_SHA_256,
        (const uint8_t*)test_message, strlen(test_message),
        hash, sizeof(hash), &hash_len);
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "Failed to hash message: %d", status);
        psa_destroy_key(psa_key_id);
        free(ds_ctx->esp_ds_data);
        free(ds_ctx);
        return ESP_FAIL;
    }

    // Prepare PKCS#1 v1.5 padded message for DS signing
    size_t rsa_bytes = ds_ctx->rsa_length_bits / 8;
    uint8_t* padded_msg = (uint8_t*)heap_caps_calloc(rsa_bytes, 1, MALLOC_CAP_DMA);
    uint8_t* signature = (uint8_t*)heap_caps_calloc(rsa_bytes, 1, MALLOC_CAP_DMA);
    if (padded_msg == NULL || signature == NULL) {
        ESP_LOGE(TAG, "Failed to allocate buffers");
        heap_caps_free(padded_msg);
        heap_caps_free(signature);
        psa_destroy_key(psa_key_id);
        free(ds_ctx->esp_ds_data);
        free(ds_ctx);
        return ESP_ERR_NO_MEM;
    }

    // PKCS#1 v1.5 padding: 0x00 0x01 [0xFF...] 0x00 [DigestInfo] [hash]
    static const uint8_t sha256_digest_info[] = {
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
        0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
    };
    size_t di_len = sizeof(sha256_digest_info);
    size_t padding_len = rsa_bytes - 3 - di_len - hash_len;

    padded_msg[0] = 0x00;
    padded_msg[1] = 0x01;
    memset(&padded_msg[2], 0xFF, padding_len);
    padded_msg[2 + padding_len] = 0x00;
    memcpy(&padded_msg[3 + padding_len], sha256_digest_info, di_len);
    memcpy(&padded_msg[3 + padding_len + di_len], hash, hash_len);

    // Reverse for DS peripheral (little-endian)
    kd_common_reverse_bytes(padded_msg, rsa_bytes);

    // Sign using DS peripheral
    ESP_LOGI(TAG, "Calling esp_ds_sign...");
    esp_ds_context_t* ds_sign_ctx = NULL;
    hmac_key_id_t hmac_key = (hmac_key_id_t)ds_ctx->efuse_key_id;

    ret = esp_ds_start_sign(padded_msg, ds_ctx->esp_ds_data, hmac_key, &ds_sign_ctx);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "esp_ds_start_sign failed: %s", esp_err_to_name(ret));
        heap_caps_free(padded_msg);
        heap_caps_free(signature);
        psa_destroy_key(psa_key_id);
        free(ds_ctx->esp_ds_data);
        free(ds_ctx);
        return ret;
    }

    ret = esp_ds_finish_sign(signature, ds_sign_ctx);
    heap_caps_free(padded_msg);
    free(ds_ctx->esp_ds_data);
    free(ds_ctx);

    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "esp_ds_finish_sign failed: %s", esp_err_to_name(ret));
        heap_caps_free(signature);
        psa_destroy_key(psa_key_id);
        return ret;
    }
    ESP_LOGI(TAG, "DS signing completed");

    // Reverse signature back to big-endian for verification
    kd_common_reverse_bytes(signature, rsa_bytes);

    ESP_LOGI(TAG, "Signature (first 16 bytes): %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
        signature[0], signature[1], signature[2], signature[3],
        signature[4], signature[5], signature[6], signature[7],
        signature[8], signature[9], signature[10], signature[11],
        signature[12], signature[13], signature[14], signature[15]);

    // Verify signature using PSA
    status = psa_verify_hash(psa_key_id, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256),
        hash, hash_len, signature, rsa_bytes);

    heap_caps_free(signature);
    psa_destroy_key(psa_key_id);

    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "=== SIGNATURE VERIFICATION FAILED: %d ===", status);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "=== SIGNATURE VERIFICATION PASSED ===");
    return ESP_OK;
}

#endif // CONFIG_KD_COMMON_CRYPTO_ENABLE
