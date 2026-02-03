#include "crypto.h"

#ifdef CONFIG_KD_COMMON_CRYPTO_ENABLE

#include "crypto_internal.h"
#include "nvs_helper.h"

#include <esp_log.h>
#include <esp_ds.h>

#include "mbedtls/base64.h"
#include "cJSON.h"

#include <string.h>
#include <stdlib.h>

static const char* TAG = "kd_crypto_storage";

//MARK: CSR Operations

esp_err_t crypto_storage_get_csr(char* buffer, size_t* len) {
    nvs_helper_t nvs = nvs_helper_open(CRYPTO_NVS_NAMESPACE, NVS_READWRITE);
    if (!nvs.valid) {
        ESP_LOGE(TAG, "nvs open failed: %s", esp_err_to_name(nvs.open_err));
        return nvs.open_err;
    }

    // If both buffer and len are NULL, just check if key exists
    if (buffer == NULL && len == NULL) {
        esp_err_t err = nvs_helper_find_key(&nvs, CRYPTO_NVS_KEY_CSR);
        nvs_helper_close(&nvs);
        return err;
    }

    // nvs_get_blob with NULL buffer returns the required size in len
    esp_err_t err = nvs_helper_get_blob(&nvs, CRYPTO_NVS_KEY_CSR, buffer, len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs get csr failed: %s", esp_err_to_name(err));
    }
    nvs_helper_close(&nvs);
    return err;
}

esp_err_t crypto_storage_clear_csr(void) {
    nvs_helper_t nvs = nvs_helper_open(CRYPTO_NVS_NAMESPACE, NVS_READWRITE);
    if (!nvs.valid) {
        ESP_LOGE(TAG, "nvs open failed: %s", esp_err_to_name(nvs.open_err));
        return nvs.open_err;
    }

    esp_err_t err = nvs_helper_erase_key(&nvs, CRYPTO_NVS_KEY_CSR);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs erase csr failed: %s", esp_err_to_name(err));
        nvs_helper_close(&nvs);
        return err;
    }

    err = nvs_helper_commit(&nvs);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs commit failed: %s", esp_err_to_name(err));
    }
    nvs_helper_close(&nvs);
    return err;
}

esp_err_t crypto_storage_store_csr(const unsigned char* csr_buffer, size_t len) {
    nvs_helper_t nvs = nvs_helper_open(CRYPTO_NVS_NAMESPACE, NVS_READWRITE);
    if (!nvs.valid) {
        ESP_LOGE(TAG, "nvs open failed: %s", esp_err_to_name(nvs.open_err));
        return nvs.open_err;
    }

    esp_err_t err = nvs_helper_set_blob(&nvs, CRYPTO_NVS_KEY_CSR, csr_buffer, len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs set CSR failed: %s", esp_err_to_name(err));
        nvs_helper_close(&nvs);
        return err;
    }

    err = nvs_helper_commit(&nvs);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs commit failed: %s", esp_err_to_name(err));
        nvs_helper_close(&nvs);
        return err;
    }

    nvs_helper_close(&nvs);
    return ESP_OK;
}

//MARK: Device Certificate Operations

esp_err_t crypto_storage_get_device_cert(char* buffer, size_t* len) {
    nvs_helper_t nvs = nvs_helper_open(CRYPTO_NVS_NAMESPACE, NVS_READWRITE);
    if (!nvs.valid) {
        ESP_LOGE(TAG, "nvs open failed: %s", esp_err_to_name(nvs.open_err));
        return nvs.open_err;
    }

    // If both buffer and len are NULL, just check if key exists
    if (buffer == NULL && len == NULL) {
        esp_err_t err = nvs_helper_find_key(&nvs, CRYPTO_NVS_KEY_DEVICE_CERT);
        nvs_helper_close(&nvs);
        return err;
    }

    // nvs_get_blob with NULL buffer returns the required size in len
    esp_err_t err = nvs_helper_get_blob(&nvs, CRYPTO_NVS_KEY_DEVICE_CERT, buffer, len);
    nvs_helper_close(&nvs);
    return err;
}

esp_err_t crypto_storage_set_device_cert(const char* buffer, size_t len) {
    nvs_helper_t nvs = nvs_helper_open(CRYPTO_NVS_NAMESPACE, NVS_READWRITE);
    if (!nvs.valid) {
        ESP_LOGE(TAG, "nvs open failed: %s", esp_err_to_name(nvs.open_err));
        return nvs.open_err;
    }

    esp_err_t err = nvs_helper_set_blob(&nvs, CRYPTO_NVS_KEY_DEVICE_CERT, buffer, len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs set device cert failed: %s", esp_err_to_name(err));
        nvs_helper_close(&nvs);
        return err;
    }

    err = nvs_helper_commit(&nvs);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs commit failed: %s", esp_err_to_name(err));
    }
    nvs_helper_close(&nvs);
    return err;
}

esp_err_t crypto_storage_clear_device_cert(void) {
    nvs_helper_t nvs = nvs_helper_open(CRYPTO_NVS_NAMESPACE, NVS_READWRITE);
    if (!nvs.valid) {
        ESP_LOGE(TAG, "nvs open failed: %s", esp_err_to_name(nvs.open_err));
        return nvs.open_err;
    }

    esp_err_t err = nvs_helper_erase_key(&nvs, CRYPTO_NVS_KEY_DEVICE_CERT);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs erase device cert failed: %s", esp_err_to_name(err));
        nvs_helper_close(&nvs);
        return err;
    }

    err = nvs_helper_commit(&nvs);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs commit failed: %s", esp_err_to_name(err));
    }
    nvs_helper_close(&nvs);
    return err;
}

//MARK: Claim Token Operations

esp_err_t crypto_storage_get_claim_token(char* buffer, size_t* len) {
    nvs_helper_t nvs = nvs_helper_open(CRYPTO_NVS_NAMESPACE, NVS_READWRITE);
    if (!nvs.valid) {
        ESP_LOGE(TAG, "nvs open failed: %s", esp_err_to_name(nvs.open_err));
        return nvs.open_err;
    }

    // If both buffer and len are NULL, just check if key exists
    if (buffer == NULL && len == NULL) {
        esp_err_t err = nvs_helper_find_key(&nvs, CRYPTO_NVS_KEY_CLAIM_TOKEN);
        nvs_helper_close(&nvs);
        return err;
    }

    // nvs_get_blob with NULL buffer returns the required size in len
    esp_err_t err = nvs_helper_get_blob(&nvs, CRYPTO_NVS_KEY_CLAIM_TOKEN, buffer, len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs get claim token failed: %s", esp_err_to_name(err));
    }
    nvs_helper_close(&nvs);
    return err;
}

esp_err_t crypto_storage_set_claim_token(const char* buffer, size_t len) {
    nvs_helper_t nvs = nvs_helper_open(CRYPTO_NVS_NAMESPACE, NVS_READWRITE);
    if (!nvs.valid) {
        ESP_LOGE(TAG, "nvs open failed: %s", esp_err_to_name(nvs.open_err));
        return nvs.open_err;
    }

    esp_err_t err = nvs_helper_set_blob(&nvs, CRYPTO_NVS_KEY_CLAIM_TOKEN, buffer, len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs set claim token failed: %s", esp_err_to_name(err));
        nvs_helper_close(&nvs);
        return err;
    }

    err = nvs_helper_commit(&nvs);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs commit failed: %s", esp_err_to_name(err));
    }
    nvs_helper_close(&nvs);
    return err;
}

esp_err_t crypto_storage_clear_claim_token(void) {
    nvs_helper_t nvs = nvs_helper_open(CRYPTO_NVS_NAMESPACE, NVS_READWRITE);
    if (!nvs.valid) {
        ESP_LOGE(TAG, "nvs open failed: %s", esp_err_to_name(nvs.open_err));
        return nvs.open_err;
    }

    esp_err_t err = nvs_helper_erase_key(&nvs, CRYPTO_NVS_KEY_CLAIM_TOKEN);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        nvs_helper_close(&nvs);
        return ESP_OK;  // Already cleared
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs erase claim token failed: %s", esp_err_to_name(err));
        nvs_helper_close(&nvs);
        return err;
    }

    err = nvs_helper_commit(&nvs);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs commit failed: %s", esp_err_to_name(err));
    }
    nvs_helper_close(&nvs);
    return err;
}

//MARK: DS Parameters Operations

esp_err_t crypto_storage_store_ds_params(const uint8_t* c, const uint8_t* iv, uint8_t key_id, uint16_t rsa_length) {
    nvs_helper_t nvs = nvs_helper_open(CRYPTO_NVS_NAMESPACE, NVS_READWRITE);
    if (!nvs.valid) {
        ESP_LOGE(TAG, "nvs open failed: %s", esp_err_to_name(nvs.open_err));
        return nvs.open_err;
    }

    esp_err_t err = nvs_helper_set_blob(&nvs, CRYPTO_NVS_KEY_CIPHERTEXT, c, ESP_DS_C_LEN);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs set ciphertext failed: %s", esp_err_to_name(err));
        nvs_helper_close(&nvs);
        return err;
    }

    err = nvs_helper_set_blob(&nvs, CRYPTO_NVS_KEY_IV, iv, ESP_DS_IV_LEN);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs set iv failed: %s", esp_err_to_name(err));
        nvs_helper_close(&nvs);
        return err;
    }

    err = nvs_helper_set_u8(&nvs, CRYPTO_NVS_KEY_DS_KEY_ID, key_id);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs set ds key id failed: %s", esp_err_to_name(err));
        nvs_helper_close(&nvs);
        return err;
    }

    err = nvs_helper_set_u16(&nvs, CRYPTO_NVS_KEY_RSA_LEN, rsa_length);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs set rsa length failed: %s", esp_err_to_name(err));
        nvs_helper_close(&nvs);
        return err;
    }

    err = nvs_helper_commit(&nvs);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs commit failed: %s", esp_err_to_name(err));
        nvs_helper_close(&nvs);
        return err;
    }

    nvs_helper_close(&nvs);
    return ESP_OK;
}

esp_ds_data_ctx_t* crypto_storage_get_ds_ctx(void) {
    esp_ds_data_ctx_t* ds_data_ctx = (esp_ds_data_ctx_t*)calloc(1, sizeof(esp_ds_data_ctx_t));
    if (ds_data_ctx == NULL) {
        ESP_LOGE(TAG, "no mem for ds context");
        return NULL;
    }

    ds_data_ctx->esp_ds_data = (esp_ds_data_t*)calloc(1, sizeof(esp_ds_data_t));
    if (ds_data_ctx->esp_ds_data == NULL) {
        ESP_LOGE(TAG, "no mem for ds data");
        free(ds_data_ctx);
        return NULL;
    }

    nvs_helper_t nvs = nvs_helper_open(CRYPTO_NVS_NAMESPACE, NVS_READONLY);
    if (!nvs.valid) {
        ESP_LOGE(TAG, "nvs open failed: %s", esp_err_to_name(nvs.open_err));
        free(ds_data_ctx->esp_ds_data);
        free(ds_data_ctx);
        return NULL;
    }

    size_t len = ESP_DS_C_LEN;
    esp_err_t err = nvs_helper_get_blob(&nvs, CRYPTO_NVS_KEY_CIPHERTEXT, ds_data_ctx->esp_ds_data->c, &len);
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "failed to get ciphertext: %s", esp_err_to_name(err));
        nvs_helper_close(&nvs);
        free(ds_data_ctx->esp_ds_data);
        free(ds_data_ctx);
        return NULL;
    }

    len = ESP_DS_IV_LEN;
    err = nvs_helper_get_blob(&nvs, CRYPTO_NVS_KEY_IV, ds_data_ctx->esp_ds_data->iv, &len);
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "failed to get iv: %s", esp_err_to_name(err));
        nvs_helper_close(&nvs);
        free(ds_data_ctx->esp_ds_data);
        free(ds_data_ctx);
        return NULL;
    }

    err = nvs_helper_get_u8(&nvs, CRYPTO_NVS_KEY_DS_KEY_ID, &ds_data_ctx->efuse_key_id);
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "failed to get ds key id: %s", esp_err_to_name(err));
        nvs_helper_close(&nvs);
        free(ds_data_ctx->esp_ds_data);
        free(ds_data_ctx);
        return NULL;
    }
    ds_data_ctx->efuse_key_id -= 4;

    uint16_t rsa_len;
    err = nvs_helper_get_u16(&nvs, CRYPTO_NVS_KEY_RSA_LEN, &rsa_len);
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "failed to get rsa length: %s", esp_err_to_name(err));
        nvs_helper_close(&nvs);
        free(ds_data_ctx->esp_ds_data);
        free(ds_data_ctx);
        return NULL;
    }
    ds_data_ctx->esp_ds_data->rsa_length = rsa_len;
    ds_data_ctx->rsa_length_bits = (ds_data_ctx->esp_ds_data->rsa_length + 1) * 32;

    nvs_helper_close(&nvs);
    return ds_data_ctx;
}

//MARK: JSON DS Params (Public API wrappers)

char* crypto_get_ds_params_json(void) {
    esp_ds_data_ctx_t* ds_data_ctx = crypto_storage_get_ds_ctx();
    if (ds_data_ctx == NULL) {
        printf("{\"error_message\":\"no ds params\",\"error\":true}\n");
        return NULL;
    }

    cJSON* json = cJSON_CreateObject();

    cJSON_AddNumberToObject(json, "ds_key_id", ds_data_ctx->efuse_key_id + 4);
    cJSON_AddNumberToObject(json, "rsa_len", ds_data_ctx->esp_ds_data->rsa_length);

    // Get required base64 size for cipher_c
    size_t base64_c_len = 0;
    mbedtls_base64_encode(NULL, 0, &base64_c_len,
        (unsigned char*)ds_data_ctx->esp_ds_data->c, ESP_DS_C_LEN);
    char* base64_c = (char*)malloc(base64_c_len + 1);
    mbedtls_base64_encode((unsigned char*)base64_c, base64_c_len + 1, &base64_c_len,
        (unsigned char*)ds_data_ctx->esp_ds_data->c, ESP_DS_C_LEN);
    cJSON_AddStringToObject(json, "cipher_c", base64_c);
    free(base64_c);

    // Get required base64 size for iv
    size_t base64_iv_len = 0;
    mbedtls_base64_encode(NULL, 0, &base64_iv_len,
        (unsigned char*)ds_data_ctx->esp_ds_data->iv, ESP_DS_IV_LEN);
    char* base64_iv = (char*)malloc(base64_iv_len + 1);
    mbedtls_base64_encode((unsigned char*)base64_iv, base64_iv_len + 1, &base64_iv_len,
        (unsigned char*)ds_data_ctx->esp_ds_data->iv, ESP_DS_IV_LEN);
    cJSON_AddStringToObject(json, "iv", base64_iv);
    free(base64_iv);

    free(ds_data_ctx->esp_ds_data);
    free(ds_data_ctx);

    char* json_string = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    return json_string;
}

esp_err_t crypto_store_ds_params_json(char* params) {
    cJSON* ds_params = cJSON_Parse(params);

    if (ds_params == NULL) {
        free(params);
        return ESP_ERR_INVALID_ARG;
    }

    if (cJSON_GetObjectItem(ds_params, "ds_key_id") == NULL ||
        cJSON_GetObjectItem(ds_params, "rsa_len") == NULL ||
        cJSON_GetObjectItem(ds_params, "cipher_c") == NULL ||
        cJSON_GetObjectItem(ds_params, "iv") == NULL) {
        ESP_LOGE(TAG, "missing required ds params fields");
        free(params);
        cJSON_Delete(ds_params);
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t ds_key_id = (uint8_t)cJSON_GetObjectItem(ds_params, "ds_key_id")->valueint;
    uint16_t rsa_length = (uint16_t)cJSON_GetObjectItem(ds_params, "rsa_len")->valueint;

    char* base64_c = cJSON_GetObjectItem(ds_params, "cipher_c")->valuestring;
    char* base64_iv = cJSON_GetObjectItem(ds_params, "iv")->valuestring;

    size_t c_len = strlen(base64_c);
    size_t iv_len = strlen(base64_iv);

    uint8_t* c = (uint8_t*)malloc(ESP_DS_C_LEN);
    uint8_t* iv = (uint8_t*)malloc(ESP_DS_IV_LEN);

    if (c == NULL || iv == NULL) {
        free(c);
        free(iv);
        cJSON_Delete(ds_params);
        free(params);
        return ESP_ERR_NO_MEM;
    }

    size_t decoded_c_len = 0;
    size_t decoded_iv_len = 0;

    mbedtls_base64_decode(c, ESP_DS_C_LEN, &decoded_c_len,
        (unsigned char*)base64_c, c_len);
    mbedtls_base64_decode(iv, ESP_DS_IV_LEN, &decoded_iv_len,
        (unsigned char*)base64_iv, iv_len);

    if (decoded_c_len != ESP_DS_C_LEN || decoded_iv_len != ESP_DS_IV_LEN) {
        ESP_LOGE(TAG, "decoded length mismatch: c=%zu (expected %d), iv=%zu (expected %d)",
            decoded_c_len, ESP_DS_C_LEN, decoded_iv_len, ESP_DS_IV_LEN);
        free(c);
        free(iv);
        cJSON_Delete(ds_params);
        free(params);
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = crypto_storage_store_ds_params(c, iv, ds_key_id, rsa_length);

    free(c);
    free(iv);
    cJSON_Delete(ds_params);
    free(params);
    return err;
}

//MARK: DS Key Block Configuration

esp_efuse_block_t crypto_get_ds_key_block_internal(void) {
    nvs_helper_t nvs = nvs_helper_open(CRYPTO_NVS_NAMESPACE, NVS_READONLY);
    if (!nvs.valid) {
        return EFUSE_BLK_KEY3;  // Default
    }

    uint8_t block = 0;
    esp_err_t err = nvs_helper_get_u8(&nvs, CRYPTO_NVS_KEY_DS_KEY_BLOCK, &block);
    nvs_helper_close(&nvs);

    if (err != ESP_OK || block < 4 || block > 9) {
        return EFUSE_BLK_KEY3;  // Default
    }

    return (esp_efuse_block_t)block;
}

esp_err_t crypto_set_ds_key_block(uint8_t block) {
    if (block < 4 || block > 9) {
        ESP_LOGE(TAG, "Invalid DS key block: %d (valid range: 4-9)", block);
        return ESP_ERR_INVALID_ARG;
    }

    nvs_helper_t nvs = nvs_helper_open(CRYPTO_NVS_NAMESPACE, NVS_READWRITE);
    if (!nvs.valid) {
        ESP_LOGE(TAG, "nvs open failed: %s", esp_err_to_name(nvs.open_err));
        return nvs.open_err;
    }

    esp_err_t err = nvs_helper_set_u8(&nvs, CRYPTO_NVS_KEY_DS_KEY_BLOCK, block);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs set ds key block failed: %s", esp_err_to_name(err));
        nvs_helper_close(&nvs);
        return err;
    }

    err = nvs_helper_commit(&nvs);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs commit failed: %s", esp_err_to_name(err));
    }
    nvs_helper_close(&nvs);
    return err;
}

uint8_t crypto_get_ds_key_block(void) {
    return (uint8_t)crypto_get_ds_key_block_internal();
}

bool crypto_is_key_block_burnt(uint8_t block) {
    if (block < 4 || block > 9) {
        return false;
    }
    esp_efuse_block_t efuse_block = (esp_efuse_block_t)block;
    esp_efuse_purpose_t purpose = esp_efuse_get_key_purpose(efuse_block);
    return purpose != ESP_EFUSE_KEY_PURPOSE_USER;
}

esp_err_t crypto_clear_all_data(void) {
    esp_err_t err;

    err = crypto_storage_clear_csr();
    if (err != ESP_OK && err != ESP_ERR_NVS_NOT_FOUND) {
        ESP_LOGW(TAG, "Failed to clear CSR: %s", esp_err_to_name(err));
    }

    err = crypto_storage_clear_device_cert();
    if (err != ESP_OK && err != ESP_ERR_NVS_NOT_FOUND) {
        ESP_LOGW(TAG, "Failed to clear device cert: %s", esp_err_to_name(err));
    }

    // Clear DS params (cipher_c, iv, ds_key_id, rsa_len)
    nvs_helper_t nvs = nvs_helper_open(CRYPTO_NVS_NAMESPACE, NVS_READWRITE);
    if (!nvs.valid) {
        ESP_LOGE(TAG, "nvs open failed: %s", esp_err_to_name(nvs.open_err));
        return nvs.open_err;
    }

    nvs_helper_erase_key(&nvs, CRYPTO_NVS_KEY_CIPHERTEXT);
    nvs_helper_erase_key(&nvs, CRYPTO_NVS_KEY_IV);
    nvs_helper_erase_key(&nvs, CRYPTO_NVS_KEY_DS_KEY_ID);
    nvs_helper_erase_key(&nvs, CRYPTO_NVS_KEY_RSA_LEN);

    err = nvs_helper_commit(&nvs);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs commit failed: %s", esp_err_to_name(err));
        nvs_helper_close(&nvs);
        return err;
    }

    nvs_helper_close(&nvs);
    return ESP_OK;
}

#endif // CONFIG_KD_COMMON_CRYPTO_ENABLE
