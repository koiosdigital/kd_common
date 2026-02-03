#include "crypto.h"

#ifdef CONFIG_KD_COMMON_CRYPTO_ENABLE

#include "crypto_internal.h"
#include "nvs_handle.h"

#include <esp_log.h>
#include <esp_ds.h>

#include "mbedtls/base64.h"
#include "cJSON.h"

#include <cstring>

static const char* TAG = "kd_crypto_storage";

using namespace crypto;

//MARK: CSR Operations

esp_err_t crypto_storage_get_csr(char* buffer, size_t* len) {
    kd::NvsHandle nvs(NVS_NAMESPACE, NVS_READWRITE);
    if (!nvs) {
        ESP_LOGE(TAG, "nvs open failed: %s", esp_err_to_name(nvs.open_error()));
        return nvs.open_error();
    }

    // If both buffer and len are nullptr, just check if key exists
    if (buffer == nullptr && len == nullptr) {
        return nvs.find_key(NVS_KEY_CSR);
    }

    // nvs_get_blob with nullptr buffer returns the required size in len
    esp_err_t err = nvs.get_blob(NVS_KEY_CSR, buffer, len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs get csr failed: %s", esp_err_to_name(err));
    }
    return err;
}

esp_err_t crypto_storage_clear_csr() {
    kd::NvsHandle nvs(NVS_NAMESPACE, NVS_READWRITE);
    if (!nvs) {
        ESP_LOGE(TAG, "nvs open failed: %s", esp_err_to_name(nvs.open_error()));
        return nvs.open_error();
    }

    esp_err_t err = nvs.erase_key(NVS_KEY_CSR);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs erase csr failed: %s", esp_err_to_name(err));
        return err;
    }

    err = nvs.commit();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs commit failed: %s", esp_err_to_name(err));
    }
    return err;
}

esp_err_t crypto_storage_store_csr(const unsigned char* csr_buffer, size_t len) {
    kd::NvsHandle nvs(NVS_NAMESPACE, NVS_READWRITE);
    if (!nvs) {
        ESP_LOGE(TAG, "nvs open failed: %s", esp_err_to_name(nvs.open_error()));
        return nvs.open_error();
    }

    esp_err_t err = nvs.set_blob(NVS_KEY_CSR, csr_buffer, len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs set CSR failed: %s", esp_err_to_name(err));
        return err;
    }

    err = nvs.commit();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs commit failed: %s", esp_err_to_name(err));
        return err;
    }

    return ESP_OK;
}

//MARK: Device Certificate Operations

esp_err_t crypto_storage_get_device_cert(char* buffer, size_t* len) {
    kd::NvsHandle nvs(NVS_NAMESPACE, NVS_READWRITE);
    if (!nvs) {
        ESP_LOGE(TAG, "nvs open failed: %s", esp_err_to_name(nvs.open_error()));
        return nvs.open_error();
    }

    // If both buffer and len are nullptr, just check if key exists
    if (buffer == nullptr && len == nullptr) {
        return nvs.find_key(NVS_KEY_DEVICE_CERT);
    }

    // nvs_get_blob with nullptr buffer returns the required size in len
    return nvs.get_blob(NVS_KEY_DEVICE_CERT, buffer, len);
}

esp_err_t crypto_storage_set_device_cert(const char* buffer, size_t len) {
    kd::NvsHandle nvs(NVS_NAMESPACE, NVS_READWRITE);
    if (!nvs) {
        ESP_LOGE(TAG, "nvs open failed: %s", esp_err_to_name(nvs.open_error()));
        return nvs.open_error();
    }

    esp_err_t err = nvs.set_blob(NVS_KEY_DEVICE_CERT, buffer, len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs set device cert failed: %s", esp_err_to_name(err));
        return err;
    }

    err = nvs.commit();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs commit failed: %s", esp_err_to_name(err));
    }
    return err;
}

esp_err_t crypto_storage_clear_device_cert() {
    kd::NvsHandle nvs(NVS_NAMESPACE, NVS_READWRITE);
    if (!nvs) {
        ESP_LOGE(TAG, "nvs open failed: %s", esp_err_to_name(nvs.open_error()));
        return nvs.open_error();
    }

    esp_err_t err = nvs.erase_key(NVS_KEY_DEVICE_CERT);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs erase device cert failed: %s", esp_err_to_name(err));
        return err;
    }

    err = nvs.commit();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs commit failed: %s", esp_err_to_name(err));
    }
    return err;
}

//MARK: Claim Token Operations

esp_err_t crypto_storage_get_claim_token(char* buffer, size_t* len) {
    kd::NvsHandle nvs(NVS_NAMESPACE, NVS_READWRITE);
    if (!nvs) {
        ESP_LOGE(TAG, "nvs open failed: %s", esp_err_to_name(nvs.open_error()));
        return nvs.open_error();
    }

    // If both buffer and len are nullptr, just check if key exists
    if (buffer == nullptr && len == nullptr) {
        return nvs.find_key(NVS_KEY_CLAIM_TOKEN);
    }

    // nvs_get_blob with nullptr buffer returns the required size in len
    esp_err_t err = nvs.get_blob(NVS_KEY_CLAIM_TOKEN, buffer, len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs get claim token failed: %s", esp_err_to_name(err));
    }
    return err;
}

esp_err_t crypto_storage_set_claim_token(const char* buffer, size_t len) {
    kd::NvsHandle nvs(NVS_NAMESPACE, NVS_READWRITE);
    if (!nvs) {
        ESP_LOGE(TAG, "nvs open failed: %s", esp_err_to_name(nvs.open_error()));
        return nvs.open_error();
    }

    esp_err_t err = nvs.set_blob(NVS_KEY_CLAIM_TOKEN, buffer, len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs set claim token failed: %s", esp_err_to_name(err));
        return err;
    }

    err = nvs.commit();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs commit failed: %s", esp_err_to_name(err));
    }
    return err;
}

esp_err_t crypto_storage_clear_claim_token() {
    kd::NvsHandle nvs(NVS_NAMESPACE, NVS_READWRITE);
    if (!nvs) {
        ESP_LOGE(TAG, "nvs open failed: %s", esp_err_to_name(nvs.open_error()));
        return nvs.open_error();
    }

    esp_err_t err = nvs.erase_key(NVS_KEY_CLAIM_TOKEN);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        return ESP_OK;  // Already cleared
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs erase claim token failed: %s", esp_err_to_name(err));
        return err;
    }

    err = nvs.commit();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs commit failed: %s", esp_err_to_name(err));
    }
    return err;
}

//MARK: DS Parameters Operations

esp_err_t crypto_storage_store_ds_params(const uint8_t* c, const uint8_t* iv, uint8_t key_id, uint16_t rsa_length) {
    kd::NvsHandle nvs(NVS_NAMESPACE, NVS_READWRITE);
    if (!nvs) {
        ESP_LOGE(TAG, "nvs open failed: %s", esp_err_to_name(nvs.open_error()));
        return nvs.open_error();
    }

    esp_err_t err = nvs.set_blob(NVS_KEY_CIPHERTEXT, c, ESP_DS_C_LEN);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs set ciphertext failed: %s", esp_err_to_name(err));
        return err;
    }

    err = nvs.set_blob(NVS_KEY_IV, iv, ESP_DS_IV_LEN);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs set iv failed: %s", esp_err_to_name(err));
        return err;
    }

    err = nvs.set_u8(NVS_KEY_DS_KEY_ID, key_id);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs set ds key id failed: %s", esp_err_to_name(err));
        return err;
    }

    err = nvs.set_u16(NVS_KEY_RSA_LEN, rsa_length);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs set rsa length failed: %s", esp_err_to_name(err));
        return err;
    }

    err = nvs.commit();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs commit failed: %s", esp_err_to_name(err));
        return err;
    }

    return ESP_OK;
}

esp_ds_data_ctx_t* crypto_storage_get_ds_ctx() {
    auto* ds_data_ctx = static_cast<esp_ds_data_ctx_t*>(
        calloc(1, sizeof(esp_ds_data_ctx_t)));
    if (ds_data_ctx == nullptr) {
        ESP_LOGE(TAG, "no mem for ds context");
        return nullptr;
    }

    ds_data_ctx->esp_ds_data = static_cast<esp_ds_data_t*>(
        calloc(1, sizeof(esp_ds_data_t)));
    if (ds_data_ctx->esp_ds_data == nullptr) {
        ESP_LOGE(TAG, "no mem for ds data");
        free(ds_data_ctx);
        return nullptr;
    }

    kd::NvsHandle nvs(NVS_NAMESPACE, NVS_READONLY);
    if (!nvs) {
        ESP_LOGE(TAG, "nvs open failed: %s", esp_err_to_name(nvs.open_error()));
        free(ds_data_ctx->esp_ds_data);
        free(ds_data_ctx);
        return nullptr;
    }

    size_t len = ESP_DS_C_LEN;
    esp_err_t err = nvs.get_blob(NVS_KEY_CIPHERTEXT, ds_data_ctx->esp_ds_data->c, &len);
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "failed to get ciphertext: %s", esp_err_to_name(err));
        free(ds_data_ctx->esp_ds_data);
        free(ds_data_ctx);
        return nullptr;
    }

    len = ESP_DS_IV_LEN;
    err = nvs.get_blob(NVS_KEY_IV, ds_data_ctx->esp_ds_data->iv, &len);
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "failed to get iv: %s", esp_err_to_name(err));
        free(ds_data_ctx->esp_ds_data);
        free(ds_data_ctx);
        return nullptr;
    }

    err = nvs.get_u8(NVS_KEY_DS_KEY_ID, &ds_data_ctx->efuse_key_id);
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "failed to get ds key id: %s", esp_err_to_name(err));
        free(ds_data_ctx->esp_ds_data);
        free(ds_data_ctx);
        return nullptr;
    }
    ds_data_ctx->efuse_key_id -= 4;

    err = nvs.get_u16(NVS_KEY_RSA_LEN, reinterpret_cast<uint16_t*>(&ds_data_ctx->esp_ds_data->rsa_length));
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "failed to get rsa length: %s", esp_err_to_name(err));
        free(ds_data_ctx->esp_ds_data);
        free(ds_data_ctx);
        return nullptr;
    }
    ds_data_ctx->rsa_length_bits = (ds_data_ctx->esp_ds_data->rsa_length + 1) * 32;

    return ds_data_ctx;
}

//MARK: JSON DS Params (Public API wrappers)

char* crypto_get_ds_params_json() {
    esp_ds_data_ctx_t* ds_data_ctx = crypto_storage_get_ds_ctx();
    if (ds_data_ctx == nullptr) {
        printf("{\"error_message\":\"no ds params\",\"error\":true}\n");
        return nullptr;
    }

    cJSON* json = cJSON_CreateObject();

    cJSON_AddNumberToObject(json, "ds_key_id", ds_data_ctx->efuse_key_id + 4);
    cJSON_AddNumberToObject(json, "rsa_len", ds_data_ctx->esp_ds_data->rsa_length);

    // Get required base64 size for cipher_c
    size_t base64_c_len = 0;
    mbedtls_base64_encode(nullptr, 0, &base64_c_len,
        reinterpret_cast<unsigned char*>(ds_data_ctx->esp_ds_data->c), ESP_DS_C_LEN);
    char* base64_c = static_cast<char*>(malloc(base64_c_len + 1));
    mbedtls_base64_encode(reinterpret_cast<unsigned char*>(base64_c), base64_c_len + 1, &base64_c_len,
        reinterpret_cast<unsigned char*>(ds_data_ctx->esp_ds_data->c), ESP_DS_C_LEN);
    cJSON_AddStringToObject(json, "cipher_c", base64_c);
    free(base64_c);

    // Get required base64 size for iv
    size_t base64_iv_len = 0;
    mbedtls_base64_encode(nullptr, 0, &base64_iv_len,
        reinterpret_cast<unsigned char*>(ds_data_ctx->esp_ds_data->iv), ESP_DS_IV_LEN);
    char* base64_iv = static_cast<char*>(malloc(base64_iv_len + 1));
    mbedtls_base64_encode(reinterpret_cast<unsigned char*>(base64_iv), base64_iv_len + 1, &base64_iv_len,
        reinterpret_cast<unsigned char*>(ds_data_ctx->esp_ds_data->iv), ESP_DS_IV_LEN);
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

    if (ds_params == nullptr) {
        free(params);
        return ESP_ERR_INVALID_ARG;
    }

    if (cJSON_GetObjectItem(ds_params, "ds_key_id") == nullptr ||
        cJSON_GetObjectItem(ds_params, "rsa_len") == nullptr ||
        cJSON_GetObjectItem(ds_params, "cipher_c") == nullptr ||
        cJSON_GetObjectItem(ds_params, "iv") == nullptr) {
        ESP_LOGE(TAG, "missing required ds params fields");
        free(params);
        cJSON_Delete(ds_params);
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t ds_key_id = static_cast<uint8_t>(cJSON_GetObjectItem(ds_params, "ds_key_id")->valueint);
    uint16_t rsa_length = static_cast<uint16_t>(cJSON_GetObjectItem(ds_params, "rsa_len")->valueint);

    char* base64_c = cJSON_GetObjectItem(ds_params, "cipher_c")->valuestring;
    char* base64_iv = cJSON_GetObjectItem(ds_params, "iv")->valuestring;

    size_t c_len = std::strlen(base64_c);
    size_t iv_len = std::strlen(base64_iv);

    uint8_t* c = static_cast<uint8_t*>(malloc(ESP_DS_C_LEN));
    uint8_t* iv = static_cast<uint8_t*>(malloc(ESP_DS_IV_LEN));

    if (c == nullptr || iv == nullptr) {
        free(c);
        free(iv);
        cJSON_Delete(ds_params);
        free(params);
        return ESP_ERR_NO_MEM;
    }

    size_t decoded_c_len = 0;
    size_t decoded_iv_len = 0;

    mbedtls_base64_decode(c, ESP_DS_C_LEN, &decoded_c_len,
        reinterpret_cast<unsigned char*>(base64_c), c_len);
    mbedtls_base64_decode(iv, ESP_DS_IV_LEN, &decoded_iv_len,
        reinterpret_cast<unsigned char*>(base64_iv), iv_len);

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

esp_efuse_block_t crypto::get_ds_key_block() {
    kd::NvsHandle nvs(NVS_NAMESPACE, NVS_READONLY);
    if (!nvs) {
        return EFUSE_BLK_KEY3;  // Default
    }

    uint8_t block = 0;
    esp_err_t err = nvs.get_u8(NVS_KEY_DS_KEY_BLOCK, &block);
    if (err != ESP_OK || block < 4 || block > 9) {
        return EFUSE_BLK_KEY3;  // Default
    }

    return static_cast<esp_efuse_block_t>(block);
}

esp_err_t crypto_set_ds_key_block(uint8_t block) {
    if (block < 4 || block > 9) {
        ESP_LOGE(TAG, "Invalid DS key block: %d (valid range: 4-9)", block);
        return ESP_ERR_INVALID_ARG;
    }

    kd::NvsHandle nvs(crypto::NVS_NAMESPACE, NVS_READWRITE);
    if (!nvs) {
        ESP_LOGE(TAG, "nvs open failed: %s", esp_err_to_name(nvs.open_error()));
        return nvs.open_error();
    }

    esp_err_t err = nvs.set_u8(crypto::NVS_KEY_DS_KEY_BLOCK, block);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs set ds key block failed: %s", esp_err_to_name(err));
        return err;
    }

    err = nvs.commit();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs commit failed: %s", esp_err_to_name(err));
    }
    return err;
}

uint8_t crypto_get_ds_key_block() {
    return static_cast<uint8_t>(crypto::get_ds_key_block());
}

bool crypto_is_key_block_burnt(uint8_t block) {
    if (block < 4 || block > 9) {
        return false;
    }
    esp_efuse_block_t efuse_block = static_cast<esp_efuse_block_t>(block);
    esp_efuse_purpose_t purpose = esp_efuse_get_key_purpose(efuse_block);
    return purpose != ESP_EFUSE_KEY_PURPOSE_USER;
}

esp_err_t crypto_clear_all_data() {
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
    kd::NvsHandle nvs(crypto::NVS_NAMESPACE, NVS_READWRITE);
    if (!nvs) {
        ESP_LOGE(TAG, "nvs open failed: %s", esp_err_to_name(nvs.open_error()));
        return nvs.open_error();
    }

    nvs.erase_key(crypto::NVS_KEY_CIPHERTEXT);
    nvs.erase_key(crypto::NVS_KEY_IV);
    nvs.erase_key(crypto::NVS_KEY_DS_KEY_ID);
    nvs.erase_key(crypto::NVS_KEY_RSA_LEN);

    err = nvs.commit();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs commit failed: %s", esp_err_to_name(err));
        return err;
    }

    return ESP_OK;
}

#endif // CONFIG_KD_COMMON_CRYPTO_ENABLE
