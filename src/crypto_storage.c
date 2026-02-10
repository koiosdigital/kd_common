#include "crypto.h"

#ifdef CONFIG_KD_COMMON_CRYPTO_ENABLE

#include "crypto_internal.h"
#include "nvs_helper.h"

#include <esp_log.h>
#include <esp_ds.h>

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
    if (len > CRYPTO_MAX_CLAIM_TOKEN_SIZE) {
        ESP_LOGE(TAG, "claim token too large: %zu > %d", len, CRYPTO_MAX_CLAIM_TOKEN_SIZE);
        return ESP_ERR_INVALID_SIZE;
    }

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

esp_err_t crypto_storage_store_ds_params(uint32_t key_block_id, uint32_t rsa_len,
                                         const uint8_t* cipher_c, size_t cipher_c_len,
                                         const uint8_t* iv, size_t iv_len) {
    if (cipher_c_len != ESP_DS_C_LEN) {
        ESP_LOGE(TAG, "invalid cipher_c length: %zu (expected %d)", cipher_c_len, ESP_DS_C_LEN);
        return ESP_ERR_INVALID_ARG;
    }
    if (iv_len != ESP_DS_IV_LEN) {
        ESP_LOGE(TAG, "invalid iv length: %zu (expected %d)", iv_len, ESP_DS_IV_LEN);
        return ESP_ERR_INVALID_ARG;
    }

    nvs_helper_t nvs = nvs_helper_open(CRYPTO_NVS_NAMESPACE, NVS_READWRITE);
    if (!nvs.valid) {
        ESP_LOGE(TAG, "nvs open failed: %s", esp_err_to_name(nvs.open_err));
        return nvs.open_err;
    }

    esp_err_t err = nvs_helper_set_blob(&nvs, CRYPTO_NVS_KEY_CIPHERTEXT, cipher_c, ESP_DS_C_LEN);
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

    err = nvs_helper_set_u8(&nvs, CRYPTO_NVS_KEY_DS_KEY_ID, (uint8_t)key_block_id);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs set ds key id failed: %s", esp_err_to_name(err));
        nvs_helper_close(&nvs);
        return err;
    }

    err = nvs_helper_set_u16(&nvs, CRYPTO_NVS_KEY_RSA_LEN, (uint16_t)rsa_len);
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

esp_err_t crypto_storage_get_ds_params(uint32_t* key_block_id, uint32_t* rsa_len,
                                       uint8_t* cipher_c, size_t* cipher_c_len,
                                       uint8_t* iv, size_t* iv_len) {
    nvs_helper_t nvs = nvs_helper_open(CRYPTO_NVS_NAMESPACE, NVS_READONLY);
    if (!nvs.valid) {
        ESP_LOGE(TAG, "nvs open failed: %s", esp_err_to_name(nvs.open_err));
        return nvs.open_err;
    }

    // Get key_block_id
    uint8_t key_id = 0;
    esp_err_t err = nvs_helper_get_u8(&nvs, CRYPTO_NVS_KEY_DS_KEY_ID, &key_id);
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "failed to get ds key id: %s", esp_err_to_name(err));
        nvs_helper_close(&nvs);
        return err;
    }
    if (key_block_id != NULL) {
        *key_block_id = (uint32_t)key_id;
    }

    // Get rsa_len
    uint16_t rsa_length = 0;
    err = nvs_helper_get_u16(&nvs, CRYPTO_NVS_KEY_RSA_LEN, &rsa_length);
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "failed to get rsa length: %s", esp_err_to_name(err));
        nvs_helper_close(&nvs);
        return err;
    }
    if (rsa_len != NULL) {
        *rsa_len = (uint32_t)rsa_length;
    }

    // Get cipher_c
    if (cipher_c != NULL && cipher_c_len != NULL) {
        size_t len = *cipher_c_len;
        err = nvs_helper_get_blob(&nvs, CRYPTO_NVS_KEY_CIPHERTEXT, cipher_c, &len);
        if (err != ESP_OK) {
            ESP_LOGD(TAG, "failed to get ciphertext: %s", esp_err_to_name(err));
            nvs_helper_close(&nvs);
            return err;
        }
        *cipher_c_len = len;
    } else if (cipher_c_len != NULL) {
        *cipher_c_len = ESP_DS_C_LEN;
    }

    // Get iv
    if (iv != NULL && iv_len != NULL) {
        size_t len = *iv_len;
        err = nvs_helper_get_blob(&nvs, CRYPTO_NVS_KEY_IV, iv, &len);
        if (err != ESP_OK) {
            ESP_LOGD(TAG, "failed to get iv: %s", esp_err_to_name(err));
            nvs_helper_close(&nvs);
            return err;
        }
        *iv_len = len;
    } else if (iv_len != NULL) {
        *iv_len = ESP_DS_IV_LEN;
    }

    nvs_helper_close(&nvs);
    return ESP_OK;
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
