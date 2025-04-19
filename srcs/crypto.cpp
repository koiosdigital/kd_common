#include "kd_common.h"

#include "esp_ds.h"
#include "esp_efuse.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_heap_caps.h"
#include "nvs_flash.h"
#include "esp_wifi.h"


#include "mbedtls/rsa.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"
#include "mbedtls/sha256.h"
#include "mbedtls/bignum.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#include "provisioning.h"
#include "crypto_private.h"

#include "string.h"
#include "stdlib.h"

esp_err_t kd_common_get_device_cert(char* buffer, size_t* len) {
    esp_err_t error;
    nvs_handle handle;

    nvs_open(NVS_CRYPTO_NAMESPACE, NVS_READWRITE, &handle);

    if (buffer == NULL) {
        error = nvs_find_key(handle, NVS_CRYPTO_DEVICE_CERT, NULL);
        goto exit;
    }

    error = nvs_get_blob(handle, NVS_CRYPTO_DEVICE_CERT, buffer, len);

exit:
    nvs_close(handle);
    return error;
}

CryptoState_t kd_common_crypto_get_state() {
    CryptoState_t state = CRYPTO_STATE_UNINITIALIZED;
    if (crypto_get_csr(NULL, NULL) == ESP_OK) {
        state = CRYPTO_STATE_VALID_CSR;
    }

    if (kd_common_get_device_cert(NULL, NULL) == ESP_OK) {
        state = CRYPTO_STATE_VALID_CERT;
    }

    return state;
}


esp_ds_data_ctx_t* kd_common_crypto_get_ctx() {
    esp_ds_data_ctx_t* ds_data_ctx;
    nvs_handle handle;
    uint32_t len = 0;

    ds_data_ctx = (esp_ds_data_ctx_t*)calloc(1, sizeof(esp_ds_data_ctx_t));
    ds_data_ctx->esp_ds_data = (esp_ds_data_t*)calloc(1, sizeof(esp_ds_data_t));

    nvs_open(NVS_CRYPTO_NAMESPACE, NVS_READONLY, &handle);

    len = ESP_DS_C_LEN;
    nvs_get_blob(handle, NVS_CRYPTO_CIPHERTEXT, (char*)ds_data_ctx->esp_ds_data->c, (size_t*)&len);

    len = ESP_DS_IV_LEN;
    nvs_get_blob(handle, NVS_CRYPTO_IV, (char*)ds_data_ctx->esp_ds_data->iv, (size_t*)&len);

    nvs_get_u8(handle, NVS_CRYPTO_DS_KEY_ID, &ds_data_ctx->efuse_key_id);
    ds_data_ctx->efuse_key_id -= 4;

    nvs_get_u16(handle, NVS_CRYPTO_RSA_LEN, (uint16_t*)(void*)&ds_data_ctx->esp_ds_data->rsa_length);

    ds_data_ctx->rsa_length_bits = (ds_data_ctx->esp_ds_data->rsa_length + 1) * 32;

    nvs_close(handle);
    return ds_data_ctx;
}