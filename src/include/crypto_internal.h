#pragma once

#include "sdkconfig.h"

#include <esp_ds.h>
#include <esp_efuse.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

#include "kd_common.h"  // for esp_ds_data_ctx_t

#ifdef __cplusplus
extern "C" {
#endif

// Shared constants
#define CRYPTO_NVS_NAMESPACE "secure_crypto"
#define CRYPTO_NVS_KEY_DEVICE_CERT "dev_cert"
#define CRYPTO_NVS_KEY_CIPHERTEXT "cipher_c"
#define CRYPTO_NVS_KEY_IV "iv"
#define CRYPTO_NVS_KEY_DS_KEY_ID "ds_key_id"
#define CRYPTO_NVS_KEY_RSA_LEN "rsa_len"
#define CRYPTO_NVS_KEY_CSR "csr"
#define CRYPTO_NVS_KEY_CLAIM_TOKEN "claim_token"
#define CRYPTO_NVS_KEY_DS_KEY_BLOCK "ds_key_blk"

#define CRYPTO_MAX_CLAIM_TOKEN_SIZE 256

#define CRYPTO_KEY_SIZE 4096
#define CRYPTO_PEM_BUFFER_SIZE 12288  // 12KB for fullchain (leaf + intermediates)

// Get current DS key block (reads from NVS, defaults to EFUSE_BLK_KEY3)
esp_efuse_block_t crypto_get_ds_key_block_internal(void);

// Global keygen mutex (defined in crypto.c)
extern SemaphoreHandle_t g_keygen_mutex;

// Internal functions - crypto_storage.c
esp_err_t crypto_storage_get_csr(char* buffer, size_t* len);
esp_err_t crypto_storage_clear_csr(void);
esp_err_t crypto_storage_store_csr(const unsigned char* csr_buffer, size_t len);
esp_err_t crypto_storage_get_device_cert(char* buffer, size_t* len);
esp_err_t crypto_storage_set_device_cert(const char* buffer, size_t len);
esp_err_t crypto_storage_clear_device_cert(void);
esp_err_t crypto_storage_get_claim_token(char* buffer, size_t* len);
esp_err_t crypto_storage_set_claim_token(const char* buffer, size_t len);
esp_err_t crypto_storage_clear_claim_token(void);
esp_err_t crypto_storage_store_ds_params(uint32_t key_block_id, uint32_t rsa_len,
                                         const uint8_t* cipher_c, size_t cipher_c_len,
                                         const uint8_t* iv, size_t iv_len);
esp_err_t crypto_storage_get_ds_params(uint32_t* key_block_id, uint32_t* rsa_len,
                                       uint8_t* cipher_c, size_t* cipher_c_len,
                                       uint8_t* iv, size_t* iv_len);
esp_ds_data_ctx_t* crypto_storage_get_ds_ctx(void);

// Internal functions - crypto_keygen.c
esp_err_t ensure_key_exists(void);

#ifdef __cplusplus
}
#endif
