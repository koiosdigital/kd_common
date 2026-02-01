#pragma once

#include <esp_ds.h>
#include <esp_efuse.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

#include "mbedtls/rsa.h"

#include "kd_common.h"  // for esp_ds_data_ctx_t

// Shared constants
namespace crypto {

    constexpr const char* NVS_NAMESPACE = "secure_crypto";
    constexpr const char* NVS_KEY_DEVICE_CERT = "dev_cert";
    constexpr const char* NVS_KEY_CIPHERTEXT = "cipher_c";
    constexpr const char* NVS_KEY_IV = "iv";
    constexpr const char* NVS_KEY_DS_KEY_ID = "ds_key_id";
    constexpr const char* NVS_KEY_RSA_LEN = "rsa_len";
    constexpr const char* NVS_KEY_CSR = "csr";
    constexpr const char* NVS_KEY_CLAIM_TOKEN = "claim_token";
    constexpr const char* NVS_KEY_DS_KEY_BLOCK = "ds_key_blk";

    constexpr size_t KEY_SIZE = 4096;
    constexpr size_t PEM_BUFFER_SIZE = 12288;  // 12KB for fullchain (leaf + intermediates)

    // Get current DS key block (reads from NVS, defaults to EFUSE_BLK_KEY3)
    esp_efuse_block_t get_ds_key_block();

    // Global keygen mutex (defined in crypto.cpp)
    extern SemaphoreHandle_t keygen_mutex;

}  // namespace crypto

// Internal functions - crypto_storage.cpp
esp_err_t crypto_storage_get_csr(char* buffer, size_t* len);
esp_err_t crypto_storage_clear_csr();
esp_err_t crypto_storage_store_csr(const unsigned char* csr_buffer, size_t len);
esp_err_t crypto_storage_get_device_cert(char* buffer, size_t* len);
esp_err_t crypto_storage_set_device_cert(const char* buffer, size_t len);
esp_err_t crypto_storage_clear_device_cert();
esp_err_t crypto_storage_get_claim_token(char* buffer, size_t* len);
esp_err_t crypto_storage_set_claim_token(const char* buffer, size_t len);
esp_err_t crypto_storage_clear_claim_token();
esp_err_t crypto_storage_store_ds_params(const uint8_t* c, const uint8_t* iv, uint8_t key_id, uint16_t rsa_length);
esp_ds_data_ctx_t* crypto_storage_get_ds_ctx();

// Internal functions - crypto_keygen.cpp
void keygen_task(void* pvParameter);
void calculate_rinv_mprime(mbedtls_mpi* N, mbedtls_mpi* rinv, uint32_t* mprime);
void rinv_mprime_to_ds_params(mbedtls_mpi* D, mbedtls_mpi* N, mbedtls_mpi* rinv, uint32_t mprime, esp_ds_p_data_t* params);
esp_err_t store_csr(mbedtls_rsa_context* rsa);
esp_err_t ensure_key_exists();
