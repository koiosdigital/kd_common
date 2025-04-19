#pragma once

#include <esp_err.h>

#define NVS_CRYPTO_PARTITION "nvs_factory"
#define NVS_CRYPTO_NAMESPACE "secure_crypto"

#define NVS_CRYPTO_DEVICE_CERT "dev_cert"
#define NVS_CRYPTO_CIPHERTEXT "cipher_c"
#define NVS_CRYPTO_IV "iv"
#define NVS_CRYPTO_DS_KEY_ID "ds_key_id"
#define NVS_CRYPTO_RSA_LEN "rsa_len"
#define NVS_CRYPTO_CSR "csr"

#define DS_KEY_BLOCK EFUSE_BLK_KEY3
#define KEY_SIZE 4096

esp_err_t crypto_init();
esp_err_t crypto_get_csr(char* buffer, size_t* len);
esp_err_t crypto_clear_csr();
esp_err_t crypto_set_device_cert(char* buffer, size_t len);
