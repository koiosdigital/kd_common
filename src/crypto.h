#pragma once

#include <esp_err.h>

#define NVS_CRYPTO_NAMESPACE "secure_crypto"

#define NVS_CRYPTO_DEVICE_CERT "dev_cert"
#define NVS_CRYPTO_CIPHERTEXT "cipher_c"
#define NVS_CRYPTO_IV "iv"
#define NVS_CRYPTO_DS_KEY_ID "ds_key_id"
#define NVS_CRYPTO_RSA_LEN "rsa_len"
#define NVS_CRYPTO_CSR "csr"
#define NVS_CRYPTO_CLAIM_TOKEN "claim_token" //really just the user's access token, provided by BLE provisioning

#define DS_KEY_BLOCK EFUSE_BLK_KEY3
#define KEY_SIZE 4096

esp_err_t crypto_init();
esp_err_t crypto_get_csr(char* buffer, size_t* len);
esp_err_t crypto_clear_csr();
esp_err_t store_ds_params(uint8_t* c, uint8_t* iv, uint8_t key_id, uint16_t rsa_length);
esp_err_t crypto_set_device_cert(char* buffer, size_t len);
esp_err_t crypto_set_claim_token(char* buffer, size_t len);
char* crypto_get_ds_params_json();
esp_err_t crypto_store_ds_params_json(char* params);
