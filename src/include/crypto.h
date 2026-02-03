#pragma once

#include "sdkconfig.h"

#include <esp_err.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NVS_CRYPTO_NAMESPACE "secure_crypto"

#define NVS_CRYPTO_DEVICE_CERT "dev_cert"
#define NVS_CRYPTO_CIPHERTEXT "cipher_c"
#define NVS_CRYPTO_IV "iv"
#define NVS_CRYPTO_DS_KEY_ID "ds_key_id"
#define NVS_CRYPTO_RSA_LEN "rsa_len"
#define NVS_CRYPTO_CSR "csr"
#define NVS_CRYPTO_CLAIM_TOKEN "claim_token" //really just the user's access token, provided by BLE provisioning
#define NVS_CRYPTO_DS_KEY_BLOCK "ds_key_blk"

// Valid DS key block range (EFUSE_BLK_KEY0 = 4, EFUSE_BLK_KEY5 = 9)
#define DS_KEY_BLOCK_MIN 4
#define DS_KEY_BLOCK_MAX 9
#define DS_KEY_BLOCK_DEFAULT 7  // EFUSE_BLK_KEY3

#ifdef CONFIG_KD_COMMON_CRYPTO_ENABLE

esp_err_t crypto_init(void);
esp_err_t crypto_get_csr(char* buffer, size_t* len);
esp_err_t crypto_clear_csr(void);
esp_err_t store_ds_params(uint8_t* c, uint8_t* iv, uint8_t key_id, uint16_t rsa_length);
esp_err_t crypto_set_device_cert(char* buffer, size_t len);
esp_err_t kd_common_clear_device_cert(void);
esp_err_t crypto_set_claim_token(char* buffer, size_t len);
char* crypto_get_ds_params_json(void);
esp_err_t crypto_store_ds_params_json(char* params);
bool crypto_will_generate_key(void);
esp_err_t crypto_clear_all_data(void);
esp_err_t crypto_set_ds_key_block(uint8_t block);
uint8_t crypto_get_ds_key_block(void);
bool crypto_is_key_block_burnt(uint8_t block);

#endif

#ifdef __cplusplus
}
#endif
