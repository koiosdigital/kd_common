#pragma once

#include "sdkconfig.h"

#ifdef CONFIG_KD_COMMON_CRYPTO_ENABLE

#include "esp_err.h"
#include "esp_ds.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct esp_ds_data_ctx {
    esp_ds_data_t* esp_ds_data;
    uint8_t efuse_key_id;
    uint16_t rsa_length_bits;
} esp_ds_data_ctx_t;

#define KD_CRYPTO_MAX_CLAIM_TOKEN_SIZE 256

typedef enum CryptoState_t {
    CRYPTO_STATE_UNINITIALIZED,
    CRYPTO_STATE_KEY_GENERATED,
    CRYPTO_STATE_VALID_CSR,
    CRYPTO_STATE_VALID_CERT,
    CRYPTO_STATE_BAD_DS_PARAMS,
} CryptoState_t;

// Crypto functions
esp_ds_data_ctx_t* kd_common_crypto_get_ctx(void);
esp_err_t kd_common_get_device_cert(char* buffer, size_t* len);
esp_err_t kd_common_set_device_cert(const char* cert, size_t len);
esp_err_t kd_common_get_csr(char* buffer, size_t* len);
esp_err_t kd_common_get_claim_token(char* buffer, size_t* len);
esp_err_t kd_common_clear_claim_token(void);

CryptoState_t kd_common_crypto_get_state(void);
bool kd_common_crypto_will_generate_key(void);
esp_err_t kd_common_crypto_test_ds_signing(void);  // Debug: test DS peripheral signing

#ifdef __cplusplus
}
#endif

#endif // CONFIG_KD_COMMON_CRYPTO_ENABLE
