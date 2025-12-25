#pragma once

#ifndef KD_COMMON_CRYPTO_DISABLE
#include "esp_ds.h"
#endif

#include "stdlib.h"

#ifndef DEVICE_NAME_PREFIX
#define DEVICE_NAME_PREFIX "KD"
#endif

#ifndef KD_COMMON_CRYPTO_DISABLE
typedef struct esp_ds_data_ctx {
    esp_ds_data_t* esp_ds_data;
    uint8_t efuse_key_id;
    uint16_t rsa_length_bits;
} esp_ds_data_ctx_t;

typedef enum CryptoState_t {
    CRYPTO_STATE_UNINITIALIZED,
    CRYPTO_STATE_KEY_GENERATED,
    CRYPTO_STATE_VALID_CSR,
    CRYPTO_STATE_VALID_CERT,
    CRYPTO_STATE_BAD_DS_PARAMS,
} CryptoState_t;
#endif

typedef enum ProvisioningTaskNotification_t {
    STOP_PROVISIONING = 1,
    START_PROVISIONING = 2,
    RESET_SM_ON_FAILURE = 3,
} ProvisioningTaskNotification_t;

typedef enum ProvisioningPOPTokenFormat_t {
    NONE = 0,
    ALPHA_8 = 1,
    NUMERIC_6 = 2,
} ProvisioningPOPTokenFormat_t;

void kd_common_init();
void kd_common_reverse_bytes(uint8_t* data, size_t len);

#ifndef KD_COMMON_CRYPTO_DISABLE
esp_ds_data_ctx_t* kd_common_crypto_get_ctx();
esp_err_t kd_common_get_device_cert(char* buffer, size_t* len);
esp_err_t kd_common_get_claim_token(char* buffer, size_t* len);
esp_err_t kd_common_clear_claim_token();

CryptoState_t kd_common_crypto_get_state();
bool kd_common_crypto_will_generate_key();
#endif

char* kd_common_get_device_name();

void kd_common_notify_provisioning_task(ProvisioningTaskNotification_t notification);
char* kd_common_provisioning_get_pop_token();
char* kd_common_get_provisioning_qr_payload();

char* kd_common_run_command(char* input, int* return_code);

void kd_common_wifi_disconnect();
void kd_common_clear_wifi_credentials();
bool kd_common_is_wifi_connected();
void kd_common_set_provisioning_pop_token_format(ProvisioningPOPTokenFormat_t format);

// WiFi hostname functions (separate from device name)
void kd_common_set_wifi_hostname(const char* hostname);
char* kd_common_get_wifi_hostname();

// OTA functions
#ifdef ENABLE_OTA
bool kd_common_ota_has_completed_boot_check();
#endif