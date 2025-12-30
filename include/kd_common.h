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
esp_err_t kd_common_set_device_cert(const char* cert, size_t len);
esp_err_t kd_common_get_csr(char* buffer, size_t* len);
esp_err_t kd_common_get_claim_token(char* buffer, size_t* len);
esp_err_t kd_common_clear_claim_token();

CryptoState_t kd_common_crypto_get_state();
bool kd_common_crypto_will_generate_key();
esp_err_t kd_common_crypto_test_ds_signing();  // Debug: test DS peripheral signing
#endif

char* kd_common_get_device_name();

// Provisioning functions
char* kd_common_provisioning_get_pop_token();
char* kd_common_get_provisioning_qr_payload();
void kd_common_set_provisioning_pop_token_format(ProvisioningPOPTokenFormat_t format);
void kd_common_start_provisioning();  // Start BLE provisioning manually (e.g., button hold)

char* kd_common_run_command(char* input, int* return_code);

// WiFi functions
void kd_common_wifi_disconnect();
void kd_common_clear_wifi_credentials();
bool kd_common_is_wifi_connected();

// WiFi hostname functions (separate from device name)
void kd_common_set_wifi_hostname(const char* hostname);
char* kd_common_get_wifi_hostname();

// OTA functions
#ifdef ENABLE_OTA
bool kd_common_ota_has_completed_boot_check();
void kd_common_check_ota();  // Trigger manual OTA check
#endif

// NTP/Time functions
bool kd_common_ntp_is_synced();
void kd_common_ntp_sync();

// Timezone functions
void kd_common_set_auto_timezone(bool enabled);
bool kd_common_get_auto_timezone();
void kd_common_set_fetch_tz_on_boot(bool enabled);  // Disable for UTC-only apps
bool kd_common_get_fetch_tz_on_boot();
void kd_common_set_timezone(const char* timezone);  // IANA name like "America/New_York"
const char* kd_common_get_timezone();
void kd_common_set_ntp_server(const char* server);
const char* kd_common_get_ntp_server();