#pragma once

#include "stdlib.h"
#include "esp_err.h"
#include "esp_event.h"
#include "sdkconfig.h"

#ifdef CONFIG_KD_COMMON_CRYPTO_ENABLE
#include "esp_ds.h"
#endif

#ifdef CONFIG_KD_COMMON_API_ENABLE
#include <esp_http_server.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

    // NTP Events - posted when sync state changes
    ESP_EVENT_DECLARE_BASE(KD_NTP_EVENTS);

    typedef enum {
        KD_NTP_EVENT_SYNC_COMPLETE = 0,  // Time successfully synchronized
        KD_NTP_EVENT_SYNC_LOST = 1,      // WiFi disconnected, sync may be stale
    } kd_ntp_event_id_t;

#ifdef __cplusplus
}
#endif

#ifdef CONFIG_KD_COMMON_CRYPTO_ENABLE
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

typedef enum ProvisioningSRPPasswordFormat_t {
    STATIC = 0,
    NUMERIC_6 = 1,
    NUMERIC_6_REDUCED = 2,
    NUMERIC_4 = 3
} ProvisioningSRPPasswordFormat_t;

void kd_common_init();
void kd_common_reverse_bytes(uint8_t* data, size_t len);

#ifdef CONFIG_KD_COMMON_CRYPTO_ENABLE
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
char* kd_common_provisioning_get_srp_password();
void kd_common_set_provisioning_srp_password_format(ProvisioningSRPPasswordFormat_t format);
void kd_common_start_provisioning();  // Start BLE provisioning manually (e.g., button hold)

char* kd_common_run_command(char* input, int* return_code);

#ifdef CONFIG_KD_COMMON_CONSOLE_ENABLE
// Console command registration for external components
typedef int (*kd_console_cmd_func_t)(int argc, char** argv);

esp_err_t kd_console_register_cmd(const char* command, const char* help,
    kd_console_cmd_func_t func);

esp_err_t kd_console_register_cmd_with_args(const char* command, const char* help,
    kd_console_cmd_func_t func, void* argtable);

// Formatted output (respects capture mode for kd_common_run_command)
int console_out(const char* format, ...) __attribute__((format(printf, 1, 2)));
#endif

// WiFi functions
void kd_common_wifi_disconnect();
void kd_common_clear_wifi_credentials();
bool kd_common_is_wifi_connected();
esp_err_t kd_common_wifi_connect(const char* ssid, const char* password);

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

// Timezone database access (for API endpoints)
typedef struct {
    const char* name;
    const char* rule;
} kd_common_tz_entry_t;

const kd_common_tz_entry_t* kd_common_get_all_timezones();
int kd_common_get_timezone_count();

// mDNS functions
void kd_common_set_device_info(const char* model, const char* type);

// API functions
#ifdef CONFIG_KD_COMMON_API_ENABLE
// Callback type for registering HTTP handlers
typedef void (*kd_common_api_handler_registrar_fn)(httpd_handle_t server);

// Register a callback to be called with httpd handle when server starts.
// If server is already running, callback is invoked immediately.
// Callbacks are stored and re-invoked on WiFi reconnect.
void kd_common_api_register_handlers(kd_common_api_handler_registrar_fn registrar);
#endif