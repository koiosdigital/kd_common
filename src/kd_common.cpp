#include "kd_common.h"

#include <nvs_flash.h>
#include <esp_log.h>

#include "crypto.h"
#include "console.h"
#include "provisioning.h"
#include "wifi.h"
#include "ota.h"
#include "ntp.h"
#include "embedded_tz_db.h"
#include "kdmdns.h"
#ifdef CONFIG_KD_COMMON_API_ENABLE
#include "api.h"
#endif

static const char* TAG = "kd_common";

void kd_common_init() {
    ESP_LOGI(TAG, "initializing");

    // Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        ret = nvs_flash_init();
    }

#ifdef CONFIG_KD_COMMON_CONSOLE_ENABLE
    console_init();
#endif

#ifdef CONFIG_KD_COMMON_CRYPTO_ENABLE
    crypto_init();
#endif

    wifi_init();         // Start WiFi and connect
    provisioning_init(); // Check provisioned state, start BLE if needed
    ntp_init();          // Start NTP when WiFi connects

#ifdef ENABLE_OTA
    ota_init();
#endif

    kdmdns_init();

#ifdef CONFIG_KD_COMMON_API_ENABLE
    api_init();
#endif
}

void kd_common_reverse_bytes(uint8_t* data, size_t len) {
    for (size_t i = 0; i < len / 2; i++) {
        uint8_t temp = data[i];
        data[i] = data[len - i - 1];
        data[len - i - 1] = temp;
    }
}

#ifdef ENABLE_OTA
bool kd_common_ota_has_completed_boot_check() {
    return ota_has_completed_boot_check();
}

void kd_common_check_ota() {
    ota_check_now();
}
#endif

#ifdef CONFIG_KD_COMMON_CRYPTO_ENABLE
bool kd_common_crypto_will_generate_key() {
    return crypto_will_generate_key();
}
#endif

bool kd_common_ntp_is_synced() {
    return ntp_is_synced();
}

void kd_common_ntp_sync() {
    ntp_sync();
}

void kd_common_set_auto_timezone(bool enabled) {
    ntp_set_auto_timezone(enabled);
}

bool kd_common_get_auto_timezone() {
    return ntp_get_auto_timezone();
}

void kd_common_set_fetch_tz_on_boot(bool enabled) {
    ntp_set_fetch_tz_on_boot(enabled);
}

bool kd_common_get_fetch_tz_on_boot() {
    return ntp_get_fetch_tz_on_boot();
}

void kd_common_set_timezone(const char* timezone) {
    ntp_set_timezone(timezone);
}

const char* kd_common_get_timezone() {
    return ntp_get_timezone();
}

void kd_common_set_ntp_server(const char* server) {
    ntp_set_server(server);
}

const char* kd_common_get_ntp_server() {
    return ntp_get_server();
}

const kd_common_tz_entry_t* kd_common_get_all_timezones() {
    // The struct layouts are identical (name, rule pointers), safe to cast
    return reinterpret_cast<const kd_common_tz_entry_t*>(tz_db_get_all_zones());
}

int kd_common_get_timezone_count() {
    return TZ_DB_NUM_ZONES;
}

// mDNS functions
void kd_common_set_device_info(const char* model, const char* type) {
    kdmdns_set_device_info(model, type);
}

// API functions
#ifdef CONFIG_KD_COMMON_API_ENABLE
httpd_handle_t kd_common_api_get_httpd_handle() {
    return api_get_httpd_handle();
}
#endif