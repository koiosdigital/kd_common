#include "kd_common.h"

#include <nvs_flash.h>
#include <esp_log.h>

#include <esp_netif.h>

#include "crypto.h"
#include "console.h"
#include "kd_http.h"
#include "provisioning.h"
#include "wifi.h"
#include "eth.h"
#include "ntp.h"
#include "embedded_tz_db.h"
#include "kdmdns.h"
#ifdef CONFIG_KD_COMMON_API_ENABLE
#include "api.h"
#endif

static const char* TAG = "kd_common";

void kd_common_init(void) {
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

    // Shared HTTP client — must exist before any module that fetches
    kd_http_init();

#ifdef CONFIG_KD_COMMON_CRYPTO_ENABLE
    ret = crypto_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "crypto_init failed: %s", esp_err_to_name(ret));
    }
#endif

    // Phase 1: one-time network stack init, shared by every interface.
    esp_netif_init();

    // Phase 2: Initialize modules that register network connect/disconnect
    // callbacks. All callbacks are registered BEFORE any interface starts,
    // preventing the race where GOT_IP fires before handlers are ready. These
    // callbacks are interface-agnostic (see net.h), so they serve WiFi,
    // Ethernet, and any future link identically.
    ntp_init();

    kdmdns_init();

#ifdef CONFIG_KD_COMMON_API_ENABLE
    api_init();
#endif

    // Phase 3: Try Ethernet first. If it acquires an IP within the timeout,
    // the device runs over Ethernet and we skip WiFi + BLE provisioning
    // entirely. The driver is left running on timeout so a cable plugged in
    // later still connects via the same net callbacks.
    bool eth_active = false;
#ifdef CONFIG_KD_COMMON_ETH_ENABLE
    eth_active = eth_init(CONFIG_KD_COMMON_ETH_LINK_TIMEOUT_MS);
#endif

    if (eth_active) {
        ESP_LOGI(TAG, "Ethernet active; WiFi and BLE provisioning disabled");
        return;
    }

    // Phase 4: WiFi fallback. Bring up the WiFi driver, register provisioning's
    // event handlers, then start WiFi — all callbacks are already registered.
    wifi_init();
    provisioning_init();
    wifi_start();
}

void kd_common_reverse_bytes(uint8_t* data, size_t len) {
    for (size_t i = 0; i < len / 2; i++) {
        uint8_t temp = data[i];
        data[i] = data[len - i - 1];
        data[len - i - 1] = temp;
    }
}

#ifdef CONFIG_KD_COMMON_CRYPTO_ENABLE
bool kd_common_crypto_will_generate_key(void) {
    return crypto_will_generate_key();
}
#endif

bool kd_common_ntp_is_synced(void) {
    return ntp_is_synced();
}

void kd_common_ntp_sync(void) {
    ntp_sync();
}

void kd_common_set_auto_timezone(bool enabled) {
    ntp_set_auto_timezone(enabled);
}

bool kd_common_get_auto_timezone(void) {
    return ntp_get_auto_timezone();
}

void kd_common_set_fetch_tz_on_boot(bool enabled) {
    ntp_set_fetch_tz_on_boot(enabled);
}

bool kd_common_get_fetch_tz_on_boot(void) {
    return ntp_get_fetch_tz_on_boot();
}

void kd_common_set_timezone(const char* timezone) {
    ntp_set_timezone(timezone);
}

const char* kd_common_get_timezone(void) {
    return ntp_get_timezone();
}

void kd_common_set_ntp_server(const char* server) {
    ntp_set_server(server);
}

const char* kd_common_get_ntp_server(void) {
    return ntp_get_server();
}

const kd_common_tz_entry_t* kd_common_get_all_timezones(void) {
    // The struct layouts are identical (name, rule pointers), safe to cast
    return (const kd_common_tz_entry_t*)tz_db_get_all_zones();
}

int kd_common_get_timezone_count(void) {
    return TZ_DB_NUM_ZONES;
}

// mDNS functions
void kd_common_set_device_info(const char* model, const char* type) {
    kdmdns_set_device_info(model, type);
}

void kd_common_mdns_add_svc_record(const char* service, const char* key, const char* value) {
    kdmdns_add_svc_record(service, key, value);
}

// API functions
#ifdef CONFIG_KD_COMMON_API_ENABLE
void kd_common_api_register_handlers(kd_common_api_handler_registrar_fn registrar) {
    api_register_handlers(registrar);
}
#endif
