#include "wifi.h"

#include <esp_err.h>
#include <esp_event.h>
#include <esp_log.h>
#include <esp_wifi.h>

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include <cstring>

#include "kd_common.h"
#include "nvs_handle.h"

static const char* TAG = "kd_wifi";

namespace {

constexpr const char* NVS_NAMESPACE = "kd_common";
constexpr const char* HOSTNAME_KEY = "wifi_hostname";
constexpr size_t MAX_HOSTNAME_LEN = 63;  // RFC 1123

struct HostnameCache {
    char buffer[MAX_HOSTNAME_LEN + 1] = {};
    bool loaded = false;
};

HostnameCache hostname_cache;

}  // namespace

void kd_common_wifi_disconnect() {
    esp_wifi_disconnect();
}

void kd_common_clear_wifi_credentials() {
    ESP_LOGI(TAG, "Clearing WiFi credentials");
    kd_common_wifi_disconnect();

    wifi_config_t wifi_cfg = {};
    esp_wifi_set_config(WIFI_IF_STA, &wifi_cfg);
}

void wifi_init() {
    ESP_LOGI(TAG, "Initializing");

    esp_netif_init();
    esp_netif_t* netif = esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_set_ps(WIFI_PS_NONE);
    esp_netif_set_hostname(netif, kd_common_get_wifi_hostname());
    esp_wifi_start();
    esp_wifi_connect();  // Connect directly (reconnects handled by event handler)
}

void wifi_restart() {
    ESP_LOGI(TAG, "Restarting WiFi");
    esp_wifi_stop();
    esp_wifi_deinit();
    wifi_init();
}

void kd_common_set_wifi_hostname(const char* hostname) {
    if (!hostname || std::strlen(hostname) == 0 || std::strlen(hostname) > MAX_HOSTNAME_LEN) {
        ESP_LOGE(TAG, "Invalid hostname length");
        return;
    }

    kd::NvsHandle nvs(NVS_NAMESPACE, NVS_READWRITE);
    if (!nvs) {
        ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(nvs.open_error()));
        return;
    }

    esp_err_t err = nvs.set_str(HOSTNAME_KEY, hostname);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to save hostname: %s", esp_err_to_name(err));
        return;
    }

    err = nvs.commit();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to commit hostname: %s", esp_err_to_name(err));
        return;
    }

    ESP_LOGI(TAG, "WiFi hostname set to: %s", hostname);

    // Invalidate cache and restart WiFi
    hostname_cache.loaded = false;
    wifi_restart();
}

char* kd_common_get_wifi_hostname() {
    // Return cached hostname if available
    if (hostname_cache.loaded && hostname_cache.buffer[0] != '\0') {
        return hostname_cache.buffer;
    }

    // Try to load from NVS
    kd::NvsHandle nvs(NVS_NAMESPACE, NVS_READONLY);
    if (nvs) {
        size_t required_size = sizeof(hostname_cache.buffer);
        esp_err_t err = nvs.get_str(HOSTNAME_KEY, hostname_cache.buffer, &required_size);

        if (err == ESP_OK && hostname_cache.buffer[0] != '\0') {
            hostname_cache.loaded = true;
            ESP_LOGI(TAG, "Using stored hostname: %s", hostname_cache.buffer);
            return hostname_cache.buffer;
        }

        if (err != ESP_ERR_NVS_NOT_FOUND) {
            ESP_LOGW(TAG, "Failed to get hostname from NVS: %s", esp_err_to_name(err));
        }
    }

    // Fall back to device name
    char* device_name = kd_common_get_device_name();
    if (device_name) {
        std::strncpy(hostname_cache.buffer, device_name, MAX_HOSTNAME_LEN);
        hostname_cache.buffer[MAX_HOSTNAME_LEN] = '\0';
        hostname_cache.loaded = true;
        ESP_LOGI(TAG, "Using device name as hostname: %s", hostname_cache.buffer);
        return hostname_cache.buffer;
    }

    // Ultimate fallback
    std::strcpy(hostname_cache.buffer, "kd-device");
    hostname_cache.loaded = true;
    ESP_LOGI(TAG, "Using fallback hostname: %s", hostname_cache.buffer);
    return hostname_cache.buffer;
}
