#include "wifi.h"

#include <esp_err.h>
#include <esp_event.h>
#include <esp_log.h>
#include <esp_wifi.h>
#include <esp_http_client.h>
#include <esp_crt_bundle.h>
#include <nvs_flash.h>
#include <nvs.h>
#include "cJSON.h"

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <string.h>

#include "kd_common.h"

static const char* TAG = "kd_wifi";

#define KD_COMMON_NVS_NAMESPACE "kd_common"
#define WIFI_HOSTNAME_KEY "wifi_hostname"
#define MAX_HOSTNAME_LEN 63  // Maximum hostname length per RFC 1123

//MARK: Public API
void kd_common_wifi_disconnect() {
    esp_wifi_disconnect();
}

void kd_common_clear_wifi_credentials() {
    ESP_LOGI(TAG, "clearing wifi credentials");

    kd_common_wifi_disconnect();
    wifi_config_t wifi_cfg;
    memset(&wifi_cfg, 0, sizeof(wifi_cfg));
    esp_wifi_set_config(WIFI_IF_STA, &wifi_cfg);
}

//MARK: Private API
void wifi_init() {
    ESP_LOGI(TAG, "initializing");

    esp_netif_init();

    esp_netif_t* netif = esp_netif_create_default_wifi_sta();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();

    esp_wifi_init(&cfg);
    esp_wifi_set_mode(wifi_mode_t::WIFI_MODE_STA);
    esp_netif_set_hostname(netif, kd_common_get_wifi_hostname());
    esp_wifi_start();
}

void kd_common_set_wifi_hostname(const char* hostname) {
    if (hostname == NULL || strlen(hostname) == 0 || strlen(hostname) > MAX_HOSTNAME_LEN) {
        ESP_LOGE(TAG, "Invalid hostname length");
        return;
    }

    nvs_handle_t handle;
    esp_err_t err = nvs_open(KD_COMMON_NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open NVS handle for hostname: %s", esp_err_to_name(err));
        return;
    }

    err = nvs_set_str(handle, WIFI_HOSTNAME_KEY, hostname);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to save hostname to NVS: %s", esp_err_to_name(err));
    }
    else {
        err = nvs_commit(handle);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to commit hostname to NVS: %s", esp_err_to_name(err));
        }
        else {
            ESP_LOGI(TAG, "WiFi hostname set to: %s", hostname);
        }
    }

    nvs_close(handle);
}

char* kd_common_get_wifi_hostname() {
    static char hostname[MAX_HOSTNAME_LEN + 1] = { 0 };
    static bool hostname_loaded = false;
    size_t required_size = sizeof(hostname);
    char* device_name = kd_common_get_device_name();

    // Return cached hostname if already loaded
    if (hostname_loaded && strlen(hostname) > 0) {
        return hostname;
    }

    nvs_handle_t handle;
    esp_err_t err = nvs_open(KD_COMMON_NVS_NAMESPACE, NVS_READONLY, &handle);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to open NVS handle for hostname: %s", esp_err_to_name(err));
        goto use_default;
    }

    err = nvs_get_str(handle, WIFI_HOSTNAME_KEY, hostname, &required_size);
    nvs_close(handle);

    if (err == ESP_OK && strlen(hostname) > 0) {
        hostname_loaded = true;
        ESP_LOGI(TAG, "Using stored WiFi hostname: %s", hostname);
        return hostname;
    }
    else if (err != ESP_ERR_NVS_NOT_FOUND) {
        ESP_LOGW(TAG, "Failed to get hostname from NVS: %s", esp_err_to_name(err));
    }

use_default:
    // Default to device name if no custom hostname is set
    if (device_name != NULL) {
        strncpy(hostname, device_name, MAX_HOSTNAME_LEN);
        hostname[MAX_HOSTNAME_LEN] = '\0';
        hostname_loaded = true;
        ESP_LOGI(TAG, "Using default WiFi hostname: %s", hostname);
        return hostname;
    }

    // Fallback to a default hostname if device name is unavailable
    strcpy(hostname, "kd-clock");
    hostname_loaded = true;
    ESP_LOGI(TAG, "Using fallback WiFi hostname: %s", hostname);
    return hostname;
}