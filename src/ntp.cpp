// NTP time synchronization with timezone support
#include "ntp.h"

#include <cstring>
#include <esp_log.h>
#include <esp_sntp.h>
#include <esp_event.h>
#include <esp_wifi.h>
#include <esp_http_client.h>
#include <esp_crt_bundle.h>
#include <nvs_flash.h>
#include <nvs.h>
#include <time.h>
#include <cJSON.h>

#include "embedded_tz_db.h"

#define NTP_NVS_NAMESPACE "ntp_cfg"
#define TIME_INFO_URL "https://firmware.api.koiosdigital.net/tz"

static const char* TAG = "ntp";

namespace {

bool g_initialized = false;
bool g_synced = false;

// Track if settings were modified before init (to preserve them)
bool g_fetch_tz_set_before_init = false;
bool g_auto_tz_set_before_init = false;

// Default configuration
ntp_config_t g_config = {
    .auto_timezone = true,
    .fetch_tz_on_boot = true,
    .timezone = "UTC",
    .ntp_server = "pool.ntp.org"
};

// HTTP response buffer for timezone API
char g_http_response[512] = { 0 };

esp_err_t http_event_handler(esp_http_client_event_t* evt) {
    if (evt->event_id == HTTP_EVENT_ON_DATA) {
        size_t copy_len = evt->data_len;
        if (copy_len >= sizeof(g_http_response)) {
            copy_len = sizeof(g_http_response) - 1;
        }
        memcpy(g_http_response, evt->data, copy_len);
        g_http_response[copy_len] = '\0';
    }
    return ESP_OK;
}

void load_config_from_nvs() {
    // Save pre-init settings
    bool saved_fetch_tz = g_config.fetch_tz_on_boot;
    bool saved_auto_tz = g_config.auto_timezone;

    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open(NTP_NVS_NAMESPACE, NVS_READONLY, &nvs_handle);
    if (err != ESP_OK) {
        ESP_LOGI(TAG, "NVS namespace not found, using defaults");
        return;
    }

    size_t required_size = sizeof(ntp_config_t);
    err = nvs_get_blob(nvs_handle, "config", &g_config, &required_size);
    if (err != ESP_OK) {
        ESP_LOGI(TAG, "Config not found in NVS, using defaults");
    }
    else {
        ESP_LOGI(TAG, "Loaded config: auto_tz=%d, fetch_on_boot=%d, tz=%s, ntp=%s",
            g_config.auto_timezone, g_config.fetch_tz_on_boot,
            g_config.timezone, g_config.ntp_server);
    }

    nvs_close(nvs_handle);

    // Restore pre-init settings if they were explicitly set
    if (g_fetch_tz_set_before_init) {
        g_config.fetch_tz_on_boot = saved_fetch_tz;
        ESP_LOGI(TAG, "Preserving pre-init fetch_tz_on_boot=%d", saved_fetch_tz);
    }
    if (g_auto_tz_set_before_init) {
        g_config.auto_timezone = saved_auto_tz;
        ESP_LOGI(TAG, "Preserving pre-init auto_timezone=%d", saved_auto_tz);
    }
}

void save_config_to_nvs() {
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open(NTP_NVS_NAMESPACE, NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(err));
        return;
    }

    err = nvs_set_blob(nvs_handle, "config", &g_config, sizeof(ntp_config_t));
    if (err == ESP_OK) {
        nvs_commit(nvs_handle);
        ESP_LOGI(TAG, "Config saved to NVS");
    }
    else {
        ESP_LOGE(TAG, "Failed to save config: %s", esp_err_to_name(err));
    }

    nvs_close(nvs_handle);
}

void fetch_and_apply_timezone() {
    const char* tzname = g_config.timezone;
    const char* posixTZ = nullptr;

    if (g_config.auto_timezone && g_config.fetch_tz_on_boot) {
        ESP_LOGI(TAG, "Fetching timezone from API");

        esp_http_client_config_t config = {};
        config.url = TIME_INFO_URL;
        config.event_handler = http_event_handler;
        config.crt_bundle_attach = esp_crt_bundle_attach;
        config.timeout_ms = 10000;

        esp_http_client_handle_t client = esp_http_client_init(&config);
        esp_err_t err = esp_http_client_perform(client);

        if (err == ESP_OK) {
            ESP_LOGD(TAG, "API response: %s", g_http_response);

            cJSON* root = cJSON_Parse(g_http_response);
            if (root != nullptr) {
                cJSON* tz_json = cJSON_GetObjectItem(root, "tzname");
                if (tz_json != nullptr && cJSON_IsString(tz_json)) {
                    const char* fetched_tz = cJSON_GetStringValue(tz_json);
                    ESP_LOGI(TAG, "API timezone: %s", fetched_tz);

                    strncpy(g_config.timezone, fetched_tz, sizeof(g_config.timezone) - 1);
                    g_config.timezone[sizeof(g_config.timezone) - 1] = '\0';
                    tzname = g_config.timezone;

                    save_config_to_nvs();
                }
                cJSON_Delete(root);
            }
        }
        else {
            ESP_LOGW(TAG, "Failed to fetch timezone: %s, using cached: %s",
                esp_err_to_name(err), g_config.timezone);
        }

        esp_http_client_cleanup(client);
        memset(g_http_response, 0, sizeof(g_http_response));
    }
    else if (!g_config.fetch_tz_on_boot) {
        ESP_LOGI(TAG, "Timezone fetch on boot disabled, using: %s", tzname);
    }
    else {
        ESP_LOGI(TAG, "Using manual timezone: %s", tzname);
    }

    // Look up POSIX string from embedded database
    posixTZ = tz_db_get_posix_str(tzname);
    if (posixTZ == nullptr) {
        ESP_LOGW(TAG, "Timezone '%s' not found in database, using UTC", tzname);
        posixTZ = "UTC0";
    }

    ESP_LOGI(TAG, "Setting POSIX timezone: %s", posixTZ);
    setenv("TZ", posixTZ, 1);
    tzset();
}

void apply_timezone_local() {
    // Apply timezone from config without HTTP fetch
    const char* posixTZ = tz_db_get_posix_str(g_config.timezone);
    if (posixTZ == nullptr) posixTZ = "UTC0";
    setenv("TZ", posixTZ, 1);
    tzset();
}

void time_sync_callback(struct timeval* tv) {
    g_synced = true;

    time_t now = tv->tv_sec;
    struct tm* tm_info = localtime(&now);
    char time_str[32];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S %Z", tm_info);
    ESP_LOGI(TAG, "Time synchronized: %s", time_str);
}

void start_sntp() {
    if (esp_sntp_enabled()) {
        esp_sntp_stop();
    }

    ESP_LOGI(TAG, "Starting SNTP with server: %s", g_config.ntp_server);

    esp_sntp_setoperatingmode(SNTP_OPMODE_POLL);
    esp_sntp_setservername(0, g_config.ntp_server);
    esp_sntp_setservername(1, "time.google.com");
    esp_sntp_setservername(2, "time.cloudflare.com");
    esp_sntp_set_time_sync_notification_cb(time_sync_callback);
    esp_sntp_set_sync_interval(3600 * 1000);  // Sync every hour
    esp_sntp_init();
}

void setup_time_task(void* pvParameter) {
    // Fetch and apply timezone (may make HTTP request if enabled)
    fetch_and_apply_timezone();

    // Start NTP
    start_sntp();

    vTaskDelete(nullptr);
}

void wifi_event_handler(void*, esp_event_base_t base, int32_t id, void*) {
    if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        if (g_config.fetch_tz_on_boot && g_config.auto_timezone) {
            // Need task for HTTP request
            xTaskCreate(setup_time_task, "ntp_setup", 8192, nullptr, 5, nullptr);
        }
        else {
            // No HTTP needed, just apply cached timezone and start SNTP
            apply_timezone_local();
            start_sntp();
        }
    }
    else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        g_synced = false;
    }
}

}  // namespace

void ntp_init() {
    if (g_initialized) return;
    g_initialized = true;

    // Load configuration from NVS
    load_config_from_nvs();

    // Set initial timezone (will be updated when WiFi connects if fetch enabled)
    const char* posixTZ = tz_db_get_posix_str(g_config.timezone);
    if (posixTZ == nullptr) posixTZ = "UTC0";
    setenv("TZ", posixTZ, 1);
    tzset();

    // Register for WiFi events
    esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, wifi_event_handler, nullptr);
    esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, wifi_event_handler, nullptr);

    ESP_LOGI(TAG, "NTP initialized (tz_db version: %s)", tz_db_get_version());
}

bool ntp_is_synced() {
    return g_synced;
}

void ntp_sync() {
    if (esp_sntp_enabled()) {
        esp_sntp_restart();
    }
    else {
        start_sntp();
    }
}

ntp_config_t ntp_get_config() {
    return g_config;
}

void ntp_set_config(const ntp_config_t* config) {
    if (config == nullptr) return;

    g_config = *config;
    save_config_to_nvs();

    // Re-apply timezone
    apply_timezone_local();

    // Restart SNTP if server changed
    if (esp_sntp_enabled()) {
        start_sntp();
    }
}

void ntp_set_auto_timezone(bool enabled) {
    if (!g_initialized) {
        g_auto_tz_set_before_init = true;
        g_config.auto_timezone = enabled;
        return;
    }

    if (g_config.auto_timezone == enabled) return;

    g_config.auto_timezone = enabled;
    save_config_to_nvs();

    // If enabling and WiFi is connected, fetch timezone
    if (enabled && ntp_is_synced() && g_config.fetch_tz_on_boot) {
        xTaskCreate(setup_time_task, "ntp_setup", 8192, nullptr, 5, nullptr);
    }
}

bool ntp_get_auto_timezone() {
    return g_config.auto_timezone;
}

void ntp_set_fetch_tz_on_boot(bool enabled) {
    if (!g_initialized) {
        g_fetch_tz_set_before_init = true;
    }
    g_config.fetch_tz_on_boot = enabled;
    if (g_initialized) {
        save_config_to_nvs();
    }
}

bool ntp_get_fetch_tz_on_boot() {
    return g_config.fetch_tz_on_boot;
}

void ntp_set_timezone(const char* timezone) {
    if (timezone == nullptr) return;

    strncpy(g_config.timezone, timezone, sizeof(g_config.timezone) - 1);
    g_config.timezone[sizeof(g_config.timezone) - 1] = '\0';
    g_config.auto_timezone = false;  // Setting manual timezone disables auto

    save_config_to_nvs();
    apply_timezone_local();
}

const char* ntp_get_timezone() {
    return g_config.timezone;
}

void ntp_set_server(const char* server) {
    if (server == nullptr) return;

    strncpy(g_config.ntp_server, server, sizeof(g_config.ntp_server) - 1);
    g_config.ntp_server[sizeof(g_config.ntp_server) - 1] = '\0';

    save_config_to_nvs();

    if (esp_sntp_enabled()) {
        start_sntp();
    }
}

const char* ntp_get_server() {
    return g_config.ntp_server;
}
