// NTP time synchronization with timezone support
#include "ntp.h"
#include "kd_common.h"

#include <string.h>
#include <esp_log.h>
#include <esp_sntp.h>
#include <esp_event.h>
#include <esp_wifi.h>
#include <nvs_flash.h>
#include <nvs.h>
#include <time.h>

#include "embedded_tz_db.h"

// Define NTP event base
ESP_EVENT_DEFINE_BASE(KD_NTP_EVENTS);

#define NTP_NVS_NAMESPACE "ntp_cfg"

static const char* TAG = "ntp";

static bool s_initialized = false;
static bool s_synced = false;

// Track if settings were modified before init (to preserve them)
static bool s_fetch_tz_set_before_init = false;
static bool s_auto_tz_set_before_init = false;

// Default configuration
static ntp_config_t s_config = {
    .auto_timezone = true,
    .fetch_tz_on_boot = true,
    .timezone = "UTC",
    .ntp_server = "pool.ntp.org"
};

static void load_config_from_nvs(void) {
    // Save pre-init settings
    bool saved_fetch_tz = s_config.fetch_tz_on_boot;
    bool saved_auto_tz = s_config.auto_timezone;

    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open(NTP_NVS_NAMESPACE, NVS_READONLY, &nvs_handle);
    if (err != ESP_OK) {
        ESP_LOGI(TAG, "NVS namespace not found, using defaults");
        return;
    }

    size_t required_size = sizeof(ntp_config_t);
    err = nvs_get_blob(nvs_handle, "config", &s_config, &required_size);
    if (err != ESP_OK) {
        ESP_LOGI(TAG, "Config not found in NVS, using defaults");
    }
    else {
        ESP_LOGI(TAG, "Loaded config: auto_tz=%d, fetch_on_boot=%d, tz=%s, ntp=%s",
            s_config.auto_timezone, s_config.fetch_tz_on_boot,
            s_config.timezone, s_config.ntp_server);
    }

    nvs_close(nvs_handle);

    // Restore pre-init settings if they were explicitly set
    if (s_fetch_tz_set_before_init) {
        s_config.fetch_tz_on_boot = saved_fetch_tz;
        ESP_LOGI(TAG, "Preserving pre-init fetch_tz_on_boot=%d", saved_fetch_tz);
    }
    if (s_auto_tz_set_before_init) {
        s_config.auto_timezone = saved_auto_tz;
        ESP_LOGI(TAG, "Preserving pre-init auto_timezone=%d", saved_auto_tz);
    }
}

static void save_config_to_nvs(void) {
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open(NTP_NVS_NAMESPACE, NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(err));
        return;
    }

    err = nvs_set_blob(nvs_handle, "config", &s_config, sizeof(ntp_config_t));
    if (err == ESP_OK) {
        nvs_commit(nvs_handle);
        ESP_LOGI(TAG, "Config saved to NVS");
    }
    else {
        ESP_LOGE(TAG, "Failed to save config: %s", esp_err_to_name(err));
    }

    nvs_close(nvs_handle);
}

static void apply_timezone_local(void) {
    // Apply timezone from config without HTTP fetch
    const char* posixTZ = tz_db_get_posix_str(s_config.timezone);
    if (posixTZ == NULL) posixTZ = "UTC0";
    setenv("TZ", posixTZ, 1);
    tzset();
}

static void time_sync_callback(struct timeval* tv) {
    s_synced = true;

    time_t now = tv->tv_sec;
    struct tm* tm_info = localtime(&now);
    char time_str[32];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S %Z", tm_info);
    ESP_LOGI(TAG, "Time synchronized: %s", time_str);

    // Post sync complete event
    esp_event_post(KD_NTP_EVENTS, KD_NTP_EVENT_SYNC_COMPLETE, NULL, 0, 0);
}

static void start_sntp(void) {
    if (esp_sntp_enabled()) {
        esp_sntp_stop();
    }

    ESP_LOGI(TAG, "Starting SNTP with server: %s", s_config.ntp_server);

    esp_sntp_setoperatingmode(SNTP_OPMODE_POLL);
    esp_sntp_setservername(0, s_config.ntp_server);
    esp_sntp_setservername(1, "time.google.com");
    esp_sntp_setservername(2, "time.cloudflare.com");
    esp_sntp_set_time_sync_notification_cb(time_sync_callback);
    esp_sntp_set_sync_interval(3600 * 1000);  // Sync every hour
    esp_sntp_init();
}

static void wifi_event_handler(void* arg, esp_event_base_t base, int32_t id, void* data) {
    (void)arg;
    (void)data;

    if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        // Apply cached timezone and start SNTP immediately
        // Timezone will be updated by OTA check if auto_timezone is enabled
        apply_timezone_local();
        start_sntp();
    }
    else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        s_synced = false;
        // Post sync lost event
        esp_event_post(KD_NTP_EVENTS, KD_NTP_EVENT_SYNC_LOST, NULL, 0, 0);
    }
}

void ntp_init(void) {
    if (s_initialized) return;
    s_initialized = true;

    // Load configuration from NVS
    load_config_from_nvs();

    // Set initial timezone (will be updated when WiFi connects if fetch enabled)
    const char* posixTZ = tz_db_get_posix_str(s_config.timezone);
    if (posixTZ == NULL) posixTZ = "UTC0";
    setenv("TZ", posixTZ, 1);
    tzset();

    // Register for WiFi events
    esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, wifi_event_handler, NULL);
    esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, wifi_event_handler, NULL);

    ESP_LOGI(TAG, "NTP initialized (tz_db version: %s)", tz_db_get_version());
}

bool ntp_is_synced(void) {
    return s_synced;
}

void ntp_sync(void) {
    if (esp_sntp_enabled()) {
        esp_sntp_restart();
    }
    else {
        start_sntp();
    }
}

ntp_config_t ntp_get_config(void) {
    return s_config;
}

void ntp_set_config(const ntp_config_t* config) {
    if (config == NULL) return;

    s_config = *config;
    save_config_to_nvs();

    // Re-apply timezone
    apply_timezone_local();

    // Restart SNTP if server changed
    if (esp_sntp_enabled()) {
        start_sntp();
    }
}

void ntp_set_auto_timezone(bool enabled) {
    if (!s_initialized) {
        s_auto_tz_set_before_init = true;
        s_config.auto_timezone = enabled;
        return;
    }

    if (s_config.auto_timezone == enabled) return;

    s_config.auto_timezone = enabled;
    save_config_to_nvs();
    // Timezone will be updated on next OTA check if enabled
}

bool ntp_get_auto_timezone(void) {
    return s_config.auto_timezone;
}

void ntp_set_fetch_tz_on_boot(bool enabled) {
    if (!s_initialized) {
        s_fetch_tz_set_before_init = true;
    }
    s_config.fetch_tz_on_boot = enabled;
    if (s_initialized) {
        save_config_to_nvs();
    }
}

bool ntp_get_fetch_tz_on_boot(void) {
    return s_config.fetch_tz_on_boot;
}

void ntp_set_timezone(const char* timezone) {
    if (timezone == NULL) return;

    strncpy(s_config.timezone, timezone, sizeof(s_config.timezone) - 1);
    s_config.timezone[sizeof(s_config.timezone) - 1] = '\0';
    s_config.auto_timezone = false;  // Setting manual timezone disables auto

    save_config_to_nvs();
    apply_timezone_local();
}

const char* ntp_get_timezone(void) {
    return s_config.timezone;
}

void ntp_set_server(const char* server) {
    if (server == NULL) return;

    strncpy(s_config.ntp_server, server, sizeof(s_config.ntp_server) - 1);
    s_config.ntp_server[sizeof(s_config.ntp_server) - 1] = '\0';

    save_config_to_nvs();

    if (esp_sntp_enabled()) {
        start_sntp();
    }
}

const char* ntp_get_server(void) {
    return s_config.ntp_server;
}

void ntp_apply_timezone(const char* tzname) {
    if (tzname == NULL || tzname[0] == '\0') return;

    if (!s_config.auto_timezone) {
        ESP_LOGD(TAG, "Auto timezone disabled, ignoring external timezone");
        return;
    }

    ESP_LOGI(TAG, "Applying timezone from OTA: %s", tzname);

    strncpy(s_config.timezone, tzname, sizeof(s_config.timezone) - 1);
    s_config.timezone[sizeof(s_config.timezone) - 1] = '\0';

    save_config_to_nvs();
    apply_timezone_local();
}
