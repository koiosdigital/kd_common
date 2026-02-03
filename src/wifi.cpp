#include "wifi.h"

#include <esp_err.h>
#include <esp_event.h>
#include <esp_log.h>
#include <esp_wifi.h>

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include <cstring>
#include <cstdio>

#include "kd_common.h"
#include "kdc_heap_tracing.h"
#include "nvs_handle.h"
#include "network_provisioning/manager.h"

#ifdef CONFIG_KD_COMMON_CONSOLE_ENABLE
#include <argtable3/argtable3.h>
#endif

static const char* TAG = "kd_wifi";

void wifi_restart();
void wifi_start();

namespace kd::wifi {

    constexpr const char* NVS_NAMESPACE = "kd_common";
    constexpr const char* HOSTNAME_KEY = "wifi_hostname";
    constexpr size_t MAX_HOSTNAME_LEN = 63;  // RFC 1123

    struct HostnameCache {
        char buffer[MAX_HOSTNAME_LEN + 1] = {};
        bool loaded = false;
    };

    HostnameCache hostname_cache;

    // Global netif pointer for reuse across restarts
    esp_netif_t* g_sta_netif = nullptr;

    // Flag to track when we're clearing credentials and expect a restart
    bool g_pending_restart = false;
    bool g_event_handler_registered = false;

    void event_handler(void*, esp_event_base_t event_base, int32_t event_id, void*) {
        if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_STOP) {
            if (g_pending_restart) {
                g_pending_restart = false;
                ESP_LOGI(TAG, "WiFi stopped after credential clear, restarting...");
                wifi_restart();
            }
        }
    }

}  // namespace kd::wifi

void kd_common_wifi_disconnect() {
    esp_wifi_disconnect();
}

void kd_common_clear_wifi_credentials() {
    kdc_heap_check_integrity("wifi-clear-start");

    kd::wifi::g_pending_restart = true;
    network_prov_mgr_reset_wifi_provisioning();
    kdc_heap_check_integrity("wifi-clear-post-reset");
}

void wifi_init() {
#ifdef CONFIG_KD_COMMON_CONSOLE_ENABLE
    wifi_console_init();
#endif

    // Register for WiFi stop event (for credential clear restart) - only once
    if (!kd::wifi::g_event_handler_registered) {
        esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_STOP, kd::wifi::event_handler, nullptr);
        kd::wifi::g_event_handler_registered = true;
    }

    // One-time network interface initialization
    esp_netif_init();
    kd::wifi::g_sta_netif = esp_netif_create_default_wifi_sta();

    // Start WiFi driver
    wifi_start();
}

void wifi_start() {
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_set_ps(WIFI_PS_NONE);

    if (kd::wifi::g_sta_netif) {
        esp_netif_set_hostname(kd::wifi::g_sta_netif, kd_common_get_wifi_hostname());
    }

    esp_wifi_start();
    esp_wifi_connect();  // Connect directly (reconnects handled by event handler)

    kdc_heap_log_status("post-wifi-start");
}

void wifi_restart() {
    esp_wifi_stop();
    esp_wifi_deinit();
    wifi_start();  // NOT wifi_init() - netif already initialized
}

void kd_common_set_wifi_hostname(const char* hostname) {
    using namespace kd::wifi;

    if (!hostname || std::strlen(hostname) == 0 || std::strlen(hostname) > MAX_HOSTNAME_LEN) {
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

    kd::wifi::hostname_cache.loaded = false;
    wifi_restart();
}

char* kd_common_get_wifi_hostname() {
    using namespace kd::wifi;

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
        return hostname_cache.buffer;
    }

    // Ultimate fallback
    std::strcpy(hostname_cache.buffer, "kd-device");
    hostname_cache.loaded = true;
    return hostname_cache.buffer;
}

esp_err_t kd_common_wifi_connect(const char* ssid, const char* password) {
    if (!ssid || std::strlen(ssid) == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    wifi_config_t wifi_cfg = {};
    std::strncpy(reinterpret_cast<char*>(wifi_cfg.sta.ssid), ssid, sizeof(wifi_cfg.sta.ssid) - 1);

    if (password && std::strlen(password) > 0) {
        std::strncpy(reinterpret_cast<char*>(wifi_cfg.sta.password), password, sizeof(wifi_cfg.sta.password) - 1);
    }

    esp_err_t err = esp_wifi_set_config(WIFI_IF_STA, &wifi_cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set WiFi config: %s", esp_err_to_name(err));
        return err;
    }

    err = esp_wifi_connect();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to connect: %s", esp_err_to_name(err));
        return err;
    }

    ESP_LOGI(TAG, "Connecting to %s...", ssid);
    return ESP_OK;
}

#ifdef CONFIG_KD_COMMON_CONSOLE_ENABLE

namespace {

    static struct {
        struct arg_lit* confirm;
        struct arg_end* end;
    } wifi_clear_args;

    static int cmd_wifi_clear(int argc, char** argv) {
        kdc_heap_check_integrity("cmd-wifi-clear-entry");

        int nerrors = arg_parse(argc, argv, (void**)&wifi_clear_args);
        kdc_heap_check_integrity("cmd-wifi-clear-post-argparse");

        if (nerrors != 0) {
            arg_print_errors(stderr, wifi_clear_args.end, argv[0]);
            return 1;
        }

        if (wifi_clear_args.confirm->count == 0) {
            printf("This will clear all stored WiFi credentials.\n");
            printf("The device will need to be re-provisioned.\n");
            printf("\nTo proceed, run: wifi_clear --confirm\n");
            return 1;
        }

        kd_common_clear_wifi_credentials();

        kdc_heap_check_integrity("cmd-wifi-clear-pre-printf");
        printf("WiFi credentials cleared.\n");
        kdc_heap_check_integrity("cmd-wifi-clear-post-printf");
        return 0;
    }

    static struct {
        struct arg_str* ssid;
        struct arg_str* password;
        struct arg_end* end;
    } wifi_connect_args;

    static int cmd_wifi_connect(int argc, char** argv) {
        int nerrors = arg_parse(argc, argv, (void**)&wifi_connect_args);
        if (nerrors != 0) {
            arg_print_errors(stderr, wifi_connect_args.end, argv[0]);
            return 1;
        }

        const char* ssid = wifi_connect_args.ssid->sval[0];
        const char* password = wifi_connect_args.password->count > 0 ?
            wifi_connect_args.password->sval[0] : nullptr;

        esp_err_t err = kd_common_wifi_connect(ssid, password);
        if (err != ESP_OK) {
            printf("{\"error\":true,\"message\":\"Failed to connect: %s\"}\n", esp_err_to_name(err));
            return 1;
        }

        printf("{\"error\":false,\"message\":\"Connecting to %s...\"}\n", ssid);
        return 0;
    }

}  // namespace

void wifi_console_init() {
    static bool initialized = false;
    if (initialized) return;
    initialized = true;

    wifi_clear_args.confirm = arg_lit0(NULL, "confirm", "Confirm credential clearing");
    wifi_clear_args.end = arg_end(1);
    kd_console_register_cmd_with_args("wifi_clear", "Clear stored WiFi credentials", cmd_wifi_clear, &wifi_clear_args);

    wifi_connect_args.ssid = arg_str1(NULL, NULL, "<ssid>", "WiFi network name");
    wifi_connect_args.password = arg_str0(NULL, NULL, "<password>", "WiFi password (optional for open networks)");
    wifi_connect_args.end = arg_end(2);
    kd_console_register_cmd_with_args("wifi_connect", "Connect to a WiFi network", cmd_wifi_connect, &wifi_connect_args);

    ESP_LOGI(TAG, "WiFi console commands registered");
}

#endif // CONFIG_KD_COMMON_CONSOLE_ENABLE
