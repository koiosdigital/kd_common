#include "wifi.h"

#include <esp_err.h>
#include <esp_event.h>
#include <esp_log.h>
#include <esp_wifi.h>

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include <string.h>
#include <stdio.h>

#include <esp_netif.h>

#include "kd_common.h"
#include "nvs_helper.h"
#include "net.h"
#include "kdmdns.h"
#ifdef CONFIG_KD_COMMON_ETH_ENABLE
#include "eth.h"
#endif
#include "network_provisioning/manager.h"

#ifdef CONFIG_KD_COMMON_CONSOLE_ENABLE
#include <argtable3/argtable3.h>
#endif

static const char* TAG = "kd_wifi";

#define NVS_NAMESPACE "kd_common"
#define HOSTNAME_KEY "wifi_hostname"
#define MAX_HOSTNAME_LEN 63  // RFC 1123

typedef struct {
    char buffer[MAX_HOSTNAME_LEN + 1];
    bool loaded;
} hostname_cache_t;

static hostname_cache_t s_hostname_cache = { .buffer = {0}, .loaded = false };

// Global netif pointer for reuse across restarts
static esp_netif_t* s_sta_netif = NULL;

// Flag to track when we're clearing credentials and expect a restart
static bool s_pending_restart = false;
static bool s_event_handler_registered = false;
static bool s_started = false;  // true between wifi_start() and wifi_shutdown()

// Forward declarations
void wifi_restart(void);
void wifi_start(void);

// wifi_restart() stops/deinits/reinits the driver, which must never run on the
// event-loop task (esp_wifi_stop/deinit synchronise with events dispatched by
// that very task). The STA_STOP handler hands the work to this one-shot task.
static void wifi_restart_task(void* arg) {
    (void)arg;
    wifi_restart();
    vTaskDelete(NULL);
}

static void wifi_restart_deferred(void) {
    if (xTaskCreate(wifi_restart_task, "wifi_restart", 4096, NULL, 5, NULL) != pdPASS) {
        ESP_LOGE(TAG, "Failed to create WiFi restart task");
    }
}

static void wifi_event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data) {
    (void)arg;
    (void)event_data;

    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_STOP) {
        if (s_pending_restart) {
            s_pending_restart = false;
            ESP_LOGI(TAG, "WiFi stopped after credential clear, restarting...");
            wifi_restart_deferred();
        }
    }
    else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        net_set_link_up(NET_IF_WIFI, true);
        net_dispatch_connect();
    }
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        net_set_link_up(NET_IF_WIFI, false);
        net_dispatch_disconnect();
    }
}

// Thin compatibility wrappers: WiFi consumers still call wifi_on_connect(), but
// the callback registry now lives in the interface-agnostic net hub so the same
// callbacks fire for Ethernet (and future links) too.
void wifi_on_connect(wifi_connect_fn cb) {
    net_on_connect(cb);
}

void wifi_on_disconnect(wifi_disconnect_fn cb) {
    net_on_disconnect(cb);
}

void kd_common_wifi_disconnect(void) {
    esp_wifi_disconnect();
}

void kd_common_clear_wifi_credentials(void) {
    // Wipe the stored STA config (this is just esp_wifi_restore()).
    esp_err_t err = network_prov_mgr_reset_wifi_provisioning();
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "WiFi credential reset returned %s", esp_err_to_name(err));
    }

    // The HTTP server is NOT stopped here: this is commonly called from an
    // HTTP handler, and the DISCONNECTED path below already tears the server
    // down (off the httpd task) once the link drops.

    if (!s_started) {
        // Driver not running (never started, or Ethernet took over): nothing
        // to stop, and no STA_STOP will arrive to drive a restart.
        s_pending_restart = false;
        ESP_LOGI(TAG, "WiFi credentials cleared (driver not running)");
        return;
    }

    // Drop the link and stop the driver so WIFI_EVENT_STA_STOP fires; the
    // event handler then restarts WiFi (on its own task), which lands in
    // STA_START unprovisioned and kicks off BLE provisioning.
    s_pending_restart = true;
    esp_wifi_disconnect();
    err = esp_wifi_stop();
    if (err != ESP_OK) {
        s_pending_restart = false;
        ESP_LOGE(TAG, "esp_wifi_stop failed after credential clear: %s", esp_err_to_name(err));
    }
}

// Initialize the WiFi driver (esp_wifi_init + mode/ps/hostname). Called from
// wifi_init() during boot and from wifi_restart() after deinit. Must run
// before any consumer touches WiFi APIs (e.g. provisioning_init).
static void wifi_driver_init(void) {
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_set_ps(WIFI_PS_NONE);

    if (s_sta_netif) {
        esp_netif_set_hostname(s_sta_netif, kd_common_get_wifi_hostname());
    }
}

void wifi_init(void) {
#ifdef CONFIG_KD_COMMON_CONSOLE_ENABLE
    wifi_console_init();
#endif

    // Register central event handler for all WiFi lifecycle events (only once)
    if (!s_event_handler_registered) {
        esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_STOP, wifi_event_handler, NULL);
        esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, wifi_event_handler, NULL);
        esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, wifi_event_handler, NULL);
        s_event_handler_registered = true;
    }

    // One-time network interface initialization
    esp_netif_init();
    s_sta_netif = esp_netif_create_default_wifi_sta();

    // Init the WiFi driver now so that modules initialized later in
    // kd_common_init (notably provisioning) can safely call esp_wifi_* APIs.
    // esp_wifi_start() is deferred to wifi_start() so callbacks register first.
    wifi_driver_init();
}

void wifi_start(void) {
    esp_wifi_start();
    esp_wifi_connect();  // Connect directly (reconnects handled by event handler)
    s_started = true;
}

void wifi_shutdown(void) {
    if (!s_started) return;
    s_started = false;
    ESP_LOGI(TAG, "Shutting down WiFi (Ethernet is the active uplink)");
    esp_wifi_disconnect();
    esp_wifi_stop();
    // Driver left initialized (not deinit'd) so the netif/glue teardown never
    // races the event loop; STA is idle and issues no traffic. Provisioning's
    // reconnect handler is separately suppressed by provisioning_shutdown_for_eth().
}

void wifi_restart(void) {
    if (!s_started) {
        // Never started, or wifi_shutdown() handed the uplink to Ethernet.
        ESP_LOGW(TAG, "wifi_restart ignored: WiFi is not the active uplink");
        return;
    }
    esp_wifi_stop();
    esp_wifi_deinit();
    wifi_driver_init();  // netif already initialized; just re-init the driver
    wifi_start();
}

void kd_common_set_wifi_hostname(const char* hostname) {
    if (!hostname || strlen(hostname) == 0 || strlen(hostname) > MAX_HOSTNAME_LEN) {
        return;
    }

    nvs_helper_t nvs = nvs_helper_open(NVS_NAMESPACE, NVS_READWRITE);
    if (!nvs.valid) {
        ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(nvs.open_err));
        return;
    }

    esp_err_t err = nvs_helper_set_str(&nvs, HOSTNAME_KEY, hostname);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to save hostname: %s", esp_err_to_name(err));
        nvs_helper_close(&nvs);
        return;
    }

    err = nvs_helper_commit(&nvs);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to commit hostname: %s", esp_err_to_name(err));
        nvs_helper_close(&nvs);
        return;
    }

    nvs_helper_close(&nvs);
    s_hostname_cache.loaded = false;

    // Reload the cache from NVS so every consumer sees the new name, then
    // apply it live. No driver restart: the DHCP client picks the new name up
    // on the next association/lease renewal, and mDNS is updated immediately.
    const char* applied = kd_common_get_wifi_hostname();
    if (s_sta_netif) {
        err = esp_netif_set_hostname(s_sta_netif, applied);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "esp_netif_set_hostname failed: %s", esp_err_to_name(err));
        }
    }
#ifdef CONFIG_KD_COMMON_ETH_ENABLE
    eth_set_hostname(applied);
#endif
    kdmdns_set_hostname(applied);
    ESP_LOGI(TAG, "Hostname set to %s", applied);
}

char* kd_common_get_wifi_hostname(void) {
    // Return cached hostname if available
    if (s_hostname_cache.loaded && s_hostname_cache.buffer[0] != '\0') {
        return s_hostname_cache.buffer;
    }

    // Try to load from NVS
    nvs_helper_t nvs = nvs_helper_open(NVS_NAMESPACE, NVS_READONLY);
    if (nvs.valid) {
        size_t required_size = sizeof(s_hostname_cache.buffer);
        esp_err_t err = nvs_helper_get_str(&nvs, HOSTNAME_KEY, s_hostname_cache.buffer, &required_size);

        if (err == ESP_OK && s_hostname_cache.buffer[0] != '\0') {
            nvs_helper_close(&nvs);
            s_hostname_cache.loaded = true;
            return s_hostname_cache.buffer;
        }

        if (err != ESP_ERR_NVS_NOT_FOUND) {
            ESP_LOGW(TAG, "Failed to get hostname from NVS: %s", esp_err_to_name(err));
        }
        nvs_helper_close(&nvs);
    }

    // Fall back to device name
    char* device_name = kd_common_get_device_name();
    if (device_name) {
        strncpy(s_hostname_cache.buffer, device_name, MAX_HOSTNAME_LEN);
        s_hostname_cache.buffer[MAX_HOSTNAME_LEN] = '\0';
        s_hostname_cache.loaded = true;
        return s_hostname_cache.buffer;
    }

    // Ultimate fallback
    strcpy(s_hostname_cache.buffer, "kd-device");
    s_hostname_cache.loaded = true;
    return s_hostname_cache.buffer;
}

esp_err_t kd_common_wifi_connect(const char* ssid, const char* password) {
    if (!ssid || strlen(ssid) == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    // The driver treats ssid/password as length-bounded byte arrays, not
    // C strings: a full 32-byte SSID / 64-byte PSK is legal and need not be
    // NUL-terminated, so copy with strnlen instead of leaving a byte spare.
    wifi_config_t wifi_cfg = { 0 };
    size_t ssid_len = strnlen(ssid, sizeof(wifi_cfg.sta.ssid));
    memcpy(wifi_cfg.sta.ssid, ssid, ssid_len);

    if (password && password[0] != '\0') {
        size_t pw_len = strnlen(password, sizeof(wifi_cfg.sta.password));
        memcpy(wifi_cfg.sta.password, password, pw_len);
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

static struct {
    struct arg_lit* confirm;
    struct arg_end* end;
} s_wifi_clear_args;

static int cmd_wifi_clear(int argc, char** argv) {
    int nerrors = arg_parse(argc, argv, (void**)&s_wifi_clear_args);

    if (nerrors != 0) {
        arg_print_errors(stderr, s_wifi_clear_args.end, argv[0]);
        return 1;
    }

    if (s_wifi_clear_args.confirm->count == 0) {
        printf("This will clear all stored WiFi credentials.\n");
        printf("The device will need to be re-provisioned.\n");
        printf("\nTo proceed, run: wifi_clear --confirm\n");
        return 1;
    }

    kd_common_clear_wifi_credentials();

    printf("WiFi credentials cleared.\n");
    return 0;
}

static struct {
    struct arg_str* ssid;
    struct arg_str* password;
    struct arg_end* end;
} s_wifi_connect_args;

static int cmd_wifi_connect(int argc, char** argv) {
    int nerrors = arg_parse(argc, argv, (void**)&s_wifi_connect_args);
    if (nerrors != 0) {
        arg_print_errors(stderr, s_wifi_connect_args.end, argv[0]);
        return 1;
    }

    const char* ssid = s_wifi_connect_args.ssid->sval[0];
    const char* password = s_wifi_connect_args.password->count > 0 ?
        s_wifi_connect_args.password->sval[0] : NULL;

    esp_err_t err = kd_common_wifi_connect(ssid, password);
    if (err != ESP_OK) {
        printf("{\"error\":true,\"message\":\"Failed to connect: %s\"}\n", esp_err_to_name(err));
        return 1;
    }

    printf("{\"error\":false,\"message\":\"Connecting to %s...\"}\n", ssid);
    return 0;
}

void wifi_console_init(void) {
    static bool initialized = false;
    if (initialized) return;
    initialized = true;

    s_wifi_clear_args.confirm = arg_lit0(NULL, "confirm", "Confirm credential clearing");
    s_wifi_clear_args.end = arg_end(1);
    kd_console_register_cmd_with_args("wifi_clear", "Clear stored WiFi credentials", cmd_wifi_clear, &s_wifi_clear_args);

    s_wifi_connect_args.ssid = arg_str1(NULL, NULL, "<ssid>", "WiFi network name");
    s_wifi_connect_args.password = arg_str0(NULL, NULL, "<password>", "WiFi password (optional for open networks)");
    s_wifi_connect_args.end = arg_end(2);
    kd_console_register_cmd_with_args("wifi_connect", "Connect to a WiFi network", cmd_wifi_connect, &s_wifi_connect_args);

    ESP_LOGI(TAG, "WiFi console commands registered");
}

#endif // CONFIG_KD_COMMON_CONSOLE_ENABLE
