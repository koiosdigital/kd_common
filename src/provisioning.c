#include "provisioning.h"

#include <esp_event.h>
#include <esp_log.h>
#include <esp_wifi.h>
#include <esp_random.h>
#include <esp_timer.h>
#include <esp_system.h>
#if CONFIG_KD_COMMON_RELEASE_BLE_WHEN_PROVISIONED
#include <esp_bt.h>
#endif

#include <network_provisioning/manager.h>
#include <network_provisioning/scheme_ble.h>
#include <esp_srp.h>

#include <string.h>
#include <stdint.h>

#include "kd_common.h"
#include "net.h"
#include "ble_console.h"
#include "ble_console_protocol.h"

static const char* TAG = "kd_ble_prov";

#define SALT_LEN 16

typedef struct {
    bool ever_connected;
    bool provisioning_started;
    bool is_wifi_connected;
    bool prov_cred_failed;
    char srp_password[16];
    network_prov_security2_params_t srp_params;
} provisioning_state_t;

// Latched true once Ethernet takes over. Suppresses WiFi auto-reconnect and
// prevents (re)starting BLE provisioning.
static bool s_eth_active = false;

#if CONFIG_KD_COMMON_RELEASE_BLE_WHEN_PROVISIONED
// Latched true once the BT controller memory has been handed to the heap.
// Irreversible for this boot: BLE provisioning can no longer be started.
static bool s_bt_released = false;
#endif

// STA reconnect backoff. Each disconnect schedules the next esp_wifi_connect()
// on an esp_timer with an exponentially growing delay (1 s -> 60 s), reset on
// GOT_IP / STA_START. Repeated authentication failures jump straight to the
// cap (and are logged once) but never stop retrying: the credentials may be
// fine and the AP merely misbehaving, and provisioning replaces them anyway.
#define RECONNECT_BACKOFF_MIN_MS   1000
#define RECONNECT_BACKOFF_MAX_MS   60000
#define AUTH_FAIL_CAP_AFTER        3

static esp_timer_handle_t s_reconnect_timer = NULL;
static uint32_t s_reconnect_delay_ms = RECONNECT_BACKOFF_MIN_MS;
static uint8_t s_auth_fail_count = 0;
static bool s_auth_fail_logged = false;

static provisioning_state_t s_state = {
    .ever_connected = false,
    .provisioning_started = false,
    .is_wifi_connected = false,
    .prov_cred_failed = false,
    .srp_password = {0},
    .srp_params = {
        .salt = NULL,
        .salt_len = SALT_LEN,
        .verifier = NULL,
        .verifier_len = 0,
    }
};

static void reconnect_timer_cb(void* arg) {
    (void)arg;
    // Re-check the suppression conditions: they may have changed while the
    // timer was pending (e.g. provisioning credentials failed, Ethernet up).
    if (s_state.prov_cred_failed || s_eth_active) {
        return;
    }
    esp_err_t err = esp_wifi_connect();
    if (err != ESP_OK) {
        // Typically ESP_ERR_WIFI_NOT_STARTED after a stop: harmless.
        ESP_LOGD(TAG, "reconnect: esp_wifi_connect returned %s", esp_err_to_name(err));
    }
}

static void reconnect_backoff_reset(void) {
    s_reconnect_delay_ms = RECONNECT_BACKOFF_MIN_MS;
    s_auth_fail_count = 0;
    s_auth_fail_logged = false;
    if (s_reconnect_timer) {
        esp_timer_stop(s_reconnect_timer);  // ESP_ERR_INVALID_STATE if idle: fine
    }
}

static void schedule_reconnect(uint8_t reason) {
    if (s_reconnect_timer == NULL) {
        const esp_timer_create_args_t args = {
            .callback = reconnect_timer_cb,
            .arg = NULL,
            .dispatch_method = ESP_TIMER_TASK,
            .name = "wifi_reconnect",
        };
        esp_err_t err = esp_timer_create(&args, &s_reconnect_timer);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "reconnect timer create failed: %s; connecting inline", esp_err_to_name(err));
            esp_wifi_connect();
            return;
        }
    }

    bool auth_fail = (reason == WIFI_REASON_AUTH_FAIL ||
                      reason == WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT);
    if (auth_fail) {
        if (s_auth_fail_count < UINT8_MAX) s_auth_fail_count++;
        if (s_auth_fail_count >= AUTH_FAIL_CAP_AFTER) {
            s_reconnect_delay_ms = RECONNECT_BACKOFF_MAX_MS;
            if (!s_auth_fail_logged) {
                s_auth_fail_logged = true;
                ESP_LOGW(TAG, "Repeated WiFi auth failures (reason %u); retrying every %u s "
                              "until new credentials are provisioned",
                    (unsigned)reason, (unsigned)(RECONNECT_BACKOFF_MAX_MS / 1000));
            }
        }
    }

    uint32_t delay_ms = s_reconnect_delay_ms;
    esp_timer_stop(s_reconnect_timer);
    esp_err_t err = esp_timer_start_once(s_reconnect_timer, (uint64_t)delay_ms * 1000ULL);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "reconnect timer start failed: %s; connecting inline", esp_err_to_name(err));
        esp_wifi_connect();
        return;
    }
    ESP_LOGI(TAG, "WiFi disconnected (reason %u); reconnecting in %u ms",
        (unsigned)reason, (unsigned)delay_ms);

    // Next attempt waits twice as long, up to the cap.
    if (s_reconnect_delay_ms < RECONNECT_BACKOFF_MAX_MS / 2) {
        s_reconnect_delay_ms *= 2;
    }
    else {
        s_reconnect_delay_ms = RECONNECT_BACKOFF_MAX_MS;
    }
}

static void start_provisioning_internal(void) {
    if (s_state.provisioning_started) {
        return;
    }

#if CONFIG_KD_COMMON_RELEASE_BLE_WHEN_PROVISIONED
    if (s_bt_released) {
        // esp_bt_mem_release() is irreversible: initialising the controller
        // now would crash. Reboot instead; the next boot is unprovisioned (or
        // explicitly re-provisioning) and keeps the BT memory.
        ESP_LOGE(TAG, "BT memory was released this boot; rebooting to start BLE provisioning");
        esp_restart();
    }
#endif

    network_prov_mgr_config_t config = {
        .scheme = network_prov_scheme_ble,
        .scheme_event_handler = NETWORK_PROV_SCHEME_BLE_EVENT_HANDLER_FREE_BTDM,
        .app_event_handler = {
            .event_cb = NULL,
            .user_data = NULL,
        },
        .network_prov_wifi_conn_cfg = {
            .wifi_conn_attempts = 2,
        },
    };

    esp_err_t ret = network_prov_mgr_init(config);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to init prov mgr: %s", esp_err_to_name(ret));
        return;
    }

    char* srp_password = kd_common_provisioning_get_srp_password();
    const char* username = CONFIG_KD_COMMON_SRP_USERNAME;

    // verifier_len in the params struct is a uint16_t; esp_srp writes an int.
    int verifier_len = 0;
    ret = esp_srp_gen_salt_verifier(username, strlen(username),
        srp_password, strlen(srp_password),
        (char**)&s_state.srp_params.salt, SALT_LEN,
        (char**)&s_state.srp_params.verifier, &verifier_len);
    s_state.srp_params.verifier_len = (uint16_t)verifier_len;
    if (ret != ESP_OK || !s_state.srp_params.salt || !s_state.srp_params.verifier) {
        ESP_LOGE(TAG, "Failed to generate SRP salt/verifier: %s", esp_err_to_name(ret));
        network_prov_mgr_deinit();
        return;
    }

    ret = network_prov_mgr_endpoint_create(BLE_CONSOLE_ENDPOINT_NAME);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to create endpoint: %s", esp_err_to_name(ret));
        network_prov_mgr_deinit();
        return;
    }

    ret = network_prov_mgr_start_provisioning(NETWORK_PROV_SECURITY_2, &s_state.srp_params, kd_common_get_device_name(), NULL);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start prov: %s", esp_err_to_name(ret));
        network_prov_mgr_deinit();
        return;
    }

    ret = network_prov_mgr_endpoint_register(BLE_CONSOLE_ENDPOINT_NAME, ble_console_endpoint, NULL);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to register endpoint: %s", esp_err_to_name(ret));
        network_prov_mgr_deinit();
        return;
    }

    s_state.provisioning_started = true;
    ESP_LOGI(TAG, "BLE provisioning started (S2, user %s)", CONFIG_KD_COMMON_SRP_USERNAME);
    // The proof-of-possession is a secret: keep it out of INFO-level logs.
    ESP_LOGD(TAG, "SRP PoP: %s", s_state.srp_password);
}

static void provisioning_event_handler(void* arg, esp_event_base_t event_base,
    int32_t event_id, void* event_data) {
    (void)arg;

    if (event_base == WIFI_EVENT) {
        if (event_id == WIFI_EVENT_STA_START) {
            reconnect_backoff_reset();
            bool provisioned = false;
            network_prov_mgr_is_wifi_provisioned(&provisioned);
            if (!provisioned && !s_state.provisioning_started && !s_eth_active) {
                s_state.srp_password[0] = '\0';
                ESP_LOGI(TAG, "WiFi started but not provisioned - starting BLE");
                start_provisioning_internal();
            }
#if CONFIG_KD_COMMON_RELEASE_BLE_WHEN_PROVISIONED
            else if (provisioned) {
                // Already provisioned: BLE (only used for provisioning) will not
                // start this boot, so reclaim the BT controller's reserved
                // internal RAM for the heap. One-shot and irreversible — runtime
                // BLE re-provisioning is unavailable until the next reboot
                // (start_provisioning_internal reboots if asked to).
                if (!s_bt_released) {
                    s_bt_released = true;
                    esp_err_t rel = esp_bt_mem_release(ESP_BT_MODE_BTDM);
                    ESP_LOGI(TAG, "Provisioned boot: released BT memory (%s)",
                        esp_err_to_name(rel));
                }
            }
#endif
            return;
        }
        else if (event_id == WIFI_EVENT_STA_DISCONNECTED) {
            s_state.is_wifi_connected = false;
            // Reconnect (with backoff) unless waiting for new provisioning
            // credentials, or Ethernet has taken over (the disconnect is our
            // own shutdown).
            if (!s_state.prov_cred_failed && !s_eth_active) {
                const wifi_event_sta_disconnected_t* ev =
                    (const wifi_event_sta_disconnected_t*)event_data;
                schedule_reconnect(ev ? ev->reason : 0);
            }
        }
        else if (event_id == WIFI_EVENT_STA_STOP) {
            // Driver stopped (credential clear / Ethernet takeover): a pending
            // reconnect would only fail with WIFI_NOT_STARTED.
            reconnect_backoff_reset();
        }
    }
    else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        s_state.ever_connected = true;
        s_state.is_wifi_connected = true;
        s_state.prov_cred_failed = false;
        reconnect_backoff_reset();
    }
    else if (event_base == NETWORK_PROV_EVENT) {
        switch (event_id) {
        case NETWORK_PROV_WIFI_CRED_RECV:
            s_state.prov_cred_failed = false;
            ESP_LOGI(TAG, "Credentials received");
            break;

        case NETWORK_PROV_WIFI_CRED_FAIL:
            s_state.prov_cred_failed = true;
            ESP_LOGW(TAG, "Credentials failed");
            network_prov_mgr_reset_wifi_sm_state_on_failure();
            break;

        case NETWORK_PROV_END:
            ESP_LOGI(TAG, "Provisioning ended");
            ble_protocol_reset_all();  // Clean up BLE protocol state on disconnect
            network_prov_mgr_deinit();  // This frees BT memory via scheme handler
            s_state.provisioning_started = false;
            break;
        case NETWORK_PROV_DEINIT:
            if (s_state.srp_params.salt != NULL) {
                free((void*)s_state.srp_params.salt);
            }
            if (s_state.srp_params.verifier != NULL) {
                free((void*)s_state.srp_params.verifier);
            }

            memset(&s_state.srp_params, 0, sizeof(s_state.srp_params));
            break;
        }
    }
}

//MARK: Public API

char* kd_common_provisioning_get_srp_password(void) {
    if (s_state.srp_password[0] != '\0') {
        return s_state.srp_password;
    }

#if defined(CONFIG_KD_COMMON_SRP_FORMAT_STATIC)
    strncpy(s_state.srp_password, CONFIG_KD_COMMON_SRP_STATIC_PASSWORD, sizeof(s_state.srp_password) - 1);
    s_state.srp_password[sizeof(s_state.srp_password) - 1] = '\0';
#elif defined(CONFIG_KD_COMMON_SRP_FORMAT_NUMERIC_6)
    esp_fill_random(s_state.srp_password, 6);
    for (int i = 0; i < 6; i++) {
        s_state.srp_password[i] = (char)((s_state.srp_password[i] % 10) + '0');
    }
    s_state.srp_password[6] = '\0';
#elif defined(CONFIG_KD_COMMON_SRP_FORMAT_NUMERIC_6_REDUCED)
    esp_fill_random(s_state.srp_password, 6);
    for (int i = 0; i < 6; i++) {
        s_state.srp_password[i] = (char)((s_state.srp_password[i] % 6) + '0');
    }
    s_state.srp_password[6] = '\0';
#elif defined(CONFIG_KD_COMMON_SRP_FORMAT_NUMERIC_4)
    esp_fill_random(s_state.srp_password, 4);
    for (int i = 0; i < 4; i++) {
        s_state.srp_password[i] = (char)((s_state.srp_password[i] % 10) + '0');
    }
    s_state.srp_password[4] = '\0';
#endif

    return s_state.srp_password;
}

bool kd_common_is_network_connected(void) {
    return net_is_connected();
}

// Back-compat alias. Historically "connected" meant WiFi STA had an IP; it now
// reports connectivity over any interface (WiFi or Ethernet).
bool kd_common_is_wifi_connected(void) {
    return net_is_connected();
}

void kd_common_start_provisioning(void) {
    start_provisioning_internal();
}

//MARK: Internal API

static bool s_prov_events_registered = false;

void provisioning_init(void) {
    ESP_LOGI(TAG, "Initializing");

    // Register event handlers for WiFi state management (only once).
    // We do NOT start BLE provisioning here — wifi_start() has not run yet, so
    // network_prov_mgr_start_provisioning would fail with WIFI_NOT_INIT, and its
    // cleanup path leaves BTDM controller state half-initialized; a subsequent
    // retry crashes inside btdm_controller_init. The WIFI_EVENT_STA_START
    // handler is the sole trigger to start provisioning after the WiFi driver
    // is up and running.
    if (!s_prov_events_registered) {
        esp_event_handler_register(NETWORK_PROV_EVENT, ESP_EVENT_ANY_ID, &provisioning_event_handler, NULL);
        esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &provisioning_event_handler, NULL);
        esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_START, &provisioning_event_handler, NULL);
        esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_STOP, &provisioning_event_handler, NULL);
        esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &provisioning_event_handler, NULL);
        s_prov_events_registered = true;
    }
}

void provisioning_start(void) {
    start_provisioning_internal();
}

void provisioning_shutdown_for_eth(void) {
    s_eth_active = true;  // suppress WiFi reconnect and future prov starts
    reconnect_backoff_reset();
    if (s_state.provisioning_started) {
        ESP_LOGI(TAG, "Ethernet active: stopping BLE provisioning");
        // Async: triggers NETWORK_PROV_END -> deinit (frees BT via scheme handler).
        network_prov_mgr_stop_provisioning();
    }
}
