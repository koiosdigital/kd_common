#include "provisioning.h"

#include <esp_event.h>
#include <esp_log.h>
#include <esp_wifi.h>
#include <esp_random.h>

#include <wifi_provisioning/manager.h>
#include <wifi_provisioning/scheme_ble.h>

#include <cstring>

#include "kd_common.h"
#include "ble_console.h"

static const char* TAG = "kd_ble_prov";

namespace {

    struct ProvisioningState {
        bool ever_connected = false;
        bool provisioning_started = false;
        bool is_wifi_connected = false;
        bool prov_cred_failed = false;
        ProvisioningPOPTokenFormat_t pop_format = ProvisioningPOPTokenFormat_t::NONE;
        char* qr_payload = nullptr;
        char* pop_token = nullptr;
    };

    ProvisioningState state;

    void start_provisioning_internal() {
        if (state.provisioning_started) {
            ESP_LOGD(TAG, "Provisioning already started");
            return;
        }

        wifi_prov_mgr_config_t config = {
            .scheme = wifi_prov_scheme_ble,
            .scheme_event_handler = WIFI_PROV_SCHEME_BLE_EVENT_HANDLER_FREE_BTDM,
            .app_event_handler = {
                .event_cb = nullptr,
                .user_data = nullptr,
            },
            .wifi_prov_conn_cfg = {
                .wifi_conn_attempts = 3,
            },
        };

        esp_err_t ret = wifi_prov_mgr_init(config);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to init prov mgr: %s", esp_err_to_name(ret));
            return;
        }

#ifndef KD_COMMON_CONSOLE_DISABLE
        ret = wifi_prov_mgr_endpoint_create(BLE_CONSOLE_ENDPOINT_NAME);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to create endpoint: %s", esp_err_to_name(ret));
            wifi_prov_mgr_deinit();
            return;
        }
#endif

        char* pop = kd_common_provisioning_get_pop_token();
        wifi_prov_security_t security = pop ? WIFI_PROV_SECURITY_1 : WIFI_PROV_SECURITY_0;

        ret = wifi_prov_mgr_start_provisioning(security, pop, kd_common_get_device_name(), nullptr);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to start prov: %s", esp_err_to_name(ret));
            wifi_prov_mgr_deinit();
            return;
        }

#ifndef KD_COMMON_CONSOLE_DISABLE
        ret = wifi_prov_mgr_endpoint_register(BLE_CONSOLE_ENDPOINT_NAME, ble_console_endpoint, nullptr);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to register endpoint: %s", esp_err_to_name(ret));
        }
#endif

        state.provisioning_started = true;
        ESP_LOGI(TAG, "BLE provisioning started");
    }

    void provisioning_event_handler(void* arg, esp_event_base_t event_base,
        int32_t event_id, void* event_data) {
        if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
            state.is_wifi_connected = false;
            // Reconnect unless waiting for new provisioning credentials
            if (!state.prov_cred_failed) {
                esp_wifi_connect();
            }
        }
        else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
            state.ever_connected = true;
            state.is_wifi_connected = true;
            state.prov_cred_failed = false;
            // Provisioning will auto-stop via WIFI_PROV_END event

        }
        else if (event_base == WIFI_PROV_EVENT) {
            switch (event_id) {
            case WIFI_PROV_CRED_RECV:
                state.prov_cred_failed = false;
                ESP_LOGI(TAG, "Credentials received");
                break;

            case WIFI_PROV_CRED_FAIL:
                state.prov_cred_failed = true;
                ESP_LOGW(TAG, "Credentials failed");
                wifi_prov_mgr_reset_sm_state_on_failure();
                break;

            case WIFI_PROV_END:
                ESP_LOGI(TAG, "Provisioning ended");
                wifi_prov_mgr_deinit();  // This frees BT memory via scheme handler
                state.provisioning_started = false;
                break;
            }
        }
    }

}  // namespace

//MARK: Public API

void kd_common_set_provisioning_pop_token_format(ProvisioningPOPTokenFormat_t format) {
    state.pop_format = format;
}

char* kd_common_provisioning_get_pop_token() {
    if (state.pop_token != nullptr) {
        return state.pop_token;
    }

    if (state.pop_format == ProvisioningPOPTokenFormat_t::NUMERIC_6) {
        state.pop_token = static_cast<char*>(calloc(7, sizeof(char)));
        if (state.pop_token) {
            esp_fill_random(state.pop_token, 6);
            for (int i = 0; i < 6; i++) {
                state.pop_token[i] = static_cast<char>((state.pop_token[i] % 10) + '0');
            }
        }
        return state.pop_token;
    }

    if (state.pop_format == ProvisioningPOPTokenFormat_t::ALPHA_8) {
        state.pop_token = static_cast<char*>(calloc(9, sizeof(char)));
        if (state.pop_token) {
            esp_fill_random(state.pop_token, 8);
            for (int i = 0; i < 8; i++) {
                state.pop_token[i] = static_cast<char>((state.pop_token[i] % 26) + 'A');
            }
        }
        return state.pop_token;
    }

    return nullptr;
}

char* kd_common_get_provisioning_qr_payload() {
    if (state.qr_payload != nullptr) {
        return state.qr_payload;
    }

    state.qr_payload = static_cast<char*>(calloc(64, sizeof(char)));
    if (state.qr_payload) {
        snprintf(state.qr_payload, 63, "%s;%s", kd_common_get_device_name(), kd_common_provisioning_get_pop_token());
    }
    return state.qr_payload;
}

bool kd_common_is_wifi_connected() {
    return state.is_wifi_connected;
}

void kd_common_start_provisioning() {
    start_provisioning_internal();
}

//MARK: Internal API

void provisioning_init() {
    ESP_LOGI(TAG, "Initializing");

    // Register event handlers for WiFi state management
    esp_event_handler_register(WIFI_PROV_EVENT, ESP_EVENT_ANY_ID, &provisioning_event_handler, nullptr);
    esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &provisioning_event_handler, nullptr);
    esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &provisioning_event_handler, nullptr);

    // Check if already provisioned (requires wifi to be initialized)
    bool provisioned = false;
    wifi_prov_mgr_is_provisioned(&provisioned);

    if (!provisioned) {
        ESP_LOGI(TAG, "Not provisioned - starting BLE provisioning");
        start_provisioning_internal();
    } else {
        ESP_LOGI(TAG, "Already provisioned - skipping BLE");
    }
}

void provisioning_start() {
    start_provisioning_internal();
}
