#include "provisioning.h"

#include <esp_event.h>
#include <esp_log.h>
#include <esp_wifi.h>
#include <esp_random.h>

#include <network_provisioning/manager.h>
#include <network_provisioning/scheme_ble.h>
#include <esp_srp.h>

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
        ProvisioningSRPPasswordFormat_t srp_format = ProvisioningSRPPasswordFormat_t::STATIC;
        char srp_password[16] = { 0x00 };
        char srp_salt[16] = { 0x00 };
        char srp_verifier[384] = { 0x00 };
        network_prov_security2_params_t srp_params = { 0 };
    };

    ProvisioningState state;

    void start_provisioning_internal() {
        if (state.provisioning_started) {
            ESP_LOGD(TAG, "Provisioning already started");
            return;
        }

        network_prov_mgr_config_t config = {
            .scheme = network_prov_scheme_ble,
            .scheme_event_handler = NETWORK_PROV_SCHEME_BLE_EVENT_HANDLER_FREE_BTDM,
            .app_event_handler = {
                .event_cb = nullptr,
                .user_data = nullptr,
            },
            .network_prov_wifi_conn_cfg = {
                .wifi_conn_attempts = 3,
            },
        };

        esp_err_t ret = network_prov_mgr_init(config);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to init prov mgr: %s", esp_err_to_name(ret));
            return;
        }

#ifdef CONFIG_KD_COMMON_CONSOLE_ENABLE
        ret = network_prov_mgr_endpoint_create(BLE_CONSOLE_ENDPOINT_NAME);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to create endpoint: %s", esp_err_to_name(ret));
            network_prov_mgr_deinit();
            return;
        }
#endif

        char* srp_password = kd_common_provisioning_get_srp_password();

        const char* username = "koiosdigital";
        char* salt_out = nullptr;
        char* verifier_out = nullptr;
        int verifier_len = 0;

        ret = esp_srp_gen_salt_verifier(username, strlen(username),
            srp_password, strlen(srp_password),
            &salt_out, sizeof(state.srp_salt),
            &verifier_out, &verifier_len);
        if (ret == ESP_OK && salt_out && verifier_out) {
            memcpy(state.srp_salt, salt_out, sizeof(state.srp_salt));
            size_t copy_len = (static_cast<size_t>(verifier_len) < sizeof(state.srp_verifier))
                ? static_cast<size_t>(verifier_len)
                : sizeof(state.srp_verifier);
            memcpy(state.srp_verifier, verifier_out, copy_len);
            free(salt_out);
            free(verifier_out);
        }
        else {
            ESP_LOGE(TAG, "Failed to generate SRP salt/verifier: %s", esp_err_to_name(ret));
            network_prov_mgr_deinit();
            return;
        }

        state.srp_params.salt = state.srp_salt;
        state.srp_params.salt_len = sizeof(state.srp_salt);
        state.srp_params.verifier = state.srp_verifier;
        state.srp_params.verifier_len = sizeof(state.srp_verifier);

        ret = network_prov_mgr_start_provisioning(NETWORK_PROV_SECURITY_2, &state.srp_params, kd_common_get_device_name(), nullptr);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to start prov: %s", esp_err_to_name(ret));
            network_prov_mgr_deinit();
            return;
        }

#ifdef CONFIG_KD_COMMON_CONSOLE_ENABLE
        ret = network_prov_mgr_endpoint_register(BLE_CONSOLE_ENDPOINT_NAME, ble_console_endpoint, nullptr);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to register endpoint: %s", esp_err_to_name(ret));
        }
#endif

        state.provisioning_started = true;
        ESP_LOGI(TAG, "BLE provisioning started, S2 (%s / %s)", "koiosdigital", "psk");
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
        else if (event_base == NETWORK_PROV_EVENT) {
            switch (event_id) {
            case NETWORK_PROV_WIFI_CRED_RECV:
                state.prov_cred_failed = false;
                ESP_LOGI(TAG, "Credentials received");
                break;

            case NETWORK_PROV_WIFI_CRED_FAIL:
                state.prov_cred_failed = true;
                ESP_LOGW(TAG, "Credentials failed");
                network_prov_mgr_reset_wifi_sm_state_on_failure();
                break;

            case NETWORK_PROV_END:
                ESP_LOGI(TAG, "Provisioning ended");
                network_prov_mgr_deinit();  // This frees BT memory via scheme handler
                state.provisioning_started = false;
                break;
            }
        }
    }

}  // namespace

//MARK: Public API

void kd_common_set_provisioning_srp_password_format(ProvisioningSRPPasswordFormat_t format) {
    state.srp_format = format;
}

char* kd_common_provisioning_get_srp_password() {
    if (state.srp_password[0] != '\0') {
        return state.srp_password;
    }

    //static
    if (state.srp_format == ProvisioningSRPPasswordFormat_t::STATIC) {
        strcpy(state.srp_password, "koiosdigital");
        return state.srp_password;
    }

    //6 ascii numbers 0-9
    if (state.srp_format == ProvisioningSRPPasswordFormat_t::NUMERIC_6) {
        if (state.srp_password[0] == '\0') {
            esp_fill_random(state.srp_password, 6);
            for (int i = 0; i < 6; i++) {
                state.srp_password[i] = static_cast<char>((state.srp_password[i] % 10) + '0');
            }
        }
        return state.srp_password;
    }

    //6 ascii numbers 0-5
    if (state.srp_format == ProvisioningSRPPasswordFormat_t::NUMERIC_6_REDUCED) {
        if (state.srp_password[0] == '\0') {
            esp_fill_random(state.srp_password, 6);
            for (int i = 0; i < 6; i++) {
                state.srp_password[i] = static_cast<char>((state.srp_password[i] % 6) + '0');
            }
        }
        return state.srp_password;
    }

    //4 ascii numbers 0-9
    if (state.srp_format == ProvisioningSRPPasswordFormat_t::NUMERIC_4) {
        if (state.srp_password[0] == '\0') {
            esp_fill_random(state.srp_password, 4);
            for (int i = 0; i < 4; i++) {
                state.srp_password[i] = static_cast<char>((state.srp_password[i] % 10) + '0');
            }
        }
        return state.srp_password;
    }

    return state.srp_password;
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
    esp_event_handler_register(NETWORK_PROV_EVENT, ESP_EVENT_ANY_ID, &provisioning_event_handler, nullptr);
    esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &provisioning_event_handler, nullptr);
    esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &provisioning_event_handler, nullptr);

    // Check if already provisioned (requires wifi to be initialized)
    bool provisioned = false;
    network_prov_mgr_is_wifi_provisioned(&provisioned);

    if (!provisioned) {
        ESP_LOGI(TAG, "Not provisioned - starting BLE provisioning");
        start_provisioning_internal();
    }
    else {
        ESP_LOGI(TAG, "Already provisioned - skipping BLE");
    }
}

void provisioning_start() {
    start_provisioning_internal();
}
