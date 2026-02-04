#include "provisioning.h"

#include <esp_event.h>
#include <esp_log.h>
#include <esp_wifi.h>
#include <esp_random.h>

#include <network_provisioning/manager.h>
#include <network_provisioning/scheme_ble.h>
#include <esp_srp.h>

#include <string.h>

#include "kd_common.h"
#include "ble_console.h"

static const char* TAG = "kd_ble_prov";

#define SALT_LEN 16

typedef struct {
    bool ever_connected;
    bool provisioning_started;
    bool is_wifi_connected;
    bool prov_cred_failed;
    ProvisioningSRPPasswordFormat_t srp_format;
    char srp_password[16];
    network_prov_security2_params_t srp_params;
} provisioning_state_t;

static provisioning_state_t s_state = {
    .ever_connected = false,
    .provisioning_started = false,
    .is_wifi_connected = false,
    .prov_cred_failed = false,
    .srp_format = PROVISIONING_SRP_FORMAT_STATIC,
    .srp_password = {0},
    .srp_params = {0}
};

static void start_provisioning_internal(void) {
    if (s_state.provisioning_started) {
        ESP_LOGD(TAG, "Provisioning already started");
        return;
    }

    network_prov_mgr_config_t config = {
        .scheme = network_prov_scheme_ble,
        .scheme_event_handler = NETWORK_PROV_SCHEME_BLE_EVENT_HANDLER_FREE_BTDM,
        .app_event_handler = {
            .event_cb = NULL,
            .user_data = NULL,
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
    char* salt_out = NULL;
    char* verifier_out = NULL;
    int verifier_len = 0;

    ret = esp_srp_gen_salt_verifier(username, strlen(username),
        srp_password, strlen(srp_password),
        &salt_out, SALT_LEN,
        &verifier_out, &verifier_len);
    if (ret != ESP_OK || !salt_out || !verifier_out) {
        ESP_LOGE(TAG, "Failed to generate SRP salt/verifier: %s", esp_err_to_name(ret));
        free(salt_out);
        free(verifier_out);
        network_prov_mgr_deinit();
        return;
    }

    s_state.srp_params.salt = salt_out;
    s_state.srp_params.salt_len = SALT_LEN;
    s_state.srp_params.verifier = verifier_out;
    s_state.srp_params.verifier_len = verifier_len;

    ret = network_prov_mgr_start_provisioning(NETWORK_PROV_SECURITY_2, &s_state.srp_params, kd_common_get_device_name(), NULL);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start prov: %s", esp_err_to_name(ret));
        free((void*)s_state.srp_params.salt);
        free((void*)s_state.srp_params.verifier);
        memset(&s_state.srp_params, 0, sizeof(s_state.srp_params));
        network_prov_mgr_deinit();
        return;
    }

#ifdef CONFIG_KD_COMMON_CONSOLE_ENABLE
    ret = network_prov_mgr_endpoint_register(BLE_CONSOLE_ENDPOINT_NAME, ble_console_endpoint, NULL);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to register endpoint: %s", esp_err_to_name(ret));
    }
#endif

    s_state.provisioning_started = true;
    ESP_LOGI(TAG, "BLE provisioning started, S2 (%s / %s)", "koiosdigital", s_state.srp_password);
}

static void provisioning_event_handler(void* arg, esp_event_base_t event_base,
    int32_t event_id, void* event_data) {
    (void)arg;
    (void)event_data;

    // Check for WiFi start to potentially restart provisioning after credential clear
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        bool provisioned = false;
        network_prov_mgr_is_wifi_provisioned(&provisioned);
        if (!provisioned && !s_state.provisioning_started) {
            // Reset SRP password so a new one is generated
            s_state.srp_password[0] = '\0';
            ESP_LOGI(TAG, "WiFi started but not provisioned - starting BLE");
            start_provisioning_internal();
        }
        return;
    }

    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        s_state.is_wifi_connected = false;
        // Reconnect unless waiting for new provisioning credentials
        if (!s_state.prov_cred_failed) {
            vTaskDelay(pdMS_TO_TICKS(2500));
            esp_wifi_connect();
        }
    }
    else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        s_state.ever_connected = true;
        s_state.is_wifi_connected = true;
        s_state.prov_cred_failed = false;
        // Provisioning will auto-stop via WIFI_PROV_END event
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
            network_prov_mgr_deinit();  // This frees BT memory via scheme handler
            s_state.provisioning_started = false;
            break;
        case NETWORK_PROV_DEINIT:
            free((void*)s_state.srp_params.salt);
            free((void*)s_state.srp_params.verifier);
            memset(&s_state.srp_params, 0, sizeof(s_state.srp_params));
            break;
        }
    }
}

//MARK: Public API

void kd_common_set_provisioning_srp_password_format(ProvisioningSRPPasswordFormat_t format) {
    s_state.srp_format = format;
}

char* kd_common_provisioning_get_srp_password(void) {
    if (s_state.srp_password[0] != '\0') {
        return s_state.srp_password;
    }

    // static
    if (s_state.srp_format == PROVISIONING_SRP_FORMAT_STATIC) {
        strcpy(s_state.srp_password, "koiosdigital");
        return s_state.srp_password;
    }

    // 6 ascii numbers 0-9
    if (s_state.srp_format == PROVISIONING_SRP_FORMAT_NUMERIC_6) {
        if (s_state.srp_password[0] == '\0') {
            esp_fill_random(s_state.srp_password, 6);
            for (int i = 0; i < 6; i++) {
                s_state.srp_password[i] = (char)((s_state.srp_password[i] % 10) + '0');
            }
        }
        return s_state.srp_password;
    }

    // 6 ascii numbers 0-5
    if (s_state.srp_format == PROVISIONING_SRP_FORMAT_NUMERIC_6_REDUCED) {
        if (s_state.srp_password[0] == '\0') {
            esp_fill_random(s_state.srp_password, 6);
            for (int i = 0; i < 6; i++) {
                s_state.srp_password[i] = (char)((s_state.srp_password[i] % 6) + '0');
            }
        }
        return s_state.srp_password;
    }

    // 4 ascii numbers 0-9
    if (s_state.srp_format == PROVISIONING_SRP_FORMAT_NUMERIC_4) {
        if (s_state.srp_password[0] == '\0') {
            esp_fill_random(s_state.srp_password, 4);
            for (int i = 0; i < 4; i++) {
                s_state.srp_password[i] = (char)((s_state.srp_password[i] % 10) + '0');
            }
        }
        return s_state.srp_password;
    }

    return s_state.srp_password;
}

bool kd_common_is_wifi_connected(void) {
    return s_state.is_wifi_connected;
}

void kd_common_start_provisioning(void) {
    start_provisioning_internal();
}

//MARK: Internal API

void provisioning_init(void) {
    ESP_LOGI(TAG, "Initializing");

    // Register event handlers for WiFi state management
    esp_event_handler_register(NETWORK_PROV_EVENT, ESP_EVENT_ANY_ID, &provisioning_event_handler, NULL);
    esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &provisioning_event_handler, NULL);
    esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_START, &provisioning_event_handler, NULL);
    esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &provisioning_event_handler, NULL);

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

void provisioning_start(void) {
    start_provisioning_internal();
}
