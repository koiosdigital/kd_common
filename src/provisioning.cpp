#include "provisioning.h"

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

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

// Encapsulated provisioning state
struct ProvisioningState {
    TaskHandle_t task = nullptr;
    bool ever_connected = false;
    ProvisioningPOPTokenFormat_t pop_format = ProvisioningPOPTokenFormat_t::NONE;
    char* qr_payload = nullptr;
    char* pop_token = nullptr;
    bool is_internet = false;
    bool prov_cred_failed = false;
};

ProvisioningState state;

}  // namespace

//MARK: Public API
void kd_common_notify_provisioning_task(ProvisioningTaskNotification_t notification) {
    TaskHandle_t task_handle = provisioning_get_task_handle();
    if (task_handle != nullptr) {
        xTaskNotify(task_handle, notification, eSetValueWithOverwrite);
    }
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

char* kd_common_provisioning_get_pop_token() {
    if (state.pop_token != nullptr) {
        return state.pop_token;
    }

    if (state.pop_format == ProvisioningPOPTokenFormat_t::NUMERIC_6) {
        state.pop_token = static_cast<char*>(calloc(7, sizeof(char)));
        if (state.pop_token) {
            esp_fill_random(state.pop_token, 6);
            for (int i = 0; i < 6; i++) {
                // Fixed: % 10 + '0' generates digits 0-9 (was % 6 + '1' which generated 1-6)
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

void kd_common_set_provisioning_pop_token_format(ProvisioningPOPTokenFormat_t format) {
    state.pop_format = format;
}


//MARK: Private API
TaskHandle_t provisioning_get_task_handle() {
    return state.task;
}

void provisioning_task(void*) {
    uint32_t notification_value;
    bool provisioning_started = false;

    while (true) {
        if (xTaskNotifyWait(0, ULONG_MAX, &notification_value, portMAX_DELAY) == pdTRUE) {
            auto notification = static_cast<ProvisioningTaskNotification_t>(notification_value);
            char* pop = nullptr;
            esp_err_t ret;
            switch (notification) {
            case STOP_PROVISIONING:
                if (provisioning_started) {
                    vTaskDelay(5000);
                    ESP_LOGI(TAG, "stopping");
                    wifi_prov_mgr_stop_provisioning();
                    provisioning_started = false;
                }
                break;
            case START_PROVISIONING:
                if (provisioning_started) {
                    break;
                }
                ret = wifi_prov_mgr_init({ .scheme = wifi_prov_scheme_ble, .scheme_event_handler = WIFI_PROV_SCHEME_BLE_EVENT_HANDLER_FREE_BTDM });
                if (ret != ESP_OK) {
                    ESP_LOGE(TAG, "Failed to init provisioning manager: %s", esp_err_to_name(ret));
                    // Cancel WiFi connection, restart WiFi, and retry provisioning
                    esp_wifi_disconnect();
                    esp_wifi_stop();
                    vTaskDelay(pdMS_TO_TICKS(1000));
                    esp_wifi_start();
                    vTaskDelay(pdMS_TO_TICKS(1000));
                    // Retry provisioning init
                    ret = wifi_prov_mgr_init({ .scheme = wifi_prov_scheme_ble, .scheme_event_handler = WIFI_PROV_SCHEME_BLE_EVENT_HANDLER_FREE_BTDM });
                    if (ret != ESP_OK) {
                        ESP_LOGE(TAG, "Failed to init provisioning manager on retry: %s", esp_err_to_name(ret));
                        break;
                    }
                }

                ret = wifi_prov_mgr_endpoint_create(BLE_CONSOLE_ENDPOINT_NAME);
                if (ret != ESP_OK) {
                    ESP_LOGE(TAG, "Failed to create provisioning endpoint: %s", esp_err_to_name(ret));
                    wifi_prov_mgr_deinit();
                    break;
                }

                pop = kd_common_provisioning_get_pop_token();
                if (pop == nullptr) {
                    ret = wifi_prov_mgr_start_provisioning(WIFI_PROV_SECURITY_0, nullptr, kd_common_get_device_name(), nullptr);
                } else {
                    ret = wifi_prov_mgr_start_provisioning(WIFI_PROV_SECURITY_1, pop, kd_common_get_device_name(), nullptr);
                }

                if (ret != ESP_OK) {
                    ESP_LOGE(TAG, "Failed to start provisioning: %s", esp_err_to_name(ret));
                    wifi_prov_mgr_deinit();
                    break;
                }

#ifndef KD_COMMON_CONSOLE_DISABLE
                ret = wifi_prov_mgr_endpoint_register(BLE_CONSOLE_ENDPOINT_NAME, ble_console_endpoint, nullptr);
                if (ret != ESP_OK) {
                    ESP_LOGE(TAG, "Failed to register console endpoint: %s", esp_err_to_name(ret));
                }
#endif // KD_COMMON_CONSOLE_DISABLE

                provisioning_started = true;
                ESP_LOGI(TAG, "started");
                break;
            case RESET_SM_ON_FAILURE:
                ESP_LOGI(TAG, "resetting state machine");
                wifi_prov_mgr_reset_sm_state_on_failure();
                break;
            }
        }
    }
}

bool kd_common_is_wifi_connected() {
    return state.is_internet;
}

void provisioning_event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data) {
    static int wifi_connection_attempts = 0;

    if (event_base == WIFI_EVENT) {
        switch (event_id) {
        case WIFI_EVENT_STA_START: {
            wifi_config_t wifi_cfg;
            esp_wifi_get_config(WIFI_IF_STA, &wifi_cfg);

            if (std::strlen(reinterpret_cast<const char*>(wifi_cfg.sta.ssid)) == 0) {
                kd_common_notify_provisioning_task(ProvisioningTaskNotification_t::START_PROVISIONING);
                break;
            }

            esp_wifi_connect();
            break;
        }
        case WIFI_EVENT_STA_DISCONNECTED: {
            wifi_connection_attempts++;
            state.is_internet = false;

            // Don't auto-reconnect if provisioning credentials failed - wait for new credentials
            if (state.prov_cred_failed) {
                ESP_LOGD(TAG, "Not reconnecting - waiting for new provisioning credentials");
                break;
            }

            if (wifi_connection_attempts > 5 && !state.ever_connected) {
                kd_common_notify_provisioning_task(ProvisioningTaskNotification_t::START_PROVISIONING);
            }

            esp_wifi_connect();
            break;
        }
        }
    } else if (event_base == IP_EVENT) {
        if (event_id == IP_EVENT_STA_GOT_IP) {
            wifi_connection_attempts = 0;
            state.ever_connected = true;
            state.is_internet = true;
            state.prov_cred_failed = false;
            kd_common_notify_provisioning_task(ProvisioningTaskNotification_t::STOP_PROVISIONING);
        }
    } else if (event_base == WIFI_PROV_EVENT) {
        switch (event_id) {
        case WIFI_PROV_CRED_FAIL:
            state.prov_cred_failed = true;
            ESP_LOGW(TAG, "WiFi credentials failed - resetting provisioning state machine");
            kd_common_notify_provisioning_task(ProvisioningTaskNotification_t::RESET_SM_ON_FAILURE);
            break;
        case WIFI_PROV_CRED_RECV:
            state.prov_cred_failed = false;
            ESP_LOGI(TAG, "New WiFi credentials received");
            break;
        case WIFI_PROV_END:
            wifi_prov_mgr_deinit();
            kd_common_notify_provisioning_task(ProvisioningTaskNotification_t::STOP_PROVISIONING);
            break;
        default:
            break;
        }
    }
}

void provisioning_init() {
    ESP_LOGI(TAG, "initializing");

    esp_event_handler_register(WIFI_PROV_EVENT, ESP_EVENT_ANY_ID, &provisioning_event_handler, nullptr);
    esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_START, &provisioning_event_handler, nullptr);
    esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &provisioning_event_handler, nullptr);
    esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &provisioning_event_handler, nullptr);

    xTaskCreatePinnedToCore(provisioning_task, "provisioning", 4096, nullptr, 2, &state.task, 1);
}