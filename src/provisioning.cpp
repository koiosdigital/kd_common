#include "provisioning.h"

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include <esp_event.h>
#include <esp_log.h>
#include <esp_wifi.h>
#include <esp_random.h>

#include <wifi_provisioning/manager.h>
#include <wifi_provisioning/scheme_ble.h>

#include <string.h>

#include "kd_common.h"
#include "ble_console.h"

static const char* TAG = "kd_ble_prov";

TaskHandle_t xProvisioningTask = nullptr;
ProvisioningPOPTokenFormat_t provisioning_pop_token_format = ProvisioningPOPTokenFormat_t::ALPHA_8;

//MARK: Public API
void kd_common_notify_provisioning_task(ProvisioningTaskNotification_t notification) {
    TaskHandle_t xProvisioningTask = provisioning_get_task_handle();

    if (xProvisioningTask != NULL) {
        xTaskNotify(xProvisioningTask, notification, eSetValueWithOverwrite);
    }
}

char* provisioning_qr_payload = nullptr;
char* kd_common_get_provisioning_qr_payload() {
    if (provisioning_qr_payload != nullptr) {
        return provisioning_qr_payload;
    }

    provisioning_qr_payload = (char*)calloc(64, sizeof(char));
    snprintf(provisioning_qr_payload, 63, "%s;%s", kd_common_get_device_name(), kd_common_provisioning_get_pop_token());
    return provisioning_qr_payload;
}


char* provisioning_pop_token = nullptr;
char* kd_common_provisioning_get_pop_token() {
    if (provisioning_pop_token != nullptr) {
        return provisioning_pop_token;
    }

    if (provisioning_pop_token_format == ProvisioningPOPTokenFormat_t::NUMERIC_6) {
        provisioning_pop_token = (char*)calloc(7, sizeof(char));
        esp_fill_random(provisioning_pop_token, 6);
        for (int i = 0; i < 6; i++) {
            provisioning_pop_token[i] = (provisioning_pop_token[i] % 10) + '0';
        }
        return provisioning_pop_token;
    }

    if (provisioning_pop_token_format == ProvisioningPOPTokenFormat_t::ALPHA_8) {
        provisioning_pop_token = (char*)calloc(9, sizeof(char));
        esp_fill_random(provisioning_pop_token, 8);
        for (int i = 0; i < 8; i++) {
            provisioning_pop_token[i] = (provisioning_pop_token[i] % 26) + 'A';
        }
        return provisioning_pop_token;
    }

    return nullptr;
}

void kd_common_set_provisioning_pop_token_format(ProvisioningPOPTokenFormat_t format) {
    provisioning_pop_token_format = format;
}


//MARK: Private API
TaskHandle_t provisioning_get_task_handle() {
    return xProvisioningTask;
}

void provisioning_task(void* pvParameter) {
    ProvisioningTaskNotification_t notification;
    bool provisioning_started = false;

    while (true) {
        if (xTaskNotifyWait(0, ULONG_MAX, (uint32_t*)&notification, portMAX_DELAY) == pdTRUE) {
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
                wifi_prov_mgr_init({ .scheme = wifi_prov_scheme_ble, .scheme_event_handler = WIFI_PROV_SCHEME_BLE_EVENT_HANDLER_FREE_BTDM });
                wifi_prov_mgr_endpoint_create(BLE_CONSOLE_ENDPOINT_NAME);
                wifi_prov_mgr_start_provisioning(WIFI_PROV_SECURITY_1, kd_common_provisioning_get_pop_token(), kd_common_get_device_name(), NULL);
                wifi_prov_mgr_endpoint_register(BLE_CONSOLE_ENDPOINT_NAME, ble_console_endpoint, NULL);
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

static bool is_internet = false;
bool kd_common_is_wifi_connected() {
    return is_internet;
}

void provisioning_event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data) {
    static int wifiConnectionAttempts = 0;
    if (event_base == WIFI_EVENT) {
        switch (event_id) {
        case WIFI_EVENT_STA_START: {
            wifi_config_t wifi_cfg;
            esp_wifi_get_config(WIFI_IF_STA, &wifi_cfg);

            if (!strlen((const char*)wifi_cfg.sta.ssid)) {
                kd_common_notify_provisioning_task(ProvisioningTaskNotification_t::START_PROVISIONING);
                break;
            }

            esp_wifi_connect();
            break;
        }
        case WIFI_EVENT_STA_DISCONNECTED: {
            wifiConnectionAttempts++;
            is_internet = false;

            if (wifiConnectionAttempts > 5) {
                kd_common_notify_provisioning_task(ProvisioningTaskNotification_t::START_PROVISIONING);
            }

            esp_wifi_connect();
            break;
        }
        }
    }
    else if (event_base == IP_EVENT) {
        if (event_id == IP_EVENT_STA_GOT_IP) {
            wifiConnectionAttempts = 0;
            is_internet = true;
            kd_common_notify_provisioning_task(ProvisioningTaskNotification_t::STOP_PROVISIONING);
        }
    }
    else if (event_base == WIFI_PROV_EVENT) {
        switch (event_id) {
        case WIFI_PROV_CRED_FAIL: {
            kd_common_notify_provisioning_task(ProvisioningTaskNotification_t::RESET_SM_ON_FAILURE);
            break;
        }
        case WIFI_PROV_END: {
            wifi_prov_mgr_deinit();
            kd_common_notify_provisioning_task(ProvisioningTaskNotification_t::STOP_PROVISIONING);
            break;
        }
        case WIFI_PROV_START: {
            ESP_LOGI(TAG, "provision::%s::%s", kd_common_get_device_name(), kd_common_provisioning_get_pop_token());
            break;
        }
        default:
            break;
        }
    }
}

void provisioning_init() {
    ESP_LOGI(TAG, "initializing");

    esp_event_handler_register(WIFI_PROV_EVENT, ESP_EVENT_ANY_ID, &provisioning_event_handler, NULL);
    esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_START, &provisioning_event_handler, NULL);
    esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &provisioning_event_handler, NULL);
    esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &provisioning_event_handler, NULL);

    xTaskCreatePinnedToCore(provisioning_task, "provisioning", 4096, NULL, 2, &xProvisioningTask, 1);
}