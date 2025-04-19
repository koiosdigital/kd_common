#include "provisioning_private.h"
#include "provisioning.h"

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include <esp_event.h>
#include <esp_log.h>
#include <esp_wifi.h>
#include <wifi_provisioning/manager.h>
#include <wifi_provisioning/scheme_ble.h>

#include "device_identifiers.h"
#include "custom_prov_endpoint.h"

static const char* TAG = "provisioning";

TaskHandle_t xProvisioningTask = nullptr;
TaskHandle_t provisioning_get_task_handle() {
    return xProvisioningTask;
}

void prov_event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data) {
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

void provisioning_task(void* pvParameter) {
    ProvisioningTaskNotification_t notification;
    bool provisioning_started = false;

    while (true) {
        if (xTaskNotifyWait(0, ULONG_MAX, (uint32_t*)&notification, portMAX_DELAY) == pdTRUE) {
            switch (notification) {
            case STOP_PROVISIONING:
                if (provisioning_started) {
                    vTaskDelay(1000);
                    wifi_prov_mgr_stop_provisioning();
                    provisioning_started = false;
                }
                break;
            case START_PROVISIONING:
                if (provisioning_started) {
                    break;
                }
                wifi_prov_mgr_init({ .scheme = wifi_prov_scheme_ble, .scheme_event_handler = WIFI_PROV_SCHEME_BLE_EVENT_HANDLER_FREE_BTDM });
                wifi_prov_mgr_endpoint_create(CUSTOM_PROV_ENDPOINT);
                wifi_prov_mgr_start_provisioning(WIFI_PROV_SECURITY_1, kd_common_provisioning_get_pop_token(), kd_common_get_device_name(), NULL);
                wifi_prov_mgr_endpoint_register(CUSTOM_PROV_ENDPOINT, custom_prov_endpoint, NULL);
                provisioning_started = true;
                break;
            case RESET_PROVISIONING:
                esp_restart();
                break;
            case RESET_SM_ON_FAILURE:
                wifi_prov_mgr_reset_sm_state_on_failure();
                break;
            }
        }
    }
}

void provisioning_init() {
    esp_event_handler_register(WIFI_PROV_EVENT, ESP_EVENT_ANY_ID, &prov_event_handler, NULL);
    xTaskCreatePinnedToCore(provisioning_task, "provisioning", 4096, NULL, 2, &xProvisioningTask, 1);
}