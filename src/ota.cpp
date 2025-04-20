#include "ota.h"

#include "esp_https_ota.h"
#include "esp_http_client.h"
#include "esp_crt_bundle.h"
#include "esp_log.h"
#include "esp_app_format.h"
#include "esp_wifi.h"
#include "esp_timer.h"

#include "cJSON.h"
#include "kd_common.h"

static const char* TAG = "kd_ota";

char http_response_data[512] = { 0 };
esp_err_t _http_event_handler(esp_http_client_event_t* evt) {
    if (evt->event_id == HTTP_EVENT_ON_DATA) {
        memcpy(http_response_data, evt->data, evt->data_len);
        http_response_data[evt->data_len] = '\0';
    }
    return ESP_OK;
}

void ota_task(void* pvParameter) {
    bool has_done_boot_check = false;

    while (true) {
        if (kd_common_is_wifi_connected() == false) {
            ESP_LOGI(TAG, "waiting for wifi");
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }

        if (has_done_boot_check) {
            vTaskDelay(pdMS_TO_TICKS(1000 * 60 * 6));
        }

        ESP_LOGI(TAG, "checking for updates");

        esp_http_client_config_t config = {
            .url = FIRMWARE_ENDPOINT_URL,
            .event_handler = _http_event_handler,
            .crt_bundle_attach = esp_crt_bundle_attach,
        };

        esp_http_client_handle_t http_client = esp_http_client_init(&config);

        //esp_app_desc
        const esp_app_desc_t* app_desc = esp_app_get_description();

        esp_http_client_set_header(http_client, "x-firmware-project", app_desc->project_name);
        ESP_LOGI(TAG, "project name: %s", app_desc->project_name);
        esp_http_client_set_header(http_client, "x-firmware-version", app_desc->version);
        ESP_LOGI(TAG, "version: %s", app_desc->version);

#ifdef FIRMWARE_VARIANT
        esp_http_client_set_header(http_client, "x-firmware-variant", FIRMWARE_VARIANT);
        ESP_LOGI(TAG, "variant: %s", FIRMWARE_VARIANT);
#endif

        if (esp_http_client_perform(http_client) != ESP_OK) {
            ESP_LOGE(TAG, "http request failed");
            continue;
        }

        if (esp_http_client_get_status_code(http_client) != 200) {
            ESP_LOGE(TAG, "http request failed: status %d", esp_http_client_get_status_code(http_client));
            esp_http_client_cleanup(http_client);
            continue;
        }

        ESP_LOGI(TAG, "response: %s", http_response_data);
        esp_http_client_cleanup(http_client);

        cJSON* root = cJSON_Parse(http_response_data);
        if (root == NULL) {
            ESP_LOGE(TAG, "failed to parse json");
            continue;
        }

        memset(http_response_data, 0, sizeof(http_response_data));

        if (!cJSON_HasObjectItem(root, "update_available")) {
            ESP_LOGE(TAG, "failed to get update_available");
            cJSON_Delete(root);
            continue;
        }

        has_done_boot_check = true;

        if (cJSON_IsFalse(cJSON_GetObjectItem(root, "update_available"))) {
            ESP_LOGI(TAG, "no update available");
            cJSON_Delete(root);
            continue;
        }

        if (!cJSON_HasObjectItem(root, "ota_url")) {
            ESP_LOGE(TAG, "failed to get ota_url");
            cJSON_Delete(root);
            continue;
        }

        const char* ota_url_tmp = cJSON_GetObjectItem(root, "ota_url")->valuestring;
        char* ota_url = strdup(ota_url_tmp);

        cJSON_Delete(root);

        //do ota
        esp_http_client_config_t config2 = {
            .url = ota_url,
            .buffer_size = 4096,
            .buffer_size_tx = 4096,
            .crt_bundle_attach = esp_crt_bundle_attach,
        };

        esp_https_ota_config_t ota_config = {
            .http_config = &config2,
        };

        esp_err_t err = esp_https_ota(&ota_config);
        free(ota_url);

        if (err != ESP_OK) {
            ESP_LOGE(TAG, "update failed: %s", esp_err_to_name(err));
            continue;
        }

        ESP_LOGI(TAG, "update successful");
        esp_restart();
    }
}

void ota_init() {
    xTaskCreate(ota_task, "ota_task", 8192, NULL, 5, NULL);
}