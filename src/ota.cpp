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

#include <cstring>

static const char* TAG = "kd_ota";

namespace {
    struct HttpResponseBuffer {
        char* data;
        size_t capacity;
        size_t len;
    };

    static void http_response_buffer_reset(HttpResponseBuffer* buffer) {
        if (buffer == nullptr || buffer->data == nullptr || buffer->capacity == 0) {
            return;
        }
        buffer->len = 0;
        buffer->data[0] = '\0';
    }

    static esp_err_t http_event_handler(esp_http_client_event_t* evt) {
        if (evt == nullptr) {
            return ESP_OK;
        }

        auto* buffer = static_cast<HttpResponseBuffer*>(evt->user_data);
        if (buffer == nullptr || buffer->data == nullptr || buffer->capacity < 2) {
            return ESP_OK;
        }

        switch (evt->event_id) {
        case HTTP_EVENT_ON_DATA: {
            if (evt->data == nullptr || evt->data_len <= 0) {
                break;
            }

            const size_t available = buffer->capacity - buffer->len - 1; // keep room for NUL
            const size_t to_copy = (available < (size_t)evt->data_len) ? available : (size_t)evt->data_len;
            if (to_copy == 0) {
                break;
            }
            memcpy(buffer->data + buffer->len, evt->data, to_copy);
            buffer->len += to_copy;
            buffer->data[buffer->len] = '\0';
            break;
        }
        case HTTP_EVENT_ON_CONNECTED:
            http_response_buffer_reset(buffer);
            break;
        default:
            break;
        }

        return ESP_OK;
    }
} // namespace

static void ota_update_task(void* pvParameter) {
    bool has_done_boot_check = false;

    char http_response_data[512] = { 0 };
    HttpResponseBuffer response_buffer{ http_response_data, sizeof(http_response_data), 0 };

    while (true) {
        if (kd_common_is_wifi_connected() == false) {
            ESP_LOGI(TAG, "waiting for wifi");
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }

        if (has_done_boot_check) {
            vTaskDelay(pdMS_TO_TICKS(1000 * 60 * 60 * 3)); // check for updates every 3 hours
        }

        ESP_LOGI(TAG, "checking for updates");

        http_response_buffer_reset(&response_buffer);

        esp_http_client_config_t config = {};
        config.url = FIRMWARE_ENDPOINT_URL;
        config.event_handler = http_event_handler;
        config.crt_bundle_attach = esp_crt_bundle_attach;
        config.user_data = &response_buffer;

        esp_http_client_handle_t http_client = esp_http_client_init(&config);
        if (http_client == nullptr) {
            ESP_LOGE(TAG, "failed to init http client");
            continue;
        }

        //esp_app_desc
        const esp_app_desc_t* app_desc = esp_app_get_description();

        esp_http_client_set_header(http_client, "x-firmware-project", app_desc->project_name);
        esp_http_client_set_header(http_client, "x-firmware-version", app_desc->version);

#ifdef FIRMWARE_VARIANT
        esp_http_client_set_header(http_client, "x-firmware-variant", FIRMWARE_VARIANT);
#endif

        esp_err_t perform_err = esp_http_client_perform(http_client);
        if (perform_err != ESP_OK) {
            ESP_LOGE(TAG, "http request failed: %s", esp_err_to_name(perform_err));
            esp_http_client_cleanup(http_client);
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

        http_response_buffer_reset(&response_buffer);

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
        if (ota_url_tmp == nullptr || ota_url_tmp[0] == '\0') {
            ESP_LOGE(TAG, "ota_url missing or empty");
            cJSON_Delete(root);
            continue;
        }

        char* ota_url = strdup(ota_url_tmp);
        if (ota_url == nullptr) {
            ESP_LOGE(TAG, "failed to allocate ota_url");
            cJSON_Delete(root);
            continue;
        }

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
    xTaskCreate(ota_update_task, "ota_task", 8192, NULL, 5, NULL);
}