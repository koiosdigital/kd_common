#include "ota.h"

#include "esp_https_ota.h"
#include "esp_http_client.h"
#include "esp_crt_bundle.h"
#include "esp_log.h"
#include "esp_app_format.h"
#include "esp_wifi.h"
#include "esp_timer.h"

#include "semver.h"
#include "cJSON.h"

static const char* TAG = "ota";

esp_http_client_config_t config = {
    .url = OTA_MANIFEST_URL,
    .crt_bundle_attach = esp_crt_bundle_attach,
};

void do_ota(void* pvParameter) {
    char* binURL = (char*)pvParameter;

    if (binURL == NULL) {
        return;
    }

    esp_http_client_config_t config = {
        .url = binURL,
        .crt_bundle_attach = esp_crt_bundle_attach,
    };

    esp_https_ota_config_t ota_config = {
        .http_config = &config,
    };

    esp_err_t err = esp_https_ota(&ota_config);
    free(binURL);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "update failed: %s", esp_err_to_name(err));
        return;
    }

    ESP_LOGI(TAG, "update successful");
    esp_restart();
}

void ota_timer_handler(void* pvParameter) {
    ESP_LOGI(TAG, "checking for updates");

    esp_http_client_handle_t http_client;

    int status_code = 0;
    esp_err_t err = ESP_OK;

    cJSON* root = NULL;
    cJSON* latest = NULL;
    cJSON* bin = NULL;
    cJSON* host = NULL;
    char* response = NULL;
    char* binURL = NULL;

    semver_t current_version, latest_version;

    semver_parse_version(esp_app_get_description()->version, &current_version);

    http_client = esp_http_client_init(&config);

    err = esp_http_client_perform(http_client);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "http request failed: %s", esp_err_to_name(err));
        goto exit;
    }

    status_code = esp_http_client_get_status_code(http_client);
    if (status_code != 200) {
        goto exit;
    }

    response = (char*)calloc(512, sizeof(char));
    if (response == NULL) {
        ESP_LOGE(TAG, "malloc failed: response");
        goto exit;
    }

    if (esp_http_client_read(http_client, response, 512) <= 0) {
        ESP_LOGE(TAG, "failed to read response");
        goto exit;
    }

    root = cJSON_Parse(response);
    if (root == NULL) {
        ESP_LOGE(TAG, "failed to parse JSON");
        goto exit;
    }

    latest = cJSON_GetObjectItem(root, "version");
    if (latest == NULL) {
        ESP_LOGE(TAG, "failed to get latest version");
        goto exit;
    }

    err = semver_parse_version(latest->valuestring, &latest_version);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "failed to parse latest version");
        goto exit;
    }

    if (semver_compare(latest_version, current_version) != 1) {
        ESP_LOGI(TAG, "no update available");
        goto exit;
    }

    bin = cJSON_GetObjectItem(root, "bin");
    host = cJSON_GetObjectItem(root, "host");

    if (bin == NULL || host == NULL) {
        ESP_LOGE(TAG, "failed to get bin or host");
        goto exit;
    }

    binURL = (char*)calloc(512, sizeof(char));
    if (binURL == NULL) {
        ESP_LOGE(TAG, "malloc failed: binURL");
        goto exit;
    }

    snprintf(binURL, 512, "https://%s%s", host->valuestring, bin->valuestring);
    xTaskCreate(do_ota, "ota_task", 4096, &binURL, 5, NULL);

exit:
    esp_http_client_cleanup(http_client);
    free(response);
    vTaskDelay(pdMS_TO_TICKS(1000 * 60 * 60 * 6));
}

void ota_init() {
    //esp timer
    esp_timer_create_args_t ota_timer_args = {
        .callback = &ota_timer_handler,
        .name = "ota_timer",
    };

    esp_timer_handle_t ota_timer;
    esp_timer_create(&ota_timer_args, &ota_timer);
    esp_timer_start_periodic(ota_timer, 1000 * 60 * 60 * 6);
    ESP_LOGI(TAG, "timer started");
}