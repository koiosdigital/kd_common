#include "wifi.h"

#include <esp_err.h>
#include <esp_event.h>
#include <esp_log.h>
#include <esp_wifi.h>
#include <esp_http_client.h>
#include <esp_crt_bundle.h>
#include "cJSON.h"

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <string.h>

#include "kd_common.h"

static const char* TAG = "kd_wifi";

//MARK: Public API
void kd_common_wifi_disconnect() {
    esp_wifi_disconnect();
}

void kd_common_clear_wifi_credentials() {
    ESP_LOGI(TAG, "clearing wifi credentials");

    kd_common_wifi_disconnect();
    wifi_config_t wifi_cfg;
    memset(&wifi_cfg, 0, sizeof(wifi_cfg));
    esp_wifi_set_config(WIFI_IF_STA, &wifi_cfg);
}

//MARK: Private API
void wifi_init() {

    ESP_LOGI(TAG, "initializing");

    esp_netif_init();

    esp_netif_t* netif = esp_netif_create_default_wifi_sta();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();

    esp_wifi_init(&cfg);
    esp_wifi_set_mode(wifi_mode_t::WIFI_MODE_STA);
    esp_netif_set_hostname(netif, kd_common_get_device_name());
    esp_wifi_start();
}