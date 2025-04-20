#include "kd_common.h"

#include <nvs_flash.h>
#include <esp_log.h>

#include "crypto.h"
#include "console.h"
#include "provisioning.h"
#include "wifi.h"

static const char* TAG = "kd_common";

void kd_common_init() {
    ESP_LOGI(TAG, "initializing");

    // Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        ret = nvs_flash_init();
    }

    console_init();

    crypto_init();
    provisioning_init();
    wifi_init();
}

void kd_common_reverse_bytes(uint8_t* data, size_t len) {
    for (size_t i = 0; i < len / 2; i++) {
        uint8_t temp = data[i];
        data[i] = data[len - i - 1];
        data[len - i - 1] = temp;
    }
}