#include "kdmdns.h"
#include "kd_common.h"
#include "mdns.h"
#include <esp_app_desc.h>
#include <esp_event.h>
#include <esp_wifi.h>
#include <esp_log.h>
#include <string.h>

static const char* TAG = "kdmdns";

namespace {
    const char* g_model = nullptr;
    const char* g_type = nullptr;
    bool g_mdns_running = false;

    void start_mdns() {
        if (g_mdns_running) {
            return;
        }

        esp_err_t ret = mdns_init();
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "mdns_init failed: %s", esp_err_to_name(ret));
            return;
        }

        const char* hostname = kd_common_get_wifi_hostname();
        mdns_hostname_set(hostname);

        const esp_app_desc_t* app_desc = esp_app_get_description();

        mdns_txt_item_t serviceTxtData[3] = {
            {"model", g_model ? g_model : "unknown"},
            {"type", g_type ? g_type : "unknown"},
            {"version", app_desc->version}
        };

        ret = mdns_service_add(NULL, "_koiosdigital", "_tcp", 80, serviceTxtData, 3);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "mdns_service_add failed: %s", esp_err_to_name(ret));
            mdns_free();
            return;
        }

        g_mdns_running = true;
        ESP_LOGI(TAG, "mDNS started: %s", hostname);
    }

    void stop_mdns() {
        if (!g_mdns_running) {
            return;
        }

        mdns_free();
        g_mdns_running = false;
        ESP_LOGI(TAG, "mDNS stopped");
    }

    void wifi_event_handler(void*, esp_event_base_t base, int32_t id, void*) {
        if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
            start_mdns();
        }
        else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
            stop_mdns();
        }
    }
}

void kdmdns_init() {
    esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, wifi_event_handler, nullptr);
    esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, wifi_event_handler, nullptr);
    ESP_LOGI(TAG, "mDNS initialized (waiting for WiFi)");
}

void kdmdns_set_device_info(const char* model, const char* type) {
    g_model = model;
    g_type = type;

    // Restart mDNS if already running to pick up new device info
    if (g_mdns_running) {
        stop_mdns();
        start_mdns();
    }
}

const char* kdmdns_get_model() {
    return g_model;
}

const char* kdmdns_get_type() {
    return g_type;
}
