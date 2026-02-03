#include "kdmdns.h"
#include "kd_common.h"
#include "mdns.h"
#include <esp_app_desc.h>
#include <esp_event.h>
#include <esp_wifi.h>
#include <esp_log.h>
#include <string.h>

static const char* TAG = "kdmdns";

// Private state
static const char* s_model = NULL;
static const char* s_type = NULL;
static bool s_mdns_running = false;

static void start_mdns(void);
static void stop_mdns(void);

static void start_mdns(void) {
    if (s_mdns_running) {
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
        {"model", s_model ? s_model : "unknown"},
        {"type", s_type ? s_type : "unknown"},
        {"version", app_desc->version}
    };

    ret = mdns_service_add(NULL, "_koiosdigital", "_tcp", 80, serviceTxtData, 3);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "mdns_service_add failed: %s", esp_err_to_name(ret));
        mdns_free();
        return;
    }

    s_mdns_running = true;
    ESP_LOGI(TAG, "mDNS started: %s", hostname);
}

static void stop_mdns(void) {
    if (!s_mdns_running) {
        return;
    }

    mdns_free();
    s_mdns_running = false;
    ESP_LOGI(TAG, "mDNS stopped");
}

static void wifi_event_handler(void* arg, esp_event_base_t base, int32_t id, void* event_data) {
    (void)arg;
    (void)event_data;

    if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        start_mdns();
    }
    else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        stop_mdns();
    }
}

void kdmdns_init(void) {
    esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, wifi_event_handler, NULL);
    esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, wifi_event_handler, NULL);
    ESP_LOGI(TAG, "mDNS initialized (waiting for WiFi)");
}

void kdmdns_set_device_info(const char* model, const char* type) {
    s_model = model;
    s_type = type;

    // Restart mDNS if already running to pick up new device info
    if (s_mdns_running) {
        stop_mdns();
        start_mdns();
    }
}

const char* kdmdns_get_model(void) {
    return s_model;
}

const char* kdmdns_get_type(void) {
    return s_type;
}
