#include "kdmdns.h"
#include "kd_common.h"
#include "wifi.h"
#include "mdns.h"
#include <esp_app_desc.h>
#include <esp_log.h>
#include <stdlib.h>
#include <string.h>

static const char* TAG = "kdmdns";

// Private state
static const char* s_model = NULL;
static const char* s_type = NULL;
static bool s_mdns_running = false;

// Custom TXT records added at runtime (e.g. device_id once the cloud session
// is up). Cached here so they survive the mDNS teardown/rebuild that happens
// on every WiFi reconnect.
#define KDMDNS_MAX_CUSTOM_RECORDS 8

typedef struct {
    char* service;
    char* key;
    char* value;
} custom_record_t;

static custom_record_t s_custom_records[KDMDNS_MAX_CUSTOM_RECORDS];
static size_t s_custom_record_count = 0;

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

    // Re-apply custom records added before this (re)start
    for (size_t i = 0; i < s_custom_record_count; i++) {
        mdns_service_txt_item_set(s_custom_records[i].service, "_tcp",
            s_custom_records[i].key, s_custom_records[i].value);
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

void kdmdns_init(void) {
    wifi_on_connect(start_mdns);
    wifi_on_disconnect(stop_mdns);
    ESP_LOGI(TAG, "mDNS initialized (waiting for WiFi)");
}

void kdmdns_set_device_info(const char* model, const char* type) {
    s_model = model;
    s_type = type;

    // Update TXT records in-place if mDNS is already running
    if (s_mdns_running) {
        const esp_app_desc_t* app_desc = esp_app_get_description();
        mdns_txt_item_t txt_data[3] = {
            {"model", s_model ? s_model : "unknown"},
            {"type", s_type ? s_type : "unknown"},
            {"version", app_desc->version}
        };
        esp_err_t ret = mdns_service_txt_set("_koiosdigital", "_tcp", txt_data, 3);
        if (ret != ESP_OK) {
            ESP_LOGW(TAG, "mdns txt update failed: %s, restarting", esp_err_to_name(ret));
            stop_mdns();
            start_mdns();
        }
    }
}

void kdmdns_add_svc_record(const char* service, const char* key, const char* value) {
    if (!service || !key || !value) {
        return;
    }

    // Update in place if this service+key is already cached
    custom_record_t* rec = NULL;
    for (size_t i = 0; i < s_custom_record_count; i++) {
        if (strcmp(s_custom_records[i].service, service) == 0 &&
            strcmp(s_custom_records[i].key, key) == 0) {
            rec = &s_custom_records[i];
            break;
        }
    }

    if (rec) {
        char* new_value = strdup(value);
        if (!new_value) {
            return;
        }
        free(rec->value);
        rec->value = new_value;
    }
    else {
        if (s_custom_record_count >= KDMDNS_MAX_CUSTOM_RECORDS) {
            ESP_LOGW(TAG, "Custom record table full, dropping %s/%s", service, key);
            return;
        }
        rec = &s_custom_records[s_custom_record_count];
        rec->service = strdup(service);
        rec->key = strdup(key);
        rec->value = strdup(value);
        if (!rec->service || !rec->key || !rec->value) {
            free(rec->service);
            free(rec->key);
            free(rec->value);
            rec->service = rec->key = rec->value = NULL;
            return;
        }
        s_custom_record_count++;
    }

    if (s_mdns_running) {
        esp_err_t ret = mdns_service_txt_item_set(service, "_tcp", key, value);
        if (ret != ESP_OK) {
            ESP_LOGW(TAG, "mdns txt item set failed for %s/%s: %s",
                service, key, esp_err_to_name(ret));
        }
    }
}

const char* kdmdns_get_model(void) {
    return s_model;
}

const char* kdmdns_get_type(void) {
    return s_type;
}
