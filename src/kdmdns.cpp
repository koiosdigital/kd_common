#include "kdmdns.h"
#include "kd_common.h"
#include "mdns.h"
#include <esp_app_desc.h>
#include <string.h>

namespace {
    const char* g_model = nullptr;
    const char* g_type = nullptr;
}

void kdmdns_init() {
    mdns_init();
    const char* hostname = kd_common_get_wifi_hostname();
    mdns_hostname_set(hostname);

    const esp_app_desc_t* app_desc = esp_app_get_description();

    mdns_txt_item_t serviceTxtData[3] = {
        {"model", g_model ? g_model : "unknown"},
        {"type", g_type ? g_type : "unknown"},
        {"version", app_desc->version}
    };

    ESP_ERROR_CHECK(mdns_service_add(NULL, "_koiosdigital", "_tcp", 80, serviceTxtData, 3));
}

void kdmdns_set_device_info(const char* model, const char* type) {
    g_model = model;
    g_type = type;

    //restart mDNS
    mdns_free();
    kdmdns_init();
}

const char* kdmdns_get_model() {
    return g_model;
}

const char* kdmdns_get_type() {
    return g_type;
}
