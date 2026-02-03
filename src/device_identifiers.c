#include "kd_common.h"

#include <stdio.h>
#include <stdbool.h>

#include "esp_mac.h"

static bool s_initialized = false;
static char s_device_name_buf[64] = {0};

static void init_device_name(void) {
    uint8_t mac[6];
    esp_efuse_mac_get_default(mac);
    snprintf(s_device_name_buf, sizeof(s_device_name_buf),
        "%s-%02X%02X%02X%02X%02X%02X",
        CONFIG_KD_COMMON_DEVICE_NAME_PREFIX, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

char* kd_common_get_device_name(void) {
    if (!s_initialized) {
        init_device_name();
        s_initialized = true;
    }
    return s_device_name_buf;
}
