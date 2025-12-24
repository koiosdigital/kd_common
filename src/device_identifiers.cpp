#include "kd_common.h"

#include "stdlib.h"
#include "string.h"
#include "esp_mac.h"

char* device_name = nullptr;
char* kd_common_get_device_name() {
    if (device_name != nullptr) {
        return device_name;
    }

    device_name = (char*)calloc(64, sizeof(char));
    if (device_name == nullptr) {
        return nullptr;
    }

    uint8_t mac[6];
    esp_efuse_mac_get_default(mac);

    char macStr[13];
    snprintf(macStr, 13, "%02X%02X%02X%02X%02X%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    snprintf(device_name, 64, "%s-%s", DEVICE_NAME_PREFIX, macStr);
    return device_name;
}