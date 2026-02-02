#include "kd_common.h"

#include <cstdio>
#include <mutex>

#include "esp_mac.h"

namespace {

    std::once_flag init_flag;
    char device_name_buf[64] = {};

    void init_device_name() {
        uint8_t mac[6];
        esp_efuse_mac_get_default(mac);
        std::snprintf(device_name_buf, sizeof(device_name_buf),
            "%s-%02X%02X%02X%02X%02X%02X",
            CONFIG_KD_COMMON_DEVICE_NAME_PREFIX, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }

}  // namespace

char* kd_common_get_device_name() {
    std::call_once(init_flag, init_device_name);
    return device_name_buf;
}
