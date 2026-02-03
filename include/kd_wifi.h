#pragma once

#include "esp_err.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// WiFi connection functions
void kd_common_wifi_disconnect(void);
void kd_common_clear_wifi_credentials(void);
bool kd_common_is_wifi_connected(void);
esp_err_t kd_common_wifi_connect(const char* ssid, const char* password);

// WiFi hostname functions (separate from device name)
void kd_common_set_wifi_hostname(const char* hostname);
char* kd_common_get_wifi_hostname(void);

#ifdef __cplusplus
}
#endif
