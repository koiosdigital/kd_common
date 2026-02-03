#pragma once

#include "sdkconfig.h"

#ifdef CONFIG_KD_COMMON_API_ENABLE

#include <esp_http_server.h>

#ifdef __cplusplus
extern "C" {
#endif

// Callback type for registering HTTP handlers
typedef void (*kd_common_api_handler_registrar_fn)(httpd_handle_t server);

// Register a callback to be called with httpd handle when server starts.
// If server is already running, callback is invoked immediately.
// Callbacks are stored and re-invoked on WiFi reconnect.
void kd_common_api_register_handlers(kd_common_api_handler_registrar_fn registrar);

#ifdef __cplusplus
}
#endif

#endif // CONFIG_KD_COMMON_API_ENABLE
