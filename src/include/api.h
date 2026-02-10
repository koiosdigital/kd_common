#pragma once

#include "sdkconfig.h"

#ifdef CONFIG_KD_COMMON_API_ENABLE

#include "esp_http_server.h"

#ifdef __cplusplus
extern "C" {
#endif

// Callback type for registering HTTP handlers
typedef void (*api_handler_registrar_fn)(httpd_handle_t server);

// Initialize API (registers WiFi event handlers, httpd starts when WiFi connects)
void api_init(void);

// Stop the HTTP server immediately (call before WiFi disconnect to avoid socket errors)
void api_stop_server(void);

// Register a callback to be called with httpd handle when server starts.
// If server is already running, callback is invoked immediately.
// Callbacks are stored and re-invoked on reconnect.
void api_register_handlers(api_handler_registrar_fn registrar);

#ifdef __cplusplus
}
#endif

#endif // CONFIG_KD_COMMON_API_ENABLE
