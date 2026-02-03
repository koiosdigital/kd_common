#pragma once

#include "sdkconfig.h"

#ifdef CONFIG_KD_COMMON_API_ENABLE

#include "esp_http_server.h"

// Callback type for registering HTTP handlers
typedef void (*api_handler_registrar_fn)(httpd_handle_t server);

// Initialize API (registers WiFi event handlers, httpd starts when WiFi connects)
void api_init();

// Register a callback to be called with httpd handle when server starts.
// If server is already running, callback is invoked immediately.
// Callbacks are stored and re-invoked on reconnect.
void api_register_handlers(api_handler_registrar_fn registrar);

#endif // CONFIG_KD_COMMON_API_ENABLE
