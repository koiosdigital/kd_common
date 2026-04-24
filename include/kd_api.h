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

// ---------------------------------------------------------------------------
// Pre-handler hook
// ---------------------------------------------------------------------------
//
// Hook invoked before every URI handler registered via
// kd_common_api_register_uri_handler(). Use it to set response headers that
// must appear on every response (e.g. CORS). Headers set here via
// httpd_resp_set_hdr() persist through the user handler's response send.
//
// Set once during boot (before handlers register, or any time — the hook
// is read per-request). Pass NULL to disable.
typedef void (*kd_common_api_pre_handler_fn)(httpd_req_t* req);
void kd_common_api_set_pre_handler(kd_common_api_pre_handler_fn hook);

// Wrapper around httpd_register_uri_handler that installs a thin shim
// calling the pre-handler (if any) before dispatching to `uri->handler`.
// The user_ctx is forwarded unchanged to the handler.
//
// Returns the same codes as httpd_register_uri_handler, or ESP_ERR_NO_MEM
// if internal bookkeeping allocation fails.
esp_err_t kd_common_api_register_uri_handler(httpd_handle_t server,
                                              const httpd_uri_t* uri);

#ifdef __cplusplus
}
#endif

#endif // CONFIG_KD_COMMON_API_ENABLE
