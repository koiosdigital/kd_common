#pragma once

#include <esp_err.h>
#include <esp_http_client.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// App-wide shared HTTP client.
//
// Every HTTP(S) user in the firmware (OTA check, TZ geolocation fetch,
// render pulls) funnels through one mutex-guarded esp_http_client handle,
// so at most one HTTP/TLS operation is ever in flight. That serializes TLS
// handshakes (one set of mbedtls buffers, no competing handshakes) and
// keeps one connection alive between requests — consecutive requests to
// the same host reuse it; a different host drops it and reconnects.
//
// Usage:
//   esp_http_client_handle_t c = kd_http_acquire(url, my_event_cb, my_ctx, 20000);
//   if (c) {
//       kd_http_set_header("Authorization", auth);   // auto-removed on release
//       esp_err_t err = esp_http_client_perform(c);  // or open/fetch/read
//       if (err != ESP_OK) kd_http_invalidate();     // drop poisoned connection
//       kd_http_release();
//   }
//
// The event callback and user_data are per-acquire: events fired during this
// holder's requests are forwarded to `event_cb` with evt->user_data set to
// `user_data`. Headers set via kd_http_set_header are deleted on release so
// they can never leak into another caller's request (e.g. a bearer token
// sent to a third-party API).

void kd_http_init(void);

// Take exclusive ownership of the shared client, configured for `url`.
// Blocks up to lock_timeout_ms waiting for the current holder. Returns NULL
// on lock timeout or client allocation failure.
esp_http_client_handle_t kd_http_acquire(const char* url,
                                         http_event_handle_cb event_cb,
                                         void* user_data,
                                         int lock_timeout_ms);

// Set a request header that is automatically deleted when released.
// Only valid between acquire and release.
esp_err_t kd_http_set_header(const char* key, const char* value);

// Destroy the underlying client (connection included). Call while holding
// the client after a transport-level error; the next acquire recreates it.
void kd_http_invalidate(void);

// Release ownership. Tracked headers are removed; the connection is kept
// alive for reuse by the next same-host acquire.
void kd_http_release(void);

// Raw lock for HTTP users that own their client internally (esp_https_ota):
// hold it for the duration so the download doesn't overlap other HTTP/TLS.
bool kd_http_lock(int timeout_ms);
void kd_http_unlock(void);

#ifdef __cplusplus
}
#endif
