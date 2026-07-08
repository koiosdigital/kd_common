// kd_http - app-wide shared HTTP client. See include/kd_http.h.
#include "kd_http.h"

#include <esp_log.h>
#include <esp_crt_bundle.h>
#include <esp_timer.h>

#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

#include <string.h>
#include <stdlib.h>

static const char* TAG = "kd_http";

// Per-socket-op timeout. The API answers in well under a second; anything
// longer means the connection is dead, and every extra second here is spent
// blocked inside esp_http_client on a request that will never complete.
#define KD_HTTP_TIMEOUT_MS      8000
#define KD_HTTP_RX_BUFFER       4096
#define KD_HTTP_TX_BUFFER       2048
#define MAX_TRACKED_HEADERS     8
// esp_http_client reuses a kept-alive connection blindly (no liveness poll):
// if the peer or a NAT box dropped it, the request stalls the full timeout
// before failing. Cloudflare idle-closes well within a minute, so a
// connection idle longer than this is closed preemptively — a ~1s fresh
// connect instead of an 8s blind stall.
#define KD_HTTP_IDLE_CLOSE_US   (45LL * 1000 * 1000)

static SemaphoreHandle_t s_mutex = NULL;
static esp_http_client_handle_t s_client = NULL;
// scheme://host[:port] of the connection the client currently holds
static char s_conn_key[128];
static int64_t s_last_use_us = 0;

// Per-acquire state, valid only while the mutex is held
static http_event_handle_cb s_event_cb = NULL;
static void* s_user_data = NULL;
static char* s_headers[MAX_TRACKED_HEADERS];
static size_t s_header_count = 0;

// Single event handler registered with the client; forwards to the current
// holder's callback with their user_data (config.user_data is fixed at init,
// so it can't carry per-request context itself).
static esp_err_t dispatch_event(esp_http_client_event_t* evt) {
    if (s_event_cb) {
        evt->user_data = s_user_data;
        return s_event_cb(evt);
    }
    return ESP_OK;
}

// Extract "scheme://host[:port]" — the part of the URL that determines
// whether an existing keep-alive connection is reusable.
static void url_conn_key(const char* url, char* out, size_t out_size) {
    const char* authority = strstr(url, "://");
    const char* path = authority ? strchr(authority + 3, '/') : NULL;
    size_t len = path ? (size_t)(path - url) : strlen(url);
    if (len >= out_size) len = out_size - 1;
    memcpy(out, url, len);
    out[len] = '\0';
}

static void drop_tracked_headers(bool delete_from_client) {
    for (size_t i = 0; i < s_header_count; i++) {
        if (delete_from_client && s_client) {
            esp_http_client_delete_header(s_client, s_headers[i]);
        }
        free(s_headers[i]);
        s_headers[i] = NULL;
    }
    s_header_count = 0;
}

void kd_http_init(void) {
    if (!s_mutex) {
        s_mutex = xSemaphoreCreateMutex();
    }
}

esp_http_client_handle_t kd_http_acquire(const char* url,
                                         http_event_handle_cb event_cb,
                                         void* user_data,
                                         int lock_timeout_ms) {
    if (!s_mutex || !url) return NULL;
    if (xSemaphoreTake(s_mutex, pdMS_TO_TICKS(lock_timeout_ms)) != pdTRUE) {
        ESP_LOGW(TAG, "Timed out waiting for HTTP client (held elsewhere)");
        return NULL;
    }

    char key[sizeof(s_conn_key)];
    url_conn_key(url, key, sizeof(key));

    if (s_client && (esp_timer_get_time() - s_last_use_us) > KD_HTTP_IDLE_CLOSE_US) {
        // Idle past the peer's keep-alive window: assume it's dead.
        esp_http_client_close(s_client);
    }
    if (s_client && strcmp(key, s_conn_key) != 0) {
        // Different host: close the kept-alive connection so the next
        // request opens a fresh one instead of reusing another host's socket.
        esp_http_client_close(s_client);
    }

    if (!s_client) {
        esp_http_client_config_t cfg = {
            .url = url,
            .event_handler = dispatch_event,
            .crt_bundle_attach = esp_crt_bundle_attach,
            .timeout_ms = KD_HTTP_TIMEOUT_MS,
            .keep_alive_enable = true,
            .buffer_size = KD_HTTP_RX_BUFFER,
            .buffer_size_tx = KD_HTTP_TX_BUFFER,
        };
        s_client = esp_http_client_init(&cfg);
        if (!s_client) {
            ESP_LOGE(TAG, "Failed to init HTTP client");
            xSemaphoreGive(s_mutex);
            return NULL;
        }
    } else {
        esp_http_client_set_url(s_client, url);
        // Previous holder may have changed the method
        esp_http_client_set_method(s_client, HTTP_METHOD_GET);
    }

    strlcpy(s_conn_key, key, sizeof(s_conn_key));
    s_event_cb = event_cb;
    s_user_data = user_data;
    return s_client;
}

esp_err_t kd_http_set_header(const char* key, const char* value) {
    if (!s_client) return ESP_ERR_INVALID_STATE;

    esp_err_t err = esp_http_client_set_header(s_client, key, value);
    if (err != ESP_OK) return err;

    for (size_t i = 0; i < s_header_count; i++) {
        if (strcmp(s_headers[i], key) == 0) return ESP_OK;  // already tracked
    }
    if (s_header_count >= MAX_TRACKED_HEADERS) {
        // Can't guarantee removal on release — refuse rather than leak the
        // header into a later caller's request.
        esp_http_client_delete_header(s_client, key);
        return ESP_ERR_NO_MEM;
    }
    s_headers[s_header_count] = strdup(key);
    if (!s_headers[s_header_count]) {
        esp_http_client_delete_header(s_client, key);
        return ESP_ERR_NO_MEM;
    }
    s_header_count++;
    return ESP_OK;
}

void kd_http_invalidate(void) {
    if (s_client) {
        drop_tracked_headers(false);  // headers die with the client
        esp_http_client_cleanup(s_client);
        s_client = NULL;
        s_conn_key[0] = '\0';
    }
}

void kd_http_release(void) {
    if (!s_mutex) return;
    drop_tracked_headers(true);
    s_event_cb = NULL;
    s_user_data = NULL;
    s_last_use_us = esp_timer_get_time();
    xSemaphoreGive(s_mutex);
}

bool kd_http_lock(int timeout_ms) {
    return s_mutex && xSemaphoreTake(s_mutex, pdMS_TO_TICKS(timeout_ms)) == pdTRUE;
}

void kd_http_unlock(void) {
    if (s_mutex) xSemaphoreGive(s_mutex);
}
