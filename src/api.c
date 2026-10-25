#include "api.h"
#include "kd_api.h"

#ifdef CONFIG_KD_COMMON_API_ENABLE

#include "kdmdns.h"
#include "kd_common.h"
#include "wifi.h"
#include "esp_http_server.h"
#include "cJSON.h"
#include <esp_app_desc.h>
#include <esp_event.h>
#include <esp_wifi.h>
#include <esp_log.h>
#include <esp_system.h>
#include <stdlib.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "sdkconfig.h"

static const char* TAG = "kd_api";

// Private state
static httpd_handle_t s_kd_api_server = NULL;

// Serializes start_server()/stop_server_internal() between the event-loop
// task (WiFi connect/disconnect) and the deferred-stop task below. Never taken
// on the httpd task itself (see stop_server_internal), so httpd_stop() can
// always wait for that task to exit without a lock-order deadlock.
static SemaphoreHandle_t s_server_lock = NULL;

// Handle of the httpd worker task, captured on the first accepted connection
// (open_fn runs on it) and again in the shim. Used to detect a stop request
// issued from inside a request handler.
static TaskHandle_t s_httpd_task = NULL;
static volatile bool s_stop_deferred = false;

// Max number of external handler registrars
#define MAX_REGISTRARS 16
static api_handler_registrar_fn s_registrars[MAX_REGISTRARS] = { NULL };
static size_t s_registrar_count = 0;

// Hooks run just before the server is stopped, while the handle is still valid.
static api_stop_hook_fn s_stop_hooks[MAX_REGISTRARS] = { NULL };
static size_t s_stop_hook_count = 0;

// ---------------------------------------------------------------------------
// Pre-handler hook + wrapper registration
// ---------------------------------------------------------------------------

// One per wrapped URI. Saved so the shim can dispatch to the real handler
// with the user's original user_ctx.
typedef struct {
    esp_err_t (*user_handler)(httpd_req_t*);
    void*     user_ctx;
} kd_api_wrap_t;

// Static pool of wraps: one per registered URI, sized to max_uri_handlers.
// The count is reset every time the server is (re)started, so reconnect
// cycles reuse the same entries instead of leaking a malloc per URI.
#define KD_API_MAX_URI_HANDLERS 200
static kd_api_wrap_t s_wraps[KD_API_MAX_URI_HANDLERS];
static size_t s_wrap_count = 0;

static kd_common_api_pre_handler_fn s_pre_handler = NULL;

#ifdef CONFIG_KD_COMMON_API_LOG_REQUESTS
static const char* method_name(int method) {
    switch (method) {
        case HTTP_GET:     return "GET";
        case HTTP_POST:    return "POST";
        case HTTP_PUT:     return "PUT";
        case HTTP_DELETE:  return "DELETE";
        case HTTP_PATCH:   return "PATCH";
        case HTTP_OPTIONS: return "OPTIONS";
        case HTTP_HEAD:    return "HEAD";
        default:           return "?";
    }
}
#endif

static esp_err_t kd_api_shim_handler(httpd_req_t* req) {
    kd_api_wrap_t* w = (kd_api_wrap_t*)req->user_ctx;
    // Belt-and-braces capture of the httpd task (open_fn already does this).
    s_httpd_task = xTaskGetCurrentTaskHandle();
    // Run the pre-handler hook (e.g. to set CORS headers).
    if (s_pre_handler) s_pre_handler(req);
    // Restore caller's user_ctx before dispatch.
    req->user_ctx = w->user_ctx;

#ifdef CONFIG_KD_COMMON_API_LOG_REQUESTS
    // Heap-leak diagnostic: log every route invocation + heap after. Single
    // line per request so the serial log can be diffed to localize leaks.
    esp_err_t err = w->user_handler(req);
    ESP_LOGI(TAG, "%s %s -> %s heap=%lu",
             method_name(req->method), req->uri,
             err == ESP_OK ? "OK" : esp_err_to_name(err),
             (unsigned long)esp_get_free_heap_size());
    return err;
#else
    return w->user_handler(req);
#endif
}

void kd_common_api_set_pre_handler(kd_common_api_pre_handler_fn hook) {
    s_pre_handler = hook;
}

esp_err_t kd_common_api_register_uri_handler(httpd_handle_t server,
                                              const httpd_uri_t* uri) {
    if (!server || !uri || !uri->handler) return ESP_ERR_INVALID_ARG;

    if (s_wrap_count >= KD_API_MAX_URI_HANDLERS) {
        ESP_LOGE(TAG, "URI wrap pool exhausted (%d) registering %s",
                 KD_API_MAX_URI_HANDLERS, uri->uri);
        return ESP_ERR_NO_MEM;
    }

    kd_api_wrap_t* w = &s_wraps[s_wrap_count];
    w->user_handler = uri->handler;
    w->user_ctx     = uri->user_ctx;

    httpd_uri_t wrapped = *uri;
    wrapped.handler  = kd_api_shim_handler;
    wrapped.user_ctx = w;

    esp_err_t r = httpd_register_uri_handler(server, &wrapped);
    if (r == ESP_OK) s_wrap_count++;
    return r;
}

// Forward declarations
static void register_internal_handlers(void);
static void install_err_handlers(void);
static void start_server(void);
static void stop_server_internal(void);

// Runs on the httpd task for every accepted socket: record the task handle
// so stop_server_internal() can tell when it is being called from a handler.
static esp_err_t kd_api_open_fn(httpd_handle_t hd, int sockfd) {
    (void)hd;
    (void)sockfd;
    s_httpd_task = xTaskGetCurrentTaskHandle();
    return ESP_OK;
}

static void server_lock(void) {
    if (s_server_lock) xSemaphoreTake(s_server_lock, portMAX_DELAY);
}

static void server_unlock(void) {
    if (s_server_lock) xSemaphoreGive(s_server_lock);
}

static void start_server(void) {
    server_lock();
    if (s_kd_api_server != NULL) {
        server_unlock();
        return;
    }

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.max_uri_handlers = KD_API_MAX_URI_HANDLERS;
    // Default (8) is tight once CORS + content headers are set on a response.
    config.max_resp_headers = 16;
    config.uri_match_fn = httpd_uri_match_wildcard;
    config.stack_size = CONFIG_KD_COMMON_API_HTTPD_TASK_STACK_SIZE;
    config.open_fn = kd_api_open_fn;
    // Default cap (7) is too tight when a browser opens parallel asset fetches
    // alongside the /api/ws upgrade — accept() starts returning EMFILE. Raise
    // the per-server cap; LWIP_MAX_SOCKETS in sdkconfig must be at least
    // (max_open_sockets + listening + other lwip clients) — we run with 16.
    config.max_open_sockets = 10;
    // When max_open_sockets is reached, close the LRU socket instead of
    // returning EMFILE on the next accept. Browsers reopen idle keep-alives
    // cheaply; WS clients stay because they're newest.
    config.lru_purge_enable = true;

    // Reset before the server task exists so an immediately-accepted
    // connection's open_fn capture is not clobbered afterwards.
    s_httpd_task = NULL;

    esp_err_t ret = httpd_start(&s_kd_api_server, &config);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start httpd: %s", esp_err_to_name(ret));
        s_kd_api_server = NULL;
        server_unlock();
        return;
    }

    ESP_LOGI(TAG, "HTTP server started");

    // Any wraps handed out to the previous server instance are dead with it;
    // recycle the pool for this instance's registrations.
    s_wrap_count = 0;

    // Error-code handlers (404/405/etc) so unmatched requests get CORS too.
    install_err_handlers();

    // Register internal kd_common handlers
    register_internal_handlers();

    // Call all registered external handler registrars
    for (size_t i = 0; i < s_registrar_count; i++) {
        if (s_registrars[i] != NULL) {
            s_registrars[i](s_kd_api_server);
        }
    }
    server_unlock();
}

// One-shot task used when a stop is requested from inside a request handler:
// httpd_stop() blocks until the httpd task exits, which can never happen while
// that task is the one calling it.
static void deferred_stop_task(void* arg) {
    (void)arg;
    stop_server_internal();
    s_stop_deferred = false;
    vTaskDelete(NULL);
}

static void stop_server_internal(void) {
    if (s_kd_api_server == NULL) {
        return;
    }

    // Called from a request handler (i.e. on the httpd task)? Defer to a
    // helper task instead of deadlocking in httpd_stop(). This check is done
    // before taking s_server_lock so the httpd task never blocks on it.
    if (s_httpd_task != NULL && xTaskGetCurrentTaskHandle() == s_httpd_task) {
        if (s_stop_deferred) {
            return;
        }
        s_stop_deferred = true;
        ESP_LOGW(TAG, "Stop requested from the httpd task; deferring");
        if (xTaskCreate(deferred_stop_task, "kd_api_stop", 4096, NULL, 5, NULL) != pdPASS) {
            ESP_LOGE(TAG, "Failed to create deferred stop task");
            s_stop_deferred = false;
        }
        return;
    }

    server_lock();
    if (s_kd_api_server == NULL) {
        server_unlock();
        return;
    }

    // Notify consumers that cached the handle so they can drop it / cancel
    // timers while it is still valid. httpd_stop() frees the handle, so any
    // deferred work (e.g. an esp_timer flush) still holding it would UAF.
    for (size_t i = 0; i < s_stop_hook_count; i++) {
        if (s_stop_hooks[i] != NULL) {
            s_stop_hooks[i]();
        }
    }

    httpd_stop(s_kd_api_server);
    s_kd_api_server = NULL;
    s_httpd_task = NULL;
    ESP_LOGI(TAG, "HTTP server stopped");
    server_unlock();
}

void api_stop_server(void) {
    stop_server_internal();
}

static void api_on_wifi_connect(void) {
    start_server();
}

static void api_on_wifi_disconnect(void) {
    stop_server_internal();
}

static esp_err_t about_handler(httpd_req_t* req) {
    const esp_app_desc_t* app_desc = esp_app_get_description();

    cJSON* json = cJSON_CreateObject();
    if (json == NULL) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    cJSON* model = cJSON_CreateString(kdmdns_get_model() ? kdmdns_get_model() : "unknown");
    cJSON* type = cJSON_CreateString(kdmdns_get_type() ? kdmdns_get_type() : "unknown");
    cJSON* version = cJSON_CreateString(app_desc->version);

    cJSON_AddItemToObject(json, "model", model);
    cJSON_AddItemToObject(json, "type", type);
    cJSON_AddItemToObject(json, "version", version);

    char* json_string = cJSON_PrintUnformatted(json);
    if (json_string == NULL) {
        cJSON_Delete(json);
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json_string, strlen(json_string));

    free(json_string);
    cJSON_Delete(json);

    return ESP_OK;
}

static esp_err_t system_config_get_handler(httpd_req_t* req) {
    // kd_common_get_wifi_hostname() returns a pointer into a file-static cache
    // (wifi.c s_hostname_cache.buffer) — DO NOT free it.
    const char* wifi_hostname = kd_common_get_wifi_hostname();

    cJSON* json = cJSON_CreateObject();
    if (json == NULL) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    cJSON_AddBoolToObject(json, "auto_timezone", kd_common_get_auto_timezone());
    cJSON_AddStringToObject(json, "timezone", kd_common_get_timezone());
    cJSON_AddStringToObject(json, "ntp_server", kd_common_get_ntp_server());
    cJSON_AddStringToObject(json, "wifi_hostname", wifi_hostname ? wifi_hostname : "");

    char* json_string = cJSON_PrintUnformatted(json);
    if (json_string == NULL) {
        cJSON_Delete(json);
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json_string, strlen(json_string));

    free(json_string);
    cJSON_Delete(json);

    return ESP_OK;
}

static esp_err_t system_config_post_handler(httpd_req_t* req) {
    char content[1024];

    // Reject oversized requests (leave room for the terminating NUL).
    if (req->content_len > sizeof(content) - 1) {
        httpd_resp_set_status(req, "413 Payload Too Large");
        httpd_resp_set_type(req, "text/plain");
        httpd_resp_send(req, "Request body too large", HTTPD_RESP_USE_STRLEN);
        return ESP_FAIL;
    }

    // httpd_req_recv() may return fewer bytes than requested; loop until the
    // whole body has arrived.
    size_t received = 0;
    while (received < req->content_len) {
        int ret = httpd_req_recv(req, content + received, req->content_len - received);
        if (ret <= 0) {
            if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
                httpd_resp_send_408(req);
            }
            else {
                httpd_resp_send_500(req);
            }
            return ESP_FAIL;
        }
        received += (size_t)ret;
    }
    content[received] = '\0';

    cJSON* json = cJSON_Parse(content);
    if (json == NULL) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON format");
        return ESP_FAIL;
    }

    cJSON* auto_timezone_json = cJSON_GetObjectItem(json, "auto_timezone");
    cJSON* timezone_json = cJSON_GetObjectItem(json, "timezone");
    cJSON* ntp_server_json = cJSON_GetObjectItem(json, "ntp_server");
    cJSON* wifi_hostname_json = cJSON_GetObjectItem(json, "wifi_hostname");

    if (cJSON_IsBool(auto_timezone_json)) {
        kd_common_set_auto_timezone(cJSON_IsTrue(auto_timezone_json));
    }

    if (cJSON_IsString(timezone_json)) {
        const char* tz_str = cJSON_GetStringValue(timezone_json);
        if (tz_str && strlen(tz_str) < 64) {
            kd_common_set_timezone(tz_str);
        }
    }

    if (cJSON_IsString(ntp_server_json)) {
        const char* ntp_str = cJSON_GetStringValue(ntp_server_json);
        if (ntp_str && strlen(ntp_str) < 64) {
            kd_common_set_ntp_server(ntp_str);
        }
    }

    if (cJSON_IsString(wifi_hostname_json)) {
        const char* hostname_str = cJSON_GetStringValue(wifi_hostname_json);
        if (hostname_str && strlen(hostname_str) > 0 && strlen(hostname_str) <= 63) {
            kd_common_set_wifi_hostname(hostname_str);
        }
    }

    cJSON_Delete(json);

    cJSON* response_json = cJSON_CreateObject();
    cJSON_AddStringToObject(response_json, "status", "success");

    char* response_string = cJSON_PrintUnformatted(response_json);
    if (response_string == NULL) {
        cJSON_Delete(response_json);
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, response_string, strlen(response_string));

    free(response_string);
    cJSON_Delete(response_json);

    return ESP_OK;
}

static esp_err_t time_zones_handler(httpd_req_t* req) {
    const kd_common_tz_entry_t* zones = kd_common_get_all_timezones();
    int total_zones = kd_common_get_timezone_count();

    httpd_resp_set_type(req, "application/json");
    // httpd_resp_send_chunk() adds Transfer-Encoding itself; setting it here
    // too sent the header twice, which strict clients reject.

    // Every send is checked: once the client is gone (or the socket errored)
    // we bail out without the terminal chunk so httpd closes the connection
    // rather than us spinning through the whole zone table.
    if (httpd_resp_send_chunk(req, "[", 1) != ESP_OK) {
        return ESP_FAIL;
    }

    const int CHUNK_SIZE = 20;
    bool first_zone = true;

    for (int chunk_start = 0; chunk_start < total_zones; chunk_start += CHUNK_SIZE) {
        int chunk_end = chunk_start + CHUNK_SIZE;
        if (chunk_end > total_zones) {
            chunk_end = total_zones;
        }

        cJSON* chunk_array = cJSON_CreateArray();
        if (chunk_array == NULL) {
            return ESP_FAIL;
        }

        for (int i = chunk_start; i < chunk_end; i++) {
            cJSON* zone_obj = cJSON_CreateObject();
            if (zone_obj == NULL) continue;

            cJSON_AddStringToObject(zone_obj, "name", zones[i].name);
            cJSON_AddStringToObject(zone_obj, "rule", zones[i].rule);
            cJSON_AddItemToArray(chunk_array, zone_obj);
        }

        char* chunk_string = cJSON_PrintUnformatted(chunk_array);
        if (chunk_string == NULL) {
            cJSON_Delete(chunk_array);
            return ESP_FAIL;
        }

        esp_err_t send_err = ESP_OK;
        size_t chunk_len = strlen(chunk_string);
        if (chunk_len > 2) {
            chunk_string[chunk_len - 1] = '\0';
            char* content = chunk_string + 1;

            if (!first_zone) {
                send_err = httpd_resp_send_chunk(req, ",", 1);
            }
            if (send_err == ESP_OK) {
                send_err = httpd_resp_send_chunk(req, content, strlen(content));
            }
            first_zone = false;
        }

        free(chunk_string);
        cJSON_Delete(chunk_array);

        if (send_err != ESP_OK) {
            ESP_LOGW(TAG, "zonedb chunk send failed: %s", esp_err_to_name(send_err));
            return ESP_FAIL;
        }

        vTaskDelay(pdMS_TO_TICKS(10));
    }

    if (httpd_resp_send_chunk(req, "]", 1) != ESP_OK) {
        return ESP_FAIL;
    }
    if (httpd_resp_send_chunk(req, NULL, 0) != ESP_OK) {
        return ESP_FAIL;
    }

    return ESP_OK;
}

static esp_err_t wildcard_options_handler(httpd_req_t* req) {
    // CORS headers come from the kd_common_api_set_pre_handler() hook —
    // the application registers a single source of truth there. This
    // handler just sends an empty 200 response in reply to the preflight.
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

static void register_internal_handlers(void) {
    // Register our own data routes via the wrapper so the app-installed
    // pre-handler (e.g. CORS) runs on them too.
    static httpd_uri_t about_uri = {
        .uri = "/api/about",
        .method = HTTP_GET,
        .handler = about_handler,
        .user_ctx = NULL
    };
    kd_common_api_register_uri_handler(s_kd_api_server, &about_uri);

    static httpd_uri_t system_config_get_uri = {
        .uri = "/api/system/config",
        .method = HTTP_GET,
        .handler = system_config_get_handler,
        .user_ctx = NULL
    };
    kd_common_api_register_uri_handler(s_kd_api_server, &system_config_get_uri);

    static httpd_uri_t system_config_post_uri = {
        .uri = "/api/system/config",
        .method = HTTP_POST,
        .handler = system_config_post_handler,
        .user_ctx = NULL
    };
    kd_common_api_register_uri_handler(s_kd_api_server, &system_config_post_uri);

    static httpd_uri_t time_zones_uri = {
        .uri = "/api/time/zonedb",
        .method = HTTP_GET,
        .handler = time_zones_handler,
        .user_ctx = NULL
    };
    kd_common_api_register_uri_handler(s_kd_api_server, &time_zones_uri);

    // OPTIONS preflight also goes through the wrapper so CORS headers
    // come from the single pre-handler, not from this handler itself.
    static httpd_uri_t options_uri = {
        .uri = "/api/*",
        .method = HTTP_OPTIONS,
        .handler = wildcard_options_handler,
        .user_ctx = NULL
    };
    kd_common_api_register_uri_handler(s_kd_api_server, &options_uri);
}

// ---------------------------------------------------------------------------
// Error-code handler: ensures 404/405/etc responses ALSO carry CORS headers,
// so browsers don't reject error responses for cross-origin requests. This
// runs INSTEAD of the normal handler path — the pre-handler hook isn't
// invoked for unmatched requests, so we call it manually.
// ---------------------------------------------------------------------------

static esp_err_t kd_api_err_handler(httpd_req_t* req, httpd_err_code_t err) {
    // s_pre_handler is the file-static set by kd_common_api_set_pre_handler.
    if (s_pre_handler) s_pre_handler(req);
    // Use the default ESP-IDF status string for this error code.
    const char* status;
    switch (err) {
        case HTTPD_404_NOT_FOUND:         status = "404 Not Found"; break;
        case HTTPD_405_METHOD_NOT_ALLOWED: status = "405 Method Not Allowed"; break;
        case HTTPD_408_REQ_TIMEOUT:       status = "408 Request Timeout"; break;
        case HTTPD_414_URI_TOO_LONG:      status = "414 URI Too Long"; break;
        case HTTPD_500_INTERNAL_SERVER_ERROR: status = "500 Internal Server Error"; break;
        default:                          status = "400 Bad Request"; break;
    }
    httpd_resp_set_status(req, status);
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_send(req, status, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;   // ESP_OK so the server doesn't abort the connection
}

static void install_err_handlers(void) {
    httpd_register_err_handler(s_kd_api_server, HTTPD_404_NOT_FOUND,         kd_api_err_handler);
    httpd_register_err_handler(s_kd_api_server, HTTPD_405_METHOD_NOT_ALLOWED, kd_api_err_handler);
    httpd_register_err_handler(s_kd_api_server, HTTPD_408_REQ_TIMEOUT,       kd_api_err_handler);
    httpd_register_err_handler(s_kd_api_server, HTTPD_414_URI_TOO_LONG,      kd_api_err_handler);
    httpd_register_err_handler(s_kd_api_server, HTTPD_500_INTERNAL_SERVER_ERROR, kd_api_err_handler);
}

void api_init(void) {
    if (s_server_lock == NULL) {
        s_server_lock = xSemaphoreCreateMutex();
    }
    wifi_on_connect(api_on_wifi_connect);
    wifi_on_disconnect(api_on_wifi_disconnect);
    ESP_LOGI(TAG, "API initialized (waiting for WiFi)");
}

void api_register_handlers(api_handler_registrar_fn registrar) {
    if (registrar == NULL) {
        return;
    }

    if (s_registrar_count >= MAX_REGISTRARS) {
        ESP_LOGE(TAG, "Max handler registrars reached");
        return;
    }

    s_registrars[s_registrar_count++] = registrar;

    // If server is already running, call immediately
    if (s_kd_api_server != NULL) {
        registrar(s_kd_api_server);
    }
}

void api_register_stop_hook(api_stop_hook_fn hook) {
    if (hook == NULL) {
        return;
    }
    if (s_stop_hook_count >= MAX_REGISTRARS) {
        ESP_LOGE(TAG, "Max stop hooks reached");
        return;
    }
    s_stop_hooks[s_stop_hook_count++] = hook;
}

#endif // CONFIG_KD_COMMON_API_ENABLE
