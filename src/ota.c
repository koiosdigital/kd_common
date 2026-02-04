// OTA - Event-driven firmware update checking with esp_timer
#include "ota.h"

#include <esp_https_ota.h>
#include <esp_http_client.h>
#include <esp_crt_bundle.h>
#include <esp_log.h>
#include <esp_app_format.h>
#include <esp_timer.h>
#include <esp_event.h>
#include <esp_netif.h>

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include <cJSON.h>
#include "kd_common.h"
#include "ntp.h"

#include <stdatomic.h>
#include <string.h>
#include <stdlib.h>

static const char* TAG = "kd_ota";

//------------------------------------------------------------------------------
// Configuration
//------------------------------------------------------------------------------

#define CHECK_INTERVAL_US       (12LL * 60 * 60 * 1000 * 1000)  // 12 hours in microseconds
#define RETRY_DELAY_MS          5000
#define RESPONSE_BUFFER_SIZE    512
#define OTA_BUFFER_SIZE         4096
#define OTA_TASK_STACK_SIZE     8192
#define OTA_TASK_PRIORITY       5
#define MAX_BOOT_CHECK_RETRIES  3

//------------------------------------------------------------------------------
// State
//------------------------------------------------------------------------------

static atomic_bool s_boot_check_completed = false;
static atomic_bool s_boot_check_pending = true;
static atomic_bool s_check_in_progress = false;
static atomic_int s_boot_check_retries = 0;
static esp_timer_handle_t s_periodic_timer = NULL;

//------------------------------------------------------------------------------
// Response buffer for HTTP
//------------------------------------------------------------------------------

typedef struct {
    char data[RESPONSE_BUFFER_SIZE];
    size_t len;
} response_buffer_t;

static void response_buffer_reset(response_buffer_t* buf) {
    buf->len = 0;
    buf->data[0] = '\0';
}

static void response_buffer_append(response_buffer_t* buf, const void* src, size_t src_len) {
    size_t available = sizeof(buf->data) - buf->len - 1;
    size_t to_copy = (available < src_len) ? available : src_len;
    if (to_copy > 0) {
        memcpy(buf->data + buf->len, src, to_copy);
        buf->len += to_copy;
        buf->data[buf->len] = '\0';
    }
}

//------------------------------------------------------------------------------
// HTTP Event Handler
//------------------------------------------------------------------------------

static esp_err_t http_event_handler(esp_http_client_event_t* evt) {
    if (!evt || !evt->user_data) {
        return ESP_OK;
    }

    response_buffer_t* buffer = (response_buffer_t*)evt->user_data;

    switch (evt->event_id) {
    case HTTP_EVENT_ON_CONNECTED:
        response_buffer_reset(buffer);
        break;
    case HTTP_EVENT_ON_DATA:
        if (evt->data && evt->data_len > 0) {
            response_buffer_append(buffer, evt->data, evt->data_len);
        }
        break;
    default:
        break;
    }

    return ESP_OK;
}

//------------------------------------------------------------------------------
// Update Check Logic
//------------------------------------------------------------------------------

typedef enum {
    CHECK_RESULT_SUCCESS,
    CHECK_RESULT_UPDATE_AVAILABLE,
    CHECK_RESULT_NETWORK_ERROR,
    CHECK_RESULT_PARSE_ERROR
} check_result_t;

static check_result_t check_for_update(const char** out_url) {
    *out_url = NULL;

    response_buffer_t response = {0};

    esp_http_client_config_t config = {
        .url = FIRMWARE_ENDPOINT_URL,
        .event_handler = http_event_handler,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .user_data = &response
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) {
        ESP_LOGD(TAG, "Failed to init HTTP client");
        return CHECK_RESULT_NETWORK_ERROR;
    }

    const esp_app_desc_t* app_desc = esp_app_get_description();
    esp_http_client_set_header(client, "x-firmware-project", app_desc->project_name);
    esp_http_client_set_header(client, "x-firmware-version", app_desc->version);

#ifdef FIRMWARE_VARIANT
    esp_http_client_set_header(client, "x-firmware-variant", FIRMWARE_VARIANT);
#endif

    esp_err_t err = esp_http_client_perform(client);
    int status_code = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);

    if (err != ESP_OK || status_code != 200) {
        ESP_LOGD(TAG, "HTTP request failed (status: %d)", status_code);
        return CHECK_RESULT_NETWORK_ERROR;
    }

    cJSON* root = cJSON_Parse(response.data);
    if (!root) {
        ESP_LOGD(TAG, "Failed to parse response");
        return CHECK_RESULT_PARSE_ERROR;
    }

    // Apply timezone from OTA response if present (merged TZ API)
    cJSON* tz_item = cJSON_GetObjectItem(root, "tzname");
    if (tz_item && cJSON_IsString(tz_item) && tz_item->valuestring && tz_item->valuestring[0]) {
        ntp_apply_timezone(tz_item->valuestring);
    }

    cJSON* update_item = cJSON_GetObjectItem(root, "update_available");
    if (!update_item) {
        ESP_LOGD(TAG, "Missing update_available field");
        cJSON_Delete(root);
        return CHECK_RESULT_PARSE_ERROR;
    }

    if (cJSON_IsFalse(update_item)) {
        cJSON_Delete(root);
        return CHECK_RESULT_SUCCESS;
    }

    cJSON* url_item = cJSON_GetObjectItem(root, "ota_url");
    if (!url_item || !cJSON_IsString(url_item) || !url_item->valuestring || !url_item->valuestring[0]) {
        ESP_LOGW(TAG, "Update available but no valid URL");
        cJSON_Delete(root);
        return CHECK_RESULT_SUCCESS;
    }

    *out_url = strdup(url_item->valuestring);
    cJSON_Delete(root);
    return *out_url ? CHECK_RESULT_UPDATE_AVAILABLE : CHECK_RESULT_SUCCESS;
}

static bool perform_ota_update(const char* url) {
    ESP_LOGI(TAG, "Downloading update...");

    esp_http_client_config_t http_config = {
        .url = url,
        .buffer_size = OTA_BUFFER_SIZE,
        .buffer_size_tx = OTA_BUFFER_SIZE,
        .crt_bundle_attach = esp_crt_bundle_attach
    };

    esp_https_ota_config_t ota_config = {
        .http_config = &http_config
    };

    esp_err_t err = esp_https_ota(&ota_config);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Update failed: %s", esp_err_to_name(err));
        return false;
    }

    ESP_LOGI(TAG, "Update complete, restarting...");
    esp_restart();
    return true;  // Never reached
}

static bool perform_update_check(void) {
    const char* ota_url = NULL;
    check_result_t result = check_for_update(&ota_url);

    bool success = false;

    switch (result) {
    case CHECK_RESULT_SUCCESS:
        ESP_LOGI(TAG, "Up to date");
        success = true;
        break;

    case CHECK_RESULT_UPDATE_AVAILABLE:
        ESP_LOGI(TAG, "Update available");
        perform_ota_update(ota_url);
        success = true;
        break;

    case CHECK_RESULT_NETWORK_ERROR:
    case CHECK_RESULT_PARSE_ERROR:
        success = false;
        break;
    }

    if (ota_url) {
        free((void*)ota_url);
    }

    return success;
}

//------------------------------------------------------------------------------
// One-shot Check Task (spawned on demand, self-deletes)
//------------------------------------------------------------------------------

static void ota_check_task(void* arg) {
    bool is_boot_check = (uintptr_t)arg != 0;

    bool success = perform_update_check();

    if (is_boot_check) {
        if (success) {
            atomic_store(&s_boot_check_completed, true);
            atomic_store(&s_boot_check_pending, false);

            // Start periodic timer now that boot check is done
            if (s_periodic_timer) {
                esp_timer_start_periodic(s_periodic_timer, CHECK_INTERVAL_US);
                ESP_LOGI(TAG, "Started periodic update timer (12h)");
            }
        }
        else {
            int retries = atomic_fetch_add(&s_boot_check_retries, 1) + 1;
            if (retries >= MAX_BOOT_CHECK_RETRIES) {
                // Give up after max retries, allow normal execution to proceed
                ESP_LOGW(TAG, "Boot check failed after %d retries, giving up", retries);
                atomic_store(&s_boot_check_completed, true);
                atomic_store(&s_boot_check_pending, false);

                // Start periodic timer anyway
                if (s_periodic_timer) {
                    esp_timer_start_periodic(s_periodic_timer, CHECK_INTERVAL_US);
                    ESP_LOGI(TAG, "Started periodic update timer (12h)");
                }
            }
            else {
                ESP_LOGW(TAG, "Boot check failed (attempt %d/%d), will retry",
                    retries, MAX_BOOT_CHECK_RETRIES);
            }
        }
    }

    atomic_store(&s_check_in_progress, false);

    vTaskDelete(NULL);  // Self-delete
}

static void spawn_check_task(bool is_boot_check) {
    bool expected = false;
    if (!atomic_compare_exchange_strong(&s_check_in_progress, &expected, true)) {
        return;  // Already running
    }

    uintptr_t arg = is_boot_check ? 1 : 0;

    if (xTaskCreate(ota_check_task, "ota_check", OTA_TASK_STACK_SIZE,
        (void*)arg, OTA_TASK_PRIORITY, NULL) != pdPASS) {
        ESP_LOGE(TAG, "Failed to create OTA check task");
        atomic_store(&s_check_in_progress, false);
    }
}

//------------------------------------------------------------------------------
// Timer Callback
//------------------------------------------------------------------------------

static void timer_callback(void* arg) {
    (void)arg;
    if (kd_common_is_wifi_connected()) {
        spawn_check_task(false);  // Not a boot check
    }
}

//------------------------------------------------------------------------------
// IP Event Handler
//------------------------------------------------------------------------------

static void ip_event_handler(void* arg, esp_event_base_t base, int32_t event_id, void* event_data) {
    (void)arg;
    (void)base;
    (void)event_data;

    if (event_id == IP_EVENT_STA_GOT_IP) {
        if (atomic_load(&s_boot_check_pending)) {
            ESP_LOGI(TAG, "Got IP, starting boot check");
            spawn_check_task(true);  // Boot check
        }
    }
}

//------------------------------------------------------------------------------
// Public API
//------------------------------------------------------------------------------

void ota_init(void) {
    // Create periodic timer (initially stopped)
    esp_timer_create_args_t timer_args = {
        .callback = timer_callback,
        .arg = NULL,
        .dispatch_method = ESP_TIMER_TASK,
        .name = "ota_periodic",
        .skip_unhandled_events = true,
    };

    esp_err_t err = esp_timer_create(&timer_args, &s_periodic_timer);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to create timer: %s", esp_err_to_name(err));
    }

    // Register for IP events to trigger boot check
    esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
        ip_event_handler, NULL);

    ESP_LOGI(TAG, "Initialized (event-driven)");
}

bool ota_has_completed_boot_check(void) {
    return atomic_load(&s_boot_check_completed);
}

void ota_check_now(void) {
    if (kd_common_is_wifi_connected()) {
        spawn_check_task(false);
    }
}
