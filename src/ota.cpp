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

#include <algorithm>
#include <atomic>
#include <cstring>
#include <memory>

static const char* TAG = "kd_ota";

namespace {

//------------------------------------------------------------------------------
// Configuration
//------------------------------------------------------------------------------

constexpr int64_t CHECK_INTERVAL_US = 12LL * 60 * 60 * 1000 * 1000;  // 12 hours in microseconds
constexpr uint32_t RETRY_DELAY_MS = 5000;
constexpr size_t RESPONSE_BUFFER_SIZE = 512;
constexpr size_t OTA_BUFFER_SIZE = 4096;
constexpr size_t OTA_TASK_STACK_SIZE = 8192;
constexpr UBaseType_t OTA_TASK_PRIORITY = 5;

//------------------------------------------------------------------------------
// State
//------------------------------------------------------------------------------

std::atomic<bool> boot_check_completed{false};
std::atomic<bool> boot_check_pending{true};
std::atomic<bool> check_in_progress{false};
std::atomic<int> boot_check_retries{0};
constexpr int MAX_BOOT_CHECK_RETRIES = 3;
esp_timer_handle_t periodic_timer = nullptr;

//------------------------------------------------------------------------------
// RAII Helpers (unchanged from original)
//------------------------------------------------------------------------------

struct JsonDeleter {
    void operator()(cJSON* json) const {
        if (json) cJSON_Delete(json);
    }
};
using JsonPtr = std::unique_ptr<cJSON, JsonDeleter>;

class HttpClient {
public:
    explicit HttpClient(const esp_http_client_config_t* config)
        : handle_(esp_http_client_init(config)) {}

    ~HttpClient() {
        if (handle_) {
            esp_http_client_cleanup(handle_);
        }
    }

    HttpClient(const HttpClient&) = delete;
    HttpClient& operator=(const HttpClient&) = delete;

    explicit operator bool() const { return handle_ != nullptr; }

    esp_err_t set_header(const char* key, const char* value) {
        return esp_http_client_set_header(handle_, key, value);
    }

    esp_err_t perform() {
        return esp_http_client_perform(handle_);
    }

    int get_status_code() const {
        return esp_http_client_get_status_code(handle_);
    }

private:
    esp_http_client_handle_t handle_;
};

struct ResponseBuffer {
    char data[RESPONSE_BUFFER_SIZE] = {};
    size_t len = 0;

    void reset() {
        len = 0;
        data[0] = '\0';
    }

    void append(const void* src, size_t src_len) {
        const size_t available = sizeof(data) - len - 1;
        const size_t to_copy = std::min(available, src_len);
        if (to_copy > 0) {
            std::memcpy(data + len, src, to_copy);
            len += to_copy;
            data[len] = '\0';
        }
    }
};

//------------------------------------------------------------------------------
// HTTP Event Handler
//------------------------------------------------------------------------------

esp_err_t http_event_handler(esp_http_client_event_t* evt) {
    if (!evt || !evt->user_data) {
        return ESP_OK;
    }

    auto* buffer = static_cast<ResponseBuffer*>(evt->user_data);

    switch (evt->event_id) {
    case HTTP_EVENT_ON_CONNECTED:
        buffer->reset();
        break;
    case HTTP_EVENT_ON_DATA:
        if (evt->data && evt->data_len > 0) {
            buffer->append(evt->data, evt->data_len);
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

enum class CheckResult {
    Success,
    UpdateAvailable,
    NetworkError,
    ParseError
};

CheckResult check_for_update(const char** out_url) {
    *out_url = nullptr;

    ResponseBuffer response;

    esp_http_client_config_t config = {};
    config.url = FIRMWARE_ENDPOINT_URL;
    config.event_handler = http_event_handler;
    config.crt_bundle_attach = esp_crt_bundle_attach;
    config.user_data = &response;

    HttpClient client(&config);
    if (!client) {
        ESP_LOGD(TAG, "Failed to init HTTP client");
        return CheckResult::NetworkError;
    }

    const esp_app_desc_t* app_desc = esp_app_get_description();
    client.set_header("x-firmware-project", app_desc->project_name);
    client.set_header("x-firmware-version", app_desc->version);

#ifdef FIRMWARE_VARIANT
    client.set_header("x-firmware-variant", FIRMWARE_VARIANT);
#endif

    if (client.perform() != ESP_OK || client.get_status_code() != 200) {
        ESP_LOGD(TAG, "HTTP request failed (status: %d)", client.get_status_code());
        return CheckResult::NetworkError;
    }

    JsonPtr root(cJSON_Parse(response.data));
    if (!root) {
        ESP_LOGD(TAG, "Failed to parse response");
        return CheckResult::ParseError;
    }

    cJSON* update_item = cJSON_GetObjectItem(root.get(), "update_available");
    if (!update_item) {
        ESP_LOGD(TAG, "Missing update_available field");
        return CheckResult::ParseError;
    }

    if (cJSON_IsFalse(update_item)) {
        return CheckResult::Success;
    }

    cJSON* url_item = cJSON_GetObjectItem(root.get(), "ota_url");
    if (!url_item || !cJSON_IsString(url_item) || !url_item->valuestring || !url_item->valuestring[0]) {
        ESP_LOGW(TAG, "Update available but no valid URL");
        return CheckResult::Success;
    }

    *out_url = strdup(url_item->valuestring);
    return *out_url ? CheckResult::UpdateAvailable : CheckResult::Success;
}

bool perform_ota_update(const char* url) {
    ESP_LOGI(TAG, "Downloading update...");

    esp_http_client_config_t http_config = {};
    http_config.url = url;
    http_config.buffer_size = OTA_BUFFER_SIZE;
    http_config.buffer_size_tx = OTA_BUFFER_SIZE;
    http_config.crt_bundle_attach = esp_crt_bundle_attach;

    esp_https_ota_config_t ota_config = {};
    ota_config.http_config = &http_config;

    esp_err_t err = esp_https_ota(&ota_config);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Update failed: %s", esp_err_to_name(err));
        return false;
    }

    ESP_LOGI(TAG, "Update complete, restarting...");
    esp_restart();
    return true;  // Never reached
}

bool perform_update_check() {
    const char* ota_url = nullptr;
    CheckResult result = check_for_update(&ota_url);

    auto url_cleanup = [](const char* p) { if (p) free(const_cast<char*>(p)); };
    std::unique_ptr<const char, decltype(url_cleanup)> url_guard(ota_url, url_cleanup);

    switch (result) {
    case CheckResult::Success:
        ESP_LOGI(TAG, "Up to date");
        return true;

    case CheckResult::UpdateAvailable:
        ESP_LOGI(TAG, "Update available");
        perform_ota_update(ota_url);
        return true;

    case CheckResult::NetworkError:
    case CheckResult::ParseError:
        return false;
    }

    return false;
}

//------------------------------------------------------------------------------
// One-shot Check Task (spawned on demand, self-deletes)
//------------------------------------------------------------------------------

void ota_check_task(void* arg) {
    bool is_boot_check = reinterpret_cast<uintptr_t>(arg) != 0;

    bool success = perform_update_check();

    if (is_boot_check) {
        if (success) {
            boot_check_completed.store(true);
            boot_check_pending.store(false);

            // Start periodic timer now that boot check is done
            if (periodic_timer) {
                esp_timer_start_periodic(periodic_timer, CHECK_INTERVAL_US);
                ESP_LOGI(TAG, "Started periodic update timer (12h)");
            }
        } else {
            int retries = boot_check_retries.fetch_add(1) + 1;
            if (retries >= MAX_BOOT_CHECK_RETRIES) {
                // Give up after max retries, allow normal execution to proceed
                ESP_LOGW(TAG, "Boot check failed after %d retries, giving up", retries);
                boot_check_completed.store(true);
                boot_check_pending.store(false);

                // Start periodic timer anyway
                if (periodic_timer) {
                    esp_timer_start_periodic(periodic_timer, CHECK_INTERVAL_US);
                    ESP_LOGI(TAG, "Started periodic update timer (12h)");
                }
            } else {
                ESP_LOGW(TAG, "Boot check failed (attempt %d/%d), will retry",
                         retries, MAX_BOOT_CHECK_RETRIES);
            }
        }
    }

    check_in_progress.store(false);
    vTaskDelete(nullptr);  // Self-delete
}

void spawn_check_task(bool is_boot_check) {
    if (check_in_progress.exchange(true)) {
        return;  // Already running
    }

    uintptr_t arg = is_boot_check ? 1 : 0;

    if (xTaskCreate(ota_check_task, "ota_check", OTA_TASK_STACK_SIZE,
                    reinterpret_cast<void*>(arg), OTA_TASK_PRIORITY, nullptr) != pdPASS) {
        ESP_LOGE(TAG, "Failed to create OTA check task");
        check_in_progress.store(false);
    }
}

//------------------------------------------------------------------------------
// Timer Callback
//------------------------------------------------------------------------------

void timer_callback(void*) {
    if (kd_common_is_wifi_connected()) {
        spawn_check_task(false);  // Not a boot check
    }
}

//------------------------------------------------------------------------------
// IP Event Handler
//------------------------------------------------------------------------------

void ip_event_handler(void*, esp_event_base_t, int32_t event_id, void*) {
    if (event_id == IP_EVENT_STA_GOT_IP) {
        if (boot_check_pending.load()) {
            ESP_LOGI(TAG, "Got IP, starting boot check");
            spawn_check_task(true);  // Boot check
        }
    }
}

}  // namespace

//------------------------------------------------------------------------------
// Public API
//------------------------------------------------------------------------------

void ota_init() {
    // Create periodic timer (initially stopped)
    esp_timer_create_args_t timer_args = {
        .callback = timer_callback,
        .arg = nullptr,
        .dispatch_method = ESP_TIMER_TASK,
        .name = "ota_periodic",
        .skip_unhandled_events = true,
    };

    esp_err_t err = esp_timer_create(&timer_args, &periodic_timer);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to create timer: %s", esp_err_to_name(err));
    }

    // Register for IP events to trigger boot check
    esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                               ip_event_handler, nullptr);

    ESP_LOGI(TAG, "Initialized (event-driven)");
}

bool ota_has_completed_boot_check() {
    return boot_check_completed.load();
}

void ota_check_now() {
    if (kd_common_is_wifi_connected()) {
        spawn_check_task(false);
    }
}
