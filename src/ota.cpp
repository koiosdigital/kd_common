#include "ota.h"

#include "esp_https_ota.h"
#include "esp_http_client.h"
#include "esp_crt_bundle.h"
#include "esp_log.h"
#include "esp_app_format.h"
#include "esp_wifi.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "cJSON.h"
#include "kd_common.h"

#include <algorithm>
#include <cstring>
#include <memory>

static const char* TAG = "kd_ota";

namespace {

// Configuration
constexpr uint32_t CHECK_INTERVAL_MS = 12 * 60 * 60 * 1000;  // 12 hours
constexpr uint32_t RETRY_DELAY_MS = 5000;
constexpr uint32_t WIFI_WAIT_MS = 1000;
constexpr size_t RESPONSE_BUFFER_SIZE = 512;
constexpr size_t OTA_BUFFER_SIZE = 4096;

// State
TaskHandle_t task_handle = nullptr;
bool boot_check_completed = false;
bool task_running = false;

// RAII wrapper for cJSON
struct JsonDeleter {
    void operator()(cJSON* json) const {
        if (json) cJSON_Delete(json);
    }
};
using JsonPtr = std::unique_ptr<cJSON, JsonDeleter>;

// RAII wrapper for HTTP client
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
    esp_http_client_handle_t get() const { return handle_; }

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

// Response buffer with automatic reset
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

// Check result enumeration
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

    // Ensure cleanup of URL on all exit paths
    auto url_cleanup = [](const char* p) { if (p) free(const_cast<char*>(p)); };
    std::unique_ptr<const char, decltype(url_cleanup)> url_guard(ota_url, url_cleanup);

    switch (result) {
    case CheckResult::Success:
        ESP_LOGI(TAG, "Up to date");
        boot_check_completed = true;
        return true;

    case CheckResult::UpdateAvailable:
        ESP_LOGI(TAG, "Update available");
        boot_check_completed = true;
        perform_ota_update(ota_url);
        return true;

    case CheckResult::NetworkError:
    case CheckResult::ParseError:
        return false;
    }

    return false;
}

void ota_task_func(void*) {
    // Initial boot check - retry until successful
    while (!boot_check_completed) {
        if (!kd_common_is_wifi_connected()) {
            vTaskDelay(pdMS_TO_TICKS(WIFI_WAIT_MS));
            continue;
        }

        if (perform_update_check()) {
            break;
        }

        vTaskDelay(pdMS_TO_TICKS(RETRY_DELAY_MS));
    }

    // Periodic checks
    while (true) {
        vTaskDelay(pdMS_TO_TICKS(CHECK_INTERVAL_MS));

        if (kd_common_is_wifi_connected()) {
            perform_update_check();
        }
    }
}

}  // namespace

void ota_init() {
    if (task_running) {
        return;
    }

    task_running = true;

    if (xTaskCreate(ota_task_func, "ota", 8192, nullptr, 5, &task_handle) != pdPASS) {
        ESP_LOGE(TAG, "Failed to create task");
        task_running = false;
    }
}

bool ota_has_completed_boot_check() {
    return boot_check_completed;
}
