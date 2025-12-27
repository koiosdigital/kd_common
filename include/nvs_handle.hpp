#pragma once

#include <nvs_flash.h>
#include <esp_log.h>

namespace kd {

// RAII wrapper for NVS handle
// Automatically closes handle on destruction, eliminating goto cleanup patterns
class NvsHandle {
public:
    NvsHandle(const char* ns, nvs_open_mode_t mode)
        : namespace_(ns) {
        err_ = nvs_open(ns, mode, &handle_);
        valid_ = (err_ == ESP_OK);
    }

    ~NvsHandle() {
        if (valid_) {
            nvs_close(handle_);
        }
    }

    // Non-copyable
    NvsHandle(const NvsHandle&) = delete;
    NvsHandle& operator=(const NvsHandle&) = delete;

    // Moveable
    NvsHandle(NvsHandle&& other) noexcept
        : handle_(other.handle_)
        , valid_(other.valid_)
        , err_(other.err_)
        , namespace_(other.namespace_) {
        other.valid_ = false;
    }

    NvsHandle& operator=(NvsHandle&& other) noexcept {
        if (this != &other) {
            if (valid_) {
                nvs_close(handle_);
            }
            handle_ = other.handle_;
            valid_ = other.valid_;
            err_ = other.err_;
            namespace_ = other.namespace_;
            other.valid_ = false;
        }
        return *this;
    }

    explicit operator bool() const { return valid_; }
    nvs_handle_t get() const { return handle_; }
    esp_err_t open_error() const { return err_; }

    // Key existence check
    esp_err_t find_key(const char* key) {
        if (!valid_) return ESP_ERR_INVALID_STATE;
        return nvs_find_key(handle_, key, nullptr);
    }

    // Blob operations
    esp_err_t get_blob(const char* key, void* buffer, size_t* len) {
        if (!valid_) return ESP_ERR_INVALID_STATE;
        return nvs_get_blob(handle_, key, buffer, len);
    }

    esp_err_t set_blob(const char* key, const void* data, size_t len) {
        if (!valid_) return ESP_ERR_INVALID_STATE;
        return nvs_set_blob(handle_, key, data, len);
    }

    // String operations
    esp_err_t get_str(const char* key, char* buffer, size_t* len) {
        if (!valid_) return ESP_ERR_INVALID_STATE;
        return nvs_get_str(handle_, key, buffer, len);
    }

    esp_err_t set_str(const char* key, const char* value) {
        if (!valid_) return ESP_ERR_INVALID_STATE;
        return nvs_set_str(handle_, key, value);
    }

    // Integer operations
    esp_err_t get_u8(const char* key, uint8_t* value) {
        if (!valid_) return ESP_ERR_INVALID_STATE;
        return nvs_get_u8(handle_, key, value);
    }

    esp_err_t set_u8(const char* key, uint8_t value) {
        if (!valid_) return ESP_ERR_INVALID_STATE;
        return nvs_set_u8(handle_, key, value);
    }

    esp_err_t get_u16(const char* key, uint16_t* value) {
        if (!valid_) return ESP_ERR_INVALID_STATE;
        return nvs_get_u16(handle_, key, value);
    }

    esp_err_t set_u16(const char* key, uint16_t value) {
        if (!valid_) return ESP_ERR_INVALID_STATE;
        return nvs_set_u16(handle_, key, value);
    }

    // Erase operations
    esp_err_t erase_key(const char* key) {
        if (!valid_) return ESP_ERR_INVALID_STATE;
        return nvs_erase_key(handle_, key);
    }

    // Commit changes
    esp_err_t commit() {
        if (!valid_) return ESP_ERR_INVALID_STATE;
        return nvs_commit(handle_);
    }

private:
    nvs_handle_t handle_ = 0;
    bool valid_ = false;
    esp_err_t err_ = ESP_FAIL;
    const char* namespace_ = nullptr;
};

}  // namespace kd
