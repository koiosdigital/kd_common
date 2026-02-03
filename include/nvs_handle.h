// C++ RAII wrapper for NVS operations
// For C code, use nvs_helper.h in src/include instead
#pragma once

#include <nvs_flash.h>
#include <esp_err.h>
#include <string.h>

namespace kd {

/**
 * RAII wrapper for NVS handle with convenient typed accessors.
 * Usage:
 *   NvsHandle nvs("my_namespace", NVS_READWRITE);
 *   if (nvs) {
 *       nvs.set_u32("key", value);
 *       nvs.commit();
 *   }
 */
class NvsHandle {
public:
    NvsHandle(const char* ns, nvs_open_mode_t mode)
        : handle_(0), open_err_(ESP_OK) {
        open_err_ = nvs_open(ns, mode, &handle_);
    }

    ~NvsHandle() {
        if (handle_ != 0) {
            nvs_close(handle_);
        }
    }

    // Non-copyable
    NvsHandle(const NvsHandle&) = delete;
    NvsHandle& operator=(const NvsHandle&) = delete;

    // Check if handle is valid
    explicit operator bool() const { return open_err_ == ESP_OK && handle_ != 0; }

    esp_err_t open_error() const { return open_err_; }

    // Commit changes
    esp_err_t commit() {
        if (!*this) return ESP_ERR_INVALID_STATE;
        return nvs_commit(handle_);
    }

    // Check if key exists
    esp_err_t find_key(const char* key) {
        if (!*this) return ESP_ERR_INVALID_STATE;
        nvs_type_t type;
        return nvs_find_key(handle_, key, &type);
    }

    // Erase a key
    esp_err_t erase_key(const char* key) {
        if (!*this) return ESP_ERR_INVALID_STATE;
        return nvs_erase_key(handle_, key);
    }

    // Getters
    esp_err_t get_u8(const char* key, uint8_t* value) {
        if (!*this) return ESP_ERR_INVALID_STATE;
        return nvs_get_u8(handle_, key, value);
    }

    esp_err_t get_u16(const char* key, uint16_t* value) {
        if (!*this) return ESP_ERR_INVALID_STATE;
        return nvs_get_u16(handle_, key, value);
    }

    esp_err_t get_u32(const char* key, uint32_t* value) {
        if (!*this) return ESP_ERR_INVALID_STATE;
        return nvs_get_u32(handle_, key, value);
    }

    esp_err_t get_i32(const char* key, int32_t* value) {
        if (!*this) return ESP_ERR_INVALID_STATE;
        return nvs_get_i32(handle_, key, value);
    }

    esp_err_t get_str(const char* key, char* buffer, size_t* len) {
        if (!*this) return ESP_ERR_INVALID_STATE;
        return nvs_get_str(handle_, key, buffer, len);
    }

    esp_err_t get_blob(const char* key, void* buffer, size_t* len) {
        if (!*this) return ESP_ERR_INVALID_STATE;
        return nvs_get_blob(handle_, key, buffer, len);
    }

    // Setters
    esp_err_t set_u8(const char* key, uint8_t value) {
        if (!*this) return ESP_ERR_INVALID_STATE;
        return nvs_set_u8(handle_, key, value);
    }

    esp_err_t set_u16(const char* key, uint16_t value) {
        if (!*this) return ESP_ERR_INVALID_STATE;
        return nvs_set_u16(handle_, key, value);
    }

    esp_err_t set_u32(const char* key, uint32_t value) {
        if (!*this) return ESP_ERR_INVALID_STATE;
        return nvs_set_u32(handle_, key, value);
    }

    esp_err_t set_i32(const char* key, int32_t value) {
        if (!*this) return ESP_ERR_INVALID_STATE;
        return nvs_set_i32(handle_, key, value);
    }

    esp_err_t set_str(const char* key, const char* value) {
        if (!*this) return ESP_ERR_INVALID_STATE;
        return nvs_set_str(handle_, key, value);
    }

    esp_err_t set_blob(const char* key, const void* data, size_t len) {
        if (!*this) return ESP_ERR_INVALID_STATE;
        return nvs_set_blob(handle_, key, data, len);
    }

private:
    nvs_handle_t handle_;
    esp_err_t open_err_;
};

} // namespace kd
