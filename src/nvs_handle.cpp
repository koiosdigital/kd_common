#include "nvs_handle.h"

namespace kd {

NvsHandle::NvsHandle(const char* ns, nvs_open_mode_t mode)
    : namespace_(ns) {
    err_ = nvs_open(ns, mode, &handle_);
    valid_ = (err_ == ESP_OK);
}

NvsHandle::~NvsHandle() {
    if (valid_) {
        nvs_close(handle_);
    }
}

NvsHandle::NvsHandle(NvsHandle&& other) noexcept
    : handle_(other.handle_)
    , valid_(other.valid_)
    , err_(other.err_)
    , namespace_(other.namespace_) {
    other.valid_ = false;
}

NvsHandle& NvsHandle::operator=(NvsHandle&& other) noexcept {
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

NvsHandle::operator bool() const {
    return valid_;
}

nvs_handle_t NvsHandle::get() const {
    return handle_;
}

esp_err_t NvsHandle::open_error() const {
    return err_;
}

esp_err_t NvsHandle::find_key(const char* key) {
    if (!valid_) return ESP_ERR_INVALID_STATE;
    return nvs_find_key(handle_, key, nullptr);
}

esp_err_t NvsHandle::get_blob(const char* key, void* buffer, size_t* len) {
    if (!valid_) return ESP_ERR_INVALID_STATE;
    return nvs_get_blob(handle_, key, buffer, len);
}

esp_err_t NvsHandle::set_blob(const char* key, const void* data, size_t len) {
    if (!valid_) return ESP_ERR_INVALID_STATE;
    return nvs_set_blob(handle_, key, data, len);
}

esp_err_t NvsHandle::get_str(const char* key, char* buffer, size_t* len) {
    if (!valid_) return ESP_ERR_INVALID_STATE;
    return nvs_get_str(handle_, key, buffer, len);
}

esp_err_t NvsHandle::set_str(const char* key, const char* value) {
    if (!valid_) return ESP_ERR_INVALID_STATE;
    return nvs_set_str(handle_, key, value);
}

esp_err_t NvsHandle::get_u8(const char* key, uint8_t* value) {
    if (!valid_) return ESP_ERR_INVALID_STATE;
    return nvs_get_u8(handle_, key, value);
}

esp_err_t NvsHandle::set_u8(const char* key, uint8_t value) {
    if (!valid_) return ESP_ERR_INVALID_STATE;
    return nvs_set_u8(handle_, key, value);
}

esp_err_t NvsHandle::get_u16(const char* key, uint16_t* value) {
    if (!valid_) return ESP_ERR_INVALID_STATE;
    return nvs_get_u16(handle_, key, value);
}

esp_err_t NvsHandle::set_u16(const char* key, uint16_t value) {
    if (!valid_) return ESP_ERR_INVALID_STATE;
    return nvs_set_u16(handle_, key, value);
}

esp_err_t NvsHandle::get_u32(const char* key, uint32_t* value) {
    if (!valid_) return ESP_ERR_INVALID_STATE;
    return nvs_get_u32(handle_, key, value);
}

esp_err_t NvsHandle::set_u32(const char* key, uint32_t value) {
    if (!valid_) return ESP_ERR_INVALID_STATE;
    return nvs_set_u32(handle_, key, value);
}

esp_err_t NvsHandle::get_i32(const char* key, int32_t* value) {
    if (!valid_) return ESP_ERR_INVALID_STATE;
    return nvs_get_i32(handle_, key, value);
}

esp_err_t NvsHandle::set_i32(const char* key, int32_t value) {
    if (!valid_) return ESP_ERR_INVALID_STATE;
    return nvs_set_i32(handle_, key, value);
}

esp_err_t NvsHandle::erase_key(const char* key) {
    if (!valid_) return ESP_ERR_INVALID_STATE;
    return nvs_erase_key(handle_, key);
}

esp_err_t NvsHandle::commit() {
    if (!valid_) return ESP_ERR_INVALID_STATE;
    return nvs_commit(handle_);
}

}  // namespace kd
