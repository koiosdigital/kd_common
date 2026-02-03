#include "nvs_helper.h"

nvs_helper_t nvs_helper_open(const char* ns, nvs_open_mode_t mode) {
    nvs_helper_t nvs = {0};
    nvs.open_err = nvs_open(ns, mode, &nvs.handle);
    nvs.valid = (nvs.open_err == ESP_OK);
    return nvs;
}

void nvs_helper_close(nvs_helper_t* nvs) {
    if (nvs && nvs->valid) {
        nvs_close(nvs->handle);
        nvs->valid = false;
    }
}

esp_err_t nvs_helper_find_key(nvs_helper_t* nvs, const char* key) {
    if (!nvs || !nvs->valid) return ESP_ERR_INVALID_STATE;
    return nvs_find_key(nvs->handle, key, NULL);
}

esp_err_t nvs_helper_get_blob(nvs_helper_t* nvs, const char* key, void* buffer, size_t* len) {
    if (!nvs || !nvs->valid) return ESP_ERR_INVALID_STATE;
    return nvs_get_blob(nvs->handle, key, buffer, len);
}

esp_err_t nvs_helper_set_blob(nvs_helper_t* nvs, const char* key, const void* data, size_t len) {
    if (!nvs || !nvs->valid) return ESP_ERR_INVALID_STATE;
    return nvs_set_blob(nvs->handle, key, data, len);
}

esp_err_t nvs_helper_get_str(nvs_helper_t* nvs, const char* key, char* buffer, size_t* len) {
    if (!nvs || !nvs->valid) return ESP_ERR_INVALID_STATE;
    return nvs_get_str(nvs->handle, key, buffer, len);
}

esp_err_t nvs_helper_set_str(nvs_helper_t* nvs, const char* key, const char* value) {
    if (!nvs || !nvs->valid) return ESP_ERR_INVALID_STATE;
    return nvs_set_str(nvs->handle, key, value);
}

esp_err_t nvs_helper_get_u8(nvs_helper_t* nvs, const char* key, uint8_t* value) {
    if (!nvs || !nvs->valid) return ESP_ERR_INVALID_STATE;
    return nvs_get_u8(nvs->handle, key, value);
}

esp_err_t nvs_helper_set_u8(nvs_helper_t* nvs, const char* key, uint8_t value) {
    if (!nvs || !nvs->valid) return ESP_ERR_INVALID_STATE;
    return nvs_set_u8(nvs->handle, key, value);
}

esp_err_t nvs_helper_get_u16(nvs_helper_t* nvs, const char* key, uint16_t* value) {
    if (!nvs || !nvs->valid) return ESP_ERR_INVALID_STATE;
    return nvs_get_u16(nvs->handle, key, value);
}

esp_err_t nvs_helper_set_u16(nvs_helper_t* nvs, const char* key, uint16_t value) {
    if (!nvs || !nvs->valid) return ESP_ERR_INVALID_STATE;
    return nvs_set_u16(nvs->handle, key, value);
}

esp_err_t nvs_helper_get_u32(nvs_helper_t* nvs, const char* key, uint32_t* value) {
    if (!nvs || !nvs->valid) return ESP_ERR_INVALID_STATE;
    return nvs_get_u32(nvs->handle, key, value);
}

esp_err_t nvs_helper_set_u32(nvs_helper_t* nvs, const char* key, uint32_t value) {
    if (!nvs || !nvs->valid) return ESP_ERR_INVALID_STATE;
    return nvs_set_u32(nvs->handle, key, value);
}

esp_err_t nvs_helper_get_i32(nvs_helper_t* nvs, const char* key, int32_t* value) {
    if (!nvs || !nvs->valid) return ESP_ERR_INVALID_STATE;
    return nvs_get_i32(nvs->handle, key, value);
}

esp_err_t nvs_helper_set_i32(nvs_helper_t* nvs, const char* key, int32_t value) {
    if (!nvs || !nvs->valid) return ESP_ERR_INVALID_STATE;
    return nvs_set_i32(nvs->handle, key, value);
}

esp_err_t nvs_helper_erase_key(nvs_helper_t* nvs, const char* key) {
    if (!nvs || !nvs->valid) return ESP_ERR_INVALID_STATE;
    return nvs_erase_key(nvs->handle, key);
}

esp_err_t nvs_helper_commit(nvs_helper_t* nvs) {
    if (!nvs || !nvs->valid) return ESP_ERR_INVALID_STATE;
    return nvs_commit(nvs->handle);
}
