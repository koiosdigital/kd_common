#pragma once

#include <nvs_flash.h>
#include <esp_err.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    nvs_handle_t handle;
    bool valid;
    esp_err_t open_err;
} nvs_helper_t;

// Open NVS namespace - check nvs->valid before using
nvs_helper_t nvs_helper_open(const char* ns, nvs_open_mode_t mode);

// Close NVS handle
void nvs_helper_close(nvs_helper_t* nvs);

// Key existence check
esp_err_t nvs_helper_find_key(nvs_helper_t* nvs, const char* key);

// Blob operations
esp_err_t nvs_helper_get_blob(nvs_helper_t* nvs, const char* key, void* buffer, size_t* len);
esp_err_t nvs_helper_set_blob(nvs_helper_t* nvs, const char* key, const void* data, size_t len);

// String operations
esp_err_t nvs_helper_get_str(nvs_helper_t* nvs, const char* key, char* buffer, size_t* len);
esp_err_t nvs_helper_set_str(nvs_helper_t* nvs, const char* key, const char* value);

// Integer operations
esp_err_t nvs_helper_get_u8(nvs_helper_t* nvs, const char* key, uint8_t* value);
esp_err_t nvs_helper_set_u8(nvs_helper_t* nvs, const char* key, uint8_t value);
esp_err_t nvs_helper_get_u16(nvs_helper_t* nvs, const char* key, uint16_t* value);
esp_err_t nvs_helper_set_u16(nvs_helper_t* nvs, const char* key, uint16_t value);
esp_err_t nvs_helper_get_u32(nvs_helper_t* nvs, const char* key, uint32_t* value);
esp_err_t nvs_helper_set_u32(nvs_helper_t* nvs, const char* key, uint32_t value);
esp_err_t nvs_helper_get_i32(nvs_helper_t* nvs, const char* key, int32_t* value);
esp_err_t nvs_helper_set_i32(nvs_helper_t* nvs, const char* key, int32_t value);

// Erase operations
esp_err_t nvs_helper_erase_key(nvs_helper_t* nvs, const char* key);

// Commit changes
esp_err_t nvs_helper_commit(nvs_helper_t* nvs);

#ifdef __cplusplus
}
#endif
