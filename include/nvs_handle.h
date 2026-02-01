#pragma once

#include <nvs_flash.h>
#include <esp_err.h>
#include <cstdint>

namespace kd {

    // RAII wrapper for NVS handle
    // Automatically closes handle on destruction, eliminating goto cleanup patterns
    class NvsHandle {
    public:
        NvsHandle(const char* ns, nvs_open_mode_t mode);
        ~NvsHandle();

        // Non-copyable
        NvsHandle(const NvsHandle&) = delete;
        NvsHandle& operator=(const NvsHandle&) = delete;

        // Moveable
        NvsHandle(NvsHandle&& other) noexcept;
        NvsHandle& operator=(NvsHandle&& other) noexcept;

        explicit operator bool() const;
        nvs_handle_t get() const;
        esp_err_t open_error() const;

        // Key existence check
        esp_err_t find_key(const char* key);

        // Blob operations
        esp_err_t get_blob(const char* key, void* buffer, size_t* len);
        esp_err_t set_blob(const char* key, const void* data, size_t len);

        // String operations
        esp_err_t get_str(const char* key, char* buffer, size_t* len);
        esp_err_t set_str(const char* key, const char* value);

        // Integer operations
        esp_err_t get_u8(const char* key, uint8_t* value);
        esp_err_t set_u8(const char* key, uint8_t value);
        esp_err_t get_u16(const char* key, uint16_t* value);
        esp_err_t set_u16(const char* key, uint16_t value);
        esp_err_t get_u32(const char* key, uint32_t* value);
        esp_err_t set_u32(const char* key, uint32_t value);
        esp_err_t get_i32(const char* key, int32_t* value);
        esp_err_t set_i32(const char* key, int32_t value);

        // Erase operations
        esp_err_t erase_key(const char* key);

        // Commit changes
        esp_err_t commit();

    private:
        nvs_handle_t handle_ = 0;
        bool valid_ = false;
        esp_err_t err_ = ESP_FAIL;
        const char* namespace_ = nullptr;
    };

}  // namespace kd
