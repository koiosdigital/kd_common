#pragma once

#include "sdkconfig.h"

#ifdef CONFIG_KD_COMMON_CONSOLE_ENABLE

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

// Console command registration for external components
typedef int (*kd_console_cmd_func_t)(int argc, char** argv);

esp_err_t kd_console_register_cmd(const char* command, const char* help,
    kd_console_cmd_func_t func);

esp_err_t kd_console_register_cmd_with_args(const char* command, const char* help,
    kd_console_cmd_func_t func, void* argtable);

#ifdef __cplusplus
}
#endif

#endif // CONFIG_KD_COMMON_CONSOLE_ENABLE
