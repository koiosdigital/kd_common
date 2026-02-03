#pragma once

#include "sdkconfig.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NVS_CONSOLE_NAMESPACE "console"
#define NVS_CONSOLE_LOGLEVEL "loglevel"

#ifdef CONFIG_KD_COMMON_CONSOLE_ENABLE
void console_init(void);
#endif // CONFIG_KD_COMMON_CONSOLE_ENABLE

#ifdef __cplusplus
}
#endif
