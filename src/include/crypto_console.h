#pragma once

#include "sdkconfig.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(CONFIG_KD_COMMON_CRYPTO_ENABLE) && defined(CONFIG_KD_COMMON_CONSOLE_ENABLE)
void crypto_console_init(void);
#endif

#ifdef __cplusplus
}
#endif
