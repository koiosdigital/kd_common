#pragma once

#include "sdkconfig.h"

#if defined(CONFIG_KD_COMMON_CRYPTO_ENABLE) && defined(CONFIG_KD_COMMON_CONSOLE_ENABLE)
void crypto_console_init();
#endif
