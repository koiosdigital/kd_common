#pragma once

#include "sdkconfig.h"

void wifi_init();

#ifdef CONFIG_KD_COMMON_CONSOLE_ENABLE
void wifi_console_init();
#endif