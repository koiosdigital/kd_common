#pragma once

#define NVS_CONSOLE_NAMESPACE "console"
#define NVS_CONSOLE_LOGLEVEL "loglevel"

#ifdef CONFIG_KD_COMMON_CONSOLE_ENABLE
void console_init();
#endif // CONFIG_KD_COMMON_CONSOLE_ENABLE