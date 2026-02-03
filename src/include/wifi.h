#pragma once

#include "sdkconfig.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * One-time WiFi initialization (netif, event handlers, console commands).
 * Also calls wifi_start() at the end.
 * Call once at boot.
 */
void wifi_init(void);

/**
 * Start/restart WiFi driver and connect.
 * Safe to call after wifi_init() for restarts.
 * Does NOT reinitialize netif.
 */
void wifi_start(void);

/**
 * Stop and restart WiFi driver.
 * Does NOT reinitialize netif.
 */
void wifi_restart(void);

#ifdef CONFIG_KD_COMMON_CONSOLE_ENABLE
void wifi_console_init(void);
#endif

#ifdef __cplusplus
}
#endif
