#pragma once

#include "sdkconfig.h"

/**
 * One-time WiFi initialization (netif, event handlers, console commands).
 * Also calls wifi_start() at the end.
 * Call once at boot.
 */
void wifi_init();

/**
 * Start/restart WiFi driver and connect.
 * Safe to call after wifi_init() for restarts.
 * Does NOT reinitialize netif.
 */
void wifi_start();

#ifdef CONFIG_KD_COMMON_CONSOLE_ENABLE
void wifi_console_init();
#endif