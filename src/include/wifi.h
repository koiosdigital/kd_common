#pragma once

#include "sdkconfig.h"

#ifdef __cplusplus
extern "C" {
#endif

// Callback types for WiFi connect/disconnect events
typedef void (*wifi_connect_fn)(void);
typedef void (*wifi_disconnect_fn)(void);

/**
 * One-time WiFi initialization (netif, event handlers, console commands).
 * Does NOT start WiFi - call wifi_start() after all modules have
 * registered their callbacks.
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

/**
 * Register a callback to be invoked when WiFi gets an IP address.
 * Must be called after wifi_init() and before wifi_start().
 */
void wifi_on_connect(wifi_connect_fn cb);

/**
 * Register a callback to be invoked when WiFi disconnects.
 * Must be called after wifi_init() and before wifi_start().
 */
void wifi_on_disconnect(wifi_disconnect_fn cb);

#ifdef CONFIG_KD_COMMON_CONSOLE_ENABLE
void wifi_console_init(void);
#endif

#ifdef __cplusplus
}
#endif
