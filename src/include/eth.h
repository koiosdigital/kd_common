#pragma once

#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

// Bring up the configured SPI Ethernet controller (currently W6100) and attach
// it to a dedicated esp_netif. Non-blocking: the driver is started and a
// background supervisor task then waits up to link_wait_ms for a DHCP lease. If
// Ethernet gets an IP, the device runs over Ethernet; otherwise the supervisor
// starts the WiFi/BLE provisioning fallback. Either way the net hub's
// connect/disconnect callbacks fire on IP acquisition / link loss.
//
// Returns ESP_OK once the driver is running (the supervisor owns the
// WiFi-fallback decision, so the caller must NOT start WiFi itself). Returns an
// error if Ethernet setup failed outright, in which case the caller should
// start the WiFi fallback immediately.
//
// Only defined when CONFIG_KD_COMMON_ETH_ENABLE is set.
esp_err_t eth_init(uint32_t link_wait_ms);

#ifdef __cplusplus
}
#endif
