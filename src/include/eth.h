#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Bring up the configured SPI Ethernet controller (currently W6100), attach it
// to a dedicated esp_netif, and block up to link_wait_ms for a DHCP lease.
//
// Returns true if an IP was acquired within the timeout (Ethernet is active and
// WiFi/BLE provisioning should be skipped). Returns false on timeout or setup
// error; the driver is left running so a cable inserted later still connects,
// but the caller should start the WiFi fallback. Fires the net hub's
// connect/disconnect callbacks on IP acquisition / link loss.
//
// Only defined when CONFIG_KD_COMMON_ETH_ENABLE is set.
bool eth_init(uint32_t link_wait_ms);

#ifdef __cplusplus
}
#endif
