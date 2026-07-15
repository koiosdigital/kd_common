#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Initialize provisioning - checks if already provisioned (call AFTER wifi_init)
void provisioning_init(void);

// Start BLE provisioning manually (e.g., for button-triggered re-provisioning)
void provisioning_start(void);

// Called when Ethernet becomes the active uplink: stops BLE provisioning if it
// is advertising and suppresses WiFi auto-reconnect so the fallback stays down.
void provisioning_shutdown_for_eth(void);

#ifdef __cplusplus
}
#endif
