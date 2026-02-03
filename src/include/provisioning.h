#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Initialize provisioning - checks if already provisioned (call AFTER wifi_init)
void provisioning_init(void);

// Start BLE provisioning manually (e.g., for button-triggered re-provisioning)
void provisioning_start(void);

#ifdef __cplusplus
}
#endif
