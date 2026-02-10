#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Provisioning functions
char* kd_common_provisioning_get_srp_password(void);
void kd_common_start_provisioning(void);  // Start BLE provisioning manually (e.g., button hold)

#ifdef __cplusplus
}
#endif
