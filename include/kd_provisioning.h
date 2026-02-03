#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PROVISIONING_SRP_FORMAT_STATIC = 0,
    PROVISIONING_SRP_FORMAT_NUMERIC_6 = 1,
    PROVISIONING_SRP_FORMAT_NUMERIC_6_REDUCED = 2,
    PROVISIONING_SRP_FORMAT_NUMERIC_4 = 3
} ProvisioningSRPPasswordFormat_t;

// Provisioning functions
char* kd_common_provisioning_get_srp_password(void);
void kd_common_set_provisioning_srp_password_format(ProvisioningSRPPasswordFormat_t format);
void kd_common_start_provisioning(void);  // Start BLE provisioning manually (e.g., button hold)

#ifdef __cplusplus
}
#endif
