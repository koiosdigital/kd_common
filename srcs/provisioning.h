#pragma once

typedef enum ProvisioningTaskNotification_t {
    STOP_PROVISIONING = 1,
    START_PROVISIONING = 2,
    RESET_PROVISIONING = 3,
    RESET_SM_ON_FAILURE = 4,
} ProvisioningTaskNotification_t;

void kd_common_notify_provisioning_task(ProvisioningTaskNotification_t notification);
char* kd_common_provisioning_get_pop_token();
char* kd_common_get_provisioning_qr_payload();