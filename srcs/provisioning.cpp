#include "provisioning.h"

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include <string.h>

#include <esp_random.h>
#include <esp_mac.h>

#include "device_identifiers.h"
#include "provisioning_private.h"

//MARK: Public
void kd_common_notify_provisioning_task(ProvisioningTaskNotification_t notification) {
    TaskHandle_t xProvisioningTask = provisioning_get_task_handle();

    if (xProvisioningTask != NULL) {
        xTaskNotify(xProvisioningTask, notification, eSetValueWithOverwrite);
    }
}

char* provisioning_qr_payload = nullptr;
char* kd_common_get_provisioning_qr_payload() {
    if (provisioning_qr_payload != nullptr) {
        return provisioning_qr_payload;
    }

    provisioning_qr_payload = (char*)calloc(64, sizeof(char));
    snprintf(provisioning_qr_payload, 63, "%s;%s", kd_common_get_device_name(), kd_common_provisioning_get_pop_token());
    return provisioning_qr_payload;
}


char* provisioning_pop_token = nullptr;
char* kd_common_provisioning_get_pop_token() {
    if (provisioning_pop_token != nullptr) {
        return provisioning_pop_token;
    }
    provisioning_pop_token = (char*)calloc(9, sizeof(char));
    esp_fill_random(provisioning_pop_token, 8);
    for (int i = 0; i < 8; i++) {
        provisioning_pop_token[i] = (provisioning_pop_token[i] % 26) + 'A';
    }
    return provisioning_pop_token;
}

//MARK: Private
