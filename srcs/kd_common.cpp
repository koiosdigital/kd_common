#include "kd_common.h"

#include "crypto_private.h"
#include "provisioning_private.h"
#include "wifi_private.h"

void kd_common_init() {
    crypto_init();
    provisioning_init();
    wifi_init();
}