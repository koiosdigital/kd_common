#include "net.h"

#include <stdint.h>
#include <stdatomic.h>

#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <esp_log.h>

static const char* TAG = "kd_net";

#define MAX_NET_CALLBACKS 8

static SemaphoreHandle_t s_cb_mutex = NULL;
static net_event_fn s_connect_cbs[MAX_NET_CALLBACKS];
static net_event_fn s_disconnect_cbs[MAX_NET_CALLBACKS];
static size_t s_connect_cb_count = 0;
static size_t s_disconnect_cb_count = 0;

static atomic_uint_least32_t s_link_mask = 0;

static void ensure_mutex(void) {
    if (s_cb_mutex == NULL) {
        s_cb_mutex = xSemaphoreCreateMutex();
    }
}

void net_on_connect(net_event_fn cb) {
    if (!cb) return;
    ensure_mutex();
    if (xSemaphoreTake(s_cb_mutex, pdMS_TO_TICKS(100)) != pdTRUE) return;

    if (s_connect_cb_count < MAX_NET_CALLBACKS) {
        s_connect_cbs[s_connect_cb_count++] = cb;
    } else {
        ESP_LOGW(TAG, "Max connect callbacks reached (%d)", MAX_NET_CALLBACKS);
    }

    xSemaphoreGive(s_cb_mutex);
}

void net_on_disconnect(net_event_fn cb) {
    if (!cb) return;
    ensure_mutex();
    if (xSemaphoreTake(s_cb_mutex, pdMS_TO_TICKS(100)) != pdTRUE) return;

    if (s_disconnect_cb_count < MAX_NET_CALLBACKS) {
        s_disconnect_cbs[s_disconnect_cb_count++] = cb;
    } else {
        ESP_LOGW(TAG, "Max disconnect callbacks reached (%d)", MAX_NET_CALLBACKS);
    }

    xSemaphoreGive(s_cb_mutex);
}

void net_dispatch_connect(void) {
    ensure_mutex();
    if (xSemaphoreTake(s_cb_mutex, pdMS_TO_TICKS(100)) != pdTRUE) return;

    ESP_LOGI(TAG, "connect: dispatching to %u callbacks", (unsigned)s_connect_cb_count);
    for (size_t i = 0; i < s_connect_cb_count; i++) {
        if (s_connect_cbs[i]) s_connect_cbs[i]();
    }

    xSemaphoreGive(s_cb_mutex);
}

void net_dispatch_disconnect(void) {
    if (atomic_load(&s_link_mask) != 0) {
        ESP_LOGD(TAG, "disconnect suppressed; still up on mask 0x%x",
            (unsigned)atomic_load(&s_link_mask));
        return;
    }

    ensure_mutex();
    if (xSemaphoreTake(s_cb_mutex, pdMS_TO_TICKS(100)) != pdTRUE) return;

    ESP_LOGD(TAG, "disconnect: dispatching to %u callbacks", (unsigned)s_disconnect_cb_count);
    for (size_t i = 0; i < s_disconnect_cb_count; i++) {
        if (s_disconnect_cbs[i]) s_disconnect_cbs[i]();
    }

    xSemaphoreGive(s_cb_mutex);
}

void net_set_link_up(net_if_t iface, bool up) {
    if (iface >= NET_IF_MAX) return;
    if (up) {
        atomic_fetch_or(&s_link_mask, (1u << iface));
    } else {
        atomic_fetch_and(&s_link_mask, ~(1u << iface));
    }
}

bool net_is_connected(void) {
    return atomic_load(&s_link_mask) != 0;
}
