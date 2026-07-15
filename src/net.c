#include "net.h"

#include <stdint.h>

#include <esp_log.h>

static const char* TAG = "kd_net";

#define MAX_NET_CALLBACKS 8

static net_event_fn s_connect_cbs[MAX_NET_CALLBACKS];
static net_event_fn s_disconnect_cbs[MAX_NET_CALLBACKS];
static size_t s_connect_cb_count = 0;
static size_t s_disconnect_cb_count = 0;

// Bit per interface that currently holds an IP. Aggregate connectivity is
// simply "any bit set", so a WiFi drop while Ethernet is up (or vice versa)
// does not report the device as offline.
static uint32_t s_link_mask = 0;

void net_on_connect(net_event_fn cb) {
    if (cb && s_connect_cb_count < MAX_NET_CALLBACKS) {
        s_connect_cbs[s_connect_cb_count++] = cb;
    }
}

void net_on_disconnect(net_event_fn cb) {
    if (cb && s_disconnect_cb_count < MAX_NET_CALLBACKS) {
        s_disconnect_cbs[s_disconnect_cb_count++] = cb;
    }
}

void net_dispatch_connect(void) {
    ESP_LOGI(TAG, "connect: dispatching to %u callbacks", (unsigned)s_connect_cb_count);
    for (size_t i = 0; i < s_connect_cb_count; i++) {
        if (s_connect_cbs[i]) s_connect_cbs[i]();
    }
}

void net_dispatch_disconnect(void) {
    // Only report "disconnected" once every interface is down. This keeps a
    // WiFi drop (e.g. when Ethernet takes over) from tearing down services that
    // are still reachable over Ethernet. Callers update the link mask via
    // net_set_link_up() before dispatching.
    if (s_link_mask != 0) {
        ESP_LOGD(TAG, "disconnect suppressed; still up on mask 0x%x", (unsigned)s_link_mask);
        return;
    }
    ESP_LOGD(TAG, "disconnect: dispatching to %u callbacks", (unsigned)s_disconnect_cb_count);
    for (size_t i = 0; i < s_disconnect_cb_count; i++) {
        if (s_disconnect_cbs[i]) s_disconnect_cbs[i]();
    }
}

void net_set_link_up(net_if_t iface, bool up) {
    if (iface >= NET_IF_MAX) return;
    if (up) {
        s_link_mask |= (1u << iface);
    } else {
        s_link_mask &= ~(1u << iface);
    }
}

bool net_is_connected(void) {
    return s_link_mask != 0;
}
