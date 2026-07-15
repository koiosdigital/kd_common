#pragma once

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Interface-agnostic connectivity hub. WiFi, Ethernet (and future links such
// as a cellular modem) all funnel their "got IP" / "link down" events through
// here, so consumers (NTP, mDNS, API, cloud) register a single set of
// callbacks and never care which physical interface carried the packets.

typedef void (*net_event_fn)(void);

// Logical network interfaces that can provide connectivity. The value doubles
// as a bit index in the aggregate link mask, so keep NET_IF_MAX last.
typedef enum {
    NET_IF_WIFI = 0,
    NET_IF_ETH,
    NET_IF_MODEM,
    NET_IF_MAX
} net_if_t;

// Register callbacks fired on every got-IP (connect) / link-down (disconnect),
// regardless of which interface produced the event. Register before any
// interface is started so an early GOT_IP can't fire before subscribers exist.
void net_on_connect(net_event_fn cb);
void net_on_disconnect(net_event_fn cb);

// Called by interface drivers. dispatch_* invoke the callback lists;
// set_link_up() tracks aggregate connectivity for net_is_connected().
void net_dispatch_connect(void);
void net_dispatch_disconnect(void);
void net_set_link_up(net_if_t iface, bool up);

// True while any interface currently holds an IP address.
bool net_is_connected(void);

#ifdef __cplusplus
}
#endif
