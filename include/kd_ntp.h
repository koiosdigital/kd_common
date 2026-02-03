#pragma once

#include "esp_event.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// NTP Events - posted when sync state changes
ESP_EVENT_DECLARE_BASE(KD_NTP_EVENTS);

typedef enum {
    KD_NTP_EVENT_SYNC_COMPLETE = 0,  // Time successfully synchronized
    KD_NTP_EVENT_SYNC_LOST = 1,      // WiFi disconnected, sync may be stale
} kd_ntp_event_id_t;

// NTP/Time functions
bool kd_common_ntp_is_synced(void);
void kd_common_ntp_sync(void);

// Timezone functions
void kd_common_set_auto_timezone(bool enabled);
bool kd_common_get_auto_timezone(void);
void kd_common_set_fetch_tz_on_boot(bool enabled);  // Disable for UTC-only apps
bool kd_common_get_fetch_tz_on_boot(void);
void kd_common_set_timezone(const char* timezone);  // IANA name like "America/New_York"
const char* kd_common_get_timezone(void);
void kd_common_set_ntp_server(const char* server);
const char* kd_common_get_ntp_server(void);

// Timezone database access (for API endpoints)
typedef struct {
    const char* name;
    const char* rule;
} kd_common_tz_entry_t;

const kd_common_tz_entry_t* kd_common_get_all_timezones(void);
int kd_common_get_timezone_count(void);

#ifdef __cplusplus
}
#endif
