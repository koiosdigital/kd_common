// NTP time synchronization with timezone support
#pragma once

#include <esp_err.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

    // Time configuration structure
    typedef struct {
        bool auto_timezone;      // true to fetch TZ from API, false to use manual TZ
        bool fetch_tz_on_boot;   // true to fetch timezone on WiFi connect (default: true)
        char timezone[64];       // IANA timezone name (e.g. "America/New_York")
        char ntp_server[64];     // NTP server URL
    } ntp_config_t;

    // Initialize NTP client (called by kd_common_init)
    void ntp_init(void);

    // Check if time has been synchronized
    bool ntp_is_synced(void);

    // Force a time sync
    void ntp_sync(void);

    // Configuration functions
    ntp_config_t ntp_get_config(void);
    void ntp_set_config(const ntp_config_t* config);

    // Enable/disable auto timezone (fetched from server based on IP geolocation)
    void ntp_set_auto_timezone(bool enabled);
    bool ntp_get_auto_timezone(void);

    // Enable/disable timezone fetch on boot (default: true)
    // Set to false for apps that only need UTC time
    void ntp_set_fetch_tz_on_boot(bool enabled);
    bool ntp_get_fetch_tz_on_boot(void);

    // Set manual timezone (IANA name like "America/New_York")
    void ntp_set_timezone(const char* timezone);
    const char* ntp_get_timezone(void);

    // Set NTP server
    void ntp_set_server(const char* server);
    const char* ntp_get_server(void);

    // Apply timezone from external source (e.g., OTA check response)
    // Only applies if auto_timezone is enabled
    // tzname: IANA timezone name (e.g. "America/New_York")
    void ntp_apply_timezone(const char* tzname);

#ifdef __cplusplus
}
#endif
