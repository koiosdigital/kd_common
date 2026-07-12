#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// mDNS functions
void kd_common_set_device_info(const char* model, const char* type);

// Add (or update) a TXT record on an advertised _tcp service at runtime,
// e.g. kd_common_mdns_add_svc_record("_koiosdigital", "device_id", id).
// The record is cached and re-applied if mDNS restarts (WiFi reconnect).
void kd_common_mdns_add_svc_record(const char* service, const char* key, const char* value);

#ifdef __cplusplus
}
#endif
