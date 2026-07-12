#pragma once

#ifdef __cplusplus
extern "C" {
#endif

void kdmdns_set_device_info(const char* model, const char* type);
void kdmdns_add_svc_record(const char* service, const char* key, const char* value);
void kdmdns_init(void);
const char* kdmdns_get_model(void);
const char* kdmdns_get_type(void);

#ifdef __cplusplus
}
#endif
