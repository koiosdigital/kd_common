#pragma once

#ifdef __cplusplus
extern "C" {
#endif

void kdmdns_set_device_info(const char* model, const char* type);
void kdmdns_init(void);
const char* kdmdns_get_model(void);
const char* kdmdns_get_type(void);

#ifdef __cplusplus
}
#endif
