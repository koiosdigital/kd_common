#pragma once

void kdmdns_set_device_info(const char* model, const char* type);
void kdmdns_init();
const char* kdmdns_get_model();
const char* kdmdns_get_type();
