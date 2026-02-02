#pragma once

#ifdef CONFIG_KD_COMMON_API_ENABLE

#include "esp_http_server.h"

void api_init();
httpd_handle_t api_get_httpd_handle();

#endif // CONFIG_KD_COMMON_API_ENABLE
