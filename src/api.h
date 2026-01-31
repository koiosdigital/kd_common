#pragma once

#ifndef KD_COMMON_API_DISABLE

#include "esp_http_server.h"

void api_init();
httpd_handle_t api_get_httpd_handle();

#endif // KD_COMMON_API_DISABLE
