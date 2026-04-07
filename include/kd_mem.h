#pragma once

#include <esp_heap_caps.h>

#ifdef CONFIG_KD_COMMON_MALLOC_SPIRAM
#define KD_MALLOC_CAP MALLOC_CAP_SPIRAM
#else
#define KD_MALLOC_CAP MALLOC_CAP_DEFAULT
#endif
