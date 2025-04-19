#pragma once

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

TaskHandle_t provisioning_get_task_handle();
void provisioning_init();