#include "console.h"

#ifdef CONFIG_KD_COMMON_CONSOLE_ENABLE

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include <esp_console.h>
#include <esp_app_desc.h>

#include "driver/usb_serial_jtag.h"
#include "driver/usb_serial_jtag_vfs.h"
#include "argtable3/argtable3.h"

#include "esp_heap_caps.h"

#include "kd_common.h"
#include "kdc_heap_tracing.h"

#if SOC_USB_SERIAL_JTAG_SUPPORTED
#if !CONFIG_ESP_CONSOLE_SECONDARY_NONE
#warning "A secondary serial console is not useful when using the console component. Please disable it in menuconfig."
#endif
#endif

//MARK: Commands
static int free_mem(int argc, char** argv)
{
    printf("internal: %" PRIu32 " total: %" PRIu32 "\n", esp_get_free_internal_heap_size(), esp_get_free_heap_size());
    return 0;
}

static void register_free(void)
{
    const esp_console_cmd_t cmd = {
        .command = "free",
        .help = "Get the current size of free heap memory",
        .hint = NULL,
        .func = &free_mem,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&cmd));
}

/* 'heap' command prints heap statistics */
static int heap_info(int argc, char** argv)
{
    uint32_t free_internal = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    uint32_t free_external = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
    uint32_t min_internal = heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL);

    printf("free_internal: %" PRIu32 "\n", free_internal);
    printf("free_external: %" PRIu32 "\n", free_external);
    printf("internal_watermark: %" PRIu32 "\n", min_internal);
    return 0;
}

static void register_heap(void)
{
    const esp_console_cmd_t heap_cmd = {
        .command = "heap",
        .help = "Get heap memory statistics (internal, external, watermark)",
        .hint = NULL,
        .func = &heap_info,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&heap_cmd));
}

#if CONFIG_FREERTOS_USE_TRACE_FACILITY
/* 'task_dump' command prints task info - requires CONFIG_FREERTOS_USE_TRACE_FACILITY */
static int task_dump(int argc, char** argv)
{
    UBaseType_t num_tasks = uxTaskGetNumberOfTasks();
    TaskStatus_t* task_array = (TaskStatus_t*)malloc(num_tasks * sizeof(TaskStatus_t));
    if (task_array == nullptr) {
        printf("error: failed to allocate task array\n");
        return 1;
    }

    uint32_t total_runtime;
    num_tasks = uxTaskGetSystemState(task_array, num_tasks, &total_runtime);

    printf("%-16s %5s %5s %10s\n", "Name", "State", "Prio", "Stack");
    printf("%-16s %5s %5s %10s\n", "----", "-----", "----", "-----");

    for (UBaseType_t i = 0; i < num_tasks; i++) {
        const char* state;
        switch (task_array[i].eCurrentState) {
        case eRunning:   state = "RUN"; break;
        case eReady:     state = "RDY"; break;
        case eBlocked:   state = "BLK"; break;
        case eSuspended: state = "SUS"; break;
        case eDeleted:   state = "DEL"; break;
        default:         state = "???"; break;
        }
        printf("%-16s %5s %5u %10u\n",
            task_array[i].pcTaskName,
            state,
            (unsigned)task_array[i].uxCurrentPriority,
            (unsigned)task_array[i].usStackHighWaterMark);
    }

    free(task_array);
    return 0;
}

static void register_task_dump(void)
{
    const esp_console_cmd_t cmd = {
        .command = "task_dump",
        .help = "Print task information (name, state, priority, stack high water mark)",
        .hint = NULL,
        .func = &task_dump,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&cmd));
}
#endif // CONFIG_FREERTOS_USE_TRACE_FACILITY

static int assert_crash(int argc, char** argv)
{
    printf("Triggering system crash...\n");
    assert(false); // This will crash the system
    return 0; // This line should never be reached
}

static void register_assert(void)
{
    const esp_console_cmd_t cmd = {
        .command = "assert",
        .help = "Crash the system for testing purposes",
        .hint = NULL,
        .func = &assert_crash,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&cmd));
}

static int get_version(int argc, char** argv)
{
    const esp_app_desc_t* app_desc = esp_app_get_description();

    printf("{\n");
    printf("  \"project_name\": \"%s\",\n", app_desc->project_name);
    printf("  \"version\": \"%s\",\n", app_desc->version);
    printf("  \"compile_time\": \"%s\",\n", app_desc->time);
    printf("  \"compile_date\": \"%s\",\n", app_desc->date);
    printf("  \"idf_version\": \"%s\",\n", app_desc->idf_ver);
    printf("  \"secure_version\": %lu,\n", app_desc->secure_version);
    printf("  \"error\": false\n");
    printf("}\n");

    return 0;
}

static void register_get_version(void)
{
    const esp_console_cmd_t cmd = {
        .command = "version",
        .help = "Get firmware version information",
        .hint = NULL,
        .func = &get_version,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&cmd));
}

esp_err_t kd_console_register_cmd(const char* command, const char* help,
    kd_console_cmd_func_t func) {
    const esp_console_cmd_t cmd = {
        .command = command,
        .help = help,
        .hint = NULL,
        .func = func,
    };
    return esp_console_cmd_register(&cmd);
}

esp_err_t kd_console_register_cmd_with_args(const char* command, const char* help,
    kd_console_cmd_func_t func, void* argtable) {
    const esp_console_cmd_t cmd = {
        .command = command,
        .help = help,
        .hint = NULL,
        .func = func,
        .argtable = argtable,
    };
    return esp_console_cmd_register(&cmd);
}

void console_init() {
    kdc_heap_log_status("pre-console-start");
    esp_console_repl_t* repl = NULL;
    esp_console_repl_config_t repl_config = ESP_CONSOLE_REPL_CONFIG_DEFAULT();

    repl_config.prompt = "tty>";
    repl_config.max_cmdline_length = 16384;  // 16KB for base64-encoded fullchain certs

    esp_console_register_help_command();
    register_free();
    register_heap();
#if CONFIG_FREERTOS_USE_TRACE_FACILITY
    register_task_dump();
#endif

    register_assert();
    register_get_version();

#if SOC_USB_SERIAL_JTAG_SUPPORTED
    esp_console_dev_usb_serial_jtag_config_t hw_config = ESP_CONSOLE_DEV_USB_SERIAL_JTAG_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_console_new_repl_usb_serial_jtag(&hw_config, &repl_config, &repl));
#endif

    ESP_ERROR_CHECK(esp_console_start_repl(repl));
    kdc_heap_log_status("post-console-start");
}

#endif // CONFIG_KD_COMMON_CONSOLE_ENABLE