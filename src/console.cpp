#include "console.h"

#ifdef CONFIG_KD_COMMON_CONSOLE_ENABLE

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <unistd.h>
#include <fcntl.h>
#include "nvs_flash.h"

#include <esp_console.h>
#include <esp_log.h>
#include <esp_app_desc.h>

#include "driver/usb_serial_jtag.h"
#include "driver/usb_serial_jtag_vfs.h"
#include "argtable3/argtable3.h"

#include "cJSON.h"
#include "esp_heap_caps.h"

#include "kd_common.h"

#if SOC_USB_SERIAL_JTAG_SUPPORTED
#if !CONFIG_ESP_CONSOLE_SECONDARY_NONE
#warning "A secondary serial console is not useful when using the console component. Please disable it in menuconfig."
#endif
#endif

static const char* TAG = "console";

namespace {

    constexpr size_t OUTPUT_BUFFER_SIZE = 4096;

    // Encapsulated console output state
    struct ConsoleContext {
        bool use_printf = true;
        char* output_buffer = nullptr;
        size_t output_buffer_pos = 0;

        void reset_buffer() {
            output_buffer = nullptr;
            output_buffer_pos = 0;
        }
    };

    ConsoleContext ctx;

    // RAII guard for output mode - restores use_printf on destruction
    class OutputModeGuard {
    public:
        explicit OutputModeGuard(bool new_mode) : saved_mode_(ctx.use_printf) {
            ctx.use_printf = new_mode;
        }
        ~OutputModeGuard() {
            ctx.use_printf = saved_mode_;
        }
        OutputModeGuard(const OutputModeGuard&) = delete;
        OutputModeGuard& operator=(const OutputModeGuard&) = delete;
    private:
        bool saved_mode_;
    };

}  // namespace

int console_out(const char* format, ...)
{
    va_list args;
    va_start(args, format);

    if (ctx.use_printf) {
        vprintf(format, args);
    }
    else if (ctx.output_buffer == nullptr) {
        ESP_LOGE(TAG, "cannot override command output buffer if null");
    }
    else if (ctx.output_buffer_pos >= (OUTPUT_BUFFER_SIZE - 1)) {
        ESP_LOGW(TAG, "output buffer overflow, truncating output");
    }
    else {
        const size_t available = OUTPUT_BUFFER_SIZE - ctx.output_buffer_pos;
        int written = vsnprintf(ctx.output_buffer + ctx.output_buffer_pos, available, format, args);
        if (written > 0) {
            ctx.output_buffer_pos += static_cast<size_t>(written);
            if (ctx.output_buffer_pos >= OUTPUT_BUFFER_SIZE) {
                ctx.output_buffer_pos = OUTPUT_BUFFER_SIZE - 1;
                ctx.output_buffer[ctx.output_buffer_pos] = '\0';
            }
        }
    }

    va_end(args);
    return 0;
}

//MARK: Commands
static int free_mem(int argc, char** argv)
{
    console_out("internal: %" PRIu32 " total: %" PRIu32 "\n", esp_get_free_internal_heap_size(), esp_get_free_heap_size());
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

    console_out("free_internal: %" PRIu32 "\n", free_internal);
    console_out("free_external: %" PRIu32 "\n", free_external);
    console_out("internal_watermark: %" PRIu32 "\n", min_internal);
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
        console_out("error: failed to allocate task array\n");
        return 1;
    }

    uint32_t total_runtime;
    num_tasks = uxTaskGetSystemState(task_array, num_tasks, &total_runtime);

    console_out("%-16s %5s %5s %10s\n", "Name", "State", "Prio", "Stack");
    console_out("%-16s %5s %5s %10s\n", "----", "-----", "----", "-----");

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
        console_out("%-16s %5s %5u %10u\n",
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
    console_out("Triggering system crash...\n");
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

    console_out("{\n");
    console_out("  \"project_name\": \"%s\",\n", app_desc->project_name);
    console_out("  \"version\": \"%s\",\n", app_desc->version);
    console_out("  \"compile_time\": \"%s\",\n", app_desc->time);
    console_out("  \"compile_date\": \"%s\",\n", app_desc->date);
    console_out("  \"idf_version\": \"%s\",\n", app_desc->idf_ver);
    console_out("  \"secure_version\": %lu,\n", app_desc->secure_version);
    console_out("  \"error\": false\n");
    console_out("}\n");

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

char* kd_common_run_command(char* input, int* return_code) {
    // Allocate output buffer
    char* buffer = static_cast<char*>(calloc(OUTPUT_BUFFER_SIZE, 1));
    if (!buffer) {
        ESP_LOGE(TAG, "failed to allocate output buffer");
        return nullptr;
    }

    // Set up context for capture mode
    ctx.output_buffer = buffer;
    ctx.output_buffer_pos = 0;

    // RAII guard restores use_printf and clears buffer pointer on exit
    OutputModeGuard guard(false);

    int local_return_code = 0;
    esp_console_run(input, return_code ? return_code : &local_return_code);

    // Transfer ownership to caller
    ctx.reset_buffer();
    return buffer;
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
}

#endif // CONFIG_KD_COMMON_CONSOLE_ENABLE