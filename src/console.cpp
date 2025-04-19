#include "console.h"

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <unistd.h>
#include <fcntl.h>
#include "nvs_flash.h"

#include <esp_console.h>
#include <esp_log.h>

#include "driver/usb_serial_jtag.h"
#include "driver/usb_serial_jtag_vfs.h"
#include "mbedtls/base64.h"
#include "argtable3/argtable3.h"

#include "cJSON.h"

#include "kd_common.h"
#include "crypto.h"

#if SOC_USB_SERIAL_JTAG_SUPPORTED
#if !CONFIG_ESP_CONSOLE_SECONDARY_NONE
#warning "A secondary serial console is not useful when using the console component. Please disable it in menuconfig."
#endif
#endif

static const char* TAG = "console";
bool use_printf = false;
uint32_t output_buffer_pos = 0;
char* output_buffer = nullptr;

//Helper function (duplicates printf to redirect to buffer or stdout depending on if flag is set)
static int console_out(const char* format, ...)
{
    va_list args;
    va_start(args, format);

    if (use_printf) {
        vprintf(format, args);
    }
    else {
        if (output_buffer == nullptr) {
            ESP_LOGE(TAG, "cannot override command output buffer if null");
        }
        else {
            int written = vsnprintf(output_buffer + output_buffer_pos, 4096 - output_buffer_pos, format, args);
            if (written > 0) {
                output_buffer_pos += written;
                if (output_buffer_pos >= 4096) {
                    ESP_LOGW(TAG, "output buffer overflow, truncating output");
                    output_buffer_pos = 4095; // Ensure null-termination
                }
            }
        }
    }

    va_end(args);
    return 0;
}

//MARK: Commands
static int free_mem(int argc, char** argv)
{
    console_out("internal: %"PRIu32" total: %"PRIu32"\n", esp_get_free_internal_heap_size(), esp_get_free_heap_size());
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

/* 'heap' command prints minimum heap size */
static int heap_size(int argc, char** argv)
{
    uint32_t heap_size = heap_caps_get_minimum_free_size(MALLOC_CAP_DEFAULT);
    console_out("min heap size: %"PRIu32"\n", heap_size);
    return 0;
}

static void register_heap(void)
{
    const esp_console_cmd_t heap_cmd = {
        .command = "heap",
        .help = "Get minimum size of free heap memory that was available during program execution",
        .hint = NULL,
        .func = &heap_size,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&heap_cmd));

}

static int tasks_info(int argc, char** argv)
{
    const size_t bytes_per_task = 40; /* see vTaskList description */
    char* task_list_buffer = (char*)malloc(uxTaskGetNumberOfTasks() * bytes_per_task);
    if (task_list_buffer == NULL) {
        ESP_LOGE(TAG, "failed to allocate buffer for vTaskList output");
        return 1;
    }
    console_out("Task Name\tStatus\tPrio\tHWM\tTask#\n");
    vTaskList(task_list_buffer);
    console_out(task_list_buffer);
    free(task_list_buffer);
    return 0;
}

static void register_tasks(void)
{
    const esp_console_cmd_t cmd = {
        .command = "tasks",
        .help = "Get information about running tasks",
        .hint = NULL,
        .func = &tasks_info,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&cmd));
}

/** log_level command changes log level via esp_log_level_set */

static struct {
    struct arg_str* level;
    struct arg_end* end;
} log_level_args;

static const char* s_log_level_names[] = {
    "none",
    "error",
    "warn",
    "info",
    "debug",
    "verbose"
};

static int log_level(int argc, char** argv)
{
    int nerrors = arg_parse(argc, argv, (void**)&log_level_args);
    if (nerrors != 0) {
        arg_print_errors(stderr, log_level_args.end, argv[0]);
        return 1;
    }
    assert(log_level_args.level->count == 1);
    const char* level_str = log_level_args.level->sval[0];
    esp_log_level_t level;
    size_t level_len = strlen(level_str);
    for (level = ESP_LOG_NONE; (int)level <= (int)ESP_LOG_VERBOSE; level = (esp_log_level_t)((int)level + 1)) {
        if (memcmp(level_str, s_log_level_names[level], level_len) == 0) {
            break;
        }
    }
    if (level > ESP_LOG_VERBOSE) {
        console_out("Invalid log level '%s', choose from none|error|warn|info|debug|verbose\n", level_str);
        return 1;
    }
    if (level > CONFIG_LOG_MAXIMUM_LEVEL) {
        console_out("Can't set log level to %s, max level limited in menuconfig to %s. "
            "Please increase CONFIG_LOG_MAXIMUM_LEVEL in menuconfig.\n",
            s_log_level_names[level], s_log_level_names[CONFIG_LOG_MAXIMUM_LEVEL]);
        return 1;
    }
    esp_log_level_set("*", level);

    //store log level in NVS
    nvs_handle handle;
    nvs_open(NVS_CONSOLE_NAMESPACE, NVS_READWRITE, &handle);
    nvs_set_u32(handle, NVS_CONSOLE_LOGLEVEL, level);
    nvs_commit(handle);
    nvs_close(handle);

    return 0;
}

static void register_log_level(void)
{
    log_level_args.level = arg_str1(NULL, NULL, "<none|error|warn|debug|verbose>", "Log level to set. Abbreviated words are accepted.");
    log_level_args.end = arg_end(1);

    const esp_console_cmd_t cmd = {
        .command = "log_level",
        .help = "Set log level",
        .hint = NULL,
        .func = &log_level,
        .argtable = &log_level_args
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&cmd));

    //load log level from NVS
    nvs_handle handle;
    nvs_open(NVS_CONSOLE_NAMESPACE, NVS_READWRITE, &handle);
    uint32_t log_level;
    nvs_get_u32(handle, NVS_CONSOLE_LOGLEVEL, &log_level);
    if (log_level == ESP_ERR_NVS_NOT_FOUND) {
        log_level = CONFIG_LOG_DEFAULT_LEVEL;
    }
    esp_log_level_set("*", (esp_log_level_t)log_level);
    nvs_close(handle);
}

static int crypto_status(int argc, char** argv)
{
    console_out("{\"status\":%i,\"error\":false}\n", kd_common_crypto_get_state());
    return 0;
}

static void register_crypto_status(void)
{
    const esp_console_cmd_t cmd = {
        .command = "crypto_status",
        .help = "Get the current state of the crypto module",
        .hint = NULL,
        .func = &crypto_status,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&cmd));
}

static int get_csr(int argc, char** argv)
{
    //base64 encode the CSR
    char* csr = (char*)malloc(4096);
    size_t len = 4096;
    esp_err_t error = crypto_get_csr(csr, &len);
    if (error != ESP_OK) {
        free(csr);
        console_out("{\"error_message\":\"no csr\",\"error\":true}\n");
        return 0;
    }

    size_t encoded_len = 0;
    char* encoded_csr = (char*)malloc(4096);

    mbedtls_base64_encode((unsigned char*)encoded_csr, 4096, &encoded_len, (unsigned char*)csr, len);
    free(csr);

    console_out("{\"csr\":\"%s\",\"error\":false}\n", encoded_csr);

    free(encoded_csr);
    return 0;
}

static void register_get_csr(void)
{
    const esp_console_cmd_t cmd = {
        .command = "get_csr",
        .help = "Get the CSR associated with the device internal private key",
        .hint = NULL,
        .func = &get_csr,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&cmd));
}

static int get_ds_params(int argc, char** argv)
{

    char* json_string = crypto_get_ds_params_json();

    if (json_string == NULL) {
        console_out("{\"error_message\":\"failed to create json string\",\"error\":true}\n");
        return 0;
    }

    console_out("%s\n", json_string);
    free(json_string);
    return 0;
}

static void register_get_ds_params(void)
{
    const esp_console_cmd_t cmd = {
        .command = "get_ds_params",
        .help = "Get the encrypted DS parameters",
        .hint = NULL,
        .func = &get_ds_params,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&cmd));
}

static struct {
    struct arg_str* ds_params;
    struct arg_end* end;
} set_ds_params_args;

static int set_ds_params(int argc, char** argv)
{
    int nerrors = arg_parse(argc, argv, (void**)&set_ds_params_args);
    if (nerrors != 0) {
        arg_print_errors(stderr, set_ds_params_args.end, argv[0]);
        return 1;
    }

    const char* ds_params_str = set_ds_params_args.ds_params->sval[0];

    char* str = strdup(ds_params_str);
    return crypto_store_ds_params_json(str);
}

static void register_set_ds_params(void)
{
    set_ds_params_args.ds_params = arg_str1(NULL, NULL, "<json value>", "DS parameters in JSON format");
    set_ds_params_args.end = arg_end(1);

    const esp_console_cmd_t cmd = {
        .command = "set_ds_params",
        .help = "Set DS parameters",
        .hint = NULL,
        .func = &set_ds_params,
        .argtable = &set_ds_params_args
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&cmd));
}

static int wifi_reset(int argc, char** argv)
{

    kd_common_clear_wifi_credentials();
    return 0;
}

static void register_wifi_reset(void)
{
    const esp_console_cmd_t cmd = {
        .command = "wifi_reset",
        .help = "Reset the wifi credentials",
        .hint = NULL,
        .func = &wifi_reset,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&cmd));
}

char* kd_common_run_command(char* input, int* return_code) {
    use_printf = false;

    output_buffer = (char*)calloc(4096, sizeof(char));
    if (output_buffer == NULL) {
        ESP_LOGE(TAG, "failed to allocate output buffer");
        return NULL;
    }

    esp_console_run(input, return_code);

    output_buffer_pos = 0;

    use_printf = true;
    return output_buffer;
}

void console_init() {
    esp_console_repl_t* repl = NULL;
    esp_console_repl_config_t repl_config = ESP_CONSOLE_REPL_CONFIG_DEFAULT();
    /* Prompt to be printed before each line.
     * This can be customized, made dynamic, etc.
     */
    repl_config.prompt = "kd>";
    repl_config.max_cmdline_length = 4096;

    esp_console_register_help_command();
    register_free();
    register_heap();
    register_log_level();
    register_tasks();
    register_crypto_status();
    register_get_csr();
    register_get_ds_params();
    register_set_ds_params();
    register_wifi_reset();

    esp_console_dev_usb_serial_jtag_config_t hw_config = ESP_CONSOLE_DEV_USB_SERIAL_JTAG_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_console_new_repl_usb_serial_jtag(&hw_config, &repl_config, &repl));

    use_printf = true;
    ESP_ERROR_CHECK(esp_console_start_repl(repl));
}