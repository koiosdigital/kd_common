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
#include "mbedtls/base64.h"
#include "argtable3/argtable3.h"

#include "cJSON.h"
#include "esp_heap_caps.h"

#include "kd_common.h"
#include "crypto.h"
#include <esp_efuse.h>

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

#ifdef CONFIG_KD_COMMON_CRYPTO_ENABLE
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
    // Get CSR length first
    size_t csr_len = 0;
    esp_err_t error = crypto_get_csr(nullptr, &csr_len);
    if (error != ESP_OK || csr_len == 0) {
        console_out("{\"error_message\":\"no csr\",\"error\":true}\n");
        return 0;
    }

    // Allocate CSR buffer
    char* csr = (char*)malloc(csr_len);
    if (csr == nullptr) {
        console_out("{\"error_message\":\"alloc failed\",\"error\":true}\n");
        return 0;
    }

    error = crypto_get_csr(csr, &csr_len);
    if (error != ESP_OK) {
        free(csr);
        console_out("{\"error_message\":\"no csr\",\"error\":true}\n");
        return 0;
    }

    // Get required base64 encoded length
    size_t encoded_len = 0;
    mbedtls_base64_encode(nullptr, 0, &encoded_len, (unsigned char*)csr, csr_len);

    // Allocate encoded buffer (+1 for null terminator)
    char* encoded_csr = (char*)malloc(encoded_len + 1);
    if (encoded_csr == nullptr) {
        free(csr);
        console_out("{\"error_message\":\"alloc failed\",\"error\":true}\n");
        return 0;
    }

    mbedtls_base64_encode((unsigned char*)encoded_csr, encoded_len + 1, &encoded_len, (unsigned char*)csr, csr_len);
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

static struct {
    struct arg_str* cert;
    struct arg_end* end;
} set_device_cert_args;

static int set_device_cert(int argc, char** argv)
{
    int nerrors = arg_parse(argc, argv, (void**)&set_device_cert_args);
    if (nerrors != 0) {
        arg_print_errors(stderr, set_device_cert_args.end, argv[0]);
        return 1;
    }

    const char* cert_b64 = set_device_cert_args.cert->sval[0];
    size_t cert_len = strlen(cert_b64);

    // Get required decoded length
    size_t decoded_len = 0;
    int ret = mbedtls_base64_decode(nullptr, 0, &decoded_len, (unsigned char*)cert_b64, cert_len);
    if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL || decoded_len == 0) {
        ESP_LOGE(TAG, "failed to get decoded cert size");
        return 1;
    }

    // Allocate decoded buffer (+1 for null terminator)
    char* decoded_cert = (char*)malloc(decoded_len + 1);
    if (decoded_cert == nullptr) {
        ESP_LOGE(TAG, "failed to allocate buffer for decoded cert");
        return 1;
    }

    ret = mbedtls_base64_decode((unsigned char*)decoded_cert, decoded_len + 1, &decoded_len, (unsigned char*)cert_b64, cert_len);
    if (ret != 0) {
        ESP_LOGE(TAG, "failed to decode cert");
        free(decoded_cert);
        return 1;
    }
    decoded_cert[decoded_len] = '\0';

    esp_err_t error = crypto_set_device_cert(decoded_cert, decoded_len);
    free(decoded_cert);
    if (error != ESP_OK) {
        ESP_LOGE(TAG, "failed to set device cert");
        return 1;
    }
    console_out("{\"error\":false}\n");
    return 0;
}

static void register_set_device_cert(void)
{
    set_device_cert_args.cert = arg_str1(NULL, NULL, "base64 cert", "base64 pem");
    set_device_cert_args.end = arg_end(1);

    const esp_console_cmd_t cmd = {
        .command = "set_device_cert",
        .help = "Set device cert",
        .hint = NULL,
        .func = &set_device_cert,
        .argtable = &set_device_cert_args
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&cmd));
}
#endif // CONFIG_KD_COMMON_CRYPTO_ENABLE

#ifdef CONFIG_KD_COMMON_CRYPTO_ENABLE
static int get_device_cert(int argc, char** argv)
{
    // Get cert length first
    size_t cert_len = 0;
    esp_err_t err = kd_common_get_device_cert(nullptr, &cert_len);
    if (err != ESP_OK || cert_len == 0) {
        console_out("{\"error\":true,\"message\":\"No device certificate found\"}\n");
        return 1;
    }

    // Allocate and get cert
    char* cert = (char*)malloc(cert_len + 1);
    if (!cert) {
        console_out("{\"error\":true,\"message\":\"Memory allocation failed\"}\n");
        return 1;
    }

    err = kd_common_get_device_cert(cert, &cert_len);
    if (err != ESP_OK) {
        free(cert);
        console_out("{\"error\":true,\"message\":\"Failed to read certificate\"}\n");
        return 1;
    }
    cert[cert_len] = '\0';

    console_out("%s\n", cert);
    free(cert);
    return 0;
}

static void register_get_device_cert(void)
{
    const esp_console_cmd_t cmd = {
        .command = "get_device_cert",
        .help = "Get device certificate",
        .hint = NULL,
        .func = &get_device_cert,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&cmd));
}

static int get_ds_params(int argc, char** argv)
{
    char* json = crypto_get_ds_params_json();
    if (json == nullptr) {
        console_out("{\"error\":true,\"message\":\"No DS params found\"}\n");
        return 1;
    }
    console_out("%s\n", json);
    free(json);
    return 0;
}

static void register_get_ds_params(void)
{
    const esp_console_cmd_t cmd = {
        .command = "get_ds_params",
        .help = "Get digital signature parameters (ds_key_id, rsa_len, cipher_c, iv)",
        .hint = NULL,
        .func = &get_ds_params,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&cmd));
}

static struct {
    struct arg_int* block;
    struct arg_lit* confirm;
    struct arg_end* end;
} set_ds_key_block_args;

static int set_ds_key_block(int argc, char** argv)
{
    int nerrors = arg_parse(argc, argv, (void**)&set_ds_key_block_args);
    if (nerrors != 0) {
        arg_print_errors(stderr, set_ds_key_block_args.end, argv[0]);
        return 1;
    }

    int block = set_ds_key_block_args.block->ival[0];

    // Validate range
    if (block < 4 || block > 9) {
        console_out("{\"error\":true,\"message\":\"Invalid block. Valid range: 4-9 (KEY0-KEY5)\"}\n");
        return 1;
    }

    // Check for --confirm flag
    if (set_ds_key_block_args.confirm->count == 0) {
        console_out("\n");
        console_out("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
        console_out("!!                    CRITICAL WARNING                         !!\n");
        console_out("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
        console_out("\n");
        console_out("This command will:\n");
        console_out("  1. Change the DS key block to EFUSE_BLK_KEY%d\n", block - 4);
        console_out("  2. PERMANENTLY DELETE all crypto data (CSR, certificate, DS params)\n");
        console_out("  3. Reboot the device\n");
        console_out("\n");
        console_out("After reboot, the device will generate a NEW private key and burn\n");
        console_out("it to the new eFuse block. This is IRREVERSIBLE.\n");
        console_out("\n");
        console_out("The device will need to be RE-PROVISIONED with a new certificate.\n");
        console_out("The old certificate will NO LONGER WORK.\n");
        console_out("\n");
        console_out("If no valid HMAC key exists in the target block, this WILL\n");
        console_out("render the device PERMANENTLY UNUSABLE for mTLS authentication.\n");
        console_out("\n");
        console_out("To proceed, run: set_ds_key_block %d --confirm\n", block);
        console_out("\n");
        return 1;
    }

    // Check if target block already has a burnt key
    if (crypto_is_key_block_burnt(block)) {
        console_out("\n");
        console_out("WARNING: EFUSE_BLK_KEY%d already has a burnt key!\n", block - 4);
        console_out("Purpose: %d\n", esp_efuse_get_key_purpose(static_cast<esp_efuse_block_t>(block)));
        console_out("\n");
        console_out("If this key was not burnt for DS/HMAC_DOWN_DIGITAL_SIGNATURE,\n");
        console_out("the device will fail to generate a valid signing key.\n");
        console_out("\n");
    }

    uint8_t current_block = crypto_get_ds_key_block();
    console_out("Current DS key block: EFUSE_BLK_KEY%d (%d)\n", current_block - 4, current_block);
    console_out("New DS key block: EFUSE_BLK_KEY%d (%d)\n", block - 4, block);

    // Set the new block
    esp_err_t err = crypto_set_ds_key_block(block);
    if (err != ESP_OK) {
        console_out("{\"error\":true,\"message\":\"Failed to set DS key block: %s\"}\n", esp_err_to_name(err));
        return 1;
    }

    // Clear all crypto data
    console_out("Clearing all crypto data...\n");
    err = crypto_clear_all_data();
    if (err != ESP_OK) {
        console_out("{\"error\":true,\"message\":\"Failed to clear crypto data: %s\"}\n", esp_err_to_name(err));
        return 1;
    }

    console_out("DS key block changed successfully. Rebooting in 2 seconds...\n");
    vTaskDelay(pdMS_TO_TICKS(2000));
    esp_restart();

    return 0;  // Never reached
}

static void register_set_ds_key_block(void)
{
    set_ds_key_block_args.block = arg_int1(NULL, NULL, "<block>", "eFuse block number (4-9)");
    set_ds_key_block_args.confirm = arg_lit0(NULL, "confirm", NULL);
    set_ds_key_block_args.end = arg_end(2);

    const esp_console_cmd_t cmd = {
        .command = "set_ds_key_block",
        .help = "Set the eFuse block for DS key storage (4-9 = KEY0-KEY5)",
        .hint = NULL,
        .func = &set_ds_key_block,
        .argtable = &set_ds_key_block_args
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&cmd));
}

static int check_key_blocks(int argc, char** argv)
{
    uint8_t current_block = crypto_get_ds_key_block();

    console_out("\neFuse Key Block Status:\n");
    console_out("%-8s %-6s %s\n", "Block", "ID", "Status");
    console_out("%-8s %-6s %s\n", "-----", "--", "------");

    for (int block = DS_KEY_BLOCK_MIN; block <= DS_KEY_BLOCK_MAX; block++) {
        bool is_burnt = crypto_is_key_block_burnt(block);
        bool is_current = (block == current_block);

        console_out("KEY%d     %-6d %s%s\n",
            block - DS_KEY_BLOCK_MIN,
            block,
            is_burnt ? "BURNT" : "EMPTY",
            is_current ? " <-- current" : "");
    }

    console_out("\n");
    return 0;
}

static void register_check_key_blocks(void)
{
    const esp_console_cmd_t cmd = {
        .command = "check_key_blocks",
        .help = "Show status of all eFuse key blocks (KEY0-KEY5)",
        .hint = NULL,
        .func = &check_key_blocks,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&cmd));
}
#endif // CONFIG_KD_COMMON_CRYPTO_ENABLE

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

#ifdef CONFIG_KD_COMMON_CRYPTO_ENABLE
    register_crypto_status();
    register_get_csr();
    register_set_device_cert();
    register_get_device_cert();
    register_get_ds_params();
    register_set_ds_key_block();
    register_check_key_blocks();
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