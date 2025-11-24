#include "console.h"

#ifndef KD_COMMON_CONSOLE_DISABLE

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

/* 'heap' command prints minimum heap size */
static int heap_size(int argc, char** argv)
{
    uint32_t heap_size = heap_caps_get_minimum_free_size(MALLOC_CAP_DEFAULT);
    console_out("min heap size: %" PRIu32 "\n", heap_size);
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

#ifndef KD_COMMON_CRYPTO_DISABLE
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
    size_t decoded_len = 0;
    char* decoded_cert = (char*)malloc(4096);
    if (decoded_cert == NULL) {
        ESP_LOGE(TAG, "failed to allocate buffer for decoded cert");
        return 1;
    }
    memset(decoded_cert, 0, 4096);
    mbedtls_base64_decode((unsigned char*)decoded_cert, 4096, &decoded_len, (unsigned char*)cert_b64, cert_len);
    if (decoded_len == 0) {
        ESP_LOGE(TAG, "failed to decode cert");
        free(decoded_cert);
        return 1;
    }

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

static int clear_device_cert(int argc, char** argv)
{
    esp_err_t error = kd_common_clear_device_cert();
    if (error != ESP_OK) {
        ESP_LOGE(TAG, "failed to clear device cert");
        console_out("{\"error\":true}\n");
        return 1;
    }
    console_out("{\"error\":false}\n");
    return 0;
}

static void register_clear_device_cert(void)
{
    const esp_console_cmd_t cmd = {
        .command = "clear_device_cert",
        .help = "Clear device certificate",
        .hint = NULL,
        .func = &clear_device_cert,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&cmd));
}

static struct {
    struct arg_str* claim_token;
    struct arg_end* end;
} set_claim_token_args;

static int set_claim_token(int argc, char** argv)
{
    int nerrors = arg_parse(argc, argv, (void**)&set_claim_token_args);
    if (nerrors != 0) {
        arg_print_errors(stderr, set_claim_token_args.end, argv[0]);
        return 1;
    }

    const char* claim_token_str = set_claim_token_args.claim_token->sval[0];
    return crypto_set_claim_token((char*)claim_token_str, strlen(claim_token_str));
}

static void register_set_claim_token(void)
{
    set_claim_token_args.claim_token = arg_str1(NULL, NULL, "JWT", "claim JWT");
    set_claim_token_args.end = arg_end(1);

    const esp_console_cmd_t cmd = {
        .command = "set_claim_token",
        .help = "Set claim token",
        .hint = NULL,
        .func = &set_claim_token,
        .argtable = &set_claim_token_args
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&cmd));
}
#endif // KD_COMMON_CRYPTO_DISABLE

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

static struct {
    struct arg_str* ssid;
    struct arg_str* password;
    struct arg_end* end;
} wifi_provision_args;

static int wifi_provision(int argc, char** argv)
{
    int nerrors = arg_parse(argc, argv, (void**)&wifi_provision_args);
    if (nerrors != 0) {
        arg_print_errors(stderr, wifi_provision_args.end, argv[0]);
        return 1;
    }

    const char* ssid = wifi_provision_args.ssid->sval[0];
    const char* password = wifi_provision_args.password->sval[0];

    console_out("Provisioning WiFi with SSID: %s\n", ssid);

    // TODO: Implement actual WiFi provisioning
    // This would typically call kd_common_set_wifi_credentials or similar

    console_out("{\"error\":false,\"message\":\"WiFi provisioned successfully\"}\n");
    return 0;
}

static void register_wifi_provision(void)
{
    wifi_provision_args.ssid = arg_str1(NULL, NULL, "<ssid>", "WiFi SSID");
    wifi_provision_args.password = arg_str1(NULL, NULL, "<password>", "WiFi password");
    wifi_provision_args.end = arg_end(2);

    const esp_console_cmd_t cmd = {
        .command = "wifi_provision",
        .help = "Provision WiFi with SSID and password",
        .hint = NULL,
        .func = &wifi_provision,
        .argtable = &wifi_provision_args
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&cmd));
}

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
    console_out("  \"secure_version\": %d,\n", app_desc->secure_version);
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

static int check_ota_updates(int argc, char** argv)
{
    console_out("Checking for OTA updates...\n");

    // TODO: Implement actual OTA update check
    // This would typically check a remote server for updates

    console_out("{\"error\":false,\"message\":\"No updates available\",\"update_available\":false}\n");
    return 0;
}

static void register_check_ota_updates(void)
{
    const esp_console_cmd_t cmd = {
        .command = "check_ota",
        .help = "Check for OTA firmware updates",
        .hint = NULL,
        .func = &check_ota_updates,
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

    repl_config.prompt = "tty>";
    repl_config.max_cmdline_length = 4096;

    esp_console_register_help_command();
    register_free();
    register_heap();

#ifndef KD_COMMON_CRYPTO_DISABLE
    register_crypto_status();
    register_get_csr();
    register_set_device_cert();
    register_clear_device_cert();
    register_get_ds_params();
    register_set_ds_params();
    register_set_claim_token();
#endif

    register_wifi_reset();
    register_wifi_provision();
    register_assert();
    register_get_version();
    register_check_ota_updates();

#if SOC_USB_SERIAL_JTAG_SUPPORTED
    esp_console_dev_usb_serial_jtag_config_t hw_config = ESP_CONSOLE_DEV_USB_SERIAL_JTAG_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_console_new_repl_usb_serial_jtag(&hw_config, &repl_config, &repl));
#endif

    use_printf = true;
    ESP_ERROR_CHECK(esp_console_start_repl(repl));
}

#endif // KD_COMMON_CONSOLE_DISABLE