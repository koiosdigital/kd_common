#include "crypto_console.h"

#ifdef CONFIG_KD_COMMON_CRYPTO_ENABLE
#ifdef CONFIG_KD_COMMON_CONSOLE_ENABLE

#include "crypto.h"
#include "kd_common.h"

#include <esp_efuse.h>
#include <esp_log.h>
#include <argtable3/argtable3.h>
#include <mbedtls/base64.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include <cstdio>
#include <cstring>

static const char* TAG = "crypto_console";

namespace {

    static int cmd_crypto_status(int argc, char** argv) {
        console_out("{\"status\":%i,\"error\":false}\n", kd_common_crypto_get_state());
        return 0;
    }

    static int cmd_get_csr(int argc, char** argv) {
        size_t csr_len = 0;
        esp_err_t error = crypto_get_csr(nullptr, &csr_len);
        if (error != ESP_OK || csr_len == 0) {
            console_out("{\"error_message\":\"no csr\",\"error\":true}\n");
            return 0;
        }

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

        size_t encoded_len = 0;
        mbedtls_base64_encode(nullptr, 0, &encoded_len, (unsigned char*)csr, csr_len);

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

    static struct {
        struct arg_str* cert;
        struct arg_end* end;
    } set_device_cert_args;

    static int cmd_set_device_cert(int argc, char** argv) {
        int nerrors = arg_parse(argc, argv, (void**)&set_device_cert_args);
        if (nerrors != 0) {
            arg_print_errors(stderr, set_device_cert_args.end, argv[0]);
            return 1;
        }

        const char* cert_b64 = set_device_cert_args.cert->sval[0];
        size_t cert_len = strlen(cert_b64);

        size_t decoded_len = 0;
        int ret = mbedtls_base64_decode(nullptr, 0, &decoded_len, (unsigned char*)cert_b64, cert_len);
        if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL || decoded_len == 0) {
            ESP_LOGE(TAG, "failed to get decoded cert size");
            return 1;
        }

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

    static int cmd_get_device_cert(int argc, char** argv) {
        size_t cert_len = 0;
        esp_err_t err = kd_common_get_device_cert(nullptr, &cert_len);
        if (err != ESP_OK || cert_len == 0) {
            console_out("{\"error\":true,\"message\":\"No device certificate found\"}\n");
            return 1;
        }

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

    static int cmd_get_ds_params(int argc, char** argv) {
        char* json = crypto_get_ds_params_json();
        if (json == nullptr) {
            console_out("{\"error\":true,\"message\":\"No DS params found\"}\n");
            return 1;
        }
        console_out("%s\n", json);
        free(json);
        return 0;
    }

    static struct {
        struct arg_int* block;
        struct arg_lit* confirm;
        struct arg_end* end;
    } set_ds_key_block_args;

    static int cmd_set_ds_key_block(int argc, char** argv) {
        int nerrors = arg_parse(argc, argv, (void**)&set_ds_key_block_args);
        if (nerrors != 0) {
            arg_print_errors(stderr, set_ds_key_block_args.end, argv[0]);
            return 1;
        }

        int block = set_ds_key_block_args.block->ival[0];

        if (block < 4 || block > 9) {
            console_out("{\"error\":true,\"message\":\"Invalid block. Valid range: 4-9 (KEY0-KEY5)\"}\n");
            return 1;
        }

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

        esp_err_t err = crypto_set_ds_key_block(block);
        if (err != ESP_OK) {
            console_out("{\"error\":true,\"message\":\"Failed to set DS key block: %s\"}\n", esp_err_to_name(err));
            return 1;
        }

        console_out("Clearing all crypto data...\n");
        err = crypto_clear_all_data();
        if (err != ESP_OK) {
            console_out("{\"error\":true,\"message\":\"Failed to clear crypto data: %s\"}\n", esp_err_to_name(err));
            return 1;
        }

        console_out("DS key block changed successfully. Rebooting in 2 seconds...\n");
        vTaskDelay(pdMS_TO_TICKS(2000));
        esp_restart();

        return 0;
    }

    static int cmd_check_key_blocks(int argc, char** argv) {
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

}  // namespace

void crypto_console_init() {
    kd_console_register_cmd("crypto_status", "Get the current state of the crypto module", cmd_crypto_status);
    kd_console_register_cmd("get_csr", "Get the CSR associated with the device internal private key", cmd_get_csr);

    set_device_cert_args.cert = arg_str1(NULL, NULL, "base64 cert", "base64 pem");
    set_device_cert_args.end = arg_end(1);
    kd_console_register_cmd_with_args("set_device_cert", "Set device cert", cmd_set_device_cert, &set_device_cert_args);

    kd_console_register_cmd("get_device_cert", "Get device certificate", cmd_get_device_cert);
    kd_console_register_cmd("get_ds_params", "Get digital signature parameters (ds_key_id, rsa_len, cipher_c, iv)", cmd_get_ds_params);

    set_ds_key_block_args.block = arg_int1(NULL, NULL, "<block>", "eFuse block number (4-9)");
    set_ds_key_block_args.confirm = arg_lit0(NULL, "confirm", NULL);
    set_ds_key_block_args.end = arg_end(2);
    kd_console_register_cmd_with_args("set_ds_key_block", "Set the eFuse block for DS key storage (4-9 = KEY0-KEY5)", cmd_set_ds_key_block, &set_ds_key_block_args);

    kd_console_register_cmd("check_key_blocks", "Show status of all eFuse key blocks (KEY0-KEY5)", cmd_check_key_blocks);

    ESP_LOGI(TAG, "Crypto console commands registered");
}

#endif // CONFIG_KD_COMMON_CONSOLE_ENABLE
#endif // CONFIG_KD_COMMON_CRYPTO_ENABLE
