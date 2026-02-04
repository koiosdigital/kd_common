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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static const char* TAG = "crypto_console";

// Chunked cert upload state
#define CERT_UPLOAD_BUFFER_SIZE (16 * 1024)  // 16KB for cert chains
static char* s_cert_upload_buffer = NULL;
static size_t s_cert_upload_pos = 0;
static int s_cert_upload_next_chunk = 0;
static bool s_cert_upload_active = false;

static int cmd_crypto_status(int argc, char** argv) {
    printf("{\"status\":%i,\"error\":false}\n", kd_common_crypto_get_state());
    return 0;
}

static int cmd_get_csr(int argc, char** argv) {
    size_t csr_len = 0;
    esp_err_t error = crypto_get_csr(NULL, &csr_len);
    if (error != ESP_OK || csr_len == 0) {
        printf("[ERROR] No CSR available\n");
        return 1;
    }

    char* csr = (char*)malloc(csr_len);
    if (csr == NULL) {
        printf("[ERROR] Memory allocation failed\n");
        return 1;
    }

    error = crypto_get_csr(csr, &csr_len);
    if (error != ESP_OK) {
        free(csr);
        printf("[ERROR] Failed to read CSR\n");
        return 1;
    }

    // Output raw PEM directly
    printf("%s", csr);
    free(csr);
    return 0;
}

// Chunked cert upload commands

static int cmd_set_cert_start(int argc, char** argv) {
    // Free any existing buffer
    if (s_cert_upload_buffer != NULL) {
        free(s_cert_upload_buffer);
    }

    // Allocate buffer
    s_cert_upload_buffer = (char*)calloc(CERT_UPLOAD_BUFFER_SIZE, 1);
    if (s_cert_upload_buffer == NULL) {
        printf("[ERROR] Failed to allocate upload buffer\n");
        return 1;
    }

    s_cert_upload_pos = 0;
    s_cert_upload_next_chunk = 0;
    s_cert_upload_active = true;

    printf("[OK] Cert upload started, send chunks with set_cert_chunk\n");
    return 0;
}

static struct {
    struct arg_int* index;
    struct arg_str* data;
    struct arg_end* end;
} s_set_cert_chunk_args;

static int cmd_set_cert_chunk(int argc, char** argv) {
    int nerrors = arg_parse(argc, argv, (void**)&s_set_cert_chunk_args);
    if (nerrors != 0) {
        arg_print_errors(stderr, s_set_cert_chunk_args.end, argv[0]);
        return 1;
    }

    if (!s_cert_upload_active || s_cert_upload_buffer == NULL) {
        printf("[ERROR] No upload in progress, call set_cert_start first\n");
        return 1;
    }

    int chunk_idx = s_set_cert_chunk_args.index->ival[0];
    if (chunk_idx != s_cert_upload_next_chunk) {
        printf("[ERROR] Expected chunk %d, got %d\n", s_cert_upload_next_chunk, chunk_idx);
        return 1;
    }

    const char* b64_data = s_set_cert_chunk_args.data->sval[0];
    size_t b64_len = strlen(b64_data);

    // Append base64 data to buffer (we'll decode all at once in commit)
    if (s_cert_upload_pos + b64_len >= CERT_UPLOAD_BUFFER_SIZE) {
        printf("[ERROR] Buffer overflow, cert too large\n");
        s_cert_upload_active = false;
        return 1;
    }

    memcpy(s_cert_upload_buffer + s_cert_upload_pos, b64_data, b64_len);
    s_cert_upload_pos += b64_len;
    s_cert_upload_next_chunk++;

    printf("[OK] Chunk %d received (%zu bytes)\n", chunk_idx, b64_len);
    return 0;
}

static int cmd_set_cert_commit(int argc, char** argv) {
    if (!s_cert_upload_active || s_cert_upload_buffer == NULL) {
        printf("[ERROR] No upload in progress\n");
        return 1;
    }

    if (s_cert_upload_pos == 0) {
        printf("[ERROR] No data received\n");
        s_cert_upload_active = false;
        return 1;
    }

    // Decode base64
    size_t decoded_len = 0;
    int ret = mbedtls_base64_decode(NULL, 0, &decoded_len,
        (unsigned char*)s_cert_upload_buffer, s_cert_upload_pos);
    if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL || decoded_len == 0) {
        printf("[ERROR] Invalid base64 data\n");
        s_cert_upload_active = false;
        return 1;
    }

    char* decoded_cert = (char*)malloc(decoded_len + 1);
    if (decoded_cert == NULL) {
        printf("[ERROR] Failed to allocate decode buffer\n");
        s_cert_upload_active = false;
        return 1;
    }

    ret = mbedtls_base64_decode((unsigned char*)decoded_cert, decoded_len + 1, &decoded_len,
        (unsigned char*)s_cert_upload_buffer, s_cert_upload_pos);
    if (ret != 0) {
        printf("[ERROR] Base64 decode failed\n");
        free(decoded_cert);
        s_cert_upload_active = false;
        return 1;
    }
    decoded_cert[decoded_len] = '\0';

    // Validate it looks like a PEM cert
    if (strstr(decoded_cert, "-----BEGIN CERTIFICATE-----") == NULL) {
        printf("[ERROR] Invalid certificate format (not PEM)\n");
        free(decoded_cert);
        s_cert_upload_active = false;
        return 1;
    }

    // Save the certificate
    esp_err_t err = crypto_set_device_cert(decoded_cert, decoded_len);
    free(decoded_cert);

    // Cleanup upload state
    free(s_cert_upload_buffer);
    s_cert_upload_buffer = NULL;
    s_cert_upload_active = false;

    if (err != ESP_OK) {
        printf("[ERROR] Failed to save certificate: %s\n", esp_err_to_name(err));
        return 1;
    }

    printf("[OK] Certificate saved (%zu bytes, %d chunks)\n", decoded_len, s_cert_upload_next_chunk);
    return 0;
}

static int cmd_get_device_cert(int argc, char** argv) {
    size_t cert_len = 0;
    esp_err_t err = kd_common_get_device_cert(NULL, &cert_len);
    if (err != ESP_OK || cert_len == 0) {
        printf("{\"error\":true,\"message\":\"No device certificate found\"}\n");
        return 1;
    }

    char* cert = (char*)malloc(cert_len + 1);
    if (!cert) {
        printf("{\"error\":true,\"message\":\"Memory allocation failed\"}\n");
        return 1;
    }

    err = kd_common_get_device_cert(cert, &cert_len);
    if (err != ESP_OK) {
        free(cert);
        printf("{\"error\":true,\"message\":\"Failed to read certificate\"}\n");
        return 1;
    }
    cert[cert_len] = '\0';

    printf("%s\n", cert);
    free(cert);
    return 0;
}

static int cmd_get_ds_params(int argc, char** argv) {
    char* json = crypto_get_ds_params_json();
    if (json == NULL) {
        printf("{\"error\":true,\"message\":\"No DS params found\"}\n");
        return 1;
    }
    printf("%s\n", json);
    free(json);
    return 0;
}

static struct {
    struct arg_int* block;
    struct arg_lit* confirm;
    struct arg_end* end;
} s_set_ds_key_block_args;

static int cmd_set_ds_key_block(int argc, char** argv) {
    int nerrors = arg_parse(argc, argv, (void**)&s_set_ds_key_block_args);
    if (nerrors != 0) {
        arg_print_errors(stderr, s_set_ds_key_block_args.end, argv[0]);
        return 1;
    }

    int block = s_set_ds_key_block_args.block->ival[0];

    if (block < 4 || block > 9) {
        printf("{\"error\":true,\"message\":\"Invalid block. Valid range: 4-9 (KEY0-KEY5)\"}\n");
        return 1;
    }

    if (s_set_ds_key_block_args.confirm->count == 0) {
        printf("\n");
        printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
        printf("!!                    CRITICAL WARNING                         !!\n");
        printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
        printf("\n");
        printf("This command will:\n");
        printf("  1. Change the DS key block to EFUSE_BLK_KEY%d\n", block - 4);
        printf("  2. PERMANENTLY DELETE all crypto data (CSR, certificate, DS params)\n");
        printf("  3. Reboot the device\n");
        printf("\n");
        printf("After reboot, the device will generate a NEW private key and burn\n");
        printf("it to the new eFuse block. This is IRREVERSIBLE.\n");
        printf("\n");
        printf("The device will need to be RE-PROVISIONED with a new certificate.\n");
        printf("The old certificate will NO LONGER WORK.\n");
        printf("\n");
        printf("If no valid HMAC key exists in the target block, this WILL\n");
        printf("render the device PERMANENTLY UNUSABLE for mTLS authentication.\n");
        printf("\n");
        printf("To proceed, run: set_ds_key_block %d --confirm\n", block);
        printf("\n");
        return 1;
    }

    if (crypto_is_key_block_burnt(block)) {
        printf("\n");
        printf("WARNING: EFUSE_BLK_KEY%d already has a burnt key!\n", block - 4);
        printf("Purpose: %d\n", esp_efuse_get_key_purpose((esp_efuse_block_t)block));
        printf("\n");
        printf("If this key was not burnt for DS/HMAC_DOWN_DIGITAL_SIGNATURE,\n");
        printf("the device will fail to generate a valid signing key.\n");
        printf("\n");
    }

    uint8_t current_block = crypto_get_ds_key_block();
    printf("Current DS key block: EFUSE_BLK_KEY%d (%d)\n", current_block - 4, current_block);
    printf("New DS key block: EFUSE_BLK_KEY%d (%d)\n", block - 4, block);

    esp_err_t err = crypto_set_ds_key_block(block);
    if (err != ESP_OK) {
        printf("{\"error\":true,\"message\":\"Failed to set DS key block: %s\"}\n", esp_err_to_name(err));
        return 1;
    }

    printf("Clearing all crypto data...\n");
    err = crypto_clear_all_data();
    if (err != ESP_OK) {
        printf("{\"error\":true,\"message\":\"Failed to clear crypto data: %s\"}\n", esp_err_to_name(err));
        return 1;
    }

    printf("DS key block changed successfully. Rebooting in 2 seconds...\n");
    vTaskDelay(pdMS_TO_TICKS(2000));
    esp_restart();

    return 0;
}

static int cmd_check_key_blocks(int argc, char** argv) {
    uint8_t current_block = crypto_get_ds_key_block();

    printf("\neFuse Key Block Status:\n");
    printf("%-8s %-6s %s\n", "Block", "ID", "Status");
    printf("%-8s %-6s %s\n", "-----", "--", "------");

    for (int block = DS_KEY_BLOCK_MIN; block <= DS_KEY_BLOCK_MAX; block++) {
        bool is_burnt = crypto_is_key_block_burnt(block);
        bool is_current = (block == current_block);

        printf("KEY%d     %-6d %s%s\n",
            block - DS_KEY_BLOCK_MIN,
            block,
            is_burnt ? "BURNT" : "EMPTY",
            is_current ? " <-- current" : "");
    }

    printf("\n");
    return 0;
}

void crypto_console_init(void) {
    kd_console_register_cmd("crypto_status", "Get the current state of the crypto module", cmd_crypto_status);
    kd_console_register_cmd("get_csr", "Get the CSR (raw PEM output)", cmd_get_csr);

    // Chunked cert upload commands
    kd_console_register_cmd("set_cert_start", "Begin chunked certificate upload", cmd_set_cert_start);

    s_set_cert_chunk_args.index = arg_int1(NULL, NULL, "<index>", "Chunk index (0-based)");
    s_set_cert_chunk_args.data = arg_str1(NULL, NULL, "<base64>", "Base64-encoded chunk");
    s_set_cert_chunk_args.end = arg_end(2);
    kd_console_register_cmd_with_args("set_cert_chunk", "Add a chunk to certificate upload", cmd_set_cert_chunk, &s_set_cert_chunk_args);

    kd_console_register_cmd("set_cert_commit", "Finalize and save uploaded certificate", cmd_set_cert_commit);

    kd_console_register_cmd("get_device_cert", "Get device certificate (raw PEM output)", cmd_get_device_cert);
    kd_console_register_cmd("get_ds_params", "Get digital signature parameters (ds_key_id, rsa_len, cipher_c, iv)", cmd_get_ds_params);

    s_set_ds_key_block_args.block = arg_int1(NULL, NULL, "<block>", "eFuse block number (4-9)");
    s_set_ds_key_block_args.confirm = arg_lit0(NULL, "confirm", NULL);
    s_set_ds_key_block_args.end = arg_end(2);
    kd_console_register_cmd_with_args("set_ds_key_block", "Set the eFuse block for DS key storage (4-9 = KEY0-KEY5)", cmd_set_ds_key_block, &s_set_ds_key_block_args);

    kd_console_register_cmd("check_key_blocks", "Show status of all eFuse key blocks (KEY0-KEY5)", cmd_check_key_blocks);
}

#endif // CONFIG_KD_COMMON_CONSOLE_ENABLE
#endif // CONFIG_KD_COMMON_CRYPTO_ENABLE
