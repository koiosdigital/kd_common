#include "ble_console.h"

#ifndef KD_COMMON_CONSOLE_DISABLE

#include <string.h>
#include <stdlib.h>

#include <esp_log.h>
#include <esp_system.h>
#include <cJSON.h>

#include "kd_common.h"
#include "crypto.h"

uint8_t console_in_buffer[4096];
uint8_t console_out_buffer[4096];
uint32_t console_in_buffer_pos = 0;
uint32_t console_out_buffer_pos = 0;
uint32_t console_in_buffer_total = 0;
uint32_t console_out_buffer_total = 0;
bool multipart_sending = false;

void reset_input_buffer() {
    memset(console_in_buffer, 0, sizeof(console_in_buffer));
    console_in_buffer_pos = 0;
    console_in_buffer_total = 0;
}

void reset_output_buffer() {
    memset(console_out_buffer, 0, sizeof(console_out_buffer));
    console_out_buffer_pos = 0;
    console_out_buffer_total = 0;
    multipart_sending = false;
}

void reset_buffers() {
    reset_input_buffer();
    reset_output_buffer();
}

esp_err_t ble_console_endpoint(uint32_t session_id, const uint8_t* inbuf, ssize_t inlen, uint8_t** outbuf, ssize_t* outlen, void* priv_data) {
    //append to buffer, if not currently sending multipart message
    if (inbuf && !multipart_sending) {
        if (console_in_buffer_pos + inlen > sizeof(console_in_buffer)) {
            reset_input_buffer();
        }
        memcpy(console_in_buffer + console_in_buffer_pos, inbuf, inlen);
        console_in_buffer_pos += inlen;
        console_in_buffer_total += inlen;

        *outbuf = (uint8_t*)strdup("OK");
        *outlen = strlen((char*)*outbuf);
    }

    //if the last character of the inbuf is a newline, we can assume the message is complete
    if (console_in_buffer_pos > 0 && console_in_buffer[console_in_buffer_pos - 1] == '\n') {
        //remove the newline
        console_in_buffer[console_in_buffer_pos - 1] = '\0';

        free(*outbuf);
        *outbuf = NULL;
        *outlen = 0;

        reset_output_buffer();
        int return_code = 0;
        char* tmp_output = kd_common_run_command((char*)console_in_buffer, &return_code);

        if (strlen(tmp_output) != 0) {
            memcpy(console_out_buffer, tmp_output, strlen(tmp_output));
        }
        else {
            sprintf((char*)console_out_buffer, "{\"error\":false,\"error_message\":\"no output\",\"return_code\":%i}\n", return_code);
        }

        free(tmp_output);
        console_out_buffer_total = strlen((char*)console_out_buffer);
        multipart_sending = true;
    }

    //handle multipart sending, if we're currently sending, ignore the inbuf and write 512 bytes to the outbuf
    if (multipart_sending) {
        size_t length = console_out_buffer_total - console_out_buffer_pos;
        if (length > 512) {
            length = 512;
        }
        *outbuf = (uint8_t*)calloc(length, sizeof(uint8_t));
        memcpy(*outbuf, console_out_buffer + console_out_buffer_pos, length);

        *outlen = length;
        console_out_buffer_pos += length;

        if (console_out_buffer_pos >= console_out_buffer_total) {
            reset_buffers();
        }
    }

    return ESP_OK;
}

#endif // KD_COMMON_CONSOLE_DISABLE