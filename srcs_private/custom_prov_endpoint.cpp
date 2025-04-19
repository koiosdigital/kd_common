#include "custom_prov_endpoint.h"

#include <string.h>
#include <stdlib.h>

#include <esp_log.h>
#include <esp_system.h>
#include <cJSON.h>

#include "crypto.h"
#include "crypto_private.h"

uint8_t certmgr_in_buf[4096];
uint8_t certmgr_out_buf[4096];
uint32_t certmgr_in_pos = 0;
uint32_t certmgr_out_pos = 0;
uint32_t certmgr_out_total = 0;
uint32_t certmgr_in_total = 0;
bool multipart_sending = false;

void reset_input_buffer() {
    memset(certmgr_in_buf, 0, sizeof(certmgr_in_buf));
    certmgr_in_pos = 0;
    certmgr_in_total = 0;
}

void reset_output_buffer() {
    memset(certmgr_out_buf, 0, sizeof(certmgr_out_buf));
    certmgr_out_pos = 0;
    certmgr_out_total = 0;
    multipart_sending = false;
}

void reset_buffers() {
    reset_input_buffer();
    reset_output_buffer();
}

esp_err_t custom_prov_endpoint(uint32_t session_id, const uint8_t* inbuf, ssize_t inlen, uint8_t** outbuf, ssize_t* outlen, void* priv_data) {
    //append to buffer, if not currently sending multipart message
    if (inbuf && !multipart_sending) {
        if (certmgr_in_pos + inlen > sizeof(certmgr_in_buf)) {
            reset_input_buffer();
        }
        memcpy(certmgr_in_buf + certmgr_in_pos, inbuf, inlen);
        certmgr_in_pos += inlen;
        certmgr_in_total += inlen;
    }

    if (certmgr_in_total > 0 && !multipart_sending) {
        cJSON* json = cJSON_Parse((const char*)certmgr_in_buf);
        if (json == NULL) {
            *outbuf = (uint8_t*)strdup("{\"ack\":true, \"need_more_data\":true, \"error\":\"\"}");
            *outlen = strlen((char*)*outbuf);
            return ESP_OK; //assuming we need more data
        }

        //check for action
        if (!cJSON_HasObjectItem(json, "action")) {
            cJSON_Delete(json);
            reset_input_buffer();
            *outbuf = (uint8_t*)strdup("{\"ack\":true, \"need_more_data\":false, \"error\":\"bad packet\"}");
            *outlen = strlen((char*)*outbuf);
            return ESP_OK;
        }

        cJSON* output = cJSON_CreateObject();
        if (output == NULL) {
            cJSON_Delete(json);
            reset_input_buffer();
            return ESP_FAIL;
        }

        const char* action = cJSON_GetObjectItem(json, "action")->valuestring;
        if (strcmp(action, "get_csr") == 0) {
            size_t csr_len = 4096;
            char* temp_csr_buf = (char*)calloc(csr_len, sizeof(char));

            esp_err_t error = crypto_get_csr(temp_csr_buf, &csr_len);
            if (error != ESP_OK) {
                cJSON_Delete(json);
                cJSON_Delete(output);
                reset_input_buffer();
                reset_output_buffer();
                *outbuf = (uint8_t*)strdup("{\"ack\":true, \"need_more_data\":false, \"error\":\"no csr\"}");
                *outlen = strlen((char*)*outbuf);
                return ESP_OK;
            }

            cJSON_AddStringToObject(output, "csr", temp_csr_buf);

            reset_buffers();
            cJSON_PrintPreallocated(output, (char*)certmgr_out_buf, 4096, false);

            certmgr_out_total = strlen((char*)certmgr_out_buf);
            multipart_sending = true;

            free(temp_csr_buf);
            cJSON_Delete(output);
            cJSON_Delete(json);
        }
        else if (strcmp(action, "set_cert") == 0) {
            //check if we have cert parameter
            if (!cJSON_HasObjectItem(json, "cert")) {
                cJSON_Delete(json);
                cJSON_Delete(output);
                reset_input_buffer();
                reset_output_buffer();
                *outbuf = (uint8_t*)strdup("{\"ack\":true, \"need_more_data\":false, \"error\":\"no cert\"}");
                *outlen = strlen((char*)*outbuf);
                return ESP_OK;
            }
            const char* cert = cJSON_GetObjectItem(json, "cert")->valuestring;
            size_t cert_len = strlen(cert);

            crypto_set_device_cert((char*)cert, cert_len);
            crypto_clear_csr();

            cJSON_Delete(json);
            cJSON_Delete(output);
            reset_input_buffer();
            reset_output_buffer();
            *outbuf = (uint8_t*)strdup("{\"ack\":true, \"need_more_data\":false, \"success\":true}");
            *outlen = strlen((char*)*outbuf);
            return ESP_OK;
        }
        else if (strcmp(action, "status") == 0) {
            bool has_csr = crypto_get_csr(NULL, NULL) == ESP_OK;
            bool has_cert = kd_common_get_device_cert(NULL, NULL) == ESP_OK;

            cJSON_AddBoolToObject(output, "has_csr", has_csr);
            cJSON_AddBoolToObject(output, "has_cert", has_cert);

            reset_buffers();
            cJSON_PrintPreallocated(output, (char*)certmgr_out_buf, 4096, false);

            certmgr_out_total = strlen((char*)certmgr_out_buf);
            multipart_sending = true;

            cJSON_Delete(output);
            cJSON_Delete(json);
        }
        else {
            cJSON_Delete(json);
            cJSON_Delete(output);
            reset_input_buffer();
            reset_output_buffer();
            *outbuf = (uint8_t*)strdup("{\"ack\":true, \"need_more_data\":false, \"error\":\"invalid action\"}");
            *outlen = strlen((char*)*outbuf);
            return ESP_OK;
        }
    }

    //handle multipart sending, if we're currently sending, ignore the inbuf and write 512 bytes to the outbuf
    if (multipart_sending) {
        size_t length = certmgr_out_total - certmgr_out_pos;
        if (length > 512) {
            length = 512;
        }
        *outbuf = (uint8_t*)calloc(length, sizeof(uint8_t));
        memcpy(*outbuf, certmgr_out_buf + certmgr_out_pos, length);
        *outlen = length;
        certmgr_out_pos += length;

        if (certmgr_out_pos >= certmgr_out_total) {
            reset_buffers();
        }

        return ESP_OK;
    }

    return ESP_FAIL;
}