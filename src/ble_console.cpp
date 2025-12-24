#include "ble_console.h"

#ifndef KD_COMMON_CONSOLE_DISABLE

#include <string.h>
#include <stdlib.h>

#include <esp_log.h>
#include <esp_system.h>

#include "kd/v1/console.pb-c.h"
#include "kd/v1/common.pb-c.h"

#include "kd_common.h"
#include "crypto.h"

static const char* TAG = "ble_console";

static constexpr uint8_t BLE_CONSOLE_FRAME_MAGIC = 0xA5;
static constexpr size_t BLE_CONSOLE_MAX_PAYLOAD = 4096;
static constexpr size_t BLE_CONSOLE_MAX_FRAME = 3 + BLE_CONSOLE_MAX_PAYLOAD;
static constexpr size_t BLE_CONSOLE_CHUNK_SIZE = 512;

static constexpr size_t BLE_CONSOLE_PEM_BUFFER_SIZE = 4096;

static uint8_t ble_console_in_buffer[BLE_CONSOLE_MAX_FRAME] = { 0 };
static size_t ble_console_in_len = 0;

static uint8_t ble_console_out_buffer[BLE_CONSOLE_MAX_FRAME] = { 0 };
static size_t ble_console_out_pos = 0;
static size_t ble_console_out_len = 0;
static bool ble_console_multipart_sending = false;

static void ble_console_reset_input() {
    memset(ble_console_in_buffer, 0, sizeof(ble_console_in_buffer));
    ble_console_in_len = 0;
}

static void ble_console_reset_output() {
    memset(ble_console_out_buffer, 0, sizeof(ble_console_out_buffer));
    ble_console_out_pos = 0;
    ble_console_out_len = 0;
    ble_console_multipart_sending = false;
}

static void ble_console_reset_all() {
    ble_console_reset_input();
    ble_console_reset_output();
}

static void ble_console_make_error_response(const char* detail) {
    Kd__V1__CommandResult result = KD__V1__COMMAND_RESULT__INIT;
    result.success = false;
    result.error_code = -1;
    result.detail = (char*)(detail ? detail : "error");

    Kd__V1__ErrorResponse err = KD__V1__ERROR_RESPONSE__INIT;
    err.result = &result;

    Kd__V1__ConsoleMessage resp = KD__V1__CONSOLE_MESSAGE__INIT;
    resp.payload_case = KD__V1__CONSOLE_MESSAGE__PAYLOAD_ERROR_RESPONSE;
    resp.error_response = &err;

    size_t payload_len = kd__v1__console_message__get_packed_size(&resp);
    if (payload_len > BLE_CONSOLE_MAX_PAYLOAD) {
        ESP_LOGE(TAG, "internal error response too large (%u)", (unsigned)payload_len);
        ble_console_reset_output();
        return;
    }

    ble_console_out_buffer[0] = BLE_CONSOLE_FRAME_MAGIC;
    ble_console_out_buffer[1] = (uint8_t)((payload_len >> 8) & 0xFF);
    ble_console_out_buffer[2] = (uint8_t)(payload_len & 0xFF);
    kd__v1__console_message__pack(&resp, ble_console_out_buffer + 3);

    ble_console_out_len = 3 + payload_len;
    ble_console_out_pos = 0;
    ble_console_multipart_sending = true;
}

static esp_err_t ble_console_send_next_chunk(uint8_t** outbuf, ssize_t* outlen) {
    if (outbuf == NULL || outlen == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    *outbuf = NULL;
    *outlen = 0;

    size_t remaining = (ble_console_out_len > ble_console_out_pos) ? (ble_console_out_len - ble_console_out_pos) : 0;
    size_t chunk = remaining;
    if (chunk > BLE_CONSOLE_CHUNK_SIZE) {
        chunk = BLE_CONSOLE_CHUNK_SIZE;
    }

    if (chunk == 0) {
        ble_console_reset_all();
        return ESP_OK;
    }

    uint8_t* resp = (uint8_t*)malloc(chunk);
    if (resp == NULL) {
        ble_console_reset_all();
        return ESP_ERR_NO_MEM;
    }

    memcpy(resp, ble_console_out_buffer + ble_console_out_pos, chunk);
    ble_console_out_pos += chunk;

    *outbuf = resp;
    *outlen = (ssize_t)chunk;

    if (ble_console_out_pos >= ble_console_out_len) {
        ble_console_reset_all();
    }

    return ESP_OK;
}

static void ble_console_prepare_response(Kd__V1__ConsoleMessage* resp) {
    if (resp == NULL) {
        ble_console_make_error_response("null response");
        return;
    }

    size_t payload_len = kd__v1__console_message__get_packed_size(resp);
    if (payload_len > BLE_CONSOLE_MAX_PAYLOAD) {
        ble_console_make_error_response("response too large");
        return;
    }

    ble_console_out_buffer[0] = BLE_CONSOLE_FRAME_MAGIC;
    ble_console_out_buffer[1] = (uint8_t)((payload_len >> 8) & 0xFF);
    ble_console_out_buffer[2] = (uint8_t)(payload_len & 0xFF);
    kd__v1__console_message__pack(resp, ble_console_out_buffer + 3);

    ble_console_out_len = 3 + payload_len;
    ble_console_out_pos = 0;
    ble_console_multipart_sending = true;
}

static void ble_console_handle_request(const Kd__V1__ConsoleMessage* req) {
    if (req == NULL) {
        ble_console_make_error_response("unpack failed");
        return;
    }

    switch (req->payload_case) {
    case KD__V1__CONSOLE_MESSAGE__PAYLOAD_GET_CSR_REQUEST: {
        Kd__V1__CommandResult result = KD__V1__COMMAND_RESULT__INIT;
        result.success = false;
        result.error_code = 0;

        Kd__V1__GetCsrResponse get_csr_resp = KD__V1__GET_CSR_RESPONSE__INIT;
        get_csr_resp.result = &result;
        get_csr_resp.csr_pem.data = NULL;
        get_csr_resp.csr_pem.len = 0;

        uint8_t* csr_buf = (uint8_t*)malloc(BLE_CONSOLE_PEM_BUFFER_SIZE);
        if (csr_buf == NULL) {
            result.error_code = ESP_ERR_NO_MEM;
            result.detail = (char*)"no mem";
        }
        else {
            size_t csr_len = BLE_CONSOLE_PEM_BUFFER_SIZE;
            esp_err_t err = crypto_get_csr((char*)csr_buf, &csr_len);
            if (err == ESP_OK) {
                result.success = true;
                result.detail = (char*)"ok";
                get_csr_resp.csr_pem.data = csr_buf;
                get_csr_resp.csr_pem.len = csr_len;
            }
            else {
                result.error_code = err;
                result.detail = (char*)"no csr";
            }
        }

        Kd__V1__ConsoleMessage resp = KD__V1__CONSOLE_MESSAGE__INIT;
        resp.payload_case = KD__V1__CONSOLE_MESSAGE__PAYLOAD_GET_CSR_RESPONSE;
        resp.get_csr_response = &get_csr_resp;

        ble_console_prepare_response(&resp);
        free(csr_buf);
        break;
    }

    case KD__V1__CONSOLE_MESSAGE__PAYLOAD_SET_DEVICE_CERT_REQUEST: {
        Kd__V1__CommandResult result = KD__V1__COMMAND_RESULT__INIT;
        result.success = false;
        result.error_code = 0;
        result.detail = (char*)"invalid";

        const Kd__V1__SetDeviceCertRequest* set_req = req->set_device_cert_request;
        if (set_req && set_req->cert_pem.data && set_req->cert_pem.len > 0) {
            esp_err_t err = crypto_set_device_cert((char*)set_req->cert_pem.data, set_req->cert_pem.len);
            if (err == ESP_OK) {
                result.success = true;
                result.detail = (char*)"ok";
            }
            else {
                result.error_code = err;
                result.detail = (char*)"failed";
            }
        }

        Kd__V1__SetDeviceCertResponse set_resp = KD__V1__SET_DEVICE_CERT_RESPONSE__INIT;
        set_resp.result = &result;

        Kd__V1__ConsoleMessage resp = KD__V1__CONSOLE_MESSAGE__INIT;
        resp.payload_case = KD__V1__CONSOLE_MESSAGE__PAYLOAD_SET_DEVICE_CERT_RESPONSE;
        resp.set_device_cert_response = &set_resp;

        ble_console_prepare_response(&resp);
        break;
    }

    case KD__V1__CONSOLE_MESSAGE__PAYLOAD_CLEAR_DEVICE_CERT_REQUEST: {
        Kd__V1__CommandResult result = KD__V1__COMMAND_RESULT__INIT;
        result.success = false;
        result.error_code = 0;
        result.detail = (char*)"failed";

        esp_err_t err = kd_common_clear_device_cert();
        if (err == ESP_OK) {
            result.success = true;
            result.detail = (char*)"ok";
        }
        else {
            result.error_code = err;
        }

        Kd__V1__ClearDeviceCertResponse clear_resp = KD__V1__CLEAR_DEVICE_CERT_RESPONSE__INIT;
        clear_resp.result = &result;

        Kd__V1__ConsoleMessage resp = KD__V1__CONSOLE_MESSAGE__INIT;
        resp.payload_case = KD__V1__CONSOLE_MESSAGE__PAYLOAD_CLEAR_DEVICE_CERT_RESPONSE;
        resp.clear_device_cert_response = &clear_resp;
        ble_console_prepare_response(&resp);
        break;
    }

    case KD__V1__CONSOLE_MESSAGE__PAYLOAD_GET_DEVICE_CERT_REQUEST: {
        Kd__V1__CommandResult result = KD__V1__COMMAND_RESULT__INIT;
        result.success = false;
        result.error_code = 0;

        Kd__V1__GetDeviceCertResponse get_cert_resp = KD__V1__GET_DEVICE_CERT_RESPONSE__INIT;
        get_cert_resp.result = &result;
        get_cert_resp.cert_pem.data = NULL;
        get_cert_resp.cert_pem.len = 0;

        uint8_t* cert_buf = (uint8_t*)malloc(BLE_CONSOLE_PEM_BUFFER_SIZE);
        if (cert_buf == NULL) {
            result.error_code = ESP_ERR_NO_MEM;
            result.detail = (char*)"no mem";
        }
        else {
            size_t cert_len = BLE_CONSOLE_PEM_BUFFER_SIZE;
            esp_err_t err = kd_common_get_device_cert((char*)cert_buf, &cert_len);
            if (err == ESP_OK) {
                result.success = true;
                result.detail = (char*)"ok";
                get_cert_resp.cert_pem.data = cert_buf;
                get_cert_resp.cert_pem.len = cert_len;
            }
            else {
                result.error_code = err;
                result.detail = (char*)"no cert";
            }
        }

        Kd__V1__ConsoleMessage resp = KD__V1__CONSOLE_MESSAGE__INIT;
        resp.payload_case = KD__V1__CONSOLE_MESSAGE__PAYLOAD_GET_DEVICE_CERT_RESPONSE;
        resp.get_device_cert_response = &get_cert_resp;
        ble_console_prepare_response(&resp);
        free(cert_buf);
        break;
    }

    case KD__V1__CONSOLE_MESSAGE__PAYLOAD_GET_DS_PARAMS_REQUEST: {
        Kd__V1__CommandResult result = KD__V1__COMMAND_RESULT__INIT;
        result.success = false;
        result.error_code = 0;
        result.detail = (char*)"no ds params";

        char* json = crypto_get_ds_params_json();
        if (json != NULL) {
            result.success = true;
            result.detail = (char*)"ok";
        }

        Kd__V1__GetDsParamsResponse ds_resp = KD__V1__GET_DS_PARAMS_RESPONSE__INIT;
        ds_resp.result = &result;
        ds_resp.ds_params_json = json ? json : (char*)"";

        Kd__V1__ConsoleMessage resp = KD__V1__CONSOLE_MESSAGE__INIT;
        resp.payload_case = KD__V1__CONSOLE_MESSAGE__PAYLOAD_GET_DS_PARAMS_RESPONSE;
        resp.get_ds_params_response = &ds_resp;
        ble_console_prepare_response(&resp);

        if (json) {
            free(json);
        }
        break;
    }

    case KD__V1__CONSOLE_MESSAGE__PAYLOAD_SET_DS_PARAMS_REQUEST: {
        Kd__V1__CommandResult result = KD__V1__COMMAND_RESULT__INIT;
        result.success = false;
        result.error_code = 0;
        result.detail = (char*)"invalid";

        const Kd__V1__SetDsParamsRequest* set_req = req->set_ds_params_request;
        if (set_req && set_req->ds_params_json != NULL && strlen(set_req->ds_params_json) > 0) {
            char* params_copy = strdup(set_req->ds_params_json);
            if (params_copy == NULL) {
                result.error_code = ESP_ERR_NO_MEM;
                result.detail = (char*)"no mem";
            }
            else {
                esp_err_t err = crypto_store_ds_params_json(params_copy); // takes ownership and frees
                if (err == ESP_OK) {
                    result.success = true;
                    result.detail = (char*)"ok";
                }
                else {
                    result.error_code = err;
                    result.detail = (char*)"failed";
                }
            }
        }

        Kd__V1__SetDsParamsResponse set_resp = KD__V1__SET_DS_PARAMS_RESPONSE__INIT;
        set_resp.result = &result;

        Kd__V1__ConsoleMessage resp = KD__V1__CONSOLE_MESSAGE__INIT;
        resp.payload_case = KD__V1__CONSOLE_MESSAGE__PAYLOAD_SET_DS_PARAMS_RESPONSE;
        resp.set_ds_params_response = &set_resp;
        ble_console_prepare_response(&resp);
        break;
    }

    case KD__V1__CONSOLE_MESSAGE__PAYLOAD_CRYPTO_STATUS_REQUEST: {
        Kd__V1__CommandResult result = KD__V1__COMMAND_RESULT__INIT;
        result.success = true;
        result.error_code = 0;
        result.detail = (char*)"ok";

        Kd__V1__CryptoStatusResponse status_resp = KD__V1__CRYPTO_STATUS_RESPONSE__INIT;
        status_resp.result = &result;
        status_resp.status = (int32_t)kd_common_crypto_get_state();

        Kd__V1__ConsoleMessage resp = KD__V1__CONSOLE_MESSAGE__INIT;
        resp.payload_case = KD__V1__CONSOLE_MESSAGE__PAYLOAD_CRYPTO_STATUS_RESPONSE;
        resp.crypto_status_response = &status_resp;
        ble_console_prepare_response(&resp);
        break;
    }

    case KD__V1__CONSOLE_MESSAGE__PAYLOAD_SET_CLAIM_TOKEN_REQUEST: {
        Kd__V1__CommandResult result = KD__V1__COMMAND_RESULT__INIT;
        result.success = false;
        result.error_code = 0;
        result.detail = (char*)"invalid";

        const Kd__V1__SetClaimTokenRequest* set_req = req->set_claim_token_request;
        if (set_req && set_req->claim_token.data && set_req->claim_token.len > 0) {
            esp_err_t err = crypto_set_claim_token((char*)set_req->claim_token.data, set_req->claim_token.len);
            if (err == ESP_OK) {
                result.success = true;
                result.detail = (char*)"ok";
            }
            else {
                result.error_code = err;
                result.detail = (char*)"failed";
            }
        }
        else {
            result.error_code = ESP_ERR_INVALID_ARG;
        }

        Kd__V1__SetClaimTokenResponse set_resp = KD__V1__SET_CLAIM_TOKEN_RESPONSE__INIT;
        set_resp.result = &result;

        Kd__V1__ConsoleMessage resp = KD__V1__CONSOLE_MESSAGE__INIT;
        resp.payload_case = KD__V1__CONSOLE_MESSAGE__PAYLOAD_SET_CLAIM_TOKEN_RESPONSE;
        resp.set_claim_token_response = &set_resp;
        ble_console_prepare_response(&resp);
        break;
    }

    default:
        ble_console_make_error_response("unsupported request");
        break;
    }
}

esp_err_t ble_console_endpoint(uint32_t session_id, const uint8_t* inbuf, ssize_t inlen, uint8_t** outbuf, ssize_t* outlen, void* priv_data) {
    (void)session_id;
    (void)priv_data;

    if (outbuf == NULL || outlen == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    *outbuf = NULL;
    *outlen = 0;

    // If we're in the middle of sending a multipart response, ignore input and continue sending.
    if (ble_console_multipart_sending) {
        return ble_console_send_next_chunk(outbuf, outlen);
    }

    // Accumulate input bytes.
    if (inbuf != NULL && inlen > 0) {
        if ((size_t)inlen > (sizeof(ble_console_in_buffer) - ble_console_in_len)) {
            ESP_LOGW(TAG, "input overflow, resetting");
            ble_console_reset_input();
        }

        size_t to_copy = (size_t)inlen;
        if (to_copy > (sizeof(ble_console_in_buffer) - ble_console_in_len)) {
            to_copy = sizeof(ble_console_in_buffer) - ble_console_in_len;
        }
        memcpy(ble_console_in_buffer + ble_console_in_len, inbuf, to_copy);
        ble_console_in_len += to_copy;
    }

    // Find frame magic.
    size_t start = 0;
    while (start < ble_console_in_len && ble_console_in_buffer[start] != BLE_CONSOLE_FRAME_MAGIC) {
        start++;
    }
    if (start > 0) {
        // Discard leading noise bytes.
        memmove(ble_console_in_buffer, ble_console_in_buffer + start, ble_console_in_len - start);
        ble_console_in_len -= start;
    }

    // Need at least header.
    if (ble_console_in_len < 3) {
        return ESP_OK;
    }

    if (ble_console_in_buffer[0] != BLE_CONSOLE_FRAME_MAGIC) {
        ble_console_reset_input();
        return ESP_OK;
    }

    size_t payload_len = ((size_t)ble_console_in_buffer[1] << 8) | (size_t)ble_console_in_buffer[2];
    if (payload_len > BLE_CONSOLE_MAX_PAYLOAD) {
        ESP_LOGW(TAG, "payload too large: %u", (unsigned)payload_len);
        ble_console_make_error_response("payload too large");
        ble_console_reset_input();
    }
    else if (ble_console_in_len >= (3 + payload_len)) {
        const uint8_t* payload = ble_console_in_buffer + 3;
        Kd__V1__ConsoleMessage* req = kd__v1__console_message__unpack(NULL, payload_len, payload);
        ble_console_handle_request(req);
        if (req != NULL) {
            kd__v1__console_message__free_unpacked(req, NULL);
        }

        // Remove the frame from input buffer.
        size_t remaining = ble_console_in_len - (3 + payload_len);
        if (remaining > 0) {
            memmove(ble_console_in_buffer, ble_console_in_buffer + (3 + payload_len), remaining);
        }
        ble_console_in_len = remaining;
    }

    // If a response is now ready, send first chunk immediately.
    if (ble_console_multipart_sending) {
        return ble_console_send_next_chunk(outbuf, outlen);
    }

    return ESP_OK;
}

#endif // KD_COMMON_CONSOLE_DISABLE