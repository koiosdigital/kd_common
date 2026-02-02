#include "ble_console.h"

#ifdef CONFIG_KD_COMMON_CONSOLE_ENABLE

#include <string.h>
#include <stdlib.h>

#include <esp_log.h>
#include <esp_system.h>

#include "kd/v1/console.pb-c.h"
#include "kd/v1/common.pb-c.h"

#include "kd_common.h"
#ifdef CONFIG_KD_COMMON_CRYPTO_ENABLE
#include "crypto.h"
#endif
#include "ble_console_protocol.h"

static const char* TAG = "ble_console";


#ifdef CONFIG_KD_COMMON_CRYPTO_ENABLE
static uint8_t crypto_retry_count = 0;
static constexpr uint8_t CRYPTO_MAX_RETRIES = 3;
#endif

static void make_error_response(const char* detail) {
    ESP_LOGI(TAG, "error response: %s", detail ? detail : "error");
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
        ESP_LOGE(TAG, "error response too large");
        ble_protocol_reset_output();
        return;
    }

    uint8_t* out_buffer = (uint8_t*)malloc(payload_len);
    if (out_buffer == NULL) {
        ESP_LOGE(TAG, "malloc failed for error response");
        return;
    }

    kd__v1__console_message__pack(&resp, out_buffer);
    ble_protocol_set_output(out_buffer, payload_len);
    free(out_buffer);
}

static void prepare_response(Kd__V1__ConsoleMessage* resp) {
    if (resp == NULL) {
        make_error_response("null response");
        return;
    }

    size_t payload_len = kd__v1__console_message__get_packed_size(resp);
    if (payload_len > BLE_CONSOLE_MAX_PAYLOAD) {
        make_error_response("response too large");
        return;
    }

    uint8_t* out_buffer = (uint8_t*)malloc(payload_len);
    if (out_buffer == NULL) {
        ESP_LOGE(TAG, "malloc failed for response");
        make_error_response("no mem");
        return;
    }

    kd__v1__console_message__pack(resp, out_buffer);
    ble_protocol_set_output(out_buffer, payload_len);
    free(out_buffer);
    ESP_LOGI(TAG, "response ready: %u bytes", (unsigned)payload_len);
}

static void handle_request(const Kd__V1__ConsoleMessage* req) {
    if (req == NULL) {
        make_error_response("unpack failed");
        return;
    }

    ESP_LOGI(TAG, "handle request: payload_case=%d", req->payload_case);

    switch (req->payload_case) {
#ifdef CONFIG_KD_COMMON_CRYPTO_ENABLE
    case KD__V1__CONSOLE_MESSAGE__PAYLOAD_GET_CSR_REQUEST: {
        Kd__V1__CommandResult result = KD__V1__COMMAND_RESULT__INIT;
        result.success = false;
        result.error_code = 0;

        Kd__V1__GetCsrResponse get_csr_resp = KD__V1__GET_CSR_RESPONSE__INIT;
        get_csr_resp.result = &result;
        get_csr_resp.csr_pem.data = NULL;
        get_csr_resp.csr_pem.len = 0;

        // Get CSR length first
        size_t csr_len = 0;
        esp_err_t err = crypto_get_csr(nullptr, &csr_len);
        uint8_t* csr_buf = nullptr;

        if (err != ESP_OK || csr_len == 0) {
            result.error_code = err;
            result.detail = (char*)"no csr";
        }
        else {
            csr_buf = (uint8_t*)malloc(csr_len);
            if (csr_buf == nullptr) {
                result.error_code = ESP_ERR_NO_MEM;
                result.detail = (char*)"no mem";
            }
            else {
                err = crypto_get_csr((char*)csr_buf, &csr_len);
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
        }

        Kd__V1__ConsoleMessage resp = KD__V1__CONSOLE_MESSAGE__INIT;
        resp.payload_case = KD__V1__CONSOLE_MESSAGE__PAYLOAD_GET_CSR_RESPONSE;
        resp.get_csr_response = &get_csr_resp;
        prepare_response(&resp);
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
        prepare_response(&resp);
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

        // Get cert length first
        size_t cert_len = 0;
        esp_err_t err = kd_common_get_device_cert(nullptr, &cert_len);
        uint8_t* cert_buf = nullptr;

        if (err != ESP_OK || cert_len == 0) {
            result.error_code = err;
            result.detail = (char*)"no cert";
        }
        else {
            cert_buf = (uint8_t*)malloc(cert_len);
            if (cert_buf == nullptr) {
                result.error_code = ESP_ERR_NO_MEM;
                result.detail = (char*)"no mem";
            }
            else {
                err = kd_common_get_device_cert((char*)cert_buf, &cert_len);
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
        }

        Kd__V1__ConsoleMessage resp = KD__V1__CONSOLE_MESSAGE__INIT;
        resp.payload_case = KD__V1__CONSOLE_MESSAGE__PAYLOAD_GET_DEVICE_CERT_RESPONSE;
        resp.get_device_cert_response = &get_cert_resp;
        prepare_response(&resp);
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
            crypto_retry_count = 0;
        }
        else {
            crypto_retry_count++;
            if (crypto_retry_count >= CRYPTO_MAX_RETRIES) {
                result.error_code = -1;
                result.detail = (char*)"crypto error: max retries";
                crypto_retry_count = 0;
            }
            else {
                result.error_code = -2;
                result.detail = (char*)"crypto error: retry";
            }
        }

        Kd__V1__GetDsParamsResponse ds_resp = KD__V1__GET_DS_PARAMS_RESPONSE__INIT;
        ds_resp.result = &result;
        ds_resp.ds_params_json = json ? json : (char*)"";

        Kd__V1__ConsoleMessage resp = KD__V1__CONSOLE_MESSAGE__INIT;
        resp.payload_case = KD__V1__CONSOLE_MESSAGE__PAYLOAD_GET_DS_PARAMS_RESPONSE;
        resp.get_ds_params_response = &ds_resp;
        prepare_response(&resp);

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
                esp_err_t err = crypto_store_ds_params_json(params_copy);
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
        prepare_response(&resp);
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
        prepare_response(&resp);
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
        prepare_response(&resp);
        break;
    }
#endif // CONFIG_KD_COMMON_CRYPTO_ENABLE

    default:
        make_error_response("unsupported request");
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

    if (inbuf == NULL || inlen == 0) {
        return ESP_OK;
    }

    // Handle single-byte control commands
    if (inlen == 1) {
        switch (inbuf[0]) {
        case BLE_CMD_RESET: {
            ESP_LOGI(TAG, "CMD_RESET");
            ble_protocol_reset_all();
            *outbuf = ble_protocol_build_single_response(BLE_RSP_ACK, (size_t*)outlen);
            return ESP_OK;
        }

        case BLE_CMD_NEXT: {
            ESP_LOGI(TAG, "CMD_NEXT");
            if (ble_protocol_has_output()) {
                *outbuf = ble_protocol_build_next_chunk((size_t*)outlen);
                if (*outbuf == NULL) {
                    *outbuf = ble_protocol_build_single_response(BLE_RSP_EMPTY, (size_t*)outlen);
                }
            }
            else {
                *outbuf = ble_protocol_build_single_response(BLE_RSP_EMPTY, (size_t*)outlen);
            }
            return ESP_OK;
        }

        case BLE_CMD_RETRANSMIT: {
            ESP_LOGI(TAG, "CMD_RETRANSMIT");
            *outbuf = ble_protocol_build_retransmit((size_t*)outlen);
            if (*outbuf == NULL) {
                *outbuf = ble_protocol_build_single_response(BLE_RSP_EMPTY, (size_t*)outlen);
            }
            return ESP_OK;
        }

        default:
            // Unknown single-byte command, ignore
            return ESP_OK;
        }
    }

    // Handle data frames
    if (inbuf[0] == BLE_FRAME_MAGIC) {
        ble_receive_result_t result = ble_protocol_receive_chunk(inbuf, (size_t)inlen);

        if (result == BLE_RECEIVE_CRC_ERROR) {
            // CRC error - request retransmit
            *outbuf = ble_protocol_build_single_response(BLE_CMD_RETRANSMIT, (size_t*)outlen);
            return ESP_OK;
        }

        if (result == BLE_RECEIVE_COMPLETE) {
            ESP_LOGI(TAG, "request complete, processing...");

            const uint8_t* input_data = ble_protocol_get_input_data();
            size_t input_len = ble_protocol_get_input_len();

            Kd__V1__ConsoleMessage* req = kd__v1__console_message__unpack(NULL, input_len, input_data);
            handle_request(req);
            if (req != NULL) {
                kd__v1__console_message__free_unpacked(req, NULL);
            }
            ble_protocol_reset_input();

            // Send first response chunk
            if (ble_protocol_has_output()) {
                *outbuf = ble_protocol_build_next_chunk((size_t*)outlen);
            }
        }
        else if (result == BLE_RECEIVE_OK) {
            // More chunks expected - request next chunk
            *outbuf = ble_protocol_build_single_response(BLE_CMD_NEXT, (size_t*)outlen);
        }

        return ESP_OK;
    }

    // Unknown frame type
    ESP_LOGW(TAG, "unknown frame type: 0x%02X", inbuf[0]);
    return ESP_OK;
}

#endif // CONFIG_KD_COMMON_CONSOLE_ENABLE
