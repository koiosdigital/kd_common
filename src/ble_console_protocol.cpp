#include "ble_console_protocol.h"

#include <string.h>
#include <stdlib.h>
#include <esp_log.h>

static const char* TAG = "ble_proto";

// Input reassembly state
static uint8_t in_buffer[BLE_CONSOLE_MAX_PAYLOAD] = { 0 };
static size_t in_total_len = 0;
static size_t in_received = 0;
static uint8_t in_next_chunk_idx = 0;

// Output chunking state
static uint8_t out_buffer[BLE_CONSOLE_MAX_PAYLOAD] = { 0 };
static size_t out_len = 0;
static uint8_t out_next_chunk_idx = 0;
static bool out_has_response = false;

// Last sent frame for retransmission
static uint8_t* last_frame = NULL;
static size_t last_frame_len = 0;

uint16_t ble_protocol_crc16(const uint8_t* data, size_t len) {
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint16_t)data[i] << 8;
        for (uint8_t j = 0; j < 8; j++) {
            if (crc & 0x8000) {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc = crc << 1;
            }
        }
    }
    return crc;
}

void ble_protocol_reset_input(void) {
    ESP_LOGD(TAG, "reset input");
    memset(in_buffer, 0, sizeof(in_buffer));
    in_total_len = 0;
    in_received = 0;
    in_next_chunk_idx = 0;
}

void ble_protocol_reset_output(void) {
    ESP_LOGD(TAG, "reset output");
    memset(out_buffer, 0, sizeof(out_buffer));
    out_len = 0;
    out_next_chunk_idx = 0;
    out_has_response = false;
    if (last_frame != NULL) {
        free(last_frame);
        last_frame = NULL;
        last_frame_len = 0;
    }
}

void ble_protocol_reset_all(void) {
    ESP_LOGD(TAG, "reset all");
    ble_protocol_reset_input();
    ble_protocol_reset_output();
}

ble_receive_result_t ble_protocol_receive_chunk(const uint8_t* frame, size_t frame_len) {
    // Frame format: 0xA5 | total_len_hi | total_len_lo | chunk_idx | chunk_len_hi | chunk_len_lo | payload | crc16_hi | crc16_lo
    if (frame_len < BLE_CONSOLE_FRAME_HEADER_SIZE + BLE_CONSOLE_FRAME_TRAILER_SIZE) {
        ESP_LOGW(TAG, "frame too small: %u", (unsigned)frame_len);
        ble_protocol_reset_input();
        return BLE_RECEIVE_ERROR;
    }

    if (frame[0] != BLE_FRAME_MAGIC) {
        ESP_LOGW(TAG, "invalid magic: 0x%02X", frame[0]);
        ble_protocol_reset_input();
        return BLE_RECEIVE_ERROR;
    }

    uint16_t total_len = ((uint16_t)frame[1] << 8) | (uint16_t)frame[2];
    uint8_t chunk_idx = frame[3];
    uint16_t chunk_len = ((uint16_t)frame[4] << 8) | (uint16_t)frame[5];

    // Validate frame size
    if (frame_len != BLE_CONSOLE_FRAME_HEADER_SIZE + chunk_len + BLE_CONSOLE_FRAME_TRAILER_SIZE) {
        ESP_LOGW(TAG, "frame size mismatch");
        ble_protocol_reset_input();
        return BLE_RECEIVE_ERROR;
    }

    // Verify CRC
    uint16_t rx_crc = ((uint16_t)frame[BLE_CONSOLE_FRAME_HEADER_SIZE + chunk_len] << 8) |
                      (uint16_t)frame[BLE_CONSOLE_FRAME_HEADER_SIZE + chunk_len + 1];
    uint16_t calc_crc = ble_protocol_crc16(frame + BLE_CONSOLE_FRAME_HEADER_SIZE, chunk_len);

    if (rx_crc != calc_crc) {
        ESP_LOGE(TAG, "CRC mismatch: rx=0x%04X calc=0x%04X", rx_crc, calc_crc);
        // Don't reset input - allow retransmit
        return BLE_RECEIVE_CRC_ERROR;
    }

    // First chunk initializes reassembly
    if (chunk_idx == 0) {
        ble_protocol_reset_input();
        in_total_len = total_len;
        in_next_chunk_idx = 0;
    } else {
        // Validate chunk sequence
        if (chunk_idx != in_next_chunk_idx) {
            ESP_LOGW(TAG, "chunk idx mismatch: expected %u got %u", in_next_chunk_idx, chunk_idx);
            ble_protocol_reset_input();
            return BLE_RECEIVE_ERROR;
        }
        if (total_len != in_total_len) {
            ESP_LOGW(TAG, "total_len mismatch");
            ble_protocol_reset_input();
            return BLE_RECEIVE_ERROR;
        }
    }

    // Check buffer overflow
    if (in_received + chunk_len > sizeof(in_buffer)) {
        ESP_LOGE(TAG, "buffer overflow");
        ble_protocol_reset_input();
        return BLE_RECEIVE_ERROR;
    }

    // Copy payload
    memcpy(in_buffer + in_received, frame + BLE_CONSOLE_FRAME_HEADER_SIZE, chunk_len);
    in_received += chunk_len;
    in_next_chunk_idx++;

    ESP_LOGD(TAG, "chunk %u: %u/%u bytes", chunk_idx, (unsigned)in_received, (unsigned)in_total_len);

    // Check if complete
    if (in_received >= in_total_len) {
        return BLE_RECEIVE_COMPLETE;
    }
    return BLE_RECEIVE_OK;
}

const uint8_t* ble_protocol_get_input_data(void) {
    return in_buffer;
}

size_t ble_protocol_get_input_len(void) {
    return in_total_len;
}

void ble_protocol_set_output(const uint8_t* data, size_t len) {
    if (data == NULL || len == 0 || len > BLE_CONSOLE_MAX_PAYLOAD) {
        ESP_LOGE(TAG, "invalid output data");
        return;
    }

    memcpy(out_buffer, data, len);
    out_len = len;
    out_next_chunk_idx = 0;
    out_has_response = true;
    ESP_LOGD(TAG, "output set: %u bytes", (unsigned)len);
}

bool ble_protocol_has_output(void) {
    return out_has_response && out_len > 0;
}

uint8_t* ble_protocol_build_next_chunk(size_t* out_frame_len) {
    if (out_frame_len == NULL) {
        return NULL;
    }

    *out_frame_len = 0;

    if (!out_has_response || out_len == 0) {
        return NULL;
    }

    size_t offset = (size_t)out_next_chunk_idx * BLE_CONSOLE_CHUNK_PAYLOAD_SIZE;
    if (offset >= out_len) {
        // All chunks sent
        out_has_response = false;
        return NULL;
    }

    size_t remaining = out_len - offset;
    size_t chunk_payload_size = (remaining > BLE_CONSOLE_CHUNK_PAYLOAD_SIZE) ? BLE_CONSOLE_CHUNK_PAYLOAD_SIZE : remaining;
    size_t frame_size = BLE_CONSOLE_FRAME_HEADER_SIZE + chunk_payload_size + BLE_CONSOLE_FRAME_TRAILER_SIZE;

    uint8_t* frame = (uint8_t*)malloc(frame_size);
    if (frame == NULL) {
        ESP_LOGE(TAG, "malloc failed for frame");
        return NULL;
    }

    // Header: magic | total_len_hi | total_len_lo | chunk_idx | chunk_len_hi | chunk_len_lo
    frame[0] = BLE_FRAME_MAGIC;
    frame[1] = (uint8_t)((out_len >> 8) & 0xFF);
    frame[2] = (uint8_t)(out_len & 0xFF);
    frame[3] = out_next_chunk_idx;
    frame[4] = (uint8_t)((chunk_payload_size >> 8) & 0xFF);
    frame[5] = (uint8_t)(chunk_payload_size & 0xFF);

    // Payload
    memcpy(frame + BLE_CONSOLE_FRAME_HEADER_SIZE, out_buffer + offset, chunk_payload_size);

    // CRC on payload only
    uint16_t crc = ble_protocol_crc16(frame + BLE_CONSOLE_FRAME_HEADER_SIZE, chunk_payload_size);
    frame[BLE_CONSOLE_FRAME_HEADER_SIZE + chunk_payload_size] = (uint8_t)((crc >> 8) & 0xFF);
    frame[BLE_CONSOLE_FRAME_HEADER_SIZE + chunk_payload_size + 1] = (uint8_t)(crc & 0xFF);

    // Store for retransmission
    if (last_frame != NULL) {
        free(last_frame);
    }
    last_frame = (uint8_t*)malloc(frame_size);
    if (last_frame != NULL) {
        memcpy(last_frame, frame, frame_size);
        last_frame_len = frame_size;
    }

    *out_frame_len = frame_size;
    out_next_chunk_idx++;

    // Check if this was the last chunk
    size_t next_offset = (size_t)out_next_chunk_idx * BLE_CONSOLE_CHUNK_PAYLOAD_SIZE;
    if (next_offset >= out_len) {
        ESP_LOGD(TAG, "last chunk built");
        out_has_response = false;
    }

    ESP_LOGD(TAG, "built chunk %u: %u bytes, crc=0x%04X", out_next_chunk_idx - 1, (unsigned)frame_size, crc);
    return frame;
}

uint8_t* ble_protocol_build_retransmit(size_t* out_frame_len) {
    if (out_frame_len == NULL) {
        return NULL;
    }

    *out_frame_len = 0;

    if (last_frame == NULL || last_frame_len == 0) {
        return NULL;
    }

    uint8_t* frame = (uint8_t*)malloc(last_frame_len);
    if (frame == NULL) {
        return NULL;
    }

    memcpy(frame, last_frame, last_frame_len);
    *out_frame_len = last_frame_len;

    ESP_LOGD(TAG, "retransmit: %u bytes", (unsigned)last_frame_len);
    return frame;
}

uint8_t* ble_protocol_build_single_response(uint8_t value, size_t* out_len) {
    if (out_len == NULL) {
        return NULL;
    }

    uint8_t* rsp = (uint8_t*)malloc(1);
    if (rsp == NULL) {
        *out_len = 0;
        return NULL;
    }

    rsp[0] = value;
    *out_len = 1;
    return rsp;
}
