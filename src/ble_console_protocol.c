#include "ble_console_protocol.h"

#include <string.h>
#include <stdlib.h>

#include <esp_log.h>

static const char* TAG = "ble_proto";

// BLE protocol state
typedef struct {
    // Shared buffer for input reassembly and output chunking
    uint8_t* buffer;

    // Input state
    size_t in_total_len;
    size_t in_received;
    uint8_t in_next_chunk_idx;

    // Output state
    size_t out_len;
    uint8_t out_next_chunk_idx;
    bool out_has_response;

    // Last sent frame for retransmission
    uint8_t* last_frame;
    size_t last_frame_len;

    bool initialized;
} ble_protocol_state_t;

static ble_protocol_state_t s_proto = {0};

static bool proto_init(void) {
    if (s_proto.initialized) return true;

    s_proto.buffer = (uint8_t*)calloc(BLE_CONSOLE_MAX_PAYLOAD, 1);
    if (!s_proto.buffer) {
        ESP_LOGE(TAG, "Failed to alloc buffer from internal RAM");
        return false;
    }

    s_proto.initialized = true;
    ESP_LOGI(TAG, "BLE protocol buffer allocated from internal RAM (16KB)");
    return true;
}

static void reset_input(void) {
    if (s_proto.buffer) {
        memset(s_proto.buffer, 0, BLE_CONSOLE_MAX_PAYLOAD);
    }
    s_proto.in_total_len = 0;
    s_proto.in_received = 0;
    s_proto.in_next_chunk_idx = 0;
}

static void reset_output(void) {
    s_proto.out_len = 0;
    s_proto.out_next_chunk_idx = 0;
    s_proto.out_has_response = false;
    free(s_proto.last_frame);
    s_proto.last_frame = NULL;
    s_proto.last_frame_len = 0;
}

static void store_last_frame(const uint8_t* frame, size_t len) {
    free(s_proto.last_frame);
    s_proto.last_frame = (uint8_t*)malloc(len);
    if (s_proto.last_frame) {
        memcpy(s_proto.last_frame, frame, len);
        s_proto.last_frame_len = len;
    } else {
        s_proto.last_frame_len = 0;
    }
}

// Ensure buffers are initialized before use
static bool ensure_initialized(void) {
    if (!s_proto.initialized) {
        return proto_init();
    }
    return true;
}

uint16_t ble_protocol_crc16(const uint8_t* data, size_t len) {
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint16_t)data[i] << 8;
        for (uint8_t j = 0; j < 8; j++) {
            if (crc & 0x8000) {
                crc = (crc << 1) ^ 0x1021;
            }
            else {
                crc = crc << 1;
            }
        }
    }
    return crc;
}

void ble_protocol_reset_input(void) {
    ESP_LOGD(TAG, "reset input");
    ensure_initialized();
    reset_input();
}

void ble_protocol_reset_output(void) {
    ESP_LOGD(TAG, "reset output");
    ensure_initialized();
    reset_output();
}

void ble_protocol_reset_all(void) {
    ESP_LOGD(TAG, "reset all");
    ensure_initialized();
    reset_input();
    reset_output();
}

ble_receive_result_t ble_protocol_receive_chunk(const uint8_t* frame, size_t frame_len) {
    if (!ensure_initialized()) {
        ESP_LOGE(TAG, "Failed to initialize protocol buffers");
        return BLE_RECEIVE_ERROR;
    }

    // Frame format: 0xA5 | total_len_hi | total_len_lo | chunk_idx | chunk_len_hi | chunk_len_lo | payload | crc16_hi | crc16_lo
    if (frame_len < BLE_CONSOLE_FRAME_HEADER_SIZE + BLE_CONSOLE_FRAME_TRAILER_SIZE) {
        ESP_LOGW(TAG, "frame too small: %u", (unsigned)frame_len);
        reset_input();
        return BLE_RECEIVE_ERROR;
    }

    if (frame[0] != BLE_FRAME_MAGIC) {
        ESP_LOGW(TAG, "invalid magic: 0x%02X", frame[0]);
        reset_input();
        return BLE_RECEIVE_ERROR;
    }

    uint16_t total_len = ((uint16_t)frame[1] << 8) | (uint16_t)frame[2];
    uint8_t chunk_idx = frame[3];
    uint16_t chunk_len = ((uint16_t)frame[4] << 8) | (uint16_t)frame[5];

    // Validate frame size
    if (frame_len != BLE_CONSOLE_FRAME_HEADER_SIZE + chunk_len + BLE_CONSOLE_FRAME_TRAILER_SIZE) {
        ESP_LOGW(TAG, "frame size mismatch");
        reset_input();
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
        reset_input();
        s_proto.in_total_len = total_len;
        s_proto.in_next_chunk_idx = 0;
    }
    else {
        // Validate chunk sequence
        if (chunk_idx != s_proto.in_next_chunk_idx) {
            ESP_LOGW(TAG, "chunk idx mismatch: expected %u got %u", s_proto.in_next_chunk_idx, chunk_idx);
            reset_input();
            return BLE_RECEIVE_ERROR;
        }
        if (total_len != s_proto.in_total_len) {
            ESP_LOGW(TAG, "total_len mismatch");
            reset_input();
            return BLE_RECEIVE_ERROR;
        }
    }

    // Check buffer overflow
    if (s_proto.in_received + chunk_len > BLE_CONSOLE_MAX_PAYLOAD) {
        ESP_LOGE(TAG, "buffer overflow");
        reset_input();
        return BLE_RECEIVE_ERROR;
    }

    // Copy payload
    memcpy(s_proto.buffer + s_proto.in_received, frame + BLE_CONSOLE_FRAME_HEADER_SIZE, chunk_len);
    s_proto.in_received += chunk_len;
    s_proto.in_next_chunk_idx++;

    ESP_LOGD(TAG, "chunk %u: %u/%u bytes", chunk_idx,
        (unsigned)s_proto.in_received, (unsigned)s_proto.in_total_len);

    // Check if complete
    if (s_proto.in_received >= s_proto.in_total_len) {
        return BLE_RECEIVE_COMPLETE;
    }
    return BLE_RECEIVE_OK;
}

const uint8_t* ble_protocol_get_input_data(void) {
    return s_proto.buffer;
}

size_t ble_protocol_get_input_len(void) {
    return s_proto.in_total_len;
}

void ble_protocol_set_output(const uint8_t* data, size_t len) {
    if (!ensure_initialized()) {
        ESP_LOGE(TAG, "Failed to initialize protocol buffers");
        return;
    }

    if (data == NULL || len == 0 || len > BLE_CONSOLE_MAX_PAYLOAD) {
        ESP_LOGE(TAG, "invalid output data");
        return;
    }

    // Use memmove to handle case where data points into shared buffer
    memmove(s_proto.buffer, data, len);
    s_proto.out_len = len;
    s_proto.out_next_chunk_idx = 0;
    s_proto.out_has_response = true;
    ESP_LOGD(TAG, "output set: %u bytes", (unsigned)len);
}

bool ble_protocol_has_output(void) {
    return s_proto.out_has_response && s_proto.out_len > 0;
}

uint8_t* ble_protocol_build_next_chunk(size_t* out_frame_len) {
    if (out_frame_len == NULL) {
        return NULL;
    }

    *out_frame_len = 0;

    if (!s_proto.out_has_response || s_proto.out_len == 0) {
        return NULL;
    }

    size_t offset = (size_t)s_proto.out_next_chunk_idx * BLE_CONSOLE_CHUNK_PAYLOAD_SIZE;
    if (offset >= s_proto.out_len) {
        // All chunks sent
        s_proto.out_has_response = false;
        return NULL;
    }

    size_t remaining = s_proto.out_len - offset;
    size_t chunk_payload_size = (remaining > BLE_CONSOLE_CHUNK_PAYLOAD_SIZE) ? BLE_CONSOLE_CHUNK_PAYLOAD_SIZE : remaining;
    size_t frame_size = BLE_CONSOLE_FRAME_HEADER_SIZE + chunk_payload_size + BLE_CONSOLE_FRAME_TRAILER_SIZE;

    uint8_t* frame = (uint8_t*)malloc(frame_size);
    if (frame == NULL) {
        ESP_LOGE(TAG, "malloc failed for frame");
        return NULL;
    }

    // Header: magic | total_len_hi | total_len_lo | chunk_idx | chunk_len_hi | chunk_len_lo
    frame[0] = BLE_FRAME_MAGIC;
    frame[1] = (uint8_t)((s_proto.out_len >> 8) & 0xFF);
    frame[2] = (uint8_t)(s_proto.out_len & 0xFF);
    frame[3] = s_proto.out_next_chunk_idx;
    frame[4] = (uint8_t)((chunk_payload_size >> 8) & 0xFF);
    frame[5] = (uint8_t)(chunk_payload_size & 0xFF);

    // Payload
    memcpy(frame + BLE_CONSOLE_FRAME_HEADER_SIZE, s_proto.buffer + offset, chunk_payload_size);

    // CRC on payload only
    uint16_t crc = ble_protocol_crc16(frame + BLE_CONSOLE_FRAME_HEADER_SIZE, chunk_payload_size);
    frame[BLE_CONSOLE_FRAME_HEADER_SIZE + chunk_payload_size] = (uint8_t)((crc >> 8) & 0xFF);
    frame[BLE_CONSOLE_FRAME_HEADER_SIZE + chunk_payload_size + 1] = (uint8_t)(crc & 0xFF);

    // Store for retransmission
    store_last_frame(frame, frame_size);

    *out_frame_len = frame_size;
    s_proto.out_next_chunk_idx++;

    // Check if this was the last chunk
    size_t next_offset = (size_t)s_proto.out_next_chunk_idx * BLE_CONSOLE_CHUNK_PAYLOAD_SIZE;
    if (next_offset >= s_proto.out_len) {
        ESP_LOGD(TAG, "last chunk built");
        s_proto.out_has_response = false;
    }

    ESP_LOGD(TAG, "built chunk %u: %u bytes, crc=0x%04X",
        s_proto.out_next_chunk_idx - 1, (unsigned)frame_size, crc);
    return frame;
}

uint8_t* ble_protocol_build_retransmit(size_t* out_frame_len) {
    if (out_frame_len == NULL) {
        return NULL;
    }

    *out_frame_len = 0;

    if (!s_proto.last_frame || s_proto.last_frame_len == 0) {
        return NULL;
    }

    uint8_t* frame = (uint8_t*)malloc(s_proto.last_frame_len);
    if (frame == NULL) {
        return NULL;
    }

    memcpy(frame, s_proto.last_frame, s_proto.last_frame_len);
    *out_frame_len = s_proto.last_frame_len;

    ESP_LOGD(TAG, "retransmit: %u bytes", (unsigned)s_proto.last_frame_len);
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
