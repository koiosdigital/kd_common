#include "ble_console_protocol.h"

#include <cstring>
#include <memory>

#include <esp_log.h>
#include <esp_heap_caps.h>

static const char* TAG = "ble_proto";

namespace {

// BLE protocol state encapsulation
// Buffers are allocated from SPIRAM to save internal RAM
struct BleProtocolState {
    // Input reassembly state (allocated from SPIRAM)
    uint8_t* in_buffer = nullptr;
    size_t in_total_len = 0;
    size_t in_received = 0;
    uint8_t in_next_chunk_idx = 0;

    // Output chunking state (allocated from SPIRAM)
    uint8_t* out_buffer = nullptr;
    size_t out_len = 0;
    uint8_t out_next_chunk_idx = 0;
    bool out_has_response = false;

    // Last sent frame for retransmission (RAII managed)
    std::unique_ptr<uint8_t[]> last_frame;
    size_t last_frame_len = 0;

    bool initialized = false;

    bool init() {
        if (initialized) return true;

        in_buffer = static_cast<uint8_t*>(
            heap_caps_calloc(BLE_CONSOLE_MAX_PAYLOAD, 1, MALLOC_CAP_SPIRAM));
        if (!in_buffer) {
            ESP_LOGE(TAG, "Failed to alloc in_buffer from SPIRAM");
            return false;
        }

        out_buffer = static_cast<uint8_t*>(
            heap_caps_calloc(BLE_CONSOLE_MAX_PAYLOAD, 1, MALLOC_CAP_SPIRAM));
        if (!out_buffer) {
            ESP_LOGE(TAG, "Failed to alloc out_buffer from SPIRAM");
            heap_caps_free(in_buffer);
            in_buffer = nullptr;
            return false;
        }

        initialized = true;
        ESP_LOGI(TAG, "BLE protocol buffers allocated from SPIRAM (32KB total)");
        return true;
    }

    void reset_input() {
        if (in_buffer) {
            std::memset(in_buffer, 0, BLE_CONSOLE_MAX_PAYLOAD);
        }
        in_total_len = 0;
        in_received = 0;
        in_next_chunk_idx = 0;
    }

    void reset_output() {
        if (out_buffer) {
            std::memset(out_buffer, 0, BLE_CONSOLE_MAX_PAYLOAD);
        }
        out_len = 0;
        out_next_chunk_idx = 0;
        out_has_response = false;
        last_frame.reset();
        last_frame_len = 0;
    }

    void store_last_frame(const uint8_t* frame, size_t len) {
        last_frame = std::make_unique<uint8_t[]>(len);
        std::memcpy(last_frame.get(), frame, len);
        last_frame_len = len;
    }
};

BleProtocolState proto;

// Ensure buffers are initialized before use
bool ensure_initialized() {
    if (!proto.initialized) {
        return proto.init();
    }
    return true;
}

}  // namespace

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
    ensure_initialized();
    proto.reset_input();
}

void ble_protocol_reset_output(void) {
    ESP_LOGD(TAG, "reset output");
    ensure_initialized();
    proto.reset_output();
}

void ble_protocol_reset_all(void) {
    ESP_LOGD(TAG, "reset all");
    ensure_initialized();
    proto.reset_input();
    proto.reset_output();
}

ble_receive_result_t ble_protocol_receive_chunk(const uint8_t* frame, size_t frame_len) {
    if (!ensure_initialized()) {
        ESP_LOGE(TAG, "Failed to initialize protocol buffers");
        return BLE_RECEIVE_ERROR;
    }

    // Frame format: 0xA5 | total_len_hi | total_len_lo | chunk_idx | chunk_len_hi | chunk_len_lo | payload | crc16_hi | crc16_lo
    if (frame_len < BLE_CONSOLE_FRAME_HEADER_SIZE + BLE_CONSOLE_FRAME_TRAILER_SIZE) {
        ESP_LOGW(TAG, "frame too small: %u", static_cast<unsigned>(frame_len));
        proto.reset_input();
        return BLE_RECEIVE_ERROR;
    }

    if (frame[0] != BLE_FRAME_MAGIC) {
        ESP_LOGW(TAG, "invalid magic: 0x%02X", frame[0]);
        proto.reset_input();
        return BLE_RECEIVE_ERROR;
    }

    uint16_t total_len = (static_cast<uint16_t>(frame[1]) << 8) | static_cast<uint16_t>(frame[2]);
    uint8_t chunk_idx = frame[3];
    uint16_t chunk_len = (static_cast<uint16_t>(frame[4]) << 8) | static_cast<uint16_t>(frame[5]);

    // Validate frame size
    if (frame_len != BLE_CONSOLE_FRAME_HEADER_SIZE + chunk_len + BLE_CONSOLE_FRAME_TRAILER_SIZE) {
        ESP_LOGW(TAG, "frame size mismatch");
        proto.reset_input();
        return BLE_RECEIVE_ERROR;
    }

    // Verify CRC
    uint16_t rx_crc = (static_cast<uint16_t>(frame[BLE_CONSOLE_FRAME_HEADER_SIZE + chunk_len]) << 8) |
                      static_cast<uint16_t>(frame[BLE_CONSOLE_FRAME_HEADER_SIZE + chunk_len + 1]);
    uint16_t calc_crc = ble_protocol_crc16(frame + BLE_CONSOLE_FRAME_HEADER_SIZE, chunk_len);

    if (rx_crc != calc_crc) {
        ESP_LOGE(TAG, "CRC mismatch: rx=0x%04X calc=0x%04X", rx_crc, calc_crc);
        // Don't reset input - allow retransmit
        return BLE_RECEIVE_CRC_ERROR;
    }

    // First chunk initializes reassembly
    if (chunk_idx == 0) {
        proto.reset_input();
        proto.in_total_len = total_len;
        proto.in_next_chunk_idx = 0;
    } else {
        // Validate chunk sequence
        if (chunk_idx != proto.in_next_chunk_idx) {
            ESP_LOGW(TAG, "chunk idx mismatch: expected %u got %u", proto.in_next_chunk_idx, chunk_idx);
            proto.reset_input();
            return BLE_RECEIVE_ERROR;
        }
        if (total_len != proto.in_total_len) {
            ESP_LOGW(TAG, "total_len mismatch");
            proto.reset_input();
            return BLE_RECEIVE_ERROR;
        }
    }

    // Check buffer overflow
    if (proto.in_received + chunk_len > BLE_CONSOLE_MAX_PAYLOAD) {
        ESP_LOGE(TAG, "buffer overflow");
        proto.reset_input();
        return BLE_RECEIVE_ERROR;
    }

    // Copy payload
    std::memcpy(proto.in_buffer + proto.in_received, frame + BLE_CONSOLE_FRAME_HEADER_SIZE, chunk_len);
    proto.in_received += chunk_len;
    proto.in_next_chunk_idx++;

    ESP_LOGD(TAG, "chunk %u: %u/%u bytes", chunk_idx,
             static_cast<unsigned>(proto.in_received), static_cast<unsigned>(proto.in_total_len));

    // Check if complete
    if (proto.in_received >= proto.in_total_len) {
        return BLE_RECEIVE_COMPLETE;
    }
    return BLE_RECEIVE_OK;
}

const uint8_t* ble_protocol_get_input_data(void) {
    return proto.in_buffer;
}

size_t ble_protocol_get_input_len(void) {
    return proto.in_total_len;
}

void ble_protocol_set_output(const uint8_t* data, size_t len) {
    if (!ensure_initialized()) {
        ESP_LOGE(TAG, "Failed to initialize protocol buffers");
        return;
    }

    if (data == nullptr || len == 0 || len > BLE_CONSOLE_MAX_PAYLOAD) {
        ESP_LOGE(TAG, "invalid output data");
        return;
    }

    std::memcpy(proto.out_buffer, data, len);
    proto.out_len = len;
    proto.out_next_chunk_idx = 0;
    proto.out_has_response = true;
    ESP_LOGD(TAG, "output set: %u bytes", static_cast<unsigned>(len));
}

bool ble_protocol_has_output(void) {
    return proto.out_has_response && proto.out_len > 0;
}

uint8_t* ble_protocol_build_next_chunk(size_t* out_frame_len) {
    if (out_frame_len == nullptr) {
        return nullptr;
    }

    *out_frame_len = 0;

    if (!proto.out_has_response || proto.out_len == 0) {
        return nullptr;
    }

    size_t offset = static_cast<size_t>(proto.out_next_chunk_idx) * BLE_CONSOLE_CHUNK_PAYLOAD_SIZE;
    if (offset >= proto.out_len) {
        // All chunks sent
        proto.out_has_response = false;
        return nullptr;
    }

    size_t remaining = proto.out_len - offset;
    size_t chunk_payload_size = (remaining > BLE_CONSOLE_CHUNK_PAYLOAD_SIZE) ? BLE_CONSOLE_CHUNK_PAYLOAD_SIZE : remaining;
    size_t frame_size = BLE_CONSOLE_FRAME_HEADER_SIZE + chunk_payload_size + BLE_CONSOLE_FRAME_TRAILER_SIZE;

    uint8_t* frame = static_cast<uint8_t*>(malloc(frame_size));
    if (frame == nullptr) {
        ESP_LOGE(TAG, "malloc failed for frame");
        return nullptr;
    }

    // Header: magic | total_len_hi | total_len_lo | chunk_idx | chunk_len_hi | chunk_len_lo
    frame[0] = BLE_FRAME_MAGIC;
    frame[1] = static_cast<uint8_t>((proto.out_len >> 8) & 0xFF);
    frame[2] = static_cast<uint8_t>(proto.out_len & 0xFF);
    frame[3] = proto.out_next_chunk_idx;
    frame[4] = static_cast<uint8_t>((chunk_payload_size >> 8) & 0xFF);
    frame[5] = static_cast<uint8_t>(chunk_payload_size & 0xFF);

    // Payload
    std::memcpy(frame + BLE_CONSOLE_FRAME_HEADER_SIZE, proto.out_buffer + offset, chunk_payload_size);

    // CRC on payload only
    uint16_t crc = ble_protocol_crc16(frame + BLE_CONSOLE_FRAME_HEADER_SIZE, chunk_payload_size);
    frame[BLE_CONSOLE_FRAME_HEADER_SIZE + chunk_payload_size] = static_cast<uint8_t>((crc >> 8) & 0xFF);
    frame[BLE_CONSOLE_FRAME_HEADER_SIZE + chunk_payload_size + 1] = static_cast<uint8_t>(crc & 0xFF);

    // Store for retransmission using RAII
    proto.store_last_frame(frame, frame_size);

    *out_frame_len = frame_size;
    proto.out_next_chunk_idx++;

    // Check if this was the last chunk
    size_t next_offset = static_cast<size_t>(proto.out_next_chunk_idx) * BLE_CONSOLE_CHUNK_PAYLOAD_SIZE;
    if (next_offset >= proto.out_len) {
        ESP_LOGD(TAG, "last chunk built");
        proto.out_has_response = false;
    }

    ESP_LOGD(TAG, "built chunk %u: %u bytes, crc=0x%04X",
             proto.out_next_chunk_idx - 1, static_cast<unsigned>(frame_size), crc);
    return frame;
}

uint8_t* ble_protocol_build_retransmit(size_t* out_frame_len) {
    if (out_frame_len == nullptr) {
        return nullptr;
    }

    *out_frame_len = 0;

    if (!proto.last_frame || proto.last_frame_len == 0) {
        return nullptr;
    }

    uint8_t* frame = static_cast<uint8_t*>(malloc(proto.last_frame_len));
    if (frame == nullptr) {
        return nullptr;
    }

    std::memcpy(frame, proto.last_frame.get(), proto.last_frame_len);
    *out_frame_len = proto.last_frame_len;

    ESP_LOGD(TAG, "retransmit: %u bytes", static_cast<unsigned>(proto.last_frame_len));
    return frame;
}

uint8_t* ble_protocol_build_single_response(uint8_t value, size_t* out_len) {
    if (out_len == nullptr) {
        return nullptr;
    }

    uint8_t* rsp = static_cast<uint8_t*>(malloc(1));
    if (rsp == nullptr) {
        *out_len = 0;
        return nullptr;
    }

    rsp[0] = value;
    *out_len = 1;
    return rsp;
}
