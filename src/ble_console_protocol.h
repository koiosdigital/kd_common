#pragma once

#include <stdint.h>
#include <stddef.h>
#include <esp_err.h>

// Protocol constants
#define BLE_CONSOLE_MTU 512
#define BLE_CONSOLE_FRAME_HEADER_SIZE 6   // magic + total_len(2) + chunk_idx + chunk_len(2)
#define BLE_CONSOLE_FRAME_TRAILER_SIZE 2  // crc16(2)
#define BLE_CONSOLE_CHUNK_PAYLOAD_SIZE (BLE_CONSOLE_MTU - BLE_CONSOLE_FRAME_HEADER_SIZE - BLE_CONSOLE_FRAME_TRAILER_SIZE) // 504 bytes
#define BLE_CONSOLE_MAX_PAYLOAD 4096

// Frame magic byte for data frames
#define BLE_FRAME_MAGIC 0xA5

// Control commands (single byte)
#define BLE_CMD_RESET 0xAA       // Reset state machine
#define BLE_CMD_NEXT 0xBB        // Request next response chunk
#define BLE_CMD_RETRANSMIT 0xCC  // Retransmit last sent chunk

// Control responses (single byte)
#define BLE_RSP_ACK 0xFF         // Acknowledge (for reset)
#define BLE_RSP_EMPTY 0x00       // No data available

// Receive result codes
typedef enum {
    BLE_RECEIVE_OK = 0,          // Chunk received, more expected
    BLE_RECEIVE_COMPLETE = 1,    // All chunks received, message complete
    BLE_RECEIVE_CRC_ERROR = 2,   // CRC mismatch, need retransmit
    BLE_RECEIVE_ERROR = 3        // Other error (reset state)
} ble_receive_result_t;

#ifdef __cplusplus
extern "C" {
#endif

// CRC16-CCITT calculation
uint16_t ble_protocol_crc16(const uint8_t* data, size_t len);

// Reset protocol state
void ble_protocol_reset_input(void);
void ble_protocol_reset_output(void);
void ble_protocol_reset_all(void);

// Input handling
// Returns result code indicating chunk status
ble_receive_result_t ble_protocol_receive_chunk(const uint8_t* frame, size_t frame_len);

// Get the assembled input data (valid after receive_chunk returns true)
const uint8_t* ble_protocol_get_input_data(void);
size_t ble_protocol_get_input_len(void);

// Output handling
// Prepare response data for chunked transmission
void ble_protocol_set_output(const uint8_t* data, size_t len);
bool ble_protocol_has_output(void);

// Build next output chunk frame (caller must free returned buffer)
// Returns NULL if no more chunks
uint8_t* ble_protocol_build_next_chunk(size_t* out_len);

// Build retransmit frame (caller must free returned buffer)
// Returns NULL if no previous frame
uint8_t* ble_protocol_build_retransmit(size_t* out_len);

// Build single-byte response (caller must free returned buffer)
uint8_t* ble_protocol_build_single_response(uint8_t value, size_t* out_len);

#ifdef __cplusplus
}
#endif
