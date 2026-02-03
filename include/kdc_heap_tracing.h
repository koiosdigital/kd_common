#pragma once

#include <esp_err.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Heap snapshot structure for checkpoint comparisons
 */
typedef struct {
    size_t internal_free;
    size_t internal_min;
    size_t internal_largest_block;
    size_t spiram_free;
    size_t spiram_min;
    size_t spiram_largest_block;
    size_t dma_free;
} kdc_heap_snapshot_t;

/**
 * @brief Initialize heap tracing subsystem
 *
 * Should be called early in app_main() before any significant allocations.
 * Sets up the baseline checkpoint for delta comparisons.
 * Also runs initial integrity check.
 */
void kdc_heap_trace_init(void);

/**
 * @brief Enable or disable verbose alloc/free logging
 *
 * When enabled, logs every heap allocation and free operation.
 * WARNING: This is extremely verbose and will impact performance.
 * Use only for targeted debugging sessions.
 *
 * Requires CONFIG_HEAP_USE_HOOKS=y in sdkconfig.
 *
 * @param enabled true to enable logging, false to disable
 */
void kdc_heap_set_log_allocs(bool enabled);

/**
 * @brief Check if alloc/free logging is enabled
 *
 * @return true if logging is enabled, false otherwise
 */
bool kdc_heap_get_log_allocs(void);

/**
 * @brief Enable or disable integrity check on every alloc/free
 *
 * When enabled, runs heap_caps_check_integrity_all() after every allocation
 * and before every free. This catches corruption as soon as it happens
 * but has SEVERE performance impact.
 *
 * Requires CONFIG_HEAP_USE_HOOKS=y in sdkconfig.
 *
 * @param enabled true to enable checking, false to disable
 */
void kdc_heap_set_check_on_alloc(bool enabled);

/**
 * @brief Check if integrity check on alloc/free is enabled
 *
 * @return true if checking is enabled, false otherwise
 */
bool kdc_heap_get_check_on_alloc(void);

/**
 * @brief Log current heap status with per-capability breakdown
 *
 * Logs free heap, minimum ever, and largest free block for DRAM, SPIRAM, and DMA.
 * Also runs heap integrity check.
 *
 * @param tag Identifier for the checkpoint (e.g., "post-wifi-init")
 */
void kdc_heap_log_status(const char* tag);

/**
 * @brief Take a heap checkpoint for later comparison
 *
 * Captures current heap state and stores it for comparison with
 * kdc_heap_check_since_checkpoint().
 * Also runs heap integrity check.
 *
 * @param label Label for the checkpoint (logged)
 */
void kdc_heap_checkpoint(const char* label);

/**
 * @brief Compare current heap state against last checkpoint
 *
 * Logs the delta in heap usage since the last checkpoint.
 * Also runs heap integrity check if enabled.
 *
 * @param label Label for the comparison (logged)
 */
void kdc_heap_check_since_checkpoint(const char* label);

/**
 * @brief Get current heap snapshot
 *
 * @param snapshot Pointer to snapshot structure to fill
 */
void kdc_heap_get_snapshot(kdc_heap_snapshot_t* snapshot);

/**
 * @brief Check heap integrity
 *
 * Verifies heap metadata hasn't been corrupted.
 * Requires CONFIG_HEAP_CORRUPTION_DETECTION to be set to "Light impact" or higher.
 *
 * @param location Identifier for where the check is performed
 * @return true if heap is intact, false if corruption detected
 */
bool kdc_heap_check_integrity(const char* location);

/**
 * @brief Log detailed heap info per region
 *
 * Calls heap_caps_print_heap_info() for all memory types.
 * Useful for detailed debugging but verbose output.
 */
void kdc_heap_dump_info(void);

#ifdef __cplusplus
}
#endif
