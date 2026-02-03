#include "kdc_heap_tracing.h"

#include <esp_heap_caps.h>
#include <esp_system.h>
#include <esp_log.h>

#include <stdatomic.h>
#include <stdint.h>

static const char* TAG = "kdc_heap";

static kdc_heap_snapshot_t s_checkpoint = {0};
static kdc_heap_snapshot_t s_baseline = {0};
static bool s_initialized = false;

// Control for verbose alloc/free logging (very noisy, off by default)
static atomic_bool s_log_allocs = false;

// Control for integrity check on every alloc/free (expensive but catches corruption early)
static atomic_bool s_check_on_alloc = false;

static void take_snapshot(kdc_heap_snapshot_t* snapshot) {
    snapshot->internal_free = heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    snapshot->internal_min = heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    snapshot->internal_largest_block = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    snapshot->spiram_free = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
    snapshot->spiram_min = heap_caps_get_minimum_free_size(MALLOC_CAP_SPIRAM);
    snapshot->spiram_largest_block = heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM);
    snapshot->dma_free = heap_caps_get_free_size(MALLOC_CAP_DMA);
}

static const char* caps_to_str(uint32_t caps) {
    if (caps & MALLOC_CAP_SPIRAM) return "SPIRAM";
    if (caps & MALLOC_CAP_DMA) return "DMA";
    if (caps & MALLOC_CAP_INTERNAL) return "DRAM";
    return "OTHER";
}

// Heap allocation/free hooks - called by ESP-IDF when CONFIG_HEAP_USE_HOOKS is enabled
void esp_heap_trace_alloc_hook(void* ptr, size_t size, uint32_t caps) {
    if (atomic_load_explicit(&s_log_allocs, memory_order_relaxed)) {
        ESP_LOGI(TAG, "ALLOC: %p size=%zu caps=%s (0x%lx)",
                 ptr, size, caps_to_str(caps), (unsigned long)caps);
    }
    if (atomic_load_explicit(&s_check_on_alloc, memory_order_relaxed)) {
        if (!heap_caps_check_integrity_all(false)) {
            ESP_LOGE(TAG, "CORRUPTION after ALLOC %p size=%zu caps=0x%lx",
                     ptr, size, (unsigned long)caps);
            heap_caps_check_integrity_all(true);  // Print details
        }
    }
}

void esp_heap_trace_free_hook(void* ptr) {
    if (atomic_load_explicit(&s_log_allocs, memory_order_relaxed)) {
        ESP_LOGI(TAG, "FREE:  %p", ptr);
    }
    if (atomic_load_explicit(&s_check_on_alloc, memory_order_relaxed)) {
        if (!heap_caps_check_integrity_all(false)) {
            ESP_LOGE(TAG, "CORRUPTION before FREE %p", ptr);
            heap_caps_check_integrity_all(true);  // Print details
        }
    }
}

void kdc_heap_trace_init(void) {
    if (s_initialized) {
        return;
    }
    s_initialized = true;

    take_snapshot(&s_baseline);
    s_checkpoint = s_baseline;

    ESP_LOGI(TAG, "Heap tracing initialized");
    ESP_LOGI(TAG, "  DRAM:   free=%zu, min=%zu, blk=%zu",
             s_baseline.internal_free, s_baseline.internal_min, s_baseline.internal_largest_block);
    ESP_LOGI(TAG, "  SPIRAM: free=%zu, min=%zu, blk=%zu",
             s_baseline.spiram_free, s_baseline.spiram_min, s_baseline.spiram_largest_block);
    ESP_LOGI(TAG, "  DMA:    free=%zu", s_baseline.dma_free);

    kdc_heap_check_integrity("init");
}

void kdc_heap_set_log_allocs(bool enabled) {
    atomic_store_explicit(&s_log_allocs, enabled, memory_order_relaxed);
    ESP_LOGI(TAG, "Alloc/free logging %s", enabled ? "ENABLED" : "DISABLED");
}

bool kdc_heap_get_log_allocs(void) {
    return atomic_load_explicit(&s_log_allocs, memory_order_relaxed);
}

void kdc_heap_set_check_on_alloc(bool enabled) {
    atomic_store_explicit(&s_check_on_alloc, enabled, memory_order_relaxed);
    ESP_LOGI(TAG, "Integrity check on alloc/free %s", enabled ? "ENABLED" : "DISABLED");
}

bool kdc_heap_get_check_on_alloc(void) {
    return atomic_load_explicit(&s_check_on_alloc, memory_order_relaxed);
}

void kdc_heap_log_status(const char* tag) {
    kdc_heap_snapshot_t now;
    take_snapshot(&now);

    int32_t delta_int = (int32_t)now.internal_free - (int32_t)s_baseline.internal_free;
    int32_t delta_spi = (int32_t)now.spiram_free - (int32_t)s_baseline.spiram_free;

    ESP_LOGI(TAG, "[%s] Free heap: %lu, min ever: %lu",
             tag,
             (unsigned long)esp_get_free_heap_size(),
             (unsigned long)esp_get_minimum_free_heap_size());

    ESP_LOGI(TAG, "  DRAM:   free=%zu (%+ld since boot), min=%zu, blk=%zu",
             now.internal_free, (long)delta_int,
             now.internal_min, now.internal_largest_block);

    ESP_LOGI(TAG, "  SPIRAM: free=%zu (%+ld since boot), min=%zu, blk=%zu",
             now.spiram_free, (long)delta_spi,
             now.spiram_min, now.spiram_largest_block);

    ESP_LOGI(TAG, "  DMA:    free=%zu", now.dma_free);

    // Always check integrity at checkpoints
    kdc_heap_check_integrity(tag);
}

void kdc_heap_checkpoint(const char* label) {
    take_snapshot(&s_checkpoint);

    ESP_LOGI(TAG, "[%s] Checkpoint: DRAM=%zu, SPIRAM=%zu",
             label, s_checkpoint.internal_free, s_checkpoint.spiram_free);

    kdc_heap_check_integrity(label);
}

void kdc_heap_check_since_checkpoint(const char* label) {
    kdc_heap_snapshot_t now;
    take_snapshot(&now);

    int32_t delta_int = (int32_t)now.internal_free - (int32_t)s_checkpoint.internal_free;
    int32_t delta_spi = (int32_t)now.spiram_free - (int32_t)s_checkpoint.spiram_free;

    ESP_LOGI(TAG, "[%s] Since checkpoint: DRAM %+ld (%zu), SPIRAM %+ld (%zu)",
             label,
             (long)delta_int, now.internal_free,
             (long)delta_spi, now.spiram_free);

    // Warn on significant drops
    if (delta_int < -4096) {
        ESP_LOGW(TAG, "[%s] Significant DRAM drop: %+ld bytes", label, (long)delta_int);
    }
    if (delta_spi < -65536) {
        ESP_LOGW(TAG, "[%s] Significant SPIRAM drop: %+ld bytes", label, (long)delta_spi);
    }

    // Run integrity check
    kdc_heap_check_integrity(label);
}

void kdc_heap_get_snapshot(kdc_heap_snapshot_t* snapshot) {
    if (snapshot) {
        take_snapshot(snapshot);
    }
}

bool kdc_heap_check_integrity(const char* location) {
    bool ok = heap_caps_check_integrity_all(true);
    if (!ok) {
        ESP_LOGE(TAG, "HEAP CORRUPTION detected at %s!", location);
    }
    return ok;
}

void kdc_heap_dump_info(void) {
    ESP_LOGI(TAG, "=== Detailed Heap Info (8-bit accessible) ===");
    heap_caps_print_heap_info(MALLOC_CAP_8BIT);

    ESP_LOGI(TAG, "=== Detailed Heap Info (Internal only) ===");
    heap_caps_print_heap_info(MALLOC_CAP_INTERNAL);

    ESP_LOGI(TAG, "=== Detailed Heap Info (SPIRAM) ===");
    heap_caps_print_heap_info(MALLOC_CAP_SPIRAM);
}
