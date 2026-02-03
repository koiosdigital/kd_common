#include "kdc_heap_tracing.h"

#include <esp_heap_caps.h>
#include <esp_system.h>
#include <esp_log.h>

#include <atomic>

static const char* TAG = "kdc_heap";

namespace {

kdc_heap_snapshot_t g_checkpoint = {};
kdc_heap_snapshot_t g_baseline = {};
bool g_initialized = false;

// Control for verbose alloc/free logging (very noisy, off by default)
std::atomic<bool> g_log_allocs{false};

// Control for integrity check on every alloc/free (expensive but catches corruption early)
std::atomic<bool> g_check_on_alloc{false};

void take_snapshot(kdc_heap_snapshot_t* snapshot) {
    snapshot->internal_free = heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    snapshot->internal_min = heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    snapshot->internal_largest_block = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    snapshot->spiram_free = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
    snapshot->spiram_min = heap_caps_get_minimum_free_size(MALLOC_CAP_SPIRAM);
    snapshot->spiram_largest_block = heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM);
    snapshot->dma_free = heap_caps_get_free_size(MALLOC_CAP_DMA);
}

const char* caps_to_str(uint32_t caps) {
    if (caps & MALLOC_CAP_SPIRAM) return "SPIRAM";
    if (caps & MALLOC_CAP_DMA) return "DMA";
    if (caps & MALLOC_CAP_INTERNAL) return "DRAM";
    return "OTHER";
}

}  // namespace

// Heap allocation/free hooks - called by ESP-IDF when CONFIG_HEAP_USE_HOOKS is enabled
extern "C" {

void esp_heap_trace_alloc_hook(void* ptr, size_t size, uint32_t caps) {
    if (g_log_allocs.load(std::memory_order_relaxed)) {
        ESP_LOGI(TAG, "ALLOC: %p size=%zu caps=%s (0x%lx)",
                 ptr, size, caps_to_str(caps), static_cast<unsigned long>(caps));
    }
    if (g_check_on_alloc.load(std::memory_order_relaxed)) {
        if (!heap_caps_check_integrity_all(false)) {
            ESP_LOGE(TAG, "CORRUPTION after ALLOC %p size=%zu caps=0x%lx",
                     ptr, size, static_cast<unsigned long>(caps));
            heap_caps_check_integrity_all(true);  // Print details
        }
    }
}

void esp_heap_trace_free_hook(void* ptr) {
    if (g_log_allocs.load(std::memory_order_relaxed)) {
        ESP_LOGI(TAG, "FREE:  %p", ptr);
    }
    if (g_check_on_alloc.load(std::memory_order_relaxed)) {
        if (!heap_caps_check_integrity_all(false)) {
            ESP_LOGE(TAG, "CORRUPTION before FREE %p", ptr);
            heap_caps_check_integrity_all(true);  // Print details
        }
    }
}

}  // extern "C"

void kdc_heap_trace_init(void) {
    if (g_initialized) {
        return;
    }
    g_initialized = true;

    take_snapshot(&g_baseline);
    g_checkpoint = g_baseline;

    ESP_LOGI(TAG, "Heap tracing initialized");
    ESP_LOGI(TAG, "  DRAM:   free=%zu, min=%zu, blk=%zu",
             g_baseline.internal_free, g_baseline.internal_min, g_baseline.internal_largest_block);
    ESP_LOGI(TAG, "  SPIRAM: free=%zu, min=%zu, blk=%zu",
             g_baseline.spiram_free, g_baseline.spiram_min, g_baseline.spiram_largest_block);
    ESP_LOGI(TAG, "  DMA:    free=%zu", g_baseline.dma_free);

    kdc_heap_check_integrity("init");
}

void kdc_heap_set_log_allocs(bool enabled) {
    g_log_allocs.store(enabled, std::memory_order_relaxed);
    ESP_LOGI(TAG, "Alloc/free logging %s", enabled ? "ENABLED" : "DISABLED");
}

bool kdc_heap_get_log_allocs(void) {
    return g_log_allocs.load(std::memory_order_relaxed);
}

void kdc_heap_set_check_on_alloc(bool enabled) {
    g_check_on_alloc.store(enabled, std::memory_order_relaxed);
    ESP_LOGI(TAG, "Integrity check on alloc/free %s", enabled ? "ENABLED" : "DISABLED");
}

bool kdc_heap_get_check_on_alloc(void) {
    return g_check_on_alloc.load(std::memory_order_relaxed);
}

void kdc_heap_log_status(const char* tag) {
    kdc_heap_snapshot_t now;
    take_snapshot(&now);

    int32_t delta_int = static_cast<int32_t>(now.internal_free) - static_cast<int32_t>(g_baseline.internal_free);
    int32_t delta_spi = static_cast<int32_t>(now.spiram_free) - static_cast<int32_t>(g_baseline.spiram_free);

    ESP_LOGI(TAG, "[%s] Free heap: %lu, min ever: %lu",
             tag,
             static_cast<unsigned long>(esp_get_free_heap_size()),
             static_cast<unsigned long>(esp_get_minimum_free_heap_size()));

    ESP_LOGI(TAG, "  DRAM:   free=%zu (%+ld since boot), min=%zu, blk=%zu",
             now.internal_free, static_cast<long>(delta_int),
             now.internal_min, now.internal_largest_block);

    ESP_LOGI(TAG, "  SPIRAM: free=%zu (%+ld since boot), min=%zu, blk=%zu",
             now.spiram_free, static_cast<long>(delta_spi),
             now.spiram_min, now.spiram_largest_block);

    ESP_LOGI(TAG, "  DMA:    free=%zu", now.dma_free);

    // Always check integrity at checkpoints
    kdc_heap_check_integrity(tag);
}

void kdc_heap_checkpoint(const char* label) {
    take_snapshot(&g_checkpoint);

    ESP_LOGI(TAG, "[%s] Checkpoint: DRAM=%zu, SPIRAM=%zu",
             label, g_checkpoint.internal_free, g_checkpoint.spiram_free);

    kdc_heap_check_integrity(label);
}

void kdc_heap_check_since_checkpoint(const char* label) {
    kdc_heap_snapshot_t now;
    take_snapshot(&now);

    int32_t delta_int = static_cast<int32_t>(now.internal_free) - static_cast<int32_t>(g_checkpoint.internal_free);
    int32_t delta_spi = static_cast<int32_t>(now.spiram_free) - static_cast<int32_t>(g_checkpoint.spiram_free);

    ESP_LOGI(TAG, "[%s] Since checkpoint: DRAM %+ld (%zu), SPIRAM %+ld (%zu)",
             label,
             static_cast<long>(delta_int), now.internal_free,
             static_cast<long>(delta_spi), now.spiram_free);

    // Warn on significant drops
    if (delta_int < -4096) {
        ESP_LOGW(TAG, "[%s] Significant DRAM drop: %+ld bytes", label, static_cast<long>(delta_int));
    }
    if (delta_spi < -65536) {
        ESP_LOGW(TAG, "[%s] Significant SPIRAM drop: %+ld bytes", label, static_cast<long>(delta_spi));
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
