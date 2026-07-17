#include "sdkconfig.h"

#ifdef CONFIG_KD_COMMON_ETH_ENABLE

#include "eth.h"
#include "net.h"
#include "wifi.h"
#include "provisioning.h"
#include "kd_common.h"

#include <string.h>

#include <esp_log.h>
#include <esp_event.h>
#include <esp_mac.h>
#include <esp_netif.h>
#include <esp_eth.h>

#include <driver/spi_master.h>

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/event_groups.h>

// W6100 driver from the espressif/w6100 managed component. It plugs into the
// standard esp_eth SPI framework, exactly like the built-in W5500 driver.
#include "esp_eth_mac_w6100.h"
#include "esp_eth_phy_w6100.h"

static const char* TAG = "kd_eth";

// The Kconfig host choice maps to the esp_eth SPI host enum here.
#if CONFIG_KD_COMMON_ETH_SPI_HOST_2
#define ETH_SPI_HOST SPI2_HOST
#else
#define ETH_SPI_HOST SPI3_HOST
#endif

#define GOT_IP_BIT BIT0

static esp_eth_handle_t s_eth_handle = NULL;
static esp_netif_t* s_eth_netif = NULL;
static EventGroupHandle_t s_eth_events = NULL;

// Set true when eth_init() gives up and lets WiFi/BLE start as the fallback.
// A later Ethernet GOT_IP then means "link came back after we fell back", which
// is the only case where we need to tear the WiFi/BLE fallback down.
static volatile bool s_fallback_engaged = false;
static volatile bool s_took_over = false;

// WiFi + BLE teardown must not run in the event-loop task (BLE/prov deinit posts
// and waits on events processed by that same loop). Do it in a one-shot task.
static void eth_takeover_task(void* arg) {
    (void)arg;
    ESP_LOGI(TAG, "Ethernet up after WiFi fallback; disabling WiFi and BLE");
    provisioning_shutdown_for_eth();  // stop BLE prov + suppress WiFi reconnect
    wifi_shutdown();                  // disconnect + stop the WiFi driver
    vTaskDelete(NULL);
}

static void eth_event_handler(void* arg, esp_event_base_t base, int32_t id, void* data) {
    (void)arg;
    (void)data;
    if (base != ETH_EVENT) return;

    switch (id) {
    case ETHERNET_EVENT_CONNECTED:
        ESP_LOGI(TAG, "link up");
        break;
    case ETHERNET_EVENT_DISCONNECTED:
        ESP_LOGI(TAG, "link down");
        net_set_link_up(NET_IF_ETH, false);
        net_dispatch_disconnect();
        break;
    default:
        break;
    }
}

static void got_ip_handler(void* arg, esp_event_base_t base, int32_t id, void* data) {
    (void)arg;
    (void)base;
    (void)id;
    ip_event_got_ip_t* event = (ip_event_got_ip_t*)data;
    ESP_LOGI(TAG, "got IP: " IPSTR, IP2STR(&event->ip_info.ip));
    net_set_link_up(NET_IF_ETH, true);
    net_dispatch_connect();
    if (s_eth_events) {
        xEventGroupSetBits(s_eth_events, GOT_IP_BIT);
    }

    // Only relevant if WiFi/BLE were started as a fallback before Ethernet came
    // up (hot-plug). When Ethernet wins the boot race this stays false and the
    // fallback is never started, so there is nothing to tear down.
    if (s_fallback_engaged && !s_took_over) {
        s_took_over = true;
        xTaskCreate(eth_takeover_task, "eth_takeover", 4096, NULL, 5, NULL);
    }
}

// Runs the DHCP wait and the WiFi-fallback decision off the init path so
// kd_common_init() returns immediately instead of blocking for the timeout.
static void eth_supervisor_task(void* arg) {
    uint32_t link_wait_ms = (uint32_t)(uintptr_t)arg;

    EventBits_t bits = xEventGroupWaitBits(s_eth_events, GOT_IP_BIT, pdFALSE, pdFALSE,
        pdMS_TO_TICKS(link_wait_ms));
    if (bits & GOT_IP_BIT) {
        ESP_LOGI(TAG, "Ethernet active; WiFi and BLE provisioning not started");
        vTaskDelete(NULL);
        return;
    }

    // Timed out. Arm the hot-plug takeover first (so a link-up racing us tears
    // the fallback back down via got_ip_handler), then re-check the bit in case
    // Ethernet came up right at the boundary — avoids starting WiFi needlessly.
    s_fallback_engaged = true;
    if (xEventGroupGetBits(s_eth_events) & GOT_IP_BIT) {
        ESP_LOGI(TAG, "Ethernet came up at the timeout boundary; skipping WiFi");
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGW(TAG, "no Ethernet link/DHCP within %ums; starting WiFi/BLE fallback "
                  "(Ethernet left running; will take over if it links later)",
        (unsigned)link_wait_ms);
    wifi_init();
    provisioning_init();
    wifi_start();
    vTaskDelete(NULL);
}

esp_err_t eth_init(uint32_t link_wait_ms) {
    // Shared with WiFi; idempotent so calling before wifi_init() is fine.
    esp_netif_init();

    s_eth_events = xEventGroupCreate();
    if (!s_eth_events) {
        ESP_LOGE(TAG, "event group alloc failed");
        return ESP_FAIL;
    }

    spi_bus_config_t buscfg = {
        .miso_io_num = CONFIG_KD_COMMON_ETH_PIN_MISO,
        .mosi_io_num = CONFIG_KD_COMMON_ETH_PIN_MOSI,
        .sclk_io_num = CONFIG_KD_COMMON_ETH_PIN_SCK,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
    };
    esp_err_t err = spi_bus_initialize(ETH_SPI_HOST, &buscfg, SPI_DMA_CH_AUTO);
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "spi_bus_initialize failed: %s", esp_err_to_name(err));
        return ESP_FAIL;
    }

    spi_device_interface_config_t devcfg = {
        .mode = 0,
        .clock_speed_hz = CONFIG_KD_COMMON_ETH_SPI_CLOCK_MHZ * 1000 * 1000,
        .queue_size = 20,
        .spics_io_num = CONFIG_KD_COMMON_ETH_PIN_CS,
    };

    // .base holds the common WIZnet SPI config (int_gpio_num, poll_period_ms,
    // spi_host_id, spi_devcfg). poll_period_ms defaults to 0 => interrupt mode.
    eth_w6100_config_t w6100_config = ETH_W6100_DEFAULT_CONFIG(ETH_SPI_HOST, &devcfg);
    w6100_config.base.int_gpio_num = CONFIG_KD_COMMON_ETH_PIN_INT;

    eth_mac_config_t mac_config = ETH_MAC_DEFAULT_CONFIG();
    esp_eth_mac_t* mac = esp_eth_mac_new_w6100(&w6100_config, &mac_config);

    eth_phy_config_t phy_config = ETH_PHY_DEFAULT_CONFIG();
    phy_config.reset_gpio_num = CONFIG_KD_COMMON_ETH_PIN_RST;
    esp_eth_phy_t* phy = esp_eth_phy_new_w6100(&phy_config);

    if (!mac || !phy) {
        ESP_LOGE(TAG, "failed to create W6100 MAC/PHY");
        return ESP_FAIL;
    }

    esp_eth_config_t eth_config = ETH_DEFAULT_CONFIG(mac, phy);
    err = esp_eth_driver_install(&eth_config, &s_eth_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "driver install failed: %s", esp_err_to_name(err));
        return ESP_FAIL;
    }

    // SPI Ethernet chips have no factory MAC; assign the ESP's universal
    // Ethernet MAC (CONFIG_ESP_MAC_ADDR_UNIVERSE_ETH) so DHCP is stable.
    uint8_t mac_addr[6] = { 0 };
    if (esp_read_mac(mac_addr, ESP_MAC_ETH) == ESP_OK) {
        esp_eth_ioctl(s_eth_handle, ETH_CMD_S_MAC_ADDR, mac_addr);
    }

    esp_netif_config_t netif_cfg = ESP_NETIF_DEFAULT_ETH();
    s_eth_netif = esp_netif_new(&netif_cfg);
    if (!s_eth_netif) {
        ESP_LOGE(TAG, "esp_netif_new failed");
        return ESP_FAIL;
    }
    err = esp_netif_attach(s_eth_netif, esp_eth_new_netif_glue(s_eth_handle));
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "netif attach failed: %s", esp_err_to_name(err));
        return ESP_FAIL;
    }

    // Set before the driver starts so it lands in the first DHCP DISCOVER,
    // mirroring the WiFi path. Uses the same hostname source as WiFi.
    esp_netif_set_hostname(s_eth_netif, kd_common_get_wifi_hostname());

    esp_event_handler_register(ETH_EVENT, ESP_EVENT_ANY_ID, eth_event_handler, NULL);
    esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, got_ip_handler, NULL);

    err = esp_eth_start(s_eth_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "eth start failed: %s", esp_err_to_name(err));
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "W6100 started on SPI%d (CS %d, INT %d, RST %d); waiting up to %ums "
                  "for DHCP in the background",
        ETH_SPI_HOST + 1, CONFIG_KD_COMMON_ETH_PIN_CS, CONFIG_KD_COMMON_ETH_PIN_INT,
        CONFIG_KD_COMMON_ETH_PIN_RST, (unsigned)link_wait_ms);

    // Hand the DHCP wait and the WiFi-fallback decision to a background task so
    // kd_common_init() returns immediately instead of blocking for the timeout.
    if (xTaskCreate(eth_supervisor_task, "eth_super", 6144,
            (void*)(uintptr_t)link_wait_ms, 5, NULL) != pdPASS) {
        ESP_LOGE(TAG, "failed to spawn eth supervisor task");
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

#endif // CONFIG_KD_COMMON_ETH_ENABLE
