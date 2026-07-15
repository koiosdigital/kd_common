cmake_minimum_required(VERSION 3.16)

file(GLOB_RECURSE NESTED_SRC
       **.c
)

set(EXCLUDE_COMPONENTS wifi_provisioning)

idf_component_register(
    SRCS ${NESTED_SRC}
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "src/include"
    REQUIRES bt esp_wifi esp_eth esp_netif esp_driver_spi nvs_flash esp_security network_provisioning efuse esp_http_client cjson mbedtls bootloader_support console esp_driver_uart esp_driver_usb_serial_jtag esp_hw_support protobufs esp_http_server mdns esp_app_format
)
