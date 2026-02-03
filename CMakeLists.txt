cmake_minimum_required(VERSION 3.16)

file(GLOB_RECURSE NESTED_SRC
       **.c
)

set(EXCLUDE_COMPONENTS wifi_provisioning)

idf_component_register(
    SRCS ${NESTED_SRC}
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "src/include"
    REQUIRES bt esp_wifi nvs_flash esp_security network_provisioning efuse esp_http_client cjson esp_https_ota mbedtls bootloader_support console esp_driver_uart esp_driver_usb_serial_jtag esp_hw_support protobufs esp_http_server mdns
)
