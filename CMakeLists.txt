cmake_minimum_required(VERSION 3.16)
    
file(GLOB_RECURSE NESTED_SRC
       **.cpp
)

idf_component_register(
    SRCS ${NESTED_SRC}
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "src"
    REQUIRES bt esp_wifi nvs_flash wifi_provisioning efuse esp_http_client json esp_https_ota mbedtls bootloader_support console esp_driver_uart esp_driver_usb_serial_jtag esp_hw_support protobufs
)
