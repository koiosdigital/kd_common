cmake_minimum_required(VERSION 3.16)
    
file(GLOB_RECURSE NESTED_SRC
       **.cpp
)

idf_component_register(
    SRCS ${NESTED_SRC}
    INCLUDE_DIRS "srcs"
    PRIV_INCLUDE_DIRS "srcs_private"
    REQUIRES bt esp_wifi nvs_flash wifi_provisioning efuse esp_http_client json esp_https_ota mbedtls bootloader_support esp_hw_support
)
