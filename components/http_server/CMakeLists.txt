# QR codes for WireGuard server client configs: only the chips that have a
# server variant pull in the encoder (same rule as main/idf_component.yml).
set(http_server_extra_requires)
if(IDF_TARGET STREQUAL "esp32" OR IDF_TARGET STREQUAL "esp32s3")
    list(APPEND http_server_extra_requires espressif__qrcode)
endif()

idf_component_register(
    SRCS "http_server.c"
    INCLUDE_DIRS "include"
    PRIV_REQUIRES esp_http_server esp_wifi esp_netif esp_event nvs_flash driver
                  esp_timer json cmd_router acl pcap_capture
                  remote_console dhcpserver wpa_supplicant
                  app_update esp_app_format mbedtls
                  ${http_server_extra_requires}
)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-unused-function -Os)

# The encoder core (qrcodegen.h) is used directly: the component's own
# esp_qrcode_generate() logs the text it encodes, which here contains a
# private key.
if(CONFIG_WG_SERVER)
    idf_component_get_property(qrcode_dir espressif__qrcode COMPONENT_DIR)
    target_include_directories(${COMPONENT_LIB} PRIVATE ${qrcode_dir})
endif()
