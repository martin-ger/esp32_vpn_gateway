if(CONFIG_MQTT_BROKER)
    set(MQTT_BROKER_SRCS "mqtt_broker.c")
else()
    set(MQTT_BROKER_SRCS "")
endif()

idf_component_register(
    SRCS ${MQTT_BROKER_SRCS}
    INCLUDE_DIRS "include"
    PRIV_REQUIRES espressif__mosquitto console lwip esp_netif nvs_flash
                    freertos cmd_router remote_console esp_timer
)
target_compile_options(${COMPONENT_LIB} PRIVATE -Os)
