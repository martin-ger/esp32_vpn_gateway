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

if(CONFIG_MQTT_BROKER)
    # Accept-time interface filter: the port calls context__init() once per
    # accepted client socket and closes the socket when it returns NULL.
    # Interpose it to drop connections that arrive on unselected interfaces.
    # Same --wrap mechanism the port itself uses for mosquitto_unpwd_check;
    # the port sources stay unmodified.
    target_link_options(${COMPONENT_LIB} INTERFACE "-Wl,--wrap=context__init")
endif()
