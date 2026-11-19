if(CONFIG_MQTT_BROKER)
    set(MQTT_BROKER_SRCS "mqtt_broker.c" "mqtt_broker_limits.c")
    if(CONFIG_MQTT_HA)
        list(APPEND MQTT_BROKER_SRCS "mqtt_ha.c")
    endif()
else()
    set(MQTT_BROKER_SRCS "")
endif()

idf_component_register(
    SRCS ${MQTT_BROKER_SRCS}
    INCLUDE_DIRS "include"
    PRIV_REQUIRES espressif__mosquitto console lwip esp_netif nvs_flash
                    freertos cmd_router remote_console esp_timer
                    esp_wifi esp_app_format
)
target_compile_options(${COMPONENT_LIB} PRIVATE -Os)

if(CONFIG_MQTT_BROKER)
    # Interposers on the mosquitto port (linker --wrap, the same mechanism
    # the port itself uses for mosquitto_unpwd_check); the port sources stay
    # unmodified:
    #   context__init         accept-time interface filter (mqtt_broker.c)
    #   mosquitto_main_loop   makes a stop request that raced the broker
    #                         startup take effect (mqtt_broker.c)
    #   config__init,         packet size, queue and connection limits
    #   listener__set_defaults  (mqtt_broker_limits.c)
    target_link_options(${COMPONENT_LIB} INTERFACE
        "-Wl,--wrap=context__init"
        "-Wl,--wrap=mosquitto_main_loop"
        "-Wl,--wrap=config__init"
        "-Wl,--wrap=listener__set_defaults"
        # Nothing outside the mosquitto archive references the limits
        # object, and that archive is scanned after this one: force it in.
        "-Wl,-u,__wrap_config__init"
        "-Wl,-u,__wrap_listener__set_defaults")

    if(CONFIG_MQTT_HA)
        # Home Assistant topics (mqtt_ha.c): the port's empty
        # plugin__handle_tick() stub runs once per broker loop pass and is
        # the hook where the broker publishes its own messages.
        target_link_options(${COMPONENT_LIB} INTERFACE
            "-Wl,--wrap=plugin__handle_tick"
            "-Wl,-u,__wrap_plugin__handle_tick")
    endif()

    # mqtt_broker_limits.c sets fields in mosquitto's private config and
    # listener structs: compile it with the port's own private include path
    # and defines so the layouts match.
    idf_component_get_property(mosq_dir espressif__mosquitto COMPONENT_DIR)
    set_source_files_properties(mqtt_broker_limits.c PROPERTIES
        INCLUDE_DIRECTORIES
            "${mosq_dir}/port/priv_include;${mosq_dir}/port/priv_include/sys;${mosq_dir}/mosquitto;${mosq_dir}/mosquitto/src;${mosq_dir}/mosquitto/include;${mosq_dir}/mosquitto/lib;${mosq_dir}/mosquitto/deps"
        COMPILE_DEFINITIONS "WITH_BROKER")
endif()
