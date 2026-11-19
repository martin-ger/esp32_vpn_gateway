/* Home Assistant MQTT discovery on the built-in broker.
 *
 * Publishes router telemetry, per-client stats and HA discovery configs
 * straight into the local mosquitto broker (no MQTT client library) and
 * handles the HA command topics published by broker clients. Compiled only
 * with CONFIG_MQTT_HA; switched on and off at run time (NVS "mb_ha").
 *
 * SPDX-License-Identifier: MIT
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "sdkconfig.h"

#ifdef __cplusplus
extern "C" {
#endif

#if CONFIG_MQTT_HA

#define MQTT_HA_INTERVAL_MIN  5
#define MQTT_HA_INTERVAL_MAX  3600

/** @brief Load the persisted switch and interval (called by mqtt_broker_init). */
void mqtt_ha_load_config(void);

/** @brief Switch the HA topics on or off (persisted). Takes effect within
 *         one broker loop pass while the broker runs. */
void mqtt_ha_set_enabled(bool enabled);
bool mqtt_ha_is_enabled(void);

/** @brief Set the state publish interval in seconds (persisted, 5-3600).
 *  @return false if out of range. */
bool mqtt_ha_set_interval(uint32_t seconds);
uint32_t mqtt_ha_get_interval(void);

/** @brief Publish the discovery configs again. */
void mqtt_ha_rediscover(void);

/** @brief Device id used in discovery ("esp32_nat_router_<AP MAC>"),
 *         "" until the HA topics were first published. */
const char *mqtt_ha_device_id(void);

/* ---- Hooks for mqtt_broker.c (broker task) ---- */

/** @brief Every message a client publishes (payload not NUL-terminated). */
void mqtt_ha_on_message(const char *topic, const char *data, int len);

/** @brief Called right before the broker loop (re)starts: everything is
 *         announced again (the broker's retained store starts empty). */
void mqtt_ha_broker_started(void);

#endif /* CONFIG_MQTT_HA */

#ifdef __cplusplus
}
#endif
