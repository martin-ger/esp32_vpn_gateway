/* Built-in MQTT broker (espressif/mosquitto port).
 *
 * Runs a local MQTT broker on the router so devices can publish/subscribe
 * without an external broker. The listener is on 0.0.0.0; each accepted
 * connection is checked against the selected interfaces (AP / STA / VPN,
 * any combination) by the local address it was made to, and dropped if that
 * interface is not selected.
 *
 * SPDX-License-Identifier: MIT
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef CONFIG_MQTT_BROKER

/* Buffer size for the broker username/password (max length + NUL). */
#define MQTT_BROKER_CRED_MAX 64

typedef struct {
    bool enabled;        /* persisted in NVS */
    bool running;        /* broker main loop currently active */
    bool port_in_use;    /* the port is taken by another listener; the
                          * broker waits until it becomes free */
    uint16_t port;
    uint8_t bind;        /* bitmask of interfaces served:
                           * RC_BIND_AP | RC_BIND_STA | RC_BIND_VPN
                           * (see remote_console.h) */
    char bind_desc[24];  /* bind bitmask as text ("AP, VPN") */
    bool auth_required;  /* a broker user is configured */
    uint32_t messages;   /* total messages processed by the broker */
    char user[MQTT_BROKER_CRED_MAX]; /* configured username ("" = open) */
    char listen_addr[64];/* IPs of the selected interfaces that are up
                          * ("1.2.3.4, 5.6.7.8"), "" if none */
} mqtt_broker_info_t;

/**
 * @brief Load NVS config, register the 'mqtt' console command, start the
 *        broker task if enabled. Call once from app_main() after console
 *        init. The broker task waits until at least one selected interface
 *        has an IP before it starts listening, so the uplink init order
 *        does not matter.
 */
void mqtt_broker_init(void);

/** @brief Persist enabled=1 and start the broker task (no-op if running).
 *  @return ESP_ERR_TIMEOUT if a previous disable is still shutting down. */
esp_err_t mqtt_broker_enable(void);

/** @brief Persist enabled=0 and stop the broker (no-op if not running). */
esp_err_t mqtt_broker_disable(void);

/** @brief Set the listen port and restart the running listener. */
esp_err_t mqtt_broker_set_port(uint16_t port);

/**
 * @brief Set which interfaces the broker serves: any combination of
 *        RC_BIND_AP (default, LAN), RC_BIND_STA (uplink) and RC_BIND_VPN
 *        (tunnel) — at least one bit must be set. Connections arriving on
 *        unselected interfaces are rejected at the TCP level. The change
 *        takes effect immediately without restarting the listener. While
 *        none of the selected interfaces has an IP (e.g. VPN down), the
 *        broker waits.
 */
esp_err_t mqtt_broker_set_bind(uint8_t bind);

/**
 * @brief Set the credentials clients must use to connect.
 *
 * user == "" opens the broker (no authentication).
 * pass == NULL keeps the current password (used when only the username
 * is changed). Both must be shorter than MQTT_BROKER_CRED_MAX.
 */
esp_err_t mqtt_broker_set_credentials(const char *user, const char *pass);

/**
 * @brief Stop and restart the broker loop so it picks up a new port.
 *        Drops all connected clients. No-op while the broker is not
 *        running.
 */
void mqtt_broker_rebind(void);

/** @brief Fill @p info with current config and runtime state. */
void mqtt_broker_get_info(mqtt_broker_info_t *info);

#endif /* CONFIG_MQTT_BROKER */

#ifdef __cplusplus
}
#endif
