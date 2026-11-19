/* Resource limits for the built-in MQTT broker.
 *
 * The espressif/mosquitto port builds its configuration internally
 * (config__init() in port/config.c) with mosquitto's desktop defaults:
 * unlimited packet size, 1000 queued messages per client and no connection
 * limit. On the router that lets a single client, before authenticating,
 * make the broker allocate an arbitrarily large CONNECT packet, or hold
 * every lwIP socket. mosq_broker_config has no fields for these limits, so
 * they are set by interposing the two functions the port calls to set up
 * its config and its listener (linker --wrap, see CMakeLists.txt; the port
 * sources stay unmodified).
 *
 * This file includes mosquitto's private broker headers. It is compiled
 * with the same include path and WITH_BROKER define as the port itself, so
 * the struct layouts match; keep it free of anything else. It also hosts
 * the one shim the Home Assistant code needs into mosquitto's internals
 * (mb_internal_publish, see mb_internal.h).
 *
 * SPDX-License-Identifier: MIT
 */

/* Must come first: mosquitto's config.h sets feature macros that have to
 * precede every system header. */
#include "mosquitto_broker_internal.h"

#include "sdkconfig.h"

/* Queue limits per client. A stored message is shared by all its
 * subscribers; these bound what one slow or stalled subscriber can pin. */
#define MB_MAX_QUEUED_MESSAGES  32
#define MB_MAX_QUEUED_BYTES     (8 * 1024)
#define MB_MAX_INFLIGHT_MSGS    10
#define MB_MAX_INFLIGHT_BYTES   (8 * 1024)

void __real_config__init(struct mosquitto__config *config);

void __wrap_config__init(struct mosquitto__config *config)
{
    __real_config__init(config);
    config->max_packet_size       = CONFIG_MQTT_BROKER_MAX_PACKET;
    config->max_queued_messages   = MB_MAX_QUEUED_MESSAGES;
    config->max_queued_bytes      = MB_MAX_QUEUED_BYTES;
    config->max_inflight_messages = MB_MAX_INFLIGHT_MSGS;
    config->max_inflight_bytes    = MB_MAX_INFLIGHT_BYTES;
}

void __real_listener__set_defaults(struct mosquitto__listener *listener);

void __wrap_listener__set_defaults(struct mosquitto__listener *listener)
{
    __real_listener__set_defaults(listener);
    /* Enforced in net__socket_accept() right after accept(); the socket of
     * a connection over the limit is closed at once. */
    listener->max_connections = CONFIG_MQTT_BROKER_MAX_CLIENTS;
}

#if CONFIG_MQTT_HA
#include "mb_internal.h"

/* Broker-originated publish for the Home Assistant topics (mqtt_ha.c).
 * db__messages_easy_queue() is what mosquitto itself uses for messages a
 * plugin publishes (queue_plugin_msgs() in loop.c): context NULL marks the
 * broker as origin. It walks the subscription tree, so it must run on the
 * broker task between packets — mqtt_ha.c calls it from the
 * plugin__handle_tick interposer. Internal API of mosquitto 2.0.x (the
 * port is pinned in main/idf_component.yml). */
bool mb_internal_publish(const char *topic, const void *payload, size_t len,
                         bool retain)
{
    return db__messages_easy_queue(NULL, topic, 0, (uint32_t)len, payload,
                                   retain ? 1 : 0, 0, NULL) == MOSQ_ERR_SUCCESS;
}
#endif
