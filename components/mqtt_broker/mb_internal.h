/* Private interface between the router code and the shims that touch
 * mosquitto internals (mqtt_broker_limits.c, compiled with mosquitto's
 * private headers).
 *
 * SPDX-License-Identifier: MIT
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>

/**
 * @brief Publish a message from the broker itself (QoS 0) to all matching
 *        subscribers, and store it as retained if @p retain is set.
 *
 * Must only be called on the broker task, inside the broker main loop
 * (i.e. from the plugin__handle_tick interposer).
 *
 * @return true if the message was queued.
 */
bool mb_internal_publish(const char *topic, const void *payload, size_t len,
                         bool retain);
