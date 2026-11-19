/* Home Assistant MQTT discovery on the built-in broker.
 *
 * The broker itself is the "device": telemetry, per-client stats and the
 * HA discovery configs are injected straight into the local mosquitto
 * broker, and the HA command topics are taken from the messages clients
 * publish to it. No MQTT client library, no socket, no extra task.
 *
 * Everything that touches mosquitto runs on the broker task: the port's
 * empty plugin__handle_tick() stub is called once per main-loop pass (the
 * poll() in mux__handle times out after 100 ms) and is interposed here
 * with linker --wrap (see CMakeLists.txt). Console and HTTP tasks only
 * set flags. Topics and payloads are the ones the former esp-mqtt based
 * integration used (wiki: MQTT-Home-Assistant).
 *
 * Compile-time guarded by CONFIG_MQTT_HA, switched at run time (NVS
 * "mb_ha"; off by default).
 *
 * SPDX-License-Identifier: MIT
 */

#include "sdkconfig.h"
#if CONFIG_MQTT_HA

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <inttypes.h>

#include "mqtt_ha.h"
#include "mb_internal.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "esp_system.h"
#include "esp_app_desc.h"
#include "nvs.h"
#include "soc/soc_caps.h"

#include "esp_netif_ip_addr.h"
#include "router_config.h"
#include "wifi_config.h"
#include "client_stats.h"
#include "dhcp_reservations.h"
#include "remote_console.h"
#include "vpn_config.h"
#if CONFIG_WG_SERVER
#include "wg_server.h"
#endif

static const char *TAG = "mqtt_ha";

/* ---------- NVS keys (namespace PARAM_NAMESPACE = "esp32_nat") ---------- */
#define NVS_KEY_HA_EN    "mb_ha"
#define NVS_KEY_HA_INTV  "mb_ha_intv"

/* ---------- Topics ---------- */
#define TOPIC_PREFIX       "esp32_nat_router"
#define TOPIC_STATE        TOPIC_PREFIX "/state"
#define TOPIC_AVAILABILITY TOPIC_PREFIX "/availability"
#define TOPIC_CMD          TOPIC_PREFIX "/command/"
#define TOPIC_CLIENTS      TOPIC_PREFIX "/clients/"
#define TOPIC_HA_STATUS    "homeassistant/status"

/* ---------- Settings (written by console/HTTP tasks) ---------- */
static volatile bool     s_on       = false;
static volatile uint32_t s_interval = CONFIG_MQTT_HA_DEFAULT_INTERVAL;

/* ---------- Requests to the broker task ---------- */
static volatile bool   s_req_discover;   /* (re)publish discovery */
static volatile bool   s_req_state;      /* publish state on next tick */
static volatile bool   s_req_restart;
static volatile int8_t s_req_web_ui = -1;          /* -1 none, 0 off, 1 on */
static volatile int8_t s_req_remote_console = -1;
static volatile int8_t s_req_ap = -1;

/* ---------- Broker task state ---------- */
static bool    s_active;        /* "online" announced in this broker run */
static int     s_disc_step = -1; /* next discovery message, -1 = idle */
static int64_t s_next_state_us;

static char s_device_id[32];    /* "esp32_nat_router_AABBCCDDEEFF" */

/* ================================================================
 *  Helpers
 * ================================================================ */

static void build_device_id(void)
{
    uint8_t mac[6];
    if (esp_wifi_get_mac(WIFI_IF_AP, mac) != ESP_OK) {
        return;  /* retried on the next activation */
    }
    snprintf(s_device_id, sizeof(s_device_id),
             "esp32_nat_router_%02X%02X%02X%02X%02X%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void mac_hex(const uint8_t *mac, char out[13])
{
    snprintf(out, 13, "%02X%02X%02X%02X%02X%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* Copy a string for use inside a JSON string literal: escapes '"' and '\\',
 * writes control characters as \u00XX. If out is too small the result is
 * cut at a whole character (never inside an escape or a UTF-8 sequence).
 * Two bytes per input byte are enough unless the input has control chars. */
static void json_escape(const char *in, char *out, size_t len)
{
    static const char hex[] = "0123456789abcdef";
    size_t o = 0;

    if (len == 0) return;
    for (; *in; in++) {
        unsigned char c = (unsigned char)*in;
        size_t need = (c == '"' || c == '\\') ? 2 : (c < 0x20) ? 6 : 1;
        if (o + need >= len) {
            /* drop a multi-byte UTF-8 character that was only partly copied */
            size_t k = o;
            while (k > 0 && ((unsigned char)out[k - 1] & 0xC0) == 0x80) k--;
            if (k > 0 && ((unsigned char)out[k - 1] & 0xC0) == 0xC0) {
                unsigned char lead = (unsigned char)out[k - 1];
                size_t seq = (lead >= 0xF0) ? 4 : (lead >= 0xE0) ? 3 : 2;
                if (o - (k - 1) < seq) o = k - 1;
            }
            break;
        }
        if (need == 2) {
            out[o++] = '\\';
            out[o++] = (char)c;
        } else if (need == 6) {
            out[o++] = '\\'; out[o++] = 'u'; out[o++] = '0'; out[o++] = '0';
            out[o++] = hex[c >> 4];
            out[o++] = hex[c & 0x0F];
        } else {
            out[o++] = (char)c;
        }
    }
    out[o] = '\0';
}

/* Room for a 32-byte SSID or name with every byte escaped (2 bytes each) */
#define JSON_NAME_MAX 72

/* Append to a buffer; on overflow *n is set past the end so the caller
 * can tell (and never publishes a truncated payload). */
static void jcat(char *buf, size_t len, int *n, const char *fmt, ...)
{
    if (*n < 0 || (size_t)*n >= len) {
        *n = (int)len;
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    int r = vsnprintf(buf + *n, len - *n, fmt, ap);
    va_end(ap);
    *n = (r < 0) ? (int)len : *n + r;
}

static bool pub(const char *topic, const char *payload, bool retain)
{
    return mb_internal_publish(topic, payload, strlen(payload), retain);
}

/* ================================================================
 *  Discovery
 * ================================================================ */

typedef struct {
    const char *component;  /* HA component: sensor, binary_sensor, ... */
    const char *object;     /* object id (topic + unique id suffix) */
    const char *name;
    const char *value_key;  /* key in the state JSON, NULL = no state */
    const char *command;    /* command topic suffix, NULL = none */
    const char *extra;      /* further fields, each ending with ',' */
} ha_entity_t;

#define X_ONOFF        "\"pl_on\":\"ON\",\"pl_off\":\"OFF\","
#define X_DATA_TOTAL   "\"dev_cla\":\"data_size\",\"stat_cla\":\"total_increasing\"," \
                       "\"unit_of_meas\":\"B\","
#define X_RSSI         "\"dev_cla\":\"signal_strength\",\"stat_cla\":\"measurement\"," \
                       "\"unit_of_meas\":\"dBm\","
#define X_DIAG         "\"entity_category\":\"diagnostic\","
#define X_CONFIG       "\"entity_category\":\"config\","

static const ha_entity_t s_router_entities[] = {
    { "binary_sensor", "uplink", "Uplink Status", "uplink", NULL,
      "\"dev_cla\":\"connectivity\"," X_ONOFF },
    { "sensor", "clients", "Connected Clients", "clients", NULL,
      "\"stat_cla\":\"measurement\",\"ic\":\"mdi:wifi\"," },
    { "sensor", "bytes_tx", "Bytes Sent", "bytes_tx", NULL, X_DATA_TOTAL },
    { "sensor", "bytes_rx", "Bytes Received", "bytes_rx", NULL, X_DATA_TOTAL },
    { "sensor", "free_heap", "Free Heap", "free_heap", NULL,
      "\"dev_cla\":\"data_size\",\"stat_cla\":\"measurement\","
      "\"unit_of_meas\":\"B\"," X_DIAG },
    { "sensor", "uptime", "Uptime", "uptime", NULL,
      "\"dev_cla\":\"duration\",\"stat_cla\":\"total_increasing\","
      "\"unit_of_meas\":\"s\"," X_DIAG },
#if !CONFIG_ETH_UPLINK
    { "sensor", "rssi", "Uplink RSSI", "rssi", NULL, X_RSSI X_DIAG },
    { "sensor", "uplink_ssid", "Uplink SSID", "ssid", NULL,
      "\"ic\":\"mdi:wifi-settings\"," X_DIAG },
#endif
    { "binary_sensor", "vpn", "VPN Status", "vpn", NULL,
      "\"dev_cla\":\"connectivity\"," X_ONOFF "\"ic\":\"mdi:vpn\"," },
#if CONFIG_WG_SERVER
    { "sensor", "vpn_clients", "VPN Clients", "vpn_clients", NULL,
      "\"stat_cla\":\"measurement\",\"ic\":\"mdi:account-network\"," },
#endif
#if SOC_TEMP_SENSOR_SUPPORTED
    { "sensor", "cpu_temp", "CPU Temperature", "cpu_temp", NULL,
      "\"dev_cla\":\"temperature\",\"stat_cla\":\"measurement\","
      "\"unit_of_meas\":\"°C\"," X_DIAG },
#endif
    { "button", "restart", "Restart", NULL, "restart",
      "\"dev_cla\":\"restart\"," X_CONFIG },
    { "switch", "web_ui", "Web UI", "web_ui", "web_ui",
      "\"ic\":\"mdi:web\"," X_CONFIG },
    { "switch", "remote_console", "Remote Console", "remote_console",
      "remote_console", "\"ic\":\"mdi:console\"," X_CONFIG },
    { "switch", "ap", "AP Interface", "ap_enabled", "ap",
      "\"ic\":\"mdi:access-point\"," },
};
#define N_ROUTER_ENTITIES \
    ((int)(sizeof(s_router_entities) / sizeof(s_router_entities[0])))

/* Per DHCP reservation; state topic esp32_nat_router/clients/<MAC> */
static const ha_entity_t s_client_entities[] = {
    { "binary_sensor", "presence", "Presence", "present", NULL,
      "\"dev_cla\":\"presence\"," X_ONOFF },
    { "sensor", "tx", "TX", "tx", NULL, X_DATA_TOTAL },
    { "sensor", "rx", "RX", "rx", NULL, X_DATA_TOTAL },
    { "sensor", "rssi", "RSSI", "rssi", NULL, X_RSSI },
};
#define N_CLIENT_ENTITIES \
    ((int)(sizeof(s_client_entities) / sizeof(s_client_entities[0])))

/* Publish one discovery config.
 *   cmac   NULL for a router entity, else the client's MAC (hex)
 *   cname  client display name (JSON-escaped), with cmac only */
static void publish_config(const ha_entity_t *e, const char *cmac,
                           const char *cname)
{
    char topic[128];
    char payload[768];
    char ap_name[JSON_NAME_MAX];
    char ip_str[16];
    int n = 0;

    snprintf(topic, sizeof(topic), "homeassistant/%s/%s/%s%s%s/config",
             e->component, s_device_id,
             cmac ? cmac : "", cmac ? "_" : "", e->object);

    if (cmac) {
        jcat(payload, sizeof(payload), &n,
             "{\"name\":\"%s %s\",\"uniq_id\":\"%s_%s_%s\",",
             cname, e->name, s_device_id, cmac, e->object);
    } else {
        jcat(payload, sizeof(payload), &n,
             "{\"name\":\"%s\",\"uniq_id\":\"%s_%s\",",
             e->name, s_device_id, e->object);
    }
    if (e->value_key) {
        if (cmac) {
            jcat(payload, sizeof(payload), &n,
                 "\"stat_t\":\"" TOPIC_CLIENTS "%s\",", cmac);
        } else {
            jcat(payload, sizeof(payload), &n,
                 "\"stat_t\":\"" TOPIC_STATE "\",");
        }
        jcat(payload, sizeof(payload), &n,
             "\"val_tpl\":\"{{value_json.%s}}\",", e->value_key);
    }
    if (e->command) {
        jcat(payload, sizeof(payload), &n,
             "\"cmd_t\":\"" TOPIC_CMD "%s\",", e->command);
    }

    /* Device block: the same in every config */
    json_escape(ap_ssid ? ap_ssid : "", ap_name, sizeof(ap_name));
    uint32_t cfg_ip = my_ip != 0 ? my_ip : my_ap_ip;
    snprintf(ip_str, sizeof(ip_str), IPSTR,
             IP2STR((esp_ip4_addr_t *)&cfg_ip));
    jcat(payload, sizeof(payload), &n,
         "%s\"avty_t\":\"" TOPIC_AVAILABILITY "\","
         "\"dev\":{\"ids\":[\"%s\"],\"name\":\"%s\",\"sw\":\"%s\","
         "\"cu\":\"http://%s\"}}",
         e->extra, s_device_id, ap_name,
         esp_app_get_description()->version, ip_str);

    if (n >= (int)sizeof(payload)) {
        ESP_LOGW(TAG, "discovery config %s too long, skipped", e->object);
        return;
    }
    /* Not retained: the broker would keep every config in RAM. Home
     * Assistant sends its birth message (homeassistant/status online)
     * each time it connects, which triggers a fresh discovery round. */
    pub(topic, payload, false);
}

/* Publish the next discovery config (s_disc_step); false once all are out.
 * Steps: router entities, then N_CLIENT_ENTITIES per reservation slot
 * (empty slots are skipped without costing a tick). */
static bool publish_discovery_next(void)
{
    int step = s_disc_step;
    if (step < N_ROUTER_ENTITIES) {
        publish_config(&s_router_entities[step], NULL, NULL);
        s_disc_step = step + 1;
        return true;
    }
    for (int k = step - N_ROUTER_ENTITIES;
         k < MAX_DHCP_RESERVATIONS * N_CLIENT_ENTITIES; ) {
        const struct dhcp_reservation_entry *r =
            &dhcp_reservations[k / N_CLIENT_ENTITIES];
        if (!r->valid) {
            k = (k / N_CLIENT_ENTITIES + 1) * N_CLIENT_ENTITIES;
            continue;
        }
        char cmac[13];
        char name[JSON_NAME_MAX];
        mac_hex(r->mac, cmac);
        json_escape(r->name[0] != '\0' ? r->name : cmac, name, sizeof(name));
        publish_config(&s_client_entities[k % N_CLIENT_ENTITIES], cmac, name);
        s_disc_step = N_ROUTER_ENTITIES + k + 1;
        return true;
    }
    return false;
}

/* ================================================================
 *  State
 * ================================================================ */

static bool is_web_ui_enabled(void)
{
    /* Read NVS directly: get_config_param_str() logs every read, which
     * would put a line in the log on every state publish. */
    char lock[4] = "";
    size_t len = sizeof(lock);
    nvs_handle_t h;
    if (nvs_open(PARAM_NAMESPACE, NVS_READONLY, &h) == ESP_OK) {
        if (nvs_get_str(h, "web_disabled", lock, &len) != ESP_OK) {
            lock[0] = '\0';
        }
        nvs_close(h);
    }
    return lock[0] == '\0' || strcmp(lock, "0") == 0;
}

static void publish_state(void)
{
    int8_t rssi = 0;
    char uplink_ssid[JSON_NAME_MAX] = "";
#if !CONFIG_ETH_UPLINK
    wifi_ap_record_t ap_info;
    if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK) {
        rssi = ap_info.rssi;
        ap_info.ssid[sizeof(ap_info.ssid) - 1] = '\0';
        json_escape((const char *)ap_info.ssid, uplink_ssid,
                    sizeof(uplink_ssid));
    }
#endif

    /* Router-level state. Every key is always present so that no
     * entity's value template hits a missing key. */
    char payload[448];
    int n = 0;
    jcat(payload, sizeof(payload), &n,
         "{\"uplink\":\"%s\",\"clients\":%u,"
         "\"bytes_tx\":%" PRIu64 ",\"bytes_rx\":%" PRIu64 ","
         "\"free_heap\":%" PRIu32 ",\"uptime\":%" PRIu32 ","
         "\"rssi\":%d,\"ssid\":\"%s\","
         "\"web_ui\":\"%s\",\"remote_console\":\"%s\","
         "\"ap_enabled\":\"%s\",\"vpn\":\"%s\"",
         ap_connect ? "ON" : "OFF",
         connect_count,
         get_sta_bytes_sent(),
         get_sta_bytes_received(),
         (uint32_t)esp_get_free_heap_size(),
         get_uptime_seconds(),
         rssi, uplink_ssid,
         is_web_ui_enabled() ? "ON" : "OFF",
         remote_console_is_enabled() ? "ON" : "OFF",
         ap_disabled ? "OFF" : "ON",
         vpn_is_connected() ? "ON" : "OFF");
#if CONFIG_WG_SERVER
    jcat(payload, sizeof(payload), &n, ",\"vpn_clients\":%d",
         wgs_connected_count());
#endif
#if SOC_TEMP_SENSOR_SUPPORTED
    {
        float celsius;
        /* null makes Home Assistant show the sensor as unknown */
        if (cpu_temperature_get(&celsius)) {
            jcat(payload, sizeof(payload), &n, ",\"cpu_temp\":%.1f",
                 celsius);
        } else {
            jcat(payload, sizeof(payload), &n, ",\"cpu_temp\":null");
        }
    }
#endif
    jcat(payload, sizeof(payload), &n, "}");
    if (n < (int)sizeof(payload)) {
        pub(TOPIC_STATE, payload, true);
    } else {
        ESP_LOGW(TAG, "state payload too long, not published");
    }

    /* Per-client state (DHCP reservations only) */
    wifi_sta_list_t sta_list;
    if (esp_wifi_ap_get_sta_list(&sta_list) != ESP_OK) {
        sta_list.num = 0;
    }
    client_stats_entry_t stats[CLIENT_STATS_MAX];
    int nstats = client_stats_get_all(stats, CLIENT_STATS_MAX);

    for (int i = 0; i < MAX_DHCP_RESERVATIONS; i++) {
        const struct dhcp_reservation_entry *r = &dhcp_reservations[i];
        if (!r->valid) continue;

        uint64_t tx = 0, rx = 0;
        bool present = false;
        for (int j = 0; j < nstats; j++) {
            if (memcmp(stats[j].mac, r->mac, 6) == 0) {
                tx = stats[j].bytes_sent;
                rx = stats[j].bytes_received;
                present = (stats[j].connected != 0);
                break;
            }
        }
        int8_t client_rssi = 0;
        for (int j = 0; j < sta_list.num; j++) {
            if (memcmp(sta_list.sta[j].mac, r->mac, 6) == 0) {
                client_rssi = sta_list.sta[j].rssi;
                present = true;  /* associated even without client stats */
                break;
            }
        }

        char cmac[13];
        char topic[48];
        mac_hex(r->mac, cmac);
        snprintf(topic, sizeof(topic), TOPIC_CLIENTS "%s", cmac);
        snprintf(payload, sizeof(payload),
                 "{\"present\":\"%s\",\"tx\":%" PRIu64 ",\"rx\":%" PRIu64
                 ",\"rssi\":%d}",
                 present ? "ON" : "OFF", tx, rx, client_rssi);
        pub(topic, payload, true);
    }
}

/* ================================================================
 *  Commands (run on the broker task, outside packet handling)
 * ================================================================ */

static void handle_commands(void)
{
    if (s_req_restart) {
        ESP_LOGW(TAG, "restart requested via MQTT");
        esp_restart();
    }

    int8_t v;
    if ((v = s_req_web_ui) >= 0) {
        s_req_web_ui = -1;
        ESP_LOGI(TAG, "web UI %s via MQTT", v ? "enabled" : "disabled");
        set_config_param_str("web_disabled", v ? "0" : "1");
        s_req_state = true;
    }
    if ((v = s_req_remote_console) >= 0) {
        s_req_remote_console = -1;
        ESP_LOGI(TAG, "remote console %s via MQTT",
                 v ? "enabled" : "disabled");
        if (v) {
            remote_console_enable();
        } else {
            remote_console_disable();
        }
        s_req_state = true;
    }
    if ((v = s_req_ap) >= 0) {
        s_req_ap = -1;
        ESP_LOGI(TAG, "AP interface %s via MQTT", v ? "enabled" : "disabled");
        ap_set_enabled(v != 0);
        s_req_state = true;
    }
}

/* ================================================================
 *  Broker loop tick (linker --wrap of the port's empty stub)
 * ================================================================ */

void __real_plugin__handle_tick(void);

void __wrap_plugin__handle_tick(void)
{
    __real_plugin__handle_tick();

    if (!s_on) {
        if (s_active) {
            /* switched off at run time */
            pub(TOPIC_AVAILABILITY, "offline", true);
            s_active = false;
            s_disc_step = -1;
            ESP_LOGI(TAG, "Home Assistant topics off");
        }
        return;
    }

    int64_t now = esp_timer_get_time();

    if (!s_active) {
        if (s_device_id[0] == '\0') {
            build_device_id();
            if (s_device_id[0] == '\0') {
                return;
            }
        }
        s_active = true;
        s_req_discover = true;
        s_req_state = true;
        pub(TOPIC_AVAILABILITY, "online", true);
        ESP_LOGI(TAG, "Home Assistant topics on (%s)", s_device_id);
    }

    handle_commands();

    if (s_req_discover) {
        s_req_discover = false;
        s_disc_step = 0;
    }
    /* One discovery config per pass keeps the burst within the
     * per-client queue limits (mqtt_broker_limits.c). */
    if (s_disc_step >= 0) {
        if (!publish_discovery_next()) {
            s_disc_step = -1;
            ESP_LOGI(TAG, "discovery configs published");
        }
    }

    if (s_req_state || now >= s_next_state_us) {
        s_req_state = false;
        s_next_state_us = now + (int64_t)s_interval * 1000000;
        publish_state();
    }
}

/* ================================================================
 *  Hooks from mqtt_broker.c
 * ================================================================ */

static bool topic_is(const char *topic, const char *cmd)
{
    return strncmp(topic, TOPIC_CMD, sizeof(TOPIC_CMD) - 1) == 0 &&
           strcmp(topic + sizeof(TOPIC_CMD) - 1, cmd) == 0;
}

static int8_t parse_onoff(const char *data, int len)
{
    if (data != NULL && len == 2 && strncasecmp(data, "ON", 2) == 0) {
        return 1;
    }
    if (data != NULL && len == 3 && strncasecmp(data, "OFF", 3) == 0) {
        return 0;
    }
    return -1;  /* ignore anything else */
}

void mqtt_ha_on_message(const char *topic, const char *data, int len)
{
    if (!s_on || topic == NULL) {
        return;
    }
    if (strcmp(topic, TOPIC_HA_STATUS) == 0) {
        if (data != NULL && len == 6 && memcmp(data, "online", 6) == 0) {
            s_req_discover = true;
            s_req_state = true;
        }
        return;
    }
    if (strncmp(topic, TOPIC_CMD, sizeof(TOPIC_CMD) - 1) != 0) {
        return;
    }
    if (topic_is(topic, "restart")) {
        s_req_restart = true;
    } else if (topic_is(topic, "web_ui")) {
        s_req_web_ui = parse_onoff(data, len);
    } else if (topic_is(topic, "remote_console")) {
        s_req_remote_console = parse_onoff(data, len);
    } else if (topic_is(topic, "ap")) {
        s_req_ap = parse_onoff(data, len);
    }
}

void mqtt_ha_broker_started(void)
{
    /* New broker run: its retained store is empty, announce everything
     * again on the first tick. */
    s_active = false;
    s_disc_step = -1;
    s_next_state_us = 0;
}

/* ================================================================
 *  Settings
 * ================================================================ */

void mqtt_ha_load_config(void)
{
    nvs_handle_t h;
    if (nvs_open(PARAM_NAMESPACE, NVS_READONLY, &h) != ESP_OK) {
        return;
    }
    int32_t en = 0;
    int32_t intv = (int32_t)s_interval;
    nvs_get_i32(h, NVS_KEY_HA_EN, &en);
    nvs_get_i32(h, NVS_KEY_HA_INTV, &intv);
    nvs_close(h);

    s_on = (en != 0);
    if (intv < MQTT_HA_INTERVAL_MIN) intv = MQTT_HA_INTERVAL_MIN;
    if (intv > MQTT_HA_INTERVAL_MAX) intv = MQTT_HA_INTERVAL_MAX;
    s_interval = (uint32_t)intv;
}

void mqtt_ha_set_enabled(bool enabled)
{
    s_on = enabled;
    set_config_param_int(NVS_KEY_HA_EN, enabled ? 1 : 0);
}

bool mqtt_ha_is_enabled(void)
{
    return s_on;
}

bool mqtt_ha_set_interval(uint32_t seconds)
{
    if (seconds < MQTT_HA_INTERVAL_MIN || seconds > MQTT_HA_INTERVAL_MAX) {
        return false;
    }
    s_interval = seconds;
    set_config_param_int(NVS_KEY_HA_INTV, (int32_t)seconds);
    s_req_state = true;  /* restart the period from now */
    return true;
}

uint32_t mqtt_ha_get_interval(void)
{
    return s_interval;
}

void mqtt_ha_rediscover(void)
{
    s_req_discover = true;
}

const char *mqtt_ha_device_id(void)
{
    return s_device_id;
}

#endif /* CONFIG_MQTT_HA */
