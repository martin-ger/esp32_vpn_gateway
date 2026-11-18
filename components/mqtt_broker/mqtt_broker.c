/* Built-in MQTT broker (espressif/mosquitto port).
 *
 * Runs a local MQTT broker on the router so devices can publish/subscribe
 * without an external broker. The listener is bound to 0.0.0.0 and every
 * accepted connection is filtered at the TCP level by the interface IP it
 * arrived on (same model as the remote console): only connections coming in
 * on the selected interfaces (AP / STA / VPN, any combination) are served.
 * Compile-time guarded by CONFIG_MQTT_BROKER.
 *
 * SPDX-License-Identifier: MIT
 */

#include "sdkconfig.h"
#ifdef CONFIG_MQTT_BROKER

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "mqtt_broker.h"
#include "mosq_broker.h"
#include "esp_log.h"
#include "esp_console.h"
#include "argtable3/argtable3.h"
#include "nvs.h"
#include "freertos/FreeRTOS.h"
#include "freertos/portmacro.h"

#include "esp_netif_ip_addr.h"
#include "lwip/ip4_addr.h"
#include "esp_timer.h"
#include "router_config.h"
#include "wifi_config.h"
#include "remote_console.h"
#include "vpn_config.h"
#if CONFIG_WG_SERVER
#include "wg_server.h"
#endif

static const char *TAG = "mqtt_broker";

/* ---------- NVS keys (namespace PARAM_NAMESPACE = "esp32_nat") ---------- */
#define NVS_KEY_MB_EN    "mb_en"
#define NVS_KEY_MB_PORT  "mb_port"
#define NVS_KEY_MB_BIND  "mb_bind"
#define NVS_KEY_MB_USER  "mb_user"
#define NVS_KEY_MB_PASS  "mb_pass"

#define MB_DEFAULT_PORT  1883
#define MB_CRED_MAX      64

/* The mosquitto port needs at least 5 kB of stack; keep headroom for
 * nested topic-tree walks and large QoS 2 messages. */
#define MB_TASK_STACK    8192
#define MB_TASK_PRIO     4

#define MB_STOP_TIMEOUT_MS  3000
#define MB_STOP_POLL_MS     20

/* ---------- Runtime state ---------- */
static bool      s_enabled = false;
static uint16_t  s_port    = MB_DEFAULT_PORT;

/* Bitmask of RC_BIND_* (see remote_console.h): the listener serves all
 * selected interfaces at once. Written by console/HTTP tasks, read by the
 * broker task in the accept filter (single byte: reads are atomic). */
static volatile uint8_t s_bind = RC_BIND_AP;

static char      s_user[MB_CRED_MAX] = "";
static char      s_pass[MB_CRED_MAX] = "";

/* s_user/s_pass are written by console/HTTP tasks and read by the broker
 * task in the connect callback. */
static portMUX_TYPE s_cred_mux = portMUX_INITIALIZER_UNLOCKED;

static struct {
    TaskHandle_t task;
    volatile bool running;   /* broker main loop active */
    volatile bool shutdown;  /* task should exit */
    volatile bool rebind;    /* stop + restart with current settings */
    uint32_t messages;       /* total messages processed */
} s_state = {
    .task = NULL,
    .running = false,
    .shutdown = false,
    .rebind = false,
    .messages = 0,
};

/* ================================================================
 *  Helpers
 * ================================================================ */

/* IP of one interface (network byte order), 0 = currently no IP. */
static uint32_t bind_ip_for(uint8_t flag)
{
    switch (flag) {
    case RC_BIND_STA:
        return my_ip;
    case RC_BIND_VPN:
#if CONFIG_WG_SERVER
        if (wgs_is_running()) {
            return wgs_ip;
        }
#endif
        return vpn_tunnel_ip;
    default:  /* RC_BIND_AP */
        /* my_ap_ip is only ever set at init, so fold the AP-disabled state
         * in here: without the interface, the address is unreachable. */
        return ap_disabled ? 0 : my_ap_ip;
    }
}

/* True if at least one *selected* interface currently has an IP. The task
 * loop waits for this before starting the listener. */
static bool mb_any_bind_ip(void)
{
    if ((s_bind & RC_BIND_AP) && bind_ip_for(RC_BIND_AP) != 0) return true;
    if ((s_bind & RC_BIND_STA) && bind_ip_for(RC_BIND_STA) != 0) return true;
    if ((s_bind & RC_BIND_VPN) && bind_ip_for(RC_BIND_VPN) != 0) return true;
    return false;
}

/* "1.2.3.4, 5.6.7.8" for the selected interfaces that are up, "" if none.
 * For status output. */
static void mb_bind_ips_str(char *buf, size_t len)
{
    static const uint8_t flags[3] = { RC_BIND_AP, RC_BIND_STA, RC_BIND_VPN };
    char tmp[16];
    size_t off = 0;
    buf[0] = '\0';
    for (int i = 0; i < 3 && off < len; i++) {
        if (!(s_bind & flags[i])) continue;
        uint32_t ip = bind_ip_for(flags[i]);
        if (ip == 0) continue;
        ip4_addr_t a;
        a.addr = ip;
        snprintf(tmp, sizeof(tmp), IPSTR, IP2STR(&a));
        int n = snprintf(buf + off, len - off, "%s%s",
                         (off > 0) ? ", " : "", tmp);
        if (n > 0) off += (size_t)n;
    }
}

/* "AP" / "AP, VPN" / "AP, STA, VPN" ... for status output. */
static void mb_bind_mask_name(uint8_t mask, char *buf, size_t len)
{
    static const uint8_t flags[3] = { RC_BIND_AP, RC_BIND_STA, RC_BIND_VPN };
    static const char *names[3] = { "AP",
#if CONFIG_ETH_UPLINK
                                    "ETH",
#else
                                    "STA",
#endif
                                    "VPN" };
    size_t off = 0;
    buf[0] = '\0';
    for (int i = 0; i < 3 && off < len; i++) {
        if (!(mask & flags[i])) continue;
        int n = snprintf(buf + off, len - off, "%s%s",
                         (off > 0) ? ", " : "", names[i]);
        if (n > 0) off += (size_t)n;
    }
    if (off == 0) snprintf(buf, len, "(none)");
}

/* ================================================================
 *  Accept-time interface filter
 * ================================================================
 *
 * The port's connect callback only receives (client_id, username, password)
 * — no socket, no address — so the interface check cannot be done there.
 * Instead the port is hooked at accept time, exactly like the remote
 * console: the port calls context__init() once per accepted client socket
 * (port/net__esp_tls.c) and closes the socket when it returns NULL, so we
 * inspect getsockname() — which returns the local IP, i.e. the interface
 * the connection arrived on — and drop connections from unselected
 * interfaces.
 *
 * This is a linker-level interposer in this component (the same --wrap
 * mechanism the port itself uses for mosquitto_unpwd_check); the port
 * sources are not modified. Runs in the broker task. The port's
 * mosq_sock_t is a plain int.
 */
static bool mb_bind_allows(uint32_t local_ip)
{
    if ((s_bind & RC_BIND_AP) && !ap_disabled && local_ip == my_ap_ip) {
        return true;
    }
    if ((s_bind & RC_BIND_STA) && local_ip == my_ip) {
        return true;
    }
    if (s_bind & RC_BIND_VPN) {
#if CONFIG_WG_SERVER
        if (local_ip == wgs_ip && wgs_is_running()) {
            return true;  /* WireGuard server client on the tunnel address */
        }
#endif
        if (local_ip == vpn_tunnel_ip) {
            return true;  /* VPN uplink: connection on the tunnel IP */
        }
    }
    return false;
}

struct mosquitto *__real_context__init(int sock);

struct mosquitto *__wrap_context__init(int sock)
{
    if (sock >= 0) {
        struct sockaddr_in local;
        socklen_t len = sizeof(local);
        if (getsockname(sock, (struct sockaddr *)&local, &len) != 0) {
            /* Cannot classify the connection: fail closed. */
            ESP_LOGW(TAG, "getsockname failed, rejecting connection");
            return NULL;
        }
        if (!mb_bind_allows(local.sin_addr.s_addr)) {
            /* net__socket_accept() closes the socket for us. */
            return NULL;
        }
    }
    return __real_context__init(sock);
}

/* ================================================================
 *  Mosquitto callbacks (run in the broker task)
 * ================================================================ */

/* Called for every CONNECT. Return 0 to accept, non-zero to reject. */
static int mb_on_connect(const char *client_id, const char *username,
                         const char *password, int password_len)
{
    char user[MB_CRED_MAX], pass[MB_CRED_MAX];

    taskENTER_CRITICAL(&s_cred_mux);
    memcpy(user, s_user, sizeof(user));
    memcpy(pass, s_pass, sizeof(pass));
    taskEXIT_CRITICAL(&s_cred_mux);

    if (user[0] == '\0') {
        /* Open broker: no user configured, accept anything */
        ESP_LOGW(TAG, "client '%s' connected without credentials "
                      "(no broker user configured)", client_id);
        return 0;
    }

    if (username == NULL || strcmp(username, user) != 0) {
        ESP_LOGW(TAG, "client '%s' rejected (bad username)", client_id);
        return 1;
    }

    /* The port passes an empty MQTT password as NULL (packet__read_binary
     * leaves the pointer unset for a zero-length field). */
    size_t pass_len = strlen(pass);
    bool pass_ok;
    if (pass_len == 0) {
        pass_ok = (password == NULL || password_len == 0);
    } else {
        pass_ok = (password != NULL && (size_t)password_len == pass_len &&
                   memcmp(password, pass, pass_len) == 0);
    }
    if (!pass_ok) {
        ESP_LOGW(TAG, "client '%s' rejected (bad password)", client_id);
        return 1;
    }

    ESP_LOGI(TAG, "client '%s' authenticated", client_id);
    return 0;
}

/* Called for every message the broker processes (publish to subscribers). */
static void mb_on_message(char *client, char *topic, char *data, int len,
                          int qos, int retain)
{
    (void)data;  /* payload is not NUL-terminated, never log it */
    s_state.messages++;
    ESP_LOGD(TAG, "message from %s on %s (%d B, qos %d, retain %d)",
             client ? client : "?", topic ? topic : "?", len, qos, retain);
}

/* ================================================================
 *  Broker task
 * ================================================================ */

static void mqtt_broker_task(void *arg)
{
    while (!s_state.shutdown) {
        /* Wait until at least one selected interface has an IP: the
         * broker must not listen while none of them is up. */
        if (!s_enabled || !mb_any_bind_ip()) {
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }

        struct mosq_broker_config cfg = {
            .host = "0.0.0.0",  /* all interfaces; the accept filter
                                 * (mb_bind_allows) enforces the selection */
            .port = s_port,
            .tls_cfg = NULL,
            .handle_connect_cb = mb_on_connect,
            .handle_message_cb = mb_on_message,
        };

        s_state.running = true;
        int rc = mosq_broker_run(&cfg);  /* blocks until mosq_broker_stop() */
        s_state.running = false;

        if (s_state.shutdown) {
            break;
        }
        if (s_state.rebind) {
            /* Port changed: restart immediately with new settings. */
            s_state.rebind = false;
            continue;
        }
        /* Unexpected early exit (port collision, OOM). Note: lwIP's
         * tcp_bind() does not reject an IP no netif currently owns, so a
         * down interface is not a bind failure — the loop's guard above
         * keeps us out of mosq_broker_run() in that case anyway. */
        ESP_LOGW(TAG, "broker stopped (rc=%d), retrying", rc);
        vTaskDelay(pdMS_TO_TICKS(5000));
    }

    s_state.task = NULL;
    ESP_LOGI(TAG, "broker task exiting");
    vTaskDelete(NULL);
}

/* ================================================================
 *  Start / stop / rebind
 * ================================================================ */

esp_err_t mqtt_broker_enable(void)
{
    s_enabled = true;
    set_config_param_int(NVS_KEY_MB_EN, 1);

    /* A previous disable() may still be shutting the task down; wait for it
     * to exit so we can start a fresh one. */
    for (int waited = 0; s_state.task != NULL && s_state.shutdown &&
         waited < MB_STOP_TIMEOUT_MS; waited += MB_STOP_POLL_MS) {
        vTaskDelay(pdMS_TO_TICKS(MB_STOP_POLL_MS));
    }
    if (s_state.task != NULL) {
        return ESP_OK;  /* already running (or still shutting down) */
    }

    s_state.shutdown = false;
    s_state.rebind = false;
    if (xTaskCreate(mqtt_broker_task, "mqtt_broker", MB_TASK_STACK, NULL,
                    MB_TASK_PRIO, &s_state.task) != pdPASS) {
        s_enabled = false;
        set_config_param_int(NVS_KEY_MB_EN, 0);
        return ESP_ERR_NO_MEM;
    }

    ESP_LOGI(TAG, "enabled (port %u, auth %s)",
             s_port, s_user[0] ? "required" : "open");
    return ESP_OK;
}

esp_err_t mqtt_broker_disable(void)
{
    if (s_state.task == NULL) {
        return ESP_OK;  /* not running */
    }

    s_enabled = false;
    set_config_param_int(NVS_KEY_MB_EN, 0);
    s_state.shutdown = true;
    mosq_broker_stop();  /* unblocks mosq_broker_run() */

    /* Wait for the task to clear its own handle on the way out (same
     * pattern as the remote console). */
    for (int waited = 0; s_state.task != NULL && waited < MB_STOP_TIMEOUT_MS;
         waited += MB_STOP_POLL_MS) {
        vTaskDelay(pdMS_TO_TICKS(MB_STOP_POLL_MS));
    }
    if (s_state.task != NULL) {
        ESP_LOGW(TAG, "broker task still shutting down");
    }

    ESP_LOGI(TAG, "disabled");
    return ESP_OK;
}

void mqtt_broker_rebind(void)
{
    if (s_state.task == NULL || !s_state.running) {
        return;  /* not in the run loop: the loop picks up new settings */
    }
    s_state.rebind = true;
    mosq_broker_stop();  /* unblocks mosq_broker_run() */
    ESP_LOGI(TAG, "rebind requested");
}

/* The listener binds to 0.0.0.0, so interface IP changes (DHCP update, VPN
 * up/down, WG server restart) need no rebind — the accept filter reads the
 * current IPs on every connection. The timer only handles the stop case:
 * the broker is running but every selected interface lost its IP. (The
 * start case is picked up by the task loop on its own.) */
static esp_timer_handle_t s_watchdog;

static void bind_watchdog_cb(void *arg)
{
    (void)arg;
    if (s_state.task == NULL || !s_state.running) {
        return;
    }
    if (!mb_any_bind_ip()) {
        ESP_LOGI(TAG, "no bound interface has an IP, stopping listener");
        mqtt_broker_rebind();
    }
}

/* ================================================================
 *  Settings
 * ================================================================ */

esp_err_t mqtt_broker_set_port(uint16_t port)
{
    if (port == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    s_port = port;
    set_config_param_int(NVS_KEY_MB_PORT, port);

    if (s_state.task != NULL && s_state.running) {
        mqtt_broker_rebind();
    }
    ESP_LOGI(TAG, "port set to %u", port);
    return ESP_OK;
}

esp_err_t mqtt_broker_set_bind(uint8_t bind)
{
    if (bind == 0 ||
        (bind & ~(RC_BIND_AP | RC_BIND_STA | RC_BIND_VPN)) != 0) {
        return ESP_ERR_INVALID_ARG;
    }

    if (bind == s_bind) {
        return ESP_OK;
    }

    s_bind = bind;
    set_config_param_int(NVS_KEY_MB_BIND, (int32_t)bind);

    /* No rebind needed: the accept filter reads s_bind live, and the
     * start/stop transitions (first/last selected IP appearing) are
     * handled by the task loop and the watchdog. */
    char name[24];
    mb_bind_mask_name(bind, name, sizeof(name));
    ESP_LOGI(TAG, "bind set to %s", name);
    return ESP_OK;
}

esp_err_t mqtt_broker_set_credentials(const char *user, const char *pass)
{
    if (user == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    size_t ulen = strlen(user);
    size_t plen = (pass != NULL) ? strlen(pass) : 0;
    if (ulen >= MB_CRED_MAX || plen >= MB_CRED_MAX) {
        return ESP_ERR_INVALID_ARG;
    }

    if (ulen == 0) {
        /* Open broker: no authentication at all */
        taskENTER_CRITICAL(&s_cred_mux);
        s_user[0] = '\0';
        s_pass[0] = '\0';
        taskEXIT_CRITICAL(&s_cred_mux);
    } else {
        taskENTER_CRITICAL(&s_cred_mux);
        memcpy(s_user, user, ulen + 1);
        if (pass != NULL) {
            memcpy(s_pass, pass, plen + 1);
        }
        taskEXIT_CRITICAL(&s_cred_mux);
    }

    set_config_param_str(NVS_KEY_MB_USER, s_user);
    if (ulen == 0) {
        /* Open broker: also clear the persisted password, or it would
         * survive a reboot and silently apply when a user is set later
         * without an explicit password. */
        set_config_param_str(NVS_KEY_MB_PASS, "");
    } else if (pass != NULL) {
        set_config_param_str(NVS_KEY_MB_PASS, s_pass);
    }
    ESP_LOGI(TAG, "credentials updated (%s)",
             s_user[0] ? "authentication required" : "open");
    return ESP_OK;
}

void mqtt_broker_get_info(mqtt_broker_info_t *info)
{
    if (info == NULL) {
        return;
    }
    memset(info, 0, sizeof(*info));
    info->enabled = s_enabled;
    info->running = s_state.running;
    info->port = s_port;
    info->bind = s_bind;
    mb_bind_mask_name(s_bind, info->bind_desc, sizeof(info->bind_desc));
    info->auth_required = (s_user[0] != '\0');
    info->messages = s_state.messages;

    taskENTER_CRITICAL(&s_cred_mux);
    memcpy(info->user, s_user, sizeof(info->user) - 1);
    taskEXIT_CRITICAL(&s_cred_mux);
    info->user[sizeof(info->user) - 1] = '\0';

    mb_bind_ips_str(info->listen_addr, sizeof(info->listen_addr));
}

/* ================================================================
 *  NVS load
 * ================================================================ */

static void load_config(void)
{
    nvs_handle_t h;
    if (nvs_open(PARAM_NAMESPACE, NVS_READONLY, &h) != ESP_OK) {
        return;
    }

    /* set_config_param_int() stores i32 values — NVS is type-strict. */
    int32_t en = 0, port = 0, bind = 0;
    nvs_get_i32(h, NVS_KEY_MB_EN, &en);
    nvs_get_i32(h, NVS_KEY_MB_PORT, &port);
    nvs_get_i32(h, NVS_KEY_MB_BIND, &bind);
    s_enabled = (en != 0);
    if (port != 0) {
        s_port = (uint16_t)port;
    }
    if (bind > 0) {
        uint8_t m = (uint8_t)(bind & (RC_BIND_AP | RC_BIND_STA | RC_BIND_VPN));
        if (m != 0) {
            s_bind = m;
        }
    }

    size_t sz;
    sz = sizeof(s_user);
    if (nvs_get_str(h, NVS_KEY_MB_USER, s_user, &sz) == ESP_OK) {
        s_user[sizeof(s_user) - 1] = '\0';
    }
    sz = sizeof(s_pass);
    if (nvs_get_str(h, NVS_KEY_MB_PASS, s_pass, &sz) == ESP_OK) {
        s_pass[sizeof(s_pass) - 1] = '\0';
    }
    if (s_user[0] == '\0') {
        /* Open broker: ignore a stale persisted password (left behind by
         * older firmware that did not clear it on 'user off'). */
        s_pass[0] = '\0';
    }

    nvs_close(h);
}

/* ================================================================
 *  CLI command
 * ================================================================ */

static struct {
    struct arg_str *action;
    struct arg_str *arg1;
    struct arg_str *arg2;
    struct arg_end *end;
} mb_args;

static int mqtt_cmd(int argc, char **argv)
{
    int nerrors = arg_parse(argc, argv, (void **)&mb_args);
    if (nerrors != 0) {
        arg_print_errors(stderr, mb_args.end, argv[0]);
        return 1;
    }

    const char *action = mb_args.action->sval[0];
    mqtt_broker_info_t info;

    if (strcmp(action, "status") == 0) {
        mqtt_broker_get_info(&info);
        printf("MQTT broker:\n");
        printf("  State:     %s\n",
               !info.enabled ? "disabled"
               : info.running ? "listening"
               : "waiting for interface");
        if (info.enabled) {
            printf("  Bind:      %s\n", info.bind_desc);
            printf("  Listen:    %s:%u\n",
                   info.listen_addr[0] ? info.listen_addr : "0.0.0.0",
                   info.port);
            printf("  Auth:      %s\n",
                   info.auth_required ? "required" : "open (no user set)");
            printf("  Messages:  %" PRIu32 "\n", info.messages);
        }
        return 0;
    }

    if (strcmp(action, "enable") == 0) {
        esp_err_t err = mqtt_broker_enable();
        if (err != ESP_OK) {
            printf("Failed to start: %s\n", esp_err_to_name(err));
            return 1;
        }
        printf("MQTT broker enabled\n");
        return 0;
    }

    if (strcmp(action, "disable") == 0) {
        mqtt_broker_disable();
        printf("MQTT broker disabled\n");
        return 0;
    }

    if (strcmp(action, "port") == 0) {
        if (mb_args.arg1->count == 0) {
            printf("Usage: mqtt port <1-65535>\n");
            return 1;
        }
        int val = atoi(mb_args.arg1->sval[0]);
        if (val < 1 || val > 65535) {
            printf("Port must be 1-65535\n");
            return 1;
        }
        mqtt_broker_set_port((uint16_t)val);
        mqtt_broker_get_info(&info);
        printf("Port set to %u\n", info.port);
        return 0;
    }

    if (strcmp(action, "bind") == 0) {
        if (mb_args.arg1->count == 0) {
            char cur[24];
            mb_bind_mask_name(s_bind, cur, sizeof(cur));
            printf("Current bind: %s\n", cur);
#if CONFIG_ETH_UPLINK
            printf("Usage: mqtt bind <ap,eth,vpn>  (comma-separated, or 'all')\n");
#else
            printf("Usage: mqtt bind <ap,sta,vpn>  (comma-separated, or 'all')\n");
#endif
            return 0;
        }
        uint8_t b = 0;
        const char *arg = mb_args.arg1->sval[0];
        if (strcmp(arg, "all") == 0) {
            b = RC_BIND_AP | RC_BIND_STA | RC_BIND_VPN;
        } else {
            char arg_copy[64];
            strncpy(arg_copy, arg, sizeof(arg_copy) - 1);
            arg_copy[sizeof(arg_copy) - 1] = '\0';
            char *tok = strtok(arg_copy, ",");
            while (tok) {
                if (strcmp(tok, "ap") == 0 || strcmp(tok, "AP") == 0) {
                    b |= RC_BIND_AP;
                } else if (strcmp(tok, "sta") == 0 || strcmp(tok, "STA") == 0
#if CONFIG_ETH_UPLINK
                           || strcmp(tok, "eth") == 0 || strcmp(tok, "ETH") == 0
#endif
                           ) {
                    b |= RC_BIND_STA;
                } else if (strcmp(tok, "vpn") == 0 || strcmp(tok, "VPN") == 0) {
                    b |= RC_BIND_VPN;
                } else {
                    printf("Unknown interface: %s (use ap, sta, vpn)\n", tok);
                    return 1;
                }
                tok = strtok(NULL, ",");
            }
        }
        esp_err_t err = mqtt_broker_set_bind(b);
        if (err != ESP_OK) {
            printf("Failed to set bind: %s\n", esp_err_to_name(err));
            return 1;
        }
        char name[24];
        mb_bind_mask_name(b, name, sizeof(name));
        printf("Bind set to %s\n", name);
        return 0;
    }

    if (strcmp(action, "user") == 0) {
        if (mb_args.arg1->count == 0) {
            printf("Usage: mqtt user <username> [password]   (or: mqtt user off)\n");
            return 1;
        }
        const char *user = mb_args.arg1->sval[0];
        const char *pass = (mb_args.arg2->count > 0) ? mb_args.arg2->sval[0] : NULL;

        if (strcmp(user, "off") == 0) {
            mqtt_broker_set_credentials("", "");
            printf("Broker authentication disabled (open)\n");
            return 0;
        }
        mqtt_broker_set_credentials(user, pass);
        printf("Broker user set to: %s%s\n", user,
               pass ? " (password updated)" : " (password unchanged)");
        return 0;
    }

    printf("Unknown action: %s\n", action);
    printf("Usage: mqtt <status|enable|disable|port|bind|user>\n");
    return 1;
}

static void register_mqtt_cmd(void)
{
    mb_args.action = arg_str1(NULL, NULL, "<action>",
                              "status|enable|disable|port|bind|user");
    mb_args.arg1   = arg_str0(NULL, NULL, "<arg1>",
                              "port, interface list (ap,sta,vpn or all), username, or 'off'");
    mb_args.arg2   = arg_str0(NULL, NULL, "<arg2>", "password");
    mb_args.end    = arg_end(3);

    const esp_console_cmd_t cmd = {
        .command = "mqtt",
        .help = "Built-in MQTT broker (LAN)",
        .hint = NULL,
        .func = &mqtt_cmd,
        .argtable = &mb_args,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&cmd));
}

/* ================================================================
 *  Init (called from app_main)
 * ================================================================ */

void mqtt_broker_init(void)
{
    load_config();
    register_mqtt_cmd();

    /* Only meaningful while the broker runs; cheap no-op otherwise. */
    const esp_timer_create_args_t wd = {
        .callback = bind_watchdog_cb,
        .name = "mb_watchdog",
    };
    if (esp_timer_create(&wd, &s_watchdog) == ESP_OK) {
        esp_timer_start_periodic(s_watchdog, 2 * 1000000);
    }

    char bind_name_buf[24];
    mb_bind_mask_name(s_bind, bind_name_buf, sizeof(bind_name_buf));
    ESP_LOGI(TAG, "initialized (enabled=%d, port=%u, bind=%s, auth=%s)",
             s_enabled, s_port, bind_name_buf,
             s_user[0] ? "required" : "open");

    if (s_enabled) {
        mqtt_broker_enable();
    }
}

#endif /* CONFIG_MQTT_BROKER */
