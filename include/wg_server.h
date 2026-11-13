/* WireGuard server (inbound VPN) settings, peer table and runtime control.
 *
 * Only built when CONFIG_WG_SERVER is set (ESP32-S3 and WT32-ETH01).
 * The server and the WireGuard client uplink (vpn_config.h) are mutually
 * exclusive: the server does not start while vpn_enabled is set.
 *
 * SPDX-License-Identifier: MIT
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"
#include "sdkconfig.h"

#ifdef __cplusplus
extern "C" {
#endif

#if CONFIG_WG_SERVER

#define WGS_MAX_PEERS      8
#define WGS_NAME_SIZE      16      /* peer name incl. NUL */
#define WGS_KEY_SIZE       45      /* base64 key incl. NUL */
#define WGS_HOST_SIZE      64      /* public host name incl. NUL */
#define WGS_PORT_DEFAULT   51820
#define WGS_IP_DEFAULT     "10.8.0.1"
#define WGS_MASK_DEFAULT   "255.255.255.0"
#define WGS_CLIENT_CONF_SIZE 512   /* enough for wgs_client_config() output */

/* Stored peer record. The array of these is the NVS blob "wgs_peers", so the
 * layout must not change without a migration. */
typedef struct {
    char     name[WGS_NAME_SIZE];
    char     pubkey[WGS_KEY_SIZE];
    uint8_t  reserved[3];
    uint32_t ip;                    /* tunnel address, network byte order */
} wgs_peer_cfg_t;

typedef struct {
    wgs_peer_cfg_t cfg;
    bool     up;
    uint32_t endpoint_ip;           /* network byte order, 0 if never seen */
    uint16_t endpoint_port;
    uint32_t handshake_age_s;       /* UINT32_MAX if no session */
    uint64_t rx_bytes;
    uint64_t tx_bytes;
} wgs_peer_info_t;

/* Settings (persisted in NVS, loaded by wgs_load_config) */
extern int32_t  wgs_enabled;        /* "wgs_enabled" */
extern int32_t  wgs_port;           /* "wgs_port"    */
extern uint32_t wgs_ip;             /* "wgs_ip",   network byte order */
extern uint32_t wgs_mask;           /* "wgs_mask", network byte order */
extern char     wgs_host[WGS_HOST_SIZE];    /* "wgs_host", public name for client configs */
extern char     wgs_pubkey[WGS_KEY_SIZE];   /* derived from "wgs_privkey", "" if no key */

/* Load settings and the peer table from NVS. Call once from app_main. */
void wgs_load_config(void);

/* Start the server if enabled and not yet running. Call when the uplink has
 * an address. Safe to call repeatedly and from event handlers. */
void wgs_start(void);

bool wgs_is_running(void);

/* Wrap the tunnel netif's input/output with the to_wg/from_wg ACLs and MSS
 * clamping (netif_hooks.c). Runs on the tcpip thread; wgs_start() calls it. */
struct netif;
void wg_netif_hooks_install(struct netif *wg);

/* Settings changes; all take effect after a restart. */
esp_err_t wgs_set_enabled(bool enabled);            /* generates the server key on first enable */
esp_err_t wgs_set_port(int port);
esp_err_t wgs_set_subnet(uint32_t ip, uint32_t mask);   /* ESP_ERR_INVALID_STATE while peers exist */
esp_err_t wgs_set_host(const char *host);
esp_err_t wgs_regenerate_key(void);                 /* invalidates every exported client config */

/* Add a peer; applied to the running server immediately.
 *   pubkey       NULL to generate a key pair on the device
 *   ip           0 to assign the next free tunnel address
 *   privkey_out  WGS_KEY_SIZE bytes; receives the generated private key, or ""
 *                when pubkey was given. It is not stored anywhere.
 * Returns ESP_ERR_INVALID_ARG (bad name/key/address), ESP_ERR_INVALID_STATE
 * (name, key or address already in use), ESP_ERR_NO_MEM (table full). */
esp_err_t wgs_peer_add(const char *name, const char *pubkey, uint32_t ip,
                       char *privkey_out, wgs_peer_cfg_t *out);

esp_err_t wgs_peer_del(const char *name);

/* Copy up to max peers with their live state; returns the number copied. */
int wgs_peer_list(wgs_peer_info_t *out, int max);

/* Write a client configuration for the peer into buf. privkey may be NULL or
 * "" (a placeholder is written). Returns the length, or -1 if it did not fit. */
int wgs_client_config(const wgs_peer_cfg_t *peer, const char *privkey,
                      bool full_tunnel, char *buf, size_t len);

#endif /* CONFIG_WG_SERVER */

#ifdef __cplusplus
}
#endif
