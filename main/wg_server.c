/* WireGuard server (inbound VPN).
 *
 * Owns the wgs_* settings and the peer table in NVS and drives the server API
 * of the esp_wireguard component. Tunnel clients reach the AP network routed
 * and the uplink side through NAPT: lwIP only translates when the outgoing
 * netif has NAPT off (ip4_forward), so with NAPT enabled on both the tunnel
 * and the AP netif, traffic between those two is forwarded untouched while
 * traffic leaving through the uplink is masqueraded behind the uplink address.
 *
 * Called from the console, the HTTP server and the event task. The peer table
 * is guarded by a mutex; everything that touches lwIP goes through the
 * component, which runs it on the tcpip thread.
 */

#include "sdkconfig.h"

#if CONFIG_WG_SERVER

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_random.h"
#include "nvs.h"
#include "lwip/ip4_addr.h"
#include "lwip/lwip_napt.h"
#include "lwip/def.h"
#include "mbedtls/base64.h"
#include "mbedtls/platform_util.h"
#include "esp_wireguard_server.h"
#include "router_config.h"
#include "wifi_config.h"
#include "vpn_config.h"
#include "wg_server.h"

_Static_assert(CONFIG_WIREGUARD_MAX_PEERS >= WGS_MAX_PEERS,
               "CONFIG_WIREGUARD_MAX_PEERS is smaller than WGS_MAX_PEERS: delete the stale "
               "sdkconfig file of this build so sdkconfig.defaults is applied again");
_Static_assert(WGS_KEY_SIZE == ESP_WIREGUARD_KEY_B64_SIZE, "key buffer size mismatch");

static const char *TAG = "wg_server";

#define KEY_ENABLED  "wgs_enabled"
#define KEY_PORT     "wgs_port"
#define KEY_IP       "wgs_ip"
#define KEY_MASK     "wgs_mask"
#define KEY_HOST     "wgs_host"
#define KEY_PRIVKEY  "wgs_privkey"
#define KEY_PEERS    "wgs_peers"
#define KEY_TS       "wgs_ts"

#define TS_LEN  ESP_WIREGUARD_TIMESTAMP_LEN

/* How often changed handshake timestamps are written to NVS. A client
 * handshakes about every two minutes while active, so writing each one would
 * wear the flash; with this interval a captured initiation can be replayed
 * after a reboot only if it is newer than the last save. */
#define TS_SAVE_INTERVAL_US  (10ULL * 60 * 1000000)

/* Keepalive written into client configs: keeps the client's NAT mapping open
 * so the server can reach it between its own packets. */
#define CLIENT_KEEPALIVE_S  25

#if CONFIG_ETH_UPLINK
extern esp_netif_t *ethNetif;
#define UPLINK_NETIF      ethNetif
#define UPLINK_NETIF_KEY  "ETH_DEF"
#else
extern esp_netif_t *wifiSTA;
#define UPLINK_NETIF      wifiSTA
#define UPLINK_NETIF_KEY  "WIFI_STA_DEF"
#endif
extern esp_netif_t *wifiAP;

int32_t  wgs_enabled = 0;
int32_t  wgs_port = WGS_PORT_DEFAULT;
uint32_t wgs_ip = 0;
uint32_t wgs_mask = 0;
char     wgs_host[WGS_HOST_SIZE] = "";
char     wgs_pubkey[WGS_KEY_SIZE] = "";

static SemaphoreHandle_t lock;
static wgs_peer_cfg_t *peers;       /* WGS_MAX_PEERS entries, allocated on first use */
static uint8_t (*peer_ts)[TS_LEN];  /* newest handshake timestamp per peer, same index as peers */
static int peer_count;
static esp_timer_handle_t ts_timer;

static bool alloc_tables(void)
{
    if (peers == NULL) {
        peers = calloc(WGS_MAX_PEERS, sizeof(wgs_peer_cfg_t));
    }
    if (peer_ts == NULL) {
        peer_ts = calloc(WGS_MAX_PEERS, TS_LEN);
    }
    return peers != NULL && peer_ts != NULL;
}

/* ---- helpers ---- */

static const char *ip4str(uint32_t ip, char *buf)
{
    esp_ip4_addr_t a = { .addr = ip };
    return esp_ip4addr_ntoa(&a, buf, 16);
}

static int mask_prefix(uint32_t mask)
{
    return __builtin_popcount(mask);
}

/* True if the two subnets share any address. */
static bool nets_overlap(uint32_t ip_a, uint32_t mask_a, uint32_t ip_b, uint32_t mask_b)
{
    uint32_t common = mask_a & mask_b;
    return (ip_a & common) == (ip_b & common);
}

static bool read_privkey(char *out)
{
    nvs_handle_t nvs;
    size_t len = WGS_KEY_SIZE;
    bool ok = false;

    out[0] = '\0';
    if (nvs_open(PARAM_NAMESPACE, NVS_READONLY, &nvs) == ESP_OK) {
        ok = (nvs_get_str(nvs, KEY_PRIVKEY, out, &len) == ESP_OK) && (len == WGS_KEY_SIZE);
        nvs_close(nvs);
    }
    if (!ok) {
        out[0] = '\0';
    }
    return ok;
}

static void derive_pubkey(void)
{
    char priv[WGS_KEY_SIZE];

    wgs_pubkey[0] = '\0';
    if (read_privkey(priv)) {
        if (esp_wireguard_public_key(priv, wgs_pubkey, sizeof(wgs_pubkey)) != ESP_OK) {
            wgs_pubkey[0] = '\0';
        }
    }
    mbedtls_platform_zeroize(priv, sizeof(priv));
}

/* A base64 string that decodes to 32 bytes: public or preshared key */
static bool valid_key(const char *key)
{
    unsigned char raw[33];
    size_t len = 0;

    bool ok = key && strlen(key) == WGS_KEY_SIZE - 1 &&
              mbedtls_base64_decode(raw, sizeof(raw), &len, (const unsigned char *)key, WGS_KEY_SIZE - 1) == 0 &&
              len == 32;
    mbedtls_platform_zeroize(raw, sizeof(raw));
    return ok;
}

/* Like 'wg genpsk': 32 random bytes, base64 */
static esp_err_t generate_psk(char *out)
{
    uint8_t raw[32];
    size_t len = 0;

    esp_fill_random(raw, sizeof(raw));
    int rc = mbedtls_base64_encode((unsigned char *)out, WGS_KEY_SIZE, &len, raw, sizeof(raw));
    mbedtls_platform_zeroize(raw, sizeof(raw));
    return (rc == 0 && len == WGS_KEY_SIZE - 1) ? ESP_OK : ESP_FAIL;
}

static bool valid_name(const char *name)
{
    size_t n = name ? strlen(name) : 0;

    if (n == 0 || n >= WGS_NAME_SIZE) {
        return false;
    }
    for (size_t i = 0; i < n; i++) {
        if (!isalnum((unsigned char)name[i]) && name[i] != '_' && name[i] != '-') {
            return false;
        }
    }
    return true;
}

static esp_err_t save_peers(void)
{
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);

    if (err != ESP_OK) {
        return err;
    }
    if (peer_count > 0) {
        err = nvs_set_blob(nvs, KEY_PEERS, peers, (size_t)peer_count * sizeof(wgs_peer_cfg_t));
        if (err == ESP_OK) {
            /* Same order as the peers, so both blobs change together */
            err = nvs_set_blob(nvs, KEY_TS, peer_ts, (size_t)peer_count * TS_LEN);
        }
    } else {
        err = nvs_erase_key(nvs, KEY_PEERS);
        nvs_erase_key(nvs, KEY_TS);
        if (err == ESP_ERR_NVS_NOT_FOUND) {
            err = ESP_OK;
        }
    }
    if (err == ESP_OK) {
        err = nvs_commit(nvs);
    }
    nvs_close(nvs);
    return err;
}

static void load_peers(void)
{
    nvs_handle_t nvs;
    size_t len = 0;

    if (nvs_open(PARAM_NAMESPACE, NVS_READONLY, &nvs) != ESP_OK) {
        return;
    }
    if (nvs_get_blob(nvs, KEY_PEERS, NULL, &len) == ESP_OK && len > 0) {
        if (len % sizeof(wgs_peer_cfg_t) != 0 || len / sizeof(wgs_peer_cfg_t) > WGS_MAX_PEERS) {
            ESP_LOGW(TAG, "Ignoring peer table with unexpected size %u", (unsigned)len);
        } else if (alloc_tables() && nvs_get_blob(nvs, KEY_PEERS, peers, &len) == ESP_OK) {
            peer_count = (int)(len / sizeof(wgs_peer_cfg_t));
            for (int i = 0; i < peer_count; i++) {
                peers[i].name[WGS_NAME_SIZE - 1] = '\0';
                peers[i].pubkey[WGS_KEY_SIZE - 1] = '\0';
                peers[i].psk[WGS_KEY_SIZE - 1] = '\0';
                if (peers[i].psk[0] && !valid_key(peers[i].psk)) {
                    memset(peers[i].psk, 0, WGS_KEY_SIZE);
                }
            }
            /* Timestamps are only trusted if they match the peer table */
            size_t ts_len = (size_t)peer_count * TS_LEN;
            if (nvs_get_blob(nvs, KEY_TS, peer_ts, &ts_len) != ESP_OK ||
                ts_len != (size_t)peer_count * TS_LEN) {
                memset(peer_ts, 0, WGS_MAX_PEERS * TS_LEN);
            }
        }
    }
    nvs_close(nvs);
}

static int find_peer(const char *name)
{
    for (int i = 0; i < peer_count; i++) {
        if (strcmp(peers[i].name, name) == 0) {
            return i;
        }
    }
    return -1;
}

static bool ip_in_use(uint32_t ip)
{
    if (ip == wgs_ip) {
        return true;
    }
    for (int i = 0; i < peer_count; i++) {
        if (peers[i].ip == ip) {
            return true;
        }
    }
    return false;
}

/* A usable client address: inside the tunnel subnet, not network or broadcast. */
static bool ip_is_host_in_subnet(uint32_t ip)
{
    uint32_t host = lwip_ntohl(ip & ~wgs_mask);
    uint32_t host_max = lwip_ntohl(~wgs_mask);

    return ((ip & wgs_mask) == (wgs_ip & wgs_mask)) && host != 0 && host != host_max;
}

static uint32_t next_free_ip(void)
{
    uint32_t net = lwip_ntohl(wgs_ip & wgs_mask);
    uint32_t host_max = lwip_ntohl(~wgs_mask);

    for (uint32_t h = 1; h < host_max; h++) {
        uint32_t ip = lwip_htonl(net | h);
        if (!ip_in_use(ip)) {
            return ip;
        }
    }
    return 0;
}

static esp_err_t live_add(int i)
{
    esp_wireguard_server_peer_t peer = {
        .public_key = peers[i].pubkey,
        .preshared_key = peers[i].psk[0] ? peers[i].psk : NULL,
        .allowed_ip = peers[i].ip,
        .keepalive = 0,
        .greatest_timestamp = peer_ts[i],
    };
    return esp_wireguard_server_add_peer(&peer);
}

/* Runs on the tcpip thread right after the server created its netif */
static esp_err_t netif_setup_cb(void *ctx)
{
    (void)ctx;
    ip_napt_enable(wgs_ip, 1);
    wg_netif_hooks_install(esp_wireguard_server_netif());
    return ESP_OK;
}

/* Periodic (esp_timer task): persist handshake timestamps that moved on */
static void ts_timer_cb(void *arg)
{
    (void)arg;
    bool dirty = false;

    if (!esp_wireguard_server_is_running()) {
        return;
    }
    xSemaphoreTake(lock, portMAX_DELAY);
    for (int i = 0; i < peer_count; i++) {
        esp_wireguard_server_peer_stats_t st;
        if (esp_wireguard_server_get_peer_stats(peers[i].pubkey, &st) == ESP_OK &&
            memcmp(peer_ts[i], st.greatest_timestamp, TS_LEN) != 0) {
            memcpy(peer_ts[i], st.greatest_timestamp, TS_LEN);
            dirty = true;
        }
    }
    if (dirty) {
        nvs_handle_t nvs;
        if (nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs) == ESP_OK) {
            if (nvs_set_blob(nvs, KEY_TS, peer_ts, (size_t)peer_count * TS_LEN) == ESP_OK) {
                nvs_commit(nvs);
            }
            nvs_close(nvs);
        }
    }
    xSemaphoreGive(lock);
}

/* ---- settings ---- */

void wgs_load_config(void)
{
    int val;
    char *str = NULL;
    ip4_addr_t addr;

    lock = xSemaphoreCreateMutex();

    if (get_config_param_int(KEY_ENABLED, &val) == ESP_OK) {
        wgs_enabled = val;
    }
    if (get_config_param_int(KEY_PORT, &val) == ESP_OK && val > 0 && val < 65536) {
        wgs_port = val;
    }

    ip4addr_aton(WGS_IP_DEFAULT, &addr);
    wgs_ip = addr.addr;
    ip4addr_aton(WGS_MASK_DEFAULT, &addr);
    wgs_mask = addr.addr;
    if (get_config_param_str(KEY_IP, &str) == ESP_OK && str) {
        if (ip4addr_aton(str, &addr)) wgs_ip = addr.addr;
        free(str);
        str = NULL;
    }
    if (get_config_param_str(KEY_MASK, &str) == ESP_OK && str) {
        if (ip4addr_aton(str, &addr)) wgs_mask = addr.addr;
        free(str);
        str = NULL;
    }
    if (get_config_param_str(KEY_HOST, &str) == ESP_OK && str) {
        strlcpy(wgs_host, str, sizeof(wgs_host));
        free(str);
    }

    load_peers();
    derive_pubkey();
    if (wgs_enabled && wgs_pubkey[0] == '\0') {
        ESP_LOGW(TAG, "Enabled but no server key; run 'wg_server genkey'");
    }
}

bool wgs_is_running(void)
{
    return esp_wireguard_server_is_running();
}

void wgs_start(void)
{
    char priv[WGS_KEY_SIZE];
    char ipbuf[16];
    esp_netif_ip_info_t up;

    if (!wgs_enabled || lock == NULL || esp_wireguard_server_is_running()) {
        return;
    }
    if (vpn_enabled) {
        ESP_LOGW(TAG, "Not started: the WireGuard client uplink is enabled");
        return;
    }
    if (!read_privkey(priv)) {
        ESP_LOGE(TAG, "Not started: no server key");
        return;
    }
    if (esp_netif_get_ip_info(UPLINK_NETIF, &up) == ESP_OK && up.ip.addr != 0 &&
        nets_overlap(wgs_ip, wgs_mask, up.ip.addr, up.netmask.addr)) {
        ESP_LOGW(TAG, "Tunnel subnet overlaps the uplink network; change it with 'wg_server subnet'");
    }

    esp_wireguard_server_config_t cfg = {
        .private_key = priv,
        .listen_port = (uint16_t)wgs_port,
        .address = wgs_ip,
        .netmask = wgs_mask,
        .mtu = 0,
        .netif_key = UPLINK_NETIF_KEY,
    };

    xSemaphoreTake(lock, portMAX_DELAY);
    esp_err_t err = esp_wireguard_server_start(&cfg);
    mbedtls_platform_zeroize(priv, sizeof(priv));
    if (err == ESP_OK) {
        for (int i = 0; i < peer_count; i++) {
            esp_err_t perr = live_add(i);
            if (perr != ESP_OK) {
                ESP_LOGW(TAG, "Peer %s not added: %s", peers[i].name, esp_err_to_name(perr));
            }
        }
        esp_netif_tcpip_exec(netif_setup_cb, NULL);
        if (ts_timer == NULL) {
            const esp_timer_create_args_t args = { .callback = ts_timer_cb, .name = "wgs_ts" };
            if (esp_timer_create(&args, &ts_timer) == ESP_OK) {
                esp_timer_start_periodic(ts_timer, TS_SAVE_INTERVAL_US);
            }
        }
    }
    int n = peer_count;
    xSemaphoreGive(lock);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Start failed: %s", esp_err_to_name(err));
        return;
    }
    ESP_LOGI(TAG, "Listening on UDP %d, tunnel %s/%d, %d peer(s)",
             (int)wgs_port, ip4str(wgs_ip, ipbuf), mask_prefix(wgs_mask), n);
}

static esp_err_t generate_server_key(void)
{
    char priv[WGS_KEY_SIZE];
    esp_err_t err = esp_wireguard_generate_private_key(priv, sizeof(priv));

    if (err == ESP_OK) {
        err = set_config_param_str(KEY_PRIVKEY, priv);
    }
    mbedtls_platform_zeroize(priv, sizeof(priv));
    if (err == ESP_OK) {
        derive_pubkey();
    }
    return err;
}

esp_err_t wgs_regenerate_key(void)
{
    return generate_server_key();
}

esp_err_t wgs_set_enabled(bool enabled)
{
    if (enabled) {
        if (vpn_enabled) {
            return ESP_ERR_INVALID_STATE;
        }
        if (wgs_pubkey[0] == '\0') {
            esp_err_t err = generate_server_key();
            if (err != ESP_OK) {
                return err;
            }
        }
    }
    esp_err_t err = set_config_param_int(KEY_ENABLED, enabled ? 1 : 0);
    if (err == ESP_OK) {
        wgs_enabled = enabled ? 1 : 0;
    }
    return err;
}

esp_err_t wgs_set_port(int port)
{
    if (port < 1 || port > 65535) {
        return ESP_ERR_INVALID_ARG;
    }
    return set_config_param_int(KEY_PORT, port);
}

esp_err_t wgs_set_subnet(uint32_t ip, uint32_t mask)
{
    char buf[16];
    uint32_t m = lwip_ntohl(mask);
    uint32_t inv = ~m;
    int prefix = mask_prefix(mask);
    esp_netif_ip_info_t ap;

    /* Contiguous mask, /16 to /30, and a host address for the server itself */
    if ((inv & (inv + 1)) != 0 || prefix < 16 || prefix > 30) {
        return ESP_ERR_INVALID_ARG;
    }
    uint32_t host = lwip_ntohl(ip) & inv;
    if (host == 0 || host == inv) {
        return ESP_ERR_INVALID_ARG;
    }
    if (esp_netif_get_ip_info(wifiAP, &ap) == ESP_OK && ap.ip.addr != 0 &&
        nets_overlap(ip, mask, ap.ip.addr, ap.netmask.addr)) {
        return ESP_ERR_INVALID_ARG;
    }
    /* Peer addresses are tied to the subnet; moving them silently would
     * break every client config already handed out. */
    if (peer_count > 0) {
        return ESP_ERR_INVALID_STATE;
    }
    esp_err_t err = set_config_param_str(KEY_IP, ip4str(ip, buf));
    if (err == ESP_OK) {
        err = set_config_param_str(KEY_MASK, ip4str(mask, buf));
    }
    if (err == ESP_OK && !esp_wireguard_server_is_running()) {
        /* Not live yet, so new peers can already be numbered in the new subnet */
        wgs_ip = ip;
        wgs_mask = mask;
    }
    return err;
}

esp_err_t wgs_set_host(const char *host)
{
    if (host == NULL || strlen(host) >= WGS_HOST_SIZE) {
        return ESP_ERR_INVALID_ARG;
    }
    for (const char *p = host; *p; p++) {
        if (!isalnum((unsigned char)*p) && *p != '.' && *p != '-') {
            return ESP_ERR_INVALID_ARG;
        }
    }
    esp_err_t err = set_config_param_str(KEY_HOST, host);
    if (err == ESP_OK) {
        strlcpy(wgs_host, host, sizeof(wgs_host));
    }
    return err;
}

/* ---- peers ---- */

esp_err_t wgs_peer_add(const char *name, const char *pubkey, const char *psk, uint32_t ip,
                       char *privkey_out, wgs_peer_cfg_t *out)
{
    wgs_peer_cfg_t p = {0};
    char priv[WGS_KEY_SIZE] = "";
    esp_err_t err;

    if (privkey_out) {
        privkey_out[0] = '\0';
    }
    if (lock == NULL || !valid_name(name) || (pubkey != NULL && !valid_key(pubkey)) ||
        (psk != NULL && psk[0] != '\0' && !valid_key(psk))) {
        return ESP_ERR_INVALID_ARG;
    }
    strlcpy(p.name, name, sizeof(p.name));

    if (psk != NULL) {
        if (psk[0] != '\0') {
            strlcpy(p.psk, psk, sizeof(p.psk));
        } else if (generate_psk(p.psk) != ESP_OK) {
            return ESP_FAIL;
        }
    }

    if (pubkey != NULL) {
        strlcpy(p.pubkey, pubkey, sizeof(p.pubkey));
    } else {
        /* One X25519 in the calling task, before taking the lock */
        if (privkey_out == NULL) {
            mbedtls_platform_zeroize(&p, sizeof(p));
            return ESP_ERR_INVALID_ARG;
        }
        err = esp_wireguard_generate_private_key(priv, sizeof(priv));
        if (err == ESP_OK) {
            err = esp_wireguard_public_key(priv, p.pubkey, sizeof(p.pubkey));
        }
        if (err != ESP_OK) {
            mbedtls_platform_zeroize(priv, sizeof(priv));
            mbedtls_platform_zeroize(&p, sizeof(p));
            return err;
        }
    }

    xSemaphoreTake(lock, portMAX_DELAY);
    if (!alloc_tables() || peer_count >= WGS_MAX_PEERS) {
        err = ESP_ERR_NO_MEM;
        goto done;
    }
    if (find_peer(name) >= 0 || strcmp(p.pubkey, wgs_pubkey) == 0) {
        err = ESP_ERR_INVALID_STATE;
        goto done;
    }
    for (int i = 0; i < peer_count; i++) {
        if (strcmp(peers[i].pubkey, p.pubkey) == 0) {
            err = ESP_ERR_INVALID_STATE;
            goto done;
        }
    }
    if (ip == 0) {
        ip = next_free_ip();
        if (ip == 0) {
            err = ESP_ERR_NO_MEM;
            goto done;
        }
    } else if (!ip_is_host_in_subnet(ip)) {
        err = ESP_ERR_INVALID_ARG;
        goto done;
    } else if (ip_in_use(ip)) {
        err = ESP_ERR_INVALID_STATE;
        goto done;
    }
    p.ip = ip;

    memset(peer_ts[peer_count], 0, TS_LEN);
    peers[peer_count++] = p;
    err = save_peers();
    if (err == ESP_OK && esp_wireguard_server_is_running()) {
        err = live_add(peer_count - 1);
        if (err != ESP_OK) {
            peer_count--;
            save_peers();
        }
    } else if (err != ESP_OK) {
        peer_count--;
    }
    if (err != ESP_OK) {
        mbedtls_platform_zeroize(&peers[peer_count], sizeof(wgs_peer_cfg_t));
    }

done:
    xSemaphoreGive(lock);
    if (err == ESP_OK) {
        if (privkey_out) {
            strlcpy(privkey_out, priv, WGS_KEY_SIZE);
        }
        if (out) {
            *out = p;
        }
    }
    mbedtls_platform_zeroize(priv, sizeof(priv));
    mbedtls_platform_zeroize(&p, sizeof(p));
    return err;
}

esp_err_t wgs_peer_del(const char *name)
{
    esp_err_t err = ESP_ERR_NOT_FOUND;

    if (lock == NULL || name == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    xSemaphoreTake(lock, portMAX_DELAY);
    int i = find_peer(name);
    if (i >= 0) {
        /* Cut the live session first: if the NVS write then fails the peer is
         * back after a restart, which is visible, rather than still connected
         * while reported as deleted. */
        if (esp_wireguard_server_is_running()) {
            esp_wireguard_server_remove_peer(peers[i].pubkey);
        }
        memmove(&peers[i], &peers[i + 1], (size_t)(peer_count - i - 1) * sizeof(wgs_peer_cfg_t));
        memmove(peer_ts[i], peer_ts[i + 1], (size_t)(peer_count - i - 1) * TS_LEN);
        peer_count--;
        mbedtls_platform_zeroize(&peers[peer_count], sizeof(wgs_peer_cfg_t));
        memset(peer_ts[peer_count], 0, TS_LEN);
        err = save_peers();
    }
    xSemaphoreGive(lock);
    return err;
}

int wgs_peer_list(wgs_peer_info_t *out, int max)
{
    int n = 0;

    if (lock == NULL || out == NULL) {
        return 0;
    }
    xSemaphoreTake(lock, portMAX_DELAY);
    for (; n < peer_count && n < max; n++) {
        memset(&out[n], 0, sizeof(out[n]));
        out[n].cfg = peers[n];
        out[n].handshake_age_s = UINT32_MAX;
    }
    xSemaphoreGive(lock);

    if (esp_wireguard_server_is_running()) {
        for (int i = 0; i < n; i++) {
            esp_wireguard_server_peer_stats_t st;
            if (esp_wireguard_server_get_peer_stats(out[i].cfg.pubkey, &st) == ESP_OK) {
                out[i].up = st.up;
                out[i].endpoint_ip = st.endpoint_ip;
                out[i].endpoint_port = st.endpoint_port;
                out[i].handshake_age_s = st.handshake_age_s;
                out[i].rx_bytes = st.rx_bytes;
                out[i].tx_bytes = st.tx_bytes;
            }
        }
    }
    return n;
}

int wgs_connected_count(void)
{
    int up = 0;

    if (lock == NULL || !esp_wireguard_server_is_running()) {
        return 0;
    }
    xSemaphoreTake(lock, portMAX_DELAY);
    for (int i = 0; i < peer_count; i++) {
        esp_wireguard_server_peer_stats_t st;
        if (esp_wireguard_server_get_peer_stats(peers[i].pubkey, &st) == ESP_OK && st.up) {
            up++;
        }
    }
    xSemaphoreGive(lock);
    return up;
}

int wgs_client_config(const wgs_peer_cfg_t *peer, const char *privkey,
                      bool full_tunnel, char *buf, size_t len)
{
    char a[16], b[16];
    esp_netif_ip_info_t info;
    esp_netif_dns_info_t dns;
    int n;

    n = snprintf(buf, len, "[Interface]\nPrivateKey = %s\nAddress = %s/32\n",
                 (privkey && privkey[0]) ? privkey : "<client private key>",
                 ip4str(peer->ip, a));

    /* The router does not answer DNS itself: hand out the server the AP
     * clients get, which is reached through the tunnel and the uplink NAT. */
    if (full_tunnel && n > 0 && (size_t)n < len &&
        esp_netif_get_dns_info(wifiAP, ESP_NETIF_DNS_MAIN, &dns) == ESP_OK &&
        dns.ip.type == ESP_IPADDR_TYPE_V4 && dns.ip.u_addr.ip4.addr != 0) {
        n += snprintf(buf + n, len - n, "DNS = %s\n", ip4str(dns.ip.u_addr.ip4.addr, a));
    }
    if (n < 0 || (size_t)n >= len) {
        return -1;
    }

    n += snprintf(buf + n, len - n, "\n[Peer]\nPublicKey = %s\n", wgs_pubkey);
    if (peer->psk[0] && (size_t)n < len) {
        n += snprintf(buf + n, len - n, "PresharedKey = %s\n", peer->psk);
    }
    if ((size_t)n >= len) {
        return -1;
    }
    n += snprintf(buf + n, len - n, "Endpoint = %s:%d\nAllowedIPs = ",
                  wgs_host[0] ? wgs_host : ip4str(my_ip, a), (int)wgs_port);
    if ((size_t)n >= len) {
        return -1;
    }

    if (full_tunnel) {
        n += snprintf(buf + n, len - n, "0.0.0.0/0");
    } else {
        n += snprintf(buf + n, len - n, "%s/%d", ip4str(wgs_ip & wgs_mask, a), mask_prefix(wgs_mask));
        if ((size_t)n < len && !ap_disabled &&
            esp_netif_get_ip_info(wifiAP, &info) == ESP_OK && info.ip.addr != 0) {
            n += snprintf(buf + n, len - n, ", %s/%d",
                          ip4str(info.ip.addr & info.netmask.addr, a), mask_prefix(info.netmask.addr));
        }
        if ((size_t)n < len &&
            esp_netif_get_ip_info(UPLINK_NETIF, &info) == ESP_OK && info.ip.addr != 0) {
            n += snprintf(buf + n, len - n, ", %s/%d",
                          ip4str(info.ip.addr & info.netmask.addr, b), mask_prefix(info.netmask.addr));
        }
    }
    if ((size_t)n >= len) {
        return -1;
    }
    n += snprintf(buf + n, len - n, "\nPersistentKeepalive = %d\n", CLIENT_KEEPALIVE_S);
    return ((size_t)n < len) ? n : -1;
}

#endif /* CONFIG_WG_SERVER */
