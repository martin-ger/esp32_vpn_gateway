/* Network interface hooks: byte counting, ACL enforcement, PCAP capture,
 * TTL override, TCP MSS clamping, Path MTU, and VPN kill switch.
 *
 * Hooks into the lwIP netif input/linkoutput chains for both STA/ETH
 * and AP interfaces to intercept packets for filtering and monitoring.
 */

#include <inttypes.h>
#include <string.h>
#include <time.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "driver/gpio.h"
#include "lwip/netif.h"
#include "lwip/ip_addr.h"
#include "lwip/pbuf.h"
#include "lwip/prot/ip4.h"
#include "lwip/inet_chksum.h"
#include "lwip/ip4_napt.h"
#include "lwip/prot/ip.h"
#include "acl.h"
#include "wg_server.h"
#include "client_stats.h"
#include "pcap_capture.h"
#include "router_config.h"
#include "wifi_config.h"
#include "vpn_config.h"
#include "led_strip_status.h"

#if CONFIG_ETH_UPLINK
#include "esp_eth.h"
extern esp_netif_t* ethNetif;
#else
extern esp_netif_t* wifiSTA;
#endif
extern esp_netif_t* wifiAP;

static const char *TAG = "netif_hooks";

// Original netif input and linkoutput function pointers
static netif_input_fn original_netif_input = NULL;
static netif_linkoutput_fn original_netif_linkoutput = NULL;
static struct netif *sta_netif = NULL;

// Original AP netif function pointers
static netif_input_fn original_ap_netif_input = NULL;
static netif_linkoutput_fn original_ap_netif_linkoutput = NULL;
static struct netif *ap_netif = NULL;

// Tunnel Path MTU on the uplink: tunnel MTU reported to hosts on the uplink
// side (0 = off), set by the VPN LAN gateway or the WireGuard server. See the
// "Uplink Path MTU" section below.
static volatile uint16_t uplink_pmtu = 0;
static bool uplink_frag_needed(struct pbuf *p, struct netif *netif);

// VPN LAN gateway (vpn_lan_gw) state, see the "VPN LAN gateway" section.
static volatile bool vpn_gw_active = false;
static uint16_t vpn_gw_mtu = 0;

// Per-client traffic statistics for AP clients
static client_stats_entry_t client_stats[CLIENT_STATS_MAX];

// Per-client stats enabled flag (default off; persisted in NVS "cstats_en")
bool client_stats_enabled = false;

static IRAM_ATTR client_stats_entry_t* find_client_stats(const uint8_t *mac) {
    for (int i = 0; i < CLIENT_STATS_MAX; i++) {
        if (client_stats[i].active && memcmp(client_stats[i].mac, mac, 6) == 0) {
            return &client_stats[i];
        }
    }
    return NULL;
}

void client_stats_on_connect(const uint8_t *mac) {
    // Keep existing stats on reconnect
    client_stats_entry_t *existing = find_client_stats(mac);
    if (existing) {
        existing->connected = 1;
        return;
    }
    // Find free slot: prefer inactive, then disconnected
    int free_slot = -1;
    int disconnected_slot = -1;
    for (int i = 0; i < CLIENT_STATS_MAX; i++) {
        if (!client_stats[i].active) {
            free_slot = i;
            break;
        } else if (!client_stats[i].connected && disconnected_slot < 0) {
            disconnected_slot = i;
        }
    }
    int slot = (free_slot >= 0) ? free_slot : disconnected_slot;
    if (slot >= 0) {
        memcpy(client_stats[slot].mac, mac, 6);
        client_stats[slot].bytes_sent = 0;
        client_stats[slot].bytes_received = 0;
        client_stats[slot].packets_sent = 0;
        client_stats[slot].packets_received = 0;
        client_stats[slot].active = 1;
        client_stats[slot].connected = 1;
    }
}

bool client_stats_on_disconnect(const uint8_t *mac) {
    client_stats_entry_t *entry = find_client_stats(mac);
    if (entry && entry->connected) {
        entry->connected = 0;
        return true;
    }
    return false;
}

int client_stats_get_all(client_stats_entry_t *out, int max_entries) {
    int count = 0;
    for (int i = 0; i < CLIENT_STATS_MAX && count < max_entries; i++) {
        if (client_stats[i].active) {
            memcpy(&out[count], &client_stats[i], sizeof(client_stats_entry_t));
            count++;
        }
    }
    return count;
}

void client_stats_reset_all(void) {
    for (int i = 0; i < CLIENT_STATS_MAX; i++) {
        if (client_stats[i].active) {
            client_stats[i].bytes_sent = 0;
            client_stats[i].bytes_received = 0;
            client_stats[i].packets_sent = 0;
            client_stats[i].packets_received = 0;
        }
    }
}

void format_bytes_human(uint64_t bytes, char *buf, size_t len) {
    if (bytes >= 1073741824ULL)
        snprintf(buf, len, "%.1f GB", (double)bytes / 1073741824.0);
    else if (bytes >= 1048576ULL)
        snprintf(buf, len, "%.1f MB", (double)bytes / 1048576.0);
    else if (bytes >= 1024ULL)
        snprintf(buf, len, "%.1f KB", (double)bytes / 1024.0);
    else
        snprintf(buf, len, "%" PRIu64 " B", bytes);
}

// Rewrite the IPv4 TTL of an Ethernet frame and update the header checksum.
// Only IPv4 is handled; other frames are left untouched.
static IRAM_ATTR void ttl_override_apply(struct pbuf *p, uint8_t ttl) {
    // Ethernet header: 14 bytes (6 dst + 6 src + 2 ethertype)
    // Use p->len (first segment) to ensure header is accessible in this pbuf
    if (p == NULL || p->len < 14 + sizeof(struct ip_hdr)) {
        return;
    }
    uint8_t *payload = (uint8_t *)p->payload;
    // Check ethertype for IPv4 (0x0800)
    if (payload[12] != 0x08 || payload[13] != 0x00) {
        return;
    }
    struct ip_hdr *iphdr = (struct ip_hdr *)(payload + 14);
    if (IPH_V(iphdr) != 4 || iphdr->_ttl == ttl) {
        return;
    }

    // Read 16-bit word containing TTL and protocol
    uint16_t old_ttl_proto = *(uint16_t *)&iphdr->_ttl;
    iphdr->_ttl = ttl;
    uint16_t new_ttl_proto = *(uint16_t *)&iphdr->_ttl;

    // RFC 1624: Incremental checksum update
    // HC' = ~(~HC + ~m + m')
    // where HC = old checksum, m = old value, m' = new value
    uint32_t sum = (uint16_t)~iphdr->_chksum;
    sum += (uint16_t)~old_ttl_proto;
    sum += new_ttl_proto;
    // Fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    iphdr->_chksum = (uint16_t)~sum;
}

// Hook function to count received bytes via netif input and ACL check
static IRAM_ATTR err_t netif_input_hook(struct pbuf *p, struct netif *netif) {
    bool is_acl_monitored = false;

    // Check to_esp ACL (packets from Internet to ESP32)
    if (!acl_is_empty(ACL_TO_ESP)) {
        uint8_t result = acl_check_packet(ACL_TO_ESP, p);

        // Check if packet has monitor flag
        is_acl_monitored = (result != ACL_NO_MATCH) && (result & ACL_MONITOR) != 0;

        // Handle deny action (logging done in acl_check_packet)
        if ((result & 0x01) == ACL_DENY && result != ACL_NO_MATCH) {
            // Capture denied packet if monitoring is enabled before dropping
            if (is_acl_monitored && pcap_should_capture(true, false)) {
                pcap_capture_packet(p);
            }
            pbuf_free(p);
            return ERR_OK;
        }
    }

    // Capture packet based on mode and ACL monitor flag (STA interface = false)
    if (pcap_should_capture(is_acl_monitored, false)) {
        pcap_capture_packet(p);
    }

    // TTL override for downstream packets: rewrite the TTL before lwIP
    // forwards the packet (like an nftables prerouting "ip ttl set"), so
    // packets arriving with TTL=1 (anti-tethering) survive the decrement
    // in ip4_forward. Done after PCAP capture so the capture shows what
    // arrived on the wire. A value of 1 is skipped here, since it would
    // make every forwarded downstream packet expire.
    if (sta_ttl_override > 1) {
        ttl_override_apply(p, sta_ttl_override);
    }

    // Count received bytes and toggle LED
    if (netif == sta_netif && p != NULL) {
        sta_bytes_received += p->tot_len;
        if (led_gpio >= 0 && ap_connect) {
            led_toggle ^= 1;
            gpio_set_level(led_gpio, led_toggle ^ led_lowactive);
        }
        if (led_strip_gpio >= 0) {
            led_strip_notify_traffic();
        }
    }

    // Tunnel Path MTU: answer oversized DF replies that would go into a
    // WireGuard tunnel with ICMP Fragmentation Needed, and drop them
    if (uplink_pmtu && uplink_frag_needed(p, netif)) {
        pbuf_free(p);
        return ERR_OK;
    }

    // Call original input function
    if (original_netif_input != NULL) {
        return original_netif_input(p, netif);
    }

    return ERR_VAL;
}


// Hook function to count sent bytes via netif linkoutput and ACL check
static IRAM_ATTR err_t netif_linkoutput_hook(struct netif *netif, struct pbuf *p) {
    bool is_acl_monitored = false;

    // Check from_esp ACL (packets from ESP32 to Internet)
    if (!acl_is_empty(ACL_FROM_ESP)) {
        uint8_t result = acl_check_packet(ACL_FROM_ESP, p);

        // Check if packet has monitor flag
        is_acl_monitored = (result != ACL_NO_MATCH) && (result & ACL_MONITOR) != 0;

        // Handle deny action (logging done in acl_check_packet)
        if ((result & 0x01) == ACL_DENY && result != ACL_NO_MATCH) {
            // Capture denied packet if monitoring is enabled before dropping
            if (is_acl_monitored && pcap_should_capture(true, false)) {
                pcap_capture_packet(p);
            }
            return ERR_OK;
        }
    }

    // TTL override for upstream packets (must be before PCAP capture so the
    // capture shows what goes out on the wire)
    if (sta_ttl_override > 0) {
        ttl_override_apply(p, sta_ttl_override);
    }

    // Capture packet based on mode and ACL monitor flag (STA interface = false)
    if (pcap_should_capture(is_acl_monitored, false)) {
        pcap_capture_packet(p);
    }

    // Count sent bytes and toggle LED
    if (netif == sta_netif && p != NULL) {
        sta_bytes_sent += p->tot_len;
        if (led_gpio >= 0 && ap_connect) {
            led_toggle ^= 1;
            gpio_set_level(led_gpio, led_toggle ^ led_lowactive);
        }
        if (led_strip_gpio >= 0) {
            led_strip_notify_traffic();
        }
    }

    // Call original linkoutput function
    if (original_netif_linkoutput != NULL) {
        return original_netif_linkoutput(netif, p);
    }

    return ERR_IF;
}

void init_byte_counter(void) {
#if CONFIG_ETH_UPLINK
    if (ethNetif != NULL && original_netif_input == NULL) {
        extern struct netif *esp_netif_get_netif_impl(esp_netif_t *esp_netif);
        sta_netif = esp_netif_get_netif_impl(ethNetif);
        if (sta_netif != NULL) {
            original_netif_input = sta_netif->input;
            sta_netif->input = netif_input_hook;
            original_netif_linkoutput = sta_netif->linkoutput;
            sta_netif->linkoutput = netif_linkoutput_hook;
            ESP_LOGI(TAG, "Byte counter initialized for ETH interface (input & output)");
        }
    }
#else
    if (wifiSTA != NULL && original_netif_input == NULL) {
        // Get the underlying lwIP netif structure
        esp_netif_t *sta_netif_handle = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
        if (sta_netif_handle != NULL) {
            // Access internal lwIP netif - this is internal API but necessary for hooking
            extern struct netif *esp_netif_get_netif_impl(esp_netif_t *esp_netif);
            sta_netif = esp_netif_get_netif_impl(sta_netif_handle);

            if (sta_netif != NULL) {
                // Store and hook input function
                original_netif_input = sta_netif->input;
                sta_netif->input = netif_input_hook;

                // Store and hook linkoutput function
                original_netif_linkoutput = sta_netif->linkoutput;
                sta_netif->linkoutput = netif_linkoutput_hook;

                ESP_LOGI(TAG, "Byte counter initialized for STA interface (input & output)");
            }
        }
    }
#endif
}

uint64_t get_sta_bytes_sent(void) {
    return sta_bytes_sent;
}

uint64_t get_sta_bytes_received(void) {
    return sta_bytes_received;
}

void reset_sta_byte_counts(void) {
    sta_bytes_sent = 0;
    sta_bytes_received = 0;
}

void resync_connect_count(void) {
    wifi_sta_list_t sta_list;
    if (esp_wifi_ap_get_sta_list(&sta_list) == ESP_OK) {
        connect_count = sta_list.num;
    }
}

// Uptime functions
uint32_t get_uptime_seconds(void) {
    return (uint32_t)(esp_timer_get_time() / 1000000ULL);
}

void format_uptime(uint32_t seconds, char *buf, size_t buf_len) {
    uint32_t days = seconds / 86400;
    uint32_t hours = (seconds % 86400) / 3600;
    uint32_t mins = (seconds % 3600) / 60;
    uint32_t secs = seconds % 60;

    if (days > 0) {
        snprintf(buf, buf_len, "%lud %02lu:%02lu:%02lu",
                 (unsigned long)days, (unsigned long)hours,
                 (unsigned long)mins, (unsigned long)secs);
    } else {
        snprintf(buf, buf_len, "%02lu:%02lu:%02lu",
                 (unsigned long)hours, (unsigned long)mins, (unsigned long)secs);
    }
}

void format_boot_time(char *buf, size_t buf_len) {
    time_t now;
    time(&now);
    if (now < 100000) {
        // Time not yet synchronized
        snprintf(buf, buf_len, "unknown");
        return;
    }
    time_t boot_time = now - (time_t)get_uptime_seconds();
    struct tm timeinfo;
    localtime_r(&boot_time, &timeinfo);
    snprintf(buf, buf_len, "%04d-%02d-%02d %02d:%02d:%02d",
             timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday,
             timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);
}

// Clamp the TCP MSS option in a SYN packet to max_mss.
// l2 is the length of the link-layer header in front of the IPv4 header: 14 for
// the raw Ethernet frames the WiFi/ETH hooks see, 0 for the bare IP packets of
// the WireGuard tunnel. Updates the TCP checksum incrementally (RFC 1624).
static void clamp_tcp_mss_l2(struct pbuf *p, uint16_t max_mss, uint16_t l2) {
    if (max_mss == 0 || p == NULL) return;
    // Need at least link header + min IP(20) + min TCP(20) in the first segment
    if (p->len < l2 + 20 + 20) return;

    uint8_t *payload = (uint8_t *)p->payload;

    // IPv4 only (ethertype 0x0800)
    if (l2 == 14 && (payload[12] != 0x08 || payload[13] != 0x00)) return;

    struct ip_hdr *iphdr = (struct ip_hdr *)(payload + l2);
    if (IPH_V(iphdr) != 4 || IPH_PROTO(iphdr) != PROTO_TCP) return;

    uint16_t ip_hdr_len = IPH_HL(iphdr) * 4;
    if (p->len < l2 + ip_hdr_len + 20) return;

    uint8_t *tcphdr = payload + l2 + ip_hdr_len;

    // SYN flag must be set (TCP flags byte is at offset 13, SYN = bit 1)
    if (!(tcphdr[13] & 0x02)) return;

    uint8_t tcp_hdr_len = (tcphdr[12] >> 4) * 4;
    if (tcp_hdr_len < 20 || p->len < l2 + ip_hdr_len + tcp_hdr_len) return;

    // Scan TCP options for MSS option (kind=2, len=4)
    uint8_t *opt = tcphdr + 20;
    uint8_t *opt_end = tcphdr + tcp_hdr_len;
    while (opt < opt_end) {
        uint8_t kind = opt[0];
        if (kind == 0) break;               // End of option list
        if (kind == 1) { opt++; continue; } // NOP
        if (opt + 1 >= opt_end) break;
        uint8_t opt_len = opt[1];
        if (opt_len < 2 || opt + opt_len > opt_end) break;

        if (kind == 2 && opt_len == 4) {
            uint16_t *mss_ptr = (uint16_t *)(opt + 2);
            if (ntohs(*mss_ptr) > max_mss) {
                uint16_t old_mss_net = *mss_ptr;
                *mss_ptr = htons(max_mss);
                // Incremental TCP checksum update (RFC 1624): HC' = ~(~HC + ~m + m')
                uint16_t *chksum = (uint16_t *)(tcphdr + 16);
                uint32_t sum = (uint16_t)~(*chksum);
                sum += (uint16_t)~old_mss_net;
                sum += htons(max_mss);
                while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
                *chksum = (uint16_t)~sum;
            }
            break;
        }
        opt += opt_len;
    }
}

static inline void clamp_tcp_mss(struct pbuf *p, uint16_t max_mss) {
    clamp_tcp_mss_l2(p, max_mss, 14);
}

// Send ICMP Fragmentation Needed (Type 3, Code 4) back to the sender of an
// inbound Ethernet frame 'p' on 'netif', from 'src_ip' (network byte order),
// through 'linkout' (the netif's original linkoutput). 'mtu' is the next-hop
// MTU to report. Only sent when the IP DF flag is set and the IP total length
// exceeds 'mtu'; returns true in that case (also if no buffer was available).
static bool send_icmp_frag_needed(struct pbuf *p, struct netif *netif, uint16_t mtu,
                                  uint32_t src_ip, netif_linkoutput_fn linkout)
{
    if (p == NULL || netif == NULL || linkout == NULL) return false;
    if (p->len < 14 + 20) return false; // need Ethernet header + IP header in first segment

    uint8_t *eth = (uint8_t *)p->payload;

    // IPv4 only (ethertype 0x0800)
    if (eth[12] != 0x08 || eth[13] != 0x00) return false;

    struct ip_hdr *orig_ip = (struct ip_hdr *)(eth + 14);
    if (IPH_V(orig_ip) != 4) return false;

    // Only when the packet exceeds the reported path MTU
    uint16_t ip_total_len = lwip_ntohs(IPH_LEN(orig_ip));
    if (ip_total_len <= mtu) return false;

    // Only send ICMP when DF is set and this is not a non-first fragment
    // (DF=1 with offset>0 is malformed; fragments with offset>0 have no full transport header)
    uint16_t flags_offset = lwip_ntohs(IPH_OFFSET(orig_ip));
    if (!(flags_offset & IP_DF)) return false;      // DF not set
    if (flags_offset & IP_OFFMASK) return false;    // fragment offset > 0

    // Don't generate ICMP errors in response to ICMP (avoid feedback loops)
    if (IPH_PROTO(orig_ip) == 1 /* ICMP */) return false;

    /* IHL comes from the sender, so the claimed header length has to be backed
     * by bytes actually present in this pbuf before it is copied out below —
     * otherwise up to 40 bytes of adjacent memory would be echoed back to it. */
    uint16_t orig_ihl = IPH_HL(orig_ip) * 4;
    if (orig_ihl < 20 || orig_ihl > 60) return false;
    if (p->len < 14u + orig_ihl) return false;

    // ICMP body: 2 bytes unused + 2 bytes next-hop MTU + orig IP header + first 8 data bytes
    uint16_t avail_data = (p->len > 14u + orig_ihl) ? (p->len - 14 - orig_ihl) : 0;
    if (avail_data > 8) avail_data = 8;

    uint16_t icmp_body    = 4 + orig_ihl + avail_data; // unused+mtu + orig_hdr + orig_data
    uint16_t icmp_total   = 4 + icmp_body;              // type+code+chksum + body
    uint16_t new_ip_len   = 20 + icmp_total;
    uint16_t frame_len    = 14 + new_ip_len;

    struct pbuf *resp = pbuf_alloc(PBUF_RAW, frame_len, PBUF_RAM);
    if (resp == NULL) return true;

    uint8_t *buf = (uint8_t *)resp->payload;
    memset(buf, 0, frame_len);

    // Ethernet: swap src/dst MAC (our MAC -> sender's MAC)
    memcpy(buf + 0, eth + 6, 6); // dst = original sender's MAC
    memcpy(buf + 6, eth + 0, 6); // src = our MAC (original frame's dst)
    buf[12] = 0x08;
    buf[13] = 0x00;

    // IP header
    struct ip_hdr *rip = (struct ip_hdr *)(buf + 14);
    IPH_VHL_SET(rip, 4, 5);
    IPH_TOS_SET(rip, 0);
    IPH_LEN_SET(rip, lwip_htons(new_ip_len));
    IPH_ID_SET(rip, 0);
    IPH_OFFSET_SET(rip, 0);
    IPH_TTL_SET(rip, 64);
    IPH_PROTO_SET(rip, 1 /* ICMP */);
    IPH_CHKSUM_SET(rip, 0);
    rip->src.addr  = src_ip;
    rip->dest.addr = orig_ip->src.addr;
    IPH_CHKSUM_SET(rip, inet_chksum(rip, 20));

    // ICMP Fragmentation Needed (RFC 1191)
    uint8_t *icmp = buf + 14 + 20;
    icmp[0] = 3;                        // Type: Destination Unreachable
    icmp[1] = 4;                        // Code: Fragmentation Needed, DF set
    icmp[2] = 0; icmp[3] = 0;          // checksum (computed below)
    icmp[4] = 0; icmp[5] = 0;          // unused
    icmp[6] = (uint8_t)(mtu >> 8);     // next-hop MTU high byte
    icmp[7] = (uint8_t)(mtu & 0xFF);   // next-hop MTU low byte
    memcpy(icmp + 8, orig_ip, orig_ihl);
    if (avail_data > 0) {
        memcpy(icmp + 8 + orig_ihl, (uint8_t *)orig_ip + orig_ihl, avail_data);
    }
    *((uint16_t *)(icmp + 2)) = inet_chksum(icmp, icmp_total);

    linkout(netif, resp);
    pbuf_free(resp);
    return true;
}

// AP netif hook functions (for PCAP capture and ACL)
static IRAM_ATTR err_t ap_netif_input_hook(struct pbuf *p, struct netif *netif) {
    bool is_acl_monitored = false;

    // Check to_ap ACL (packets from Clients to ESP32)
    if (!acl_is_empty(ACL_TO_AP)) {
        uint8_t result = acl_check_packet(ACL_TO_AP, p);

        // Check if packet has monitor flag
        is_acl_monitored = (result != ACL_NO_MATCH) && (result & ACL_MONITOR) != 0;

        // Handle deny action (logging done in acl_check_packet)
        if ((result & 0x01) == ACL_DENY && result != ACL_NO_MATCH) {
            // Capture denied packet if monitoring is enabled before dropping
            if (is_acl_monitored && pcap_should_capture(true, true)) {
                pcap_capture_packet(p);
            }
            pbuf_free(p);
            return ERR_OK;
        }
    }

    // VPN kill switch: block traffic when VPN is enabled but not connected
    // Route-all mode: block all non-AP-subnet traffic (prevents internet leakage)
    // Split tunnel mode: block only VPN-subnet traffic (internet goes direct via STA)
    if (vpn_enabled && vpn_killswitch && !vpn_is_connected()) {
        if (p != NULL && p->len >= 14 + sizeof(struct ip_hdr)) {
            uint8_t *payload = (uint8_t *)p->payload;
            if (payload[12] == 0x08 && payload[13] == 0x00) {  // IPv4
                struct ip_hdr *iphdr = (struct ip_hdr *)(payload + 14);
                if (IPH_V(iphdr) == 4) {
                    uint32_t dest = iphdr->dest.addr;
                    uint32_t ap_subnet = my_ap_ip & htonl(0xFFFFFF00);
                    bool is_local = (dest & htonl(0xFFFFFF00)) == ap_subnet;
                    if (!is_local) {
                        if (vpn_route_all) {
                            // Block all non-local traffic
                            pbuf_free(p);
                            return ERR_OK;
                        } else if (vpn_in_subnet(dest)) {
                            // Split tunnel: block only VPN-subnet traffic
                            pbuf_free(p);
                            return ERR_OK;
                        }
                    }
                }
            }
        }
    }

    // PMTU: send ICMP Fragmentation Needed if client sends a DF packet larger than path MTU
    if (ap_pmtu > 0) {
        send_icmp_frag_needed(p, netif, ap_pmtu, my_ap_ip, original_ap_netif_linkoutput);
    }

    // Clamp TCP MSS on SYN packets from clients
    clamp_tcp_mss(p, ap_mss_clamp);

    // Per-client byte counting: source MAC = client
    if (client_stats_enabled && p != NULL && p->len >= 14) {
        const uint8_t *src_mac = ((const uint8_t *)p->payload) + 6;
        client_stats_entry_t *entry = find_client_stats(src_mac);
        if (entry) {
            entry->bytes_received += p->tot_len;
            entry->packets_received++;
        }
    }

    // Capture packet based on mode and ACL monitor flag (AP interface = true)
    if (pcap_should_capture(is_acl_monitored, true)) {
        pcap_capture_packet(p);
    }

    // Call original input function
    if (original_ap_netif_input != NULL) {
        return original_ap_netif_input(p, netif);
    }

    return ERR_VAL;
}

static IRAM_ATTR err_t ap_netif_linkoutput_hook(struct netif *netif, struct pbuf *p) {
    bool is_acl_monitored = false;

    // Check from_ap ACL (packets from ESP32 to Clients)
    if (!acl_is_empty(ACL_FROM_AP)) {
        uint8_t result = acl_check_packet(ACL_FROM_AP, p);

        // Check if packet has monitor flag
        is_acl_monitored = (result != ACL_NO_MATCH) && (result & ACL_MONITOR) != 0;

        // Handle deny action (logging done in acl_check_packet)
        if ((result & 0x01) == ACL_DENY && result != ACL_NO_MATCH) {
            // Capture denied packet if monitoring is enabled before dropping
            if (is_acl_monitored && pcap_should_capture(true, true)) {
                pcap_capture_packet(p);
            }
            return ERR_OK;
        }
    }

    // Clamp TCP MSS on SYN/SYN-ACK packets to clients
    clamp_tcp_mss(p, ap_mss_clamp);

    // Per-client byte counting: dest MAC = client
    if (client_stats_enabled && p != NULL && p->len >= 14) {
        const uint8_t *dst_mac = (const uint8_t *)p->payload;
        client_stats_entry_t *entry = find_client_stats(dst_mac);
        if (entry) {
            entry->bytes_sent += p->tot_len;
            entry->packets_sent++;
        }
    }

    // Capture packet based on mode and ACL monitor flag (AP interface = true)
    if (pcap_should_capture(is_acl_monitored, true)) {
        pcap_capture_packet(p);
    }

    // Call original linkoutput function
    if (original_ap_netif_linkoutput != NULL) {
        return original_ap_netif_linkoutput(netif, p);
    }

    return ERR_IF;
}

void init_ap_netif_hooks(void) {
    if (wifiAP != NULL && original_ap_netif_input == NULL) {
        // Get the underlying lwIP netif structure for AP
        esp_netif_t *ap_netif_handle = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
        if (ap_netif_handle != NULL) {
            // Access internal lwIP netif - this is internal API but necessary for hooking
            extern struct netif *esp_netif_get_netif_impl(esp_netif_t *esp_netif);
            ap_netif = esp_netif_get_netif_impl(ap_netif_handle);

            if (ap_netif != NULL) {
                // Store and hook input function
                original_ap_netif_input = ap_netif->input;
                ap_netif->input = ap_netif_input_hook;

                // Store and hook linkoutput function
                original_ap_netif_linkoutput = ap_netif->linkoutput;
                ap_netif->linkoutput = ap_netif_linkoutput_hook;

                ESP_LOGI(TAG, "AP netif hooks initialized (input & output)");
            }
        }
    }
}

/* VPN LAN gateway (vpn_lan_gw): lets the far end of the WireGuard client
 * tunnel reach hosts on the uplink LAN (the STA or Ethernet subnet).
 *
 * NAT: packets from the tunnel to the uplink subnet are masqueraded to the
 * router's uplink address, so LAN hosts answer the router and need no route
 * back into the tunnel. lwIP's own NAPT can't be used for this: it translates
 * only when the *outgoing* netif has NAPT off, so turning it on for the tunnel
 * would stop the masquerading of AP traffic into the tunnel. The input hook
 * therefore calls ip_napt_forward() itself, for uplink-subnet packets only;
 * replies are translated back by lwIP's ip_napt_recv() as usual. This runs on
 * the tcpip thread (WireGuard's UDP receive callback), like ip4_forward().
 *
 * MSS: TCP SYNs are clamped to tunnel MTU - 40 in both directions; LAN hosts
 * otherwise assume 1500.
 *
 * Path MTU: see "Uplink Path MTU" below; the input hook records the flows. */
static netif_input_fn original_gw_input = NULL;
static netif_output_fn original_gw_output = NULL;

/* Uplink Path MTU, for the VPN LAN gateway and the WireGuard server.
 *
 * Traffic from a tunnel to the uplink side is masqueraded to the router's
 * uplink address. A reply with DF set that is larger than the tunnel MTU would
 * be refused by ip4_forward() with an ICMP that carries no MTU and the
 * translated header, which the sender can't match to its connection. The
 * uplink input hook sends a proper Fragmentation Needed instead, from the
 * uplink address with the untranslated header, and drops the packet.
 *
 * The uplink hook runs in the WiFi/ETH driver task, where the NAPT table
 * can't be read, and for server traffic lwIP translates inside ip4_forward()
 * where no hook sees the mapped port. The tunnel input hooks therefore record
 * the remote endpoint (address, protocol, port) of recent tunnel flows in a
 * small ring (pmtu_flows), and a reply to the uplink address from such an
 * endpoint is taken to be headed for the tunnel. An AP client talking to the
 * same endpoint at the same time may get the smaller MTU too, which only costs
 * it some packet size. TCP is covered by the MSS clamp anyway, so the ring
 * mainly matters for UDP with DF (e.g. QUIC). */
#define PMTU_FLOWS_MAX 16
typedef struct {
    uint32_t addr;      // remote address (network order), 0 = empty
    uint32_t key;       // (proto << 16) | remote port (network order)
} pmtu_flow_t;
static volatile pmtu_flow_t pmtu_flows[PMTU_FLOWS_MAX];
static uint8_t pmtu_flows_next = 0;

static IRAM_ATTR bool pmtu_flow_known(uint32_t addr, uint32_t key) {
    for (int i = 0; i < PMTU_FLOWS_MAX; i++) {
        if (pmtu_flows[i].addr == addr && pmtu_flows[i].key == key) return true;
    }
    return false;
}

/* Tunnel input (tcpip thread): record the destination of a TCP SYN or UDP
 * packet that leaves through the uplink. p->payload is the IP header. The two
 * words of an entry are written separately; a reader catching a half-written
 * entry at worst answers one unrelated packet, which then gets resent smaller. */
static IRAM_ATTR void pmtu_flow_remember(const struct pbuf *p) {
    const struct ip_hdr *iphdr = (const struct ip_hdr *)p->payload;
    uint8_t proto = IPH_PROTO(iphdr);
    if (proto != IP_PROTO_TCP && proto != IP_PROTO_UDP) return;
    uint16_t ihl = IPH_HL(iphdr) * 4;
    if (p->len < ihl + (proto == IP_PROTO_TCP ? 14 : 4)) return;
    const uint8_t *th = (const uint8_t *)p->payload + ihl;
    if (proto == IP_PROTO_TCP && !(th[13] & 0x02)) return;      // SYN only
    uint32_t addr = iphdr->dest.addr;
    uint32_t key = ((uint32_t)proto << 16) | *(const uint16_t *)(th + 2);
    if (pmtu_flow_known(addr, key)) return;
    pmtu_flows[pmtu_flows_next].addr = 0;
    pmtu_flows[pmtu_flows_next].key = key;
    pmtu_flows[pmtu_flows_next].addr = addr;
    pmtu_flows_next = (pmtu_flows_next + 1) % PMTU_FLOWS_MAX;
}

static void uplink_pmtu_set(uint16_t mtu) {
    for (int i = 0; i < PMTU_FLOWS_MAX; i++) {
        pmtu_flows[i].addr = 0;
    }
    pmtu_flows_next = 0;
    uplink_pmtu = mtu;
}

/* Uplink input (driver task): a frame for the uplink address from a recorded
 * tunnel flow endpoint will be translated and forwarded into the tunnel. If it
 * exceeds the tunnel MTU with DF set, send ICMP Fragmentation Needed and
 * return true (the caller drops it). */
static IRAM_ATTR bool uplink_frag_needed(struct pbuf *p, struct netif *netif) {
    uint16_t mtu = uplink_pmtu;
    if (p == NULL || p->len < 14 + 20) return false;
    const uint8_t *eth = (const uint8_t *)p->payload;
    if (eth[12] != 0x08 || eth[13] != 0x00) return false;
    const struct ip_hdr *iphdr = (const struct ip_hdr *)(eth + 14);
    if (IPH_V(iphdr) != 4 || lwip_ntohs(IPH_LEN(iphdr)) <= mtu) return false;
    if (iphdr->dest.addr != ip4_addr_get_u32(netif_ip4_addr(netif))) return false;
    uint8_t proto = IPH_PROTO(iphdr);
    if (proto != IP_PROTO_TCP && proto != IP_PROTO_UDP) return false;
    uint16_t ihl = IPH_HL(iphdr) * 4;
    if (ihl < 20 || p->len < 14u + ihl + 4) return false;
    uint16_t sport = *(const uint16_t *)(eth + 14 + ihl);
    if (!pmtu_flow_known(iphdr->src.addr, ((uint32_t)proto << 16) | sport)) return false;
    return send_icmp_frag_needed(p, netif, mtu, iphdr->dest.addr, original_netif_linkoutput);
}

static IRAM_ATTR err_t gw_input_hook(struct pbuf *p, struct netif *netif) {
    clamp_tcp_mss_l2(p, vpn_gw_mtu - 40, 0);

    /* Needs the NAPT table, which exists while the AP has NAT on (default) */
    if (!vpn_gw_active || sta_netif == NULL || ap_netif == NULL || !ap_netif->napt ||
        p->len < IP_HLEN) {
        return original_gw_input(p, netif);
    }
    struct ip_hdr *iphdr = (struct ip_hdr *)p->payload;
    if (IPH_V(iphdr) != 4) {
        return original_gw_input(p, netif);
    }

    ip4_addr_t dest;
    ip4_addr_copy(dest, iphdr->dest);
    const ip4_addr_t *lan_ip = netif_ip4_addr(sta_netif);
    if (!netif_is_up(sta_netif) || ip4_addr_isany(lan_ip) || ip4_addr_eq(&dest, lan_ip) ||
        !ip4_addr_net_eq(&dest, lan_ip, netif_ip4_netmask(sta_netif)) ||
        ip4_addr_isbroadcast(&dest, sta_netif)) {
        return original_gw_input(p, netif);   // not for a host on the uplink LAN
    }

    /* ip_napt_forward() reads the transport header from the first segment */
    uint8_t proto = IPH_PROTO(iphdr);
    uint16_t ihl = IPH_HL(iphdr) * 4;
    if ((proto == IP_PROTO_TCP || proto == IP_PROTO_UDP || proto == IP_PROTO_ICMP) &&
        p->len < ihl + 8) {
        pbuf_free(p);
        return ERR_OK;
    }

    pmtu_flow_remember(p);      // before translation: dest is the LAN host

    /* ip_napt_forward() only checks inp->napt; pass the AP, whose flag is the
     * precondition checked above. The tunnel netif's own flag stays off. */
    if (ip_napt_forward(p, iphdr, ap_netif, sta_netif) != ERR_OK) {
        pbuf_free(p);   // unknown TCP/UDP session or NAPT table full
        return ERR_OK;
    }
    return original_gw_input(p, netif);
}

static IRAM_ATTR err_t gw_output_hook(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr) {
    clamp_tcp_mss_l2(p, vpn_gw_mtu - 40, 0);
    return original_gw_output(netif, p, ipaddr);
}

// Must run on the tcpip thread, after the client tunnel is up with its final MTU.
void vpn_gw_hooks_install(struct netif *wg) {
    if (wg == NULL) return;
    vpn_gw_mtu = wg->mtu;
    uplink_pmtu_set(vpn_gw_mtu);
    if (wg->input != gw_input_hook) {
        original_gw_input = wg->input;
        original_gw_output = wg->output;
        wg->input = gw_input_hook;
        wg->output = gw_output_hook;
    }
    vpn_gw_active = true;
    ESP_LOGI(TAG, "VPN LAN gateway active (MTU %u, MSS %u)", vpn_gw_mtu, vpn_gw_mtu - 40);
}

// Call before the tunnel netif is removed. The hooks stay on that netif and
// pass packets through until it is gone; a new tunnel gets fresh pointers.
void vpn_gw_hooks_remove(void) {
    vpn_gw_active = false;
    uplink_pmtu = 0;
}

bool vpn_gw_is_active(void) {
    return vpn_gw_active;
}

#if CONFIG_WG_SERVER
/* WireGuard server tunnel hooks.
 *
 * The tunnel netif has no link layer: input and output carry bare IP packets,
 * so it gets its own pair of hooks instead of the Ethernet-frame ones above.
 * They apply the to_wg/from_wg ACLs, clamp the MSS of TCP SYNs to the
 * tunnel MTU in both directions (hosts behind the router assume 1500), and
 * feed the packet capture: promiscuous mode records all tunnel traffic,
 * ACL monitor mode the packets of to_wg/from_wg rules with the monitor flag.
 * Packets are recorded decrypted, with a synthetic Ethernet header.
 * Traffic between two VPN clients is turned around in the input hook. */
static netif_input_fn original_wg_input = NULL;
static netif_output_fn original_wg_output = NULL;
static uint16_t wg_mss_clamp = 0;

/* Check a tunnel ACL. Returns true if the packet is denied; *monitored is set
 * if the matching rule has the monitor flag. A denied, monitored packet is
 * captured here, before it is dropped (as on the AP and uplink). */
static IRAM_ATTR bool wg_acl_denies(uint8_t list, struct pbuf *p, bool to_router, bool *monitored) {
    *monitored = false;
    if (acl_is_empty(list)) return false;
    uint8_t result = acl_check_ip_packet(list, p);
    if (result == ACL_NO_MATCH) return false;
    *monitored = (result & ACL_MONITOR) != 0;
    if ((result & 0x01) == ACL_DENY) {
        if (*monitored && pcap_should_capture(true, true)) {
            pcap_capture_ip_packet(p, to_router);
        }
        return true;
    }
    return false;
}

/* Client to client: all VPN clients share the tunnel netif, and lwIP never
 * forwards a packet out of the interface it arrived on. A packet for another
 * client's tunnel address is therefore sent back into the tunnel here, the
 * way ip4_forward() would (TTL decremented, no NAPT). It has passed to_wg in
 * the input hook and passes from_wg in wg_output_hook, so either list can
 * restrict it. Returns true if the packet was consumed. */
static IRAM_ATTR bool wg_forward_to_client(struct pbuf *p, struct netif *netif) {
    if (p->len < IP_HLEN) return false;
    struct ip_hdr *iphdr = (struct ip_hdr *)p->payload;
    if (IPH_V(iphdr) != 4) return false;

    ip4_addr_t dest;
    ip4_addr_copy(dest, iphdr->dest);
    const ip4_addr_t *own = netif_ip4_addr(netif);
    if (ip4_addr_eq(&dest, own) || !ip4_addr_net_eq(&dest, own, netif_ip4_netmask(netif)) ||
        ip4_addr_isbroadcast(&dest, netif) || ip4_addr_ismulticast(&dest)) {
        return false;   /* for the router itself, or not a client address */
    }

    if (IPH_TTL(iphdr) > 1) {
        IPH_TTL_SET(iphdr, IPH_TTL(iphdr) - 1);
        /* Incremental IP checksum update, as in ip4_forward() */
        if (IPH_CHKSUM(iphdr) >= PP_HTONS(0xffffU - 0x100)) {
            IPH_CHKSUM_SET(iphdr, (u16_t)(IPH_CHKSUM(iphdr) + PP_HTONS(0x100) + 1));
        } else {
            IPH_CHKSUM_SET(iphdr, (u16_t)(IPH_CHKSUM(iphdr) + PP_HTONS(0x100)));
        }
        /* wg_output_hook; the WireGuard output picks the peer by its allowed
         * IP and drops the packet if no client has this address */
        netif->output(netif, p, &dest);
    }
    pbuf_free(p);   /* netif->output does not take ownership */
    return true;
}

/* True if a packet from a VPN client is forwarded out of the uplink (and so
 * masqueraded): not for the router or the tunnel or AP subnet. */
static IRAM_ATTR bool wg_leaves_via_uplink(const struct pbuf *p, struct netif *netif) {
    if (p->len < IP_HLEN || sta_netif == NULL) return false;
    const struct ip_hdr *iphdr = (const struct ip_hdr *)p->payload;
    if (IPH_V(iphdr) != 4) return false;
    ip4_addr_t dest;
    ip4_addr_copy(dest, iphdr->dest);
    if (ip4_addr_ismulticast(&dest) || ip4_addr_isbroadcast(&dest, netif) ||
        ip4_addr_eq(&dest, netif_ip4_addr(sta_netif)) ||
        ip4_addr_net_eq(&dest, netif_ip4_addr(netif), netif_ip4_netmask(netif))) {
        return false;
    }
    if (ap_netif != NULL &&
        ip4_addr_net_eq(&dest, netif_ip4_addr(ap_netif), netif_ip4_netmask(ap_netif))) {
        return false;
    }
    return true;
}

static IRAM_ATTR err_t wg_input_hook(struct pbuf *p, struct netif *netif) {
    bool monitored;
    if (wg_acl_denies(ACL_TO_WG, p, true, &monitored)) {
        pbuf_free(p);
        return ERR_OK;
    }
    clamp_tcp_mss_l2(p, wg_mss_clamp, 0);
    if (pcap_should_capture(monitored, true)) {
        pcap_capture_ip_packet(p, true);
    }
    if (wg_forward_to_client(p, netif)) {
        return ERR_OK;
    }
    if (wg_leaves_via_uplink(p, netif)) {
        pmtu_flow_remember(p);
    }
    return original_wg_input(p, netif);
}

static IRAM_ATTR err_t wg_output_hook(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr) {
    bool monitored;
    if (wg_acl_denies(ACL_FROM_WG, p, false, &monitored)) {
        return ERR_OK;  // dropped; the caller keeps ownership of p
    }
    clamp_tcp_mss_l2(p, wg_mss_clamp, 0);
    if (pcap_should_capture(monitored, true)) {
        pcap_capture_ip_packet(p, false);
    }
    return original_wg_output(netif, p, ipaddr);
}

// Must run on the tcpip thread, after the server created its netif.
void wg_netif_hooks_install(struct netif *wg) {
    if (wg == NULL || wg->input == wg_input_hook) return;
    original_wg_input = wg->input;
    original_wg_output = wg->output;
    wg_mss_clamp = (uint16_t)(wg->mtu - 40);
    wg->input = wg_input_hook;
    wg->output = wg_output_hook;
    uplink_pmtu_set(wg->mtu);
}
#endif /* CONFIG_WG_SERVER */
