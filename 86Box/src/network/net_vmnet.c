/*
 * 86Box vmnet backend for macOS
 *
 * Socket-client version.
 *
 * This backend no longer calls vmnet.framework directly. Instead it talks to a
 * privileged helper over a UNIX domain socket. The helper owns all vmnet API
 * usage.
 */

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <poll.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <sys/un.h>

#define HAVE_STDARG_H
#include <86box/86box.h>
#include <86box/device.h>
#include <86box/plat.h>
#include <86box/thread.h>
#include <86box/timer.h>
#include <86box/network.h>
#include <86box/net_event.h>

#define VMNET_PKT_BATCH NET_QUEUE_LEN
#define VMN_SOCK_PATH   "/var/run/vmnet-helper.sock"

enum {
    NET_EVENT_STOP = 0,
    NET_EVENT_TX,
    NET_EVENT_MAX
};

enum {
    VMN_MODE_SHARED    = 1,
    VMN_MODE_HOST      = 2,
    VMN_MODE_BRIDGED   = 3,
    VMN_MODE_PUBLISHED = 4
};

enum {
    VMN_MSG_START      = 1,
    VMN_MSG_START_OK   = 2,
    VMN_MSG_START_ERR  = 3,
    VMN_MSG_SEND_FRAME = 4,
    VMN_MSG_RX_FRAME   = 5,
    VMN_MSG_STOP       = 6,
    VMN_MSG_STOPPED    = 7
};

typedef struct {
    uint32_t type;
    uint32_t length;
} vmn_msg_hdr_t;

typedef struct {
    uint32_t mode;
    uint32_t published_ip;
    char     guest_ip[16];
} vmn_start_req_t;

typedef struct {
    int32_t code;
} vmn_start_err_t;

typedef struct {
    int          sock_fd;
    netcard_t   *card;
    thread_t    *poll_tid;
    net_evt_t    tx_event;
    net_evt_t    stop_event;
    netpkt_t     pkt;
    netpkt_t     pktv[VMNET_PKT_BATCH];
    uint8_t      mac_addr[6];
} net_vmnet_t;

static void
vmnet_log(const char *fmt, ...)
{
    va_list ap;
    FILE *fp = fopen("/tmp/log", "a");
    if (fp == NULL)
        return;

    va_start(ap, fmt);
    vfprintf(fp, fmt, ap);
    va_end(ap);

    fflush(fp);
    fclose(fp);
}


static void
vmnet_log_mac(char *buf, size_t buf_sz, const uint8_t *mac)
{
    if (buf == NULL || buf_sz == 0)
        return;

    if (mac == NULL) {
        snprintf(buf, buf_sz, "<null>");
        return;
    }

    snprintf(buf, buf_sz, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void
vmnet_log_ipv4(char *buf, size_t buf_sz, const uint8_t *ip)
{
    if (buf == NULL || buf_sz == 0)
        return;

    if (ip == NULL) {
        snprintf(buf, buf_sz, "<null>");
        return;
    }

    snprintf(buf, buf_sz, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
}

static void
vmnet_log_frame_decode(const char *dir, const uint8_t *frame, size_t len)
{
    char     src_mac[18], dst_mac[18];
    uint16_t ethertype;

    if (dir == NULL)
        dir = "PKT";

    if (frame == NULL) {
        vmnet_log("VMNET: %s frame=<null> len=%zu\n", dir, len);
        return;
    }

    if (len < 14) {
        vmnet_log("VMNET: %s short ethernet frame len=%zu\n", dir, len);
        return;
    }

    vmnet_log_mac(dst_mac, sizeof(dst_mac), frame + 0);
    vmnet_log_mac(src_mac, sizeof(src_mac), frame + 6);
    ethertype = (uint16_t) (((uint16_t) frame[12] << 8) | frame[13]);

    vmnet_log("VMNET: %s eth src=%s dst=%s type=0x%04x len=%zu\n",
              dir, src_mac, dst_mac, ethertype, len);

    if (ethertype == 0x0806) {
        char     sender_mac[18], target_mac[18];
        char     sender_ip[16], target_ip[16];
        uint16_t opcode;

        if (len < 42) {
            vmnet_log("VMNET: %s arp short len=%zu\n", dir, len);
            return;
        }

        opcode = (uint16_t) (((uint16_t) frame[20] << 8) | frame[21]);
        vmnet_log_mac(sender_mac, sizeof(sender_mac), frame + 22);
        vmnet_log_ipv4(sender_ip, sizeof(sender_ip), frame + 28);
        vmnet_log_mac(target_mac, sizeof(target_mac), frame + 32);
        vmnet_log_ipv4(target_ip, sizeof(target_ip), frame + 38);

        vmnet_log("VMNET: %s arp op=%u sender=%s/%s target=%s/%s\n",
                  dir, opcode, sender_mac, sender_ip, target_mac, target_ip);
        return;
    }

    if (ethertype == 0x0800) {
        char          src_ip[16], dst_ip[16];
        const uint8_t *ip   = frame + 14;
        size_t        iplen = len - 14;
        uint8_t       ihl;
        uint8_t       proto;

        if (iplen < 20) {
            vmnet_log("VMNET: %s ipv4 short len=%zu\n", dir, iplen);
            return;
        }

        ihl   = (uint8_t) ((ip[0] & 0x0f) * 4);
        proto = ip[9];
        if (ihl < 20 || iplen < ihl) {
            vmnet_log("VMNET: %s ipv4 bad-ihl ihl=%u iplen=%zu\n", dir, ihl, iplen);
            return;
        }

        vmnet_log_ipv4(src_ip, sizeof(src_ip), ip + 12);
        vmnet_log_ipv4(dst_ip, sizeof(dst_ip), ip + 16);
        vmnet_log("VMNET: %s ipv4 %s -> %s proto=%u ttl=%u ihl=%u totlen=%u\n",
                  dir, src_ip, dst_ip, proto, ip[8], ihl,
                  (unsigned) (((uint16_t) ip[2] << 8) | ip[3]));

        if (proto == 1) {
            const uint8_t *icmp  = ip + ihl;
            size_t        icmplen = iplen - ihl;
            if (icmplen < 4) {
                vmnet_log("VMNET: %s icmp short len=%zu\n", dir, icmplen);
                return;
            }
            vmnet_log("VMNET: %s icmp type=%u code=%u\n",
                      dir, icmp[0], icmp[1]);
            return;
        }

        if (proto == 6) {
            const uint8_t *tcp   = ip + ihl;
            size_t        tcplen = iplen - ihl;
            if (tcplen < 20) {
                vmnet_log("VMNET: %s tcp short len=%zu\n", dir, tcplen);
                return;
            }
            vmnet_log("VMNET: %s tcp sport=%u dport=%u flags=0x%02x\n",
                      dir,
                      (unsigned) (((uint16_t) tcp[0] << 8) | tcp[1]),
                      (unsigned) (((uint16_t) tcp[2] << 8) | tcp[3]),
                      tcp[13]);
            return;
        }

        if (proto == 17) {
            const uint8_t *udp   = ip + ihl;
            size_t        udplen = iplen - ihl;
            if (udplen < 8) {
                vmnet_log("VMNET: %s udp short len=%zu\n", dir, udplen);
                return;
            }
            vmnet_log("VMNET: %s udp sport=%u dport=%u len=%u\n",
                      dir,
                      (unsigned) (((uint16_t) udp[0] << 8) | udp[1]),
                      (unsigned) (((uint16_t) udp[2] << 8) | udp[3]),
                      (unsigned) (((uint16_t) udp[4] << 8) | udp[5]));
            return;
        }

        return;
    }

    if (ethertype == 0x86dd) {
        vmnet_log("VMNET: %s ipv6 len=%zu\n", dir, len - 14);
        return;
    }
}

static void
net_vmnet_error(char *errbuf, const char *message)
{
    strncpy(errbuf, message, NET_DRV_ERRBUF_SIZE);
    errbuf[NET_DRV_ERRBUF_SIZE - 1] = '\0';
    vmnet_log("VMNET: %s\n", message);
}

static int
vmnet_write_full(int fd, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *) buf;

    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;

        p += n;
        len -= (size_t) n;
    }

    return 0;
}

static int
vmnet_read_full(int fd, void *buf, size_t len)
{
    uint8_t *p = (uint8_t *) buf;

    while (len > 0) {
        ssize_t n = read(fd, p, len);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;

        p += n;
        len -= (size_t) n;
    }

    return 0;
}

static int
vmnet_send_msg(int fd, uint32_t type, const void *payload, uint32_t length)
{
    vmn_msg_hdr_t hdr;

    hdr.type   = type;
    hdr.length = length;

    if (vmnet_write_full(fd, &hdr, sizeof(hdr)) < 0)
        return -1;

    if (length != 0 && payload != NULL) {
        if (vmnet_write_full(fd, payload, length) < 0)
            return -1;
    }

    return 0;
}

static int
vmnet_drain_payload(int fd, uint32_t length)
{
    uint8_t scratch[4096];

    while (length > 0) {
        uint32_t chunk = (length > sizeof(scratch)) ? (uint32_t) sizeof(scratch) : length;
        if (vmnet_read_full(fd, scratch, chunk) < 0)
            return -1;
        length -= chunk;
    }

    return 0;
}

static int
vmnet_connect_socket(void)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, VMN_SOCK_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}

static uint32_t
vmnet_parse_published_ip(const char *spec)
{
    const char *ip;

    if (spec == NULL || *spec == '\0')
        return 0;

    ip = strchr(spec, ':');
    if (ip != NULL)
        ip++;
    else
        ip = spec;

    if (*ip == '\0')
        return 0;

    return (uint32_t) inet_addr(ip);
}

static uint32_t
vmnet_get_ipv4_for_interface(const char *ifname)
{
    struct ifaddrs *ifaddr = NULL;
    struct ifaddrs *ifa;
    uint32_t        ip = 0;

    if (ifname == NULL || *ifname == '\0')
        return 0;

    if (getifaddrs(&ifaddr) != 0)
        return 0;

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        if ((ifa->ifa_addr->sa_family == AF_INET) && !strcmp(ifa->ifa_name, ifname)) {
            const struct sockaddr_in *sa = (const struct sockaddr_in *) ifa->ifa_addr;
            ip                           = sa->sin_addr.s_addr;
            break;
        }
    }

    freeifaddrs(ifaddr);
    return ip;
}

static void
vmnet_fill_start_req(vmn_start_req_t *req, const char *mode_spec)
{
    memset(req, 0, sizeof(*req));
    req->mode = VMN_MODE_SHARED;

    if (mode_spec == NULL || *mode_spec == '\0' ||
        !strcmp(mode_spec, "shared") || !strcmp(mode_spec, "nat") ||
        !strcmp(mode_spec, "vmnet-shared") || !strcmp(mode_spec, "vmnet-nat"))
        return;

    if (!strcmp(mode_spec, "host")) {
        req->mode = VMN_MODE_HOST;
        return;
    }

    if (!strcmp(mode_spec, "bridged")) {
        req->mode = VMN_MODE_BRIDGED;
        return;
    }

    if (!strcmp(mode_spec, "published") || !strcmp(mode_spec, "pub")) {
        req->mode = VMN_MODE_PUBLISHED;
        return;
    }

    if (!strncmp(mode_spec, "published:", 10) || !strncmp(mode_spec, "pub:", 4)) {
        req->mode         = VMN_MODE_PUBLISHED;
        req->published_ip = vmnet_parse_published_ip(mode_spec);
        return;
    }

    if (!strcmp(mode_spec, "vmnet-shared")) {
        req->mode = VMN_MODE_SHARED;
        return;
    }

    if (!strcmp(mode_spec, "vmnet-host")) {
        req->mode = VMN_MODE_HOST;
        return;
    }

    if (!strcmp(mode_spec, "vmnet-bridged") || !strcmp(mode_spec, "vmnet-bridge")) {
        req->mode = VMN_MODE_BRIDGED;
        return;
    }

    if (!strcmp(mode_spec, "vmnet-published") || !strcmp(mode_spec, "vmnet-pub")) {
        req->mode = VMN_MODE_PUBLISHED;
        return;
    }

    if (!strncmp(mode_spec, "vmnet-published:", 16) || !strncmp(mode_spec, "vmnet-pub:", 10)) {
        req->mode         = VMN_MODE_PUBLISHED;
        req->published_ip = vmnet_parse_published_ip(mode_spec);
        return;
    }
}

static int
vmnet_helper_start(int fd, const char *mode_spec, const char *host_ifname, const char *guest_ip_spec)
{
    vmn_start_req_t req;
    vmn_msg_hdr_t   hdr;

    vmnet_fill_start_req(&req, mode_spec);
    memset(req.guest_ip, 0, sizeof(req.guest_ip));
    if ((guest_ip_spec != NULL) && (*guest_ip_spec != '\0'))
        strncpy(req.guest_ip, guest_ip_spec, sizeof(req.guest_ip) - 1);

    if (req.mode == VMN_MODE_PUBLISHED && req.published_ip == 0)
        req.published_ip = vmnet_get_ipv4_for_interface(host_ifname);

    if (req.mode == VMN_MODE_PUBLISHED && req.published_ip == 0) {
        vmnet_log("VMNET: published mode requested but no valid IPv4 found for interface %s\n",
                  (host_ifname && *host_ifname) ? host_ifname : "(none)");
        return -95;
    }

    vmnet_log("VMNET: sending START to helper mode=%u published_ip=0x%08x guest_ip=%s spec=%s iface=%s\n",
              req.mode, req.published_ip,
              req.guest_ip[0] ? req.guest_ip : "(none)",
              mode_spec ? mode_spec : "(null)",
              (host_ifname && *host_ifname) ? host_ifname : "(none)");
    if (vmnet_send_msg(fd, VMN_MSG_START, &req, sizeof(req)) < 0)
        return -1;

    if (vmnet_read_full(fd, &hdr, sizeof(hdr)) < 0)
        return -2;

    vmnet_log("VMNET: helper replied type=%u length=%u\n", hdr.type, hdr.length);

    if (hdr.type == VMN_MSG_START_OK) {
        if (hdr.length != 0)
            return vmnet_drain_payload(fd, hdr.length);
        return 0;
    }

    if (hdr.type == VMN_MSG_START_ERR) {
        vmn_start_err_t err;

        if (hdr.length != sizeof(err))
            return -3;
        if (vmnet_read_full(fd, &err, sizeof(err)) < 0)
            return -4;

        vmnet_log("VMNET: helper START_ERR code=%d\n", err.code);
        return (err.code != 0) ? err.code : -5;
    }

    if (hdr.length != 0)
        vmnet_drain_payload(fd, hdr.length);

    return -6;
}

static int
vmnet_helper_stop(int fd)
{
    vmn_msg_hdr_t hdr;

    vmnet_log("VMNET: sending STOP to helper\n");
    if (vmnet_send_msg(fd, VMN_MSG_STOP, NULL, 0) < 0)
        return -1;

    if (vmnet_read_full(fd, &hdr, sizeof(hdr)) < 0)
        return -2;

    vmnet_log("VMNET: helper stop reply type=%u length=%u\n", hdr.type, hdr.length);

    if (hdr.length != 0) {
        if (vmnet_drain_payload(fd, hdr.length) < 0)
            return -3;
    }

    return (hdr.type == VMN_MSG_STOPPED) ? 0 : -4;
}

static int
vmnet_helper_send_frame(int fd, const uint8_t *frame, size_t len)
{
    if (len > UINT32_MAX)
        return -1;

#ifdef DEBUG
    vmnet_log_frame_decode("TX", frame, len);
#endif

    if (vmnet_send_msg(fd, VMN_MSG_SEND_FRAME, frame, (uint32_t) len) < 0)
        return -1;

    return 0;
}

static int
net_vmnet_rx_dispatch(net_vmnet_t *vmnet, const uint8_t *frame, size_t len)
{
    if (vmnet == NULL || frame == NULL || len == 0 || len > NET_MAX_FRAME)
        return -1;

    memcpy(vmnet->pkt.data, frame, len);
    vmnet->pkt.len = (int) len;

    if (!(net_cards_conf[vmnet->card->card_num].link_state & NET_LINK_DOWN))
        network_rx_put_pkt(vmnet->card, &vmnet->pkt);

    return 0;
}

static int
vmnet_handle_socket_readable(net_vmnet_t *vmnet)
{
    vmn_msg_hdr_t hdr;

    if (vmnet_read_full(vmnet->sock_fd, &hdr, sizeof(hdr)) < 0)
        return -1;

    //vmnet_log("VMNET: socket msg type=%u length=%u\n", hdr.type, hdr.length);

    if (hdr.type == VMN_MSG_RX_FRAME) {
        if (hdr.length == 0 || hdr.length > NET_MAX_FRAME) {
            if (vmnet_drain_payload(vmnet->sock_fd, hdr.length) < 0)
                return -1;
            return 0;
        }

        if (vmnet_read_full(vmnet->sock_fd, vmnet->pkt.data, hdr.length) < 0)
            return -1;

#ifdef DEBUG
        vmnet_log_frame_decode("RX", vmnet->pkt.data, hdr.length);
#endif

        vmnet->pkt.len = (int) hdr.length;
        if (!(net_cards_conf[vmnet->card->card_num].link_state & NET_LINK_DOWN))
            network_rx_put_pkt(vmnet->card, &vmnet->pkt);
        return 0;
    }

    if (hdr.length != 0) {
        if (vmnet_drain_payload(vmnet->sock_fd, hdr.length) < 0)
            return -1;
    }

    return 0;
}

static void
net_vmnet_thread(void *priv)
{
    net_vmnet_t *vmnet = (net_vmnet_t *) priv;
    struct pollfd pfd[NET_EVENT_MAX + 1];

    vmnet_log("VMNET: polling started\n");

    pfd[NET_EVENT_STOP].fd     = net_event_get_fd(&vmnet->stop_event);
    pfd[NET_EVENT_STOP].events = POLLIN | POLLPRI;

    pfd[NET_EVENT_TX].fd     = net_event_get_fd(&vmnet->tx_event);
    pfd[NET_EVENT_TX].events = POLLIN | POLLPRI;

    pfd[NET_EVENT_MAX].fd     = vmnet->sock_fd;
    pfd[NET_EVENT_MAX].events = POLLIN;

    while (1) {
        int prc = poll(pfd, NET_EVENT_MAX + 1, 10);
        if (prc < 0) {
            if (errno == EINTR)
                continue;
            vmnet_log("VMNET: poll failed errno=%d\n", errno);
            break;
        }

        if (pfd[NET_EVENT_STOP].revents & POLLIN) {
            net_event_clear(&vmnet->stop_event);
            break;
        }

        if (pfd[NET_EVENT_TX].revents & POLLIN) {
            int packets;

            net_event_clear(&vmnet->tx_event);
            packets = network_tx_popv(vmnet->card, vmnet->pktv, VMNET_PKT_BATCH);

            if (!(net_cards_conf[vmnet->card->card_num].link_state & NET_LINK_DOWN)) {
                for (int i = 0; i < packets; i++) {
		    size_t len = (size_t)vmnet->pktv[i].len;

		    if (len < 60) {
			memset(vmnet->pktv[i].data+len,0,60-len);
			len = 60;
		    }

    		    vmnet_log("VMNET: TX len=%zu dst=%02x:%02x:%02x:%02x:%02x:%02x\n",
        		len,
        		vmnet->pktv[i].data[0],
        		vmnet->pktv[i].data[1],
        		vmnet->pktv[i].data[2],
        		vmnet->pktv[i].data[3],
        		vmnet->pktv[i].data[4],
        		vmnet->pktv[i].data[5]);

                    int rc = vmnet_helper_send_frame(vmnet->sock_fd,
                                                     vmnet->pktv[i].data,
                                                     len);
                    if (rc < 0)
                        vmnet_log("VMNET: helper send_frame failed rc=%d len=%zu\n",
                                  rc, len);
                }
            }
        }

        if (pfd[NET_EVENT_MAX].revents & (POLLIN | POLLPRI)) {
            if (vmnet_handle_socket_readable(vmnet) < 0) {
                vmnet_log("VMNET: helper socket read failed\n");
                break;
            }
        }

        if (pfd[NET_EVENT_MAX].revents & (POLLERR | POLLHUP | POLLNVAL)) {
            vmnet_log("VMNET: helper socket hangup/error revents=0x%x\n",
                      pfd[NET_EVENT_MAX].revents);
            break;
        }
    }

    vmnet_log("VMNET: polling stopped\n");
}

void
net_vmnet_in_available(void *priv)
{
    net_vmnet_t *vmnet = (net_vmnet_t *) priv;
    net_event_set(&vmnet->tx_event);
}

void *
net_vmnet_init(const netcard_t *card, const uint8_t *mac_addr, void *priv, char *netdrv_errbuf)
{
    net_vmnet_t *vmnet = calloc(1, sizeof(net_vmnet_t));
    int          rc;
    const char  *mode_spec   = (const char *) priv;
    const char  *host_ifname = NULL;
    const char  *guest_ip    = NULL;

    if (card != NULL) {
        host_ifname = net_cards_conf[card->card_num].host_dev_name;
        guest_ip    = net_cards_conf[card->card_num].vmnet_guest_ip;
    }

    pclog("VMNET INIT: mode='%s' host_if='%s'\n",
          mode_spec ? mode_spec : "(null)",
          (host_ifname && *host_ifname) ? host_ifname : "(none)");

    vmnet_log("VMNET: net_vmnet_init entered priv=%s host_if=%s\n",
              mode_spec ? mode_spec : "(null)",
              (host_ifname && *host_ifname) ? host_ifname : "(none)");

    if (vmnet == NULL) {
        net_vmnet_error(netdrv_errbuf, "vmnet allocation failed");
        return NULL;
    }

    vmnet->sock_fd = -1;
    vmnet->card    = (netcard_t *) card;
    memcpy(vmnet->mac_addr, mac_addr, sizeof(vmnet->mac_addr));

    for (int i = 0; i < VMNET_PKT_BATCH; i++) {
        vmnet->pktv[i].data = calloc(1, NET_MAX_FRAME);
        if (vmnet->pktv[i].data == NULL) {
            net_vmnet_error(netdrv_errbuf, "vmnet TX packet allocation failed");
            for (int j = 0; j < i; j++)
                free(vmnet->pktv[j].data);
            free(vmnet);
            return NULL;
        }
    }

    vmnet->pkt.data = calloc(1, NET_MAX_FRAME);
    if (vmnet->pkt.data == NULL) {
        net_vmnet_error(netdrv_errbuf, "vmnet RX packet allocation failed");
        for (int i = 0; i < VMNET_PKT_BATCH; i++)
            free(vmnet->pktv[i].data);
        free(vmnet);
        return NULL;
    }

    net_event_init(&vmnet->tx_event);
    net_event_init(&vmnet->stop_event);

    vmnet_log("VMNET: connecting to helper socket %s\n", VMN_SOCK_PATH);
    vmnet->sock_fd = vmnet_connect_socket();
    if (vmnet->sock_fd < 0) {
        net_vmnet_error(netdrv_errbuf,
                        "failed to connect to vmnet helper; start the helper first");
        net_event_close(&vmnet->tx_event);
        net_event_close(&vmnet->stop_event);
        for (int i = 0; i < VMNET_PKT_BATCH; i++)
            free(vmnet->pktv[i].data);
        free(vmnet->pkt.data);
        free(vmnet);
        return NULL;
    }

    rc = vmnet_helper_start(vmnet->sock_fd, mode_spec, host_ifname, guest_ip);
    vmnet_log("VMNET: vmnet_helper_start rc=%d\n", rc);
    if (rc != 0) {
        char buf[NET_DRV_ERRBUF_SIZE];
        snprintf(buf, sizeof(buf), "vmnet helper start failed: %d", rc);
        net_vmnet_error(netdrv_errbuf, buf);

        close(vmnet->sock_fd);
        net_event_close(&vmnet->tx_event);
        net_event_close(&vmnet->stop_event);
        for (int i = 0; i < VMNET_PKT_BATCH; i++)
            free(vmnet->pktv[i].data);
        free(vmnet->pkt.data);
        free(vmnet);
        return NULL;
    }

    vmnet->poll_tid = thread_create(net_vmnet_thread, vmnet);

    vmnet_log("VMNET: initialized for card %d, MAC=%02x:%02x:%02x:%02x:%02x:%02x\n",
              vmnet->card->card_num,
              mac_addr[0], mac_addr[1], mac_addr[2],
              mac_addr[3], mac_addr[4], mac_addr[5]);

    return vmnet;
}

void
net_vmnet_close(void *priv)
{
    net_vmnet_t *vmnet = (net_vmnet_t *) priv;

    if (!vmnet)
        return;

    vmnet_log("VMNET: closing\n");

    net_event_set(&vmnet->stop_event);

    vmnet_log("VMNET: waiting for thread to end...\n");
    thread_wait(vmnet->poll_tid);
    vmnet_log("VMNET: thread ended\n");

    if (vmnet->sock_fd >= 0) {
        int rc = vmnet_helper_stop(vmnet->sock_fd);
        vmnet_log("VMNET: vmnet_helper_stop rc=%d\n", rc);
        close(vmnet->sock_fd);
        vmnet->sock_fd = -1;
    }

    net_event_close(&vmnet->tx_event);
    net_event_close(&vmnet->stop_event);

    for (int i = 0; i < VMNET_PKT_BATCH; i++)
        free(vmnet->pktv[i].data);
    free(vmnet->pkt.data);

    free(vmnet);
}

int
net_vmnet_prepare(netdev_t *list)
{
    vmnet_log("VMNET: net_vmnet_prepare entered\n");

#ifdef __APPLE__
    memset(list, 0, sizeof(netdev_t));

    strncpy(list->device, "vmnet-shared", sizeof(list->device) - 1);
    strncpy(list->description, "Apple vmnet", sizeof(list->description) - 1);

    return 1;
#else
    (void) list;
    return 0;
#endif
}

const netdrv_t net_vmnet_drv = {
    .notify_in = &net_vmnet_in_available,
    .init      = &net_vmnet_init,
    .close     = &net_vmnet_close,
    .priv      = NULL
};
