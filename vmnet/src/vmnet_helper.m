#include <dispatch/dispatch.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>
#include <xpc/xpc.h>
#include <vmnet/vmnet.h>

#include "vmnet_proto.h"

enum {
    HELPER_MAX_FRAME = 4096,
    HELPER_DRAIN_LIMIT = 64
};

typedef struct {
    interface_ref iface;
    dispatch_queue_t queue;
    dispatch_semaphore_t start_sema;
    dispatch_semaphore_t event_sema;
    dispatch_semaphore_t stop_sema;
    vmnet_return_t start_status;
    vmnet_return_t stop_status;
    bool stopping;
    bool published_active;
    char published_iface[32];
    char published_ip[INET_ADDRSTRLEN];
    char guest_ip[INET_ADDRSTRLEN];
} helper_vmnet_t;

#define HELPER_PF_ANCHOR "com.macbox.vmnethelper"
#define HELPER_PF_RULES  "/tmp/com.macbox.vmnethelper.pf"

typedef enum {
    HELPER_LOG_ERROR = 0,
    HELPER_LOG_INFO  = 1,
    HELPER_LOG_DEBUG = 2
} helper_log_level_t;

static helper_log_level_t helper_log_level(void)
{
    const char *env = getenv("VMNET_HELPER_LOG");
    if (!env || !*env) return HELPER_LOG_INFO;
    if (strcmp(env, "0") == 0 || strcasecmp(env, "error") == 0) return HELPER_LOG_ERROR;
    if (strcmp(env, "2") == 0 || strcasecmp(env, "debug") == 0 || strcasecmp(env, "trace") == 0) return HELPER_LOG_DEBUG;
    return HELPER_LOG_INFO;
}

static int helper_should_log(helper_log_level_t level)
{
    return level <= helper_log_level();
}

static int vmnet_setup_published(helper_vmnet_t *s, uint32_t published_ip);
static void vmnet_cleanup_published(helper_vmnet_t *s);

static void log_line_level(helper_log_level_t level, const char *fmt, ...)
{
    va_list ap;
    FILE *fp;
    if (!helper_should_log(level)) return;
    fp = fopen("/tmp/vmnet-helper.log", "a");
    if (!fp) return;
    fprintf(fp, "[%ld] ", (long)getpid());
    va_start(ap, fmt);
    vfprintf(fp, fmt, ap);
    va_end(ap);
    fflush(fp);
    fclose(fp);
}

#define log_error(...) log_line_level(HELPER_LOG_ERROR, __VA_ARGS__)
#define log_info(...)  log_line_level(HELPER_LOG_INFO, __VA_ARGS__)
#define log_debug(...) log_line_level(HELPER_LOG_DEBUG, __VA_ARGS__)

static int write_full(int fd, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n <= 0) return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static int read_full(int fd, void *buf, size_t len)
{
    uint8_t *p = (uint8_t *)buf;
    while (len > 0) {
        ssize_t n = read(fd, p, len);
        if (n <= 0) return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static int send_msg(int fd, uint32_t type, const void *payload, uint32_t length)
{
    vmn_msg_hdr_t hdr;
    hdr.type = type;
    hdr.length = length;
    if (write_full(fd, &hdr, sizeof(hdr)) < 0) return -1;
    if (length && payload) {
        if (write_full(fd, payload, length) < 0) return -1;
    }
    return 0;
}

static void helper_vmnet_init(helper_vmnet_t *s)
{
    s->iface = NULL;
    s->queue = NULL;
    s->start_sema = NULL;
    s->event_sema = NULL;
    s->stop_sema = NULL;
    s->start_status = VMNET_FAILURE;
    s->stop_status = VMNET_FAILURE;
    s->stopping = false;
    s->published_active = false;
    s->published_iface[0] = 0;
    s->published_ip[0] = 0;
    s->guest_ip[0] = 0;
}

static int run_cmd(const char *cmd)
{
    int rc;
    log_debug("HELPER: cmd: %s\n", cmd);
    rc = system(cmd);
    if (rc != 0)
        log_error("HELPER: cmd failed rc=%d cmd=%s\n", rc, cmd);
    else
        log_debug("HELPER: cmd rc=%d\n", rc);
    return rc;
}

static int read_cmd_first_line(const char *cmd, char *buf, size_t buf_size)
{
    FILE *fp;
    size_t len;

    if (!buf || buf_size == 0)
        return -1;

    buf[0] = 0;
    fp = popen(cmd, "r");
    if (!fp)
        return -1;

    if (!fgets(buf, (int)buf_size, fp)) {
        pclose(fp);
        buf[0] = 0;
        return -1;
    }

    pclose(fp);
    len = strlen(buf);
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r' ||
                        buf[len - 1] == ' ' || buf[len - 1] == '\t')) {
        buf[--len] = 0;
    }
    return (len > 0) ? 0 : -1;
}

static int detect_default_interface(char *buf, size_t buf_size)
{
    int rc = read_cmd_first_line(
        "/sbin/route -n get default 2>/dev/null | /usr/bin/awk '/interface:/{print $2; exit}'",
        buf,
        buf_size
    );
    if (rc == 0)
        log_info("HELPER: default interface=%s\n", buf);
    else
        log_error("HELPER: unable to detect default interface\n");
    return rc;
}

static void helper_set_guest_ip(helper_vmnet_t *s, const char *guest_ip)
{
    struct in_addr addr;

    if (!s)
        return;

    s->guest_ip[0] = 0;
    if ((guest_ip == NULL) || (*guest_ip == '\0')) {
        log_info("HELPER: no guest_ip supplied by client\n");
        return;
    }

    if (inet_pton(AF_INET, guest_ip, &addr) != 1) {
        log_error("HELPER: invalid guest_ip from client: %s\n", guest_ip);
        return;
    }

    strncpy(s->guest_ip, guest_ip, sizeof(s->guest_ip) - 1);
    s->guest_ip[sizeof(s->guest_ip) - 1] = '\0';
    log_info("HELPER: guest_ip from client=%s\n", s->guest_ip);
}

static void vmnet_stop_sync(helper_vmnet_t *s)
{
    if (!s || !s->iface) return;

    s->stopping = true;
    s->stop_status = VMNET_FAILURE;
    log_info("HELPER: stopping vmnet interface\n");
    vmnet_stop_interface(s->iface, s->queue, ^(vmnet_return_t status) {
        s->stop_status = status;
        if (status != VMNET_SUCCESS)
            log_error("HELPER: stop callback status=%d\n", (int)status);
        else
            log_debug("HELPER: stop callback status=%d\n", (int)status);
        dispatch_semaphore_signal(s->stop_sema);
    });

    (void)dispatch_semaphore_wait(
        s->stop_sema,
        dispatch_time(DISPATCH_TIME_NOW, 5LL * NSEC_PER_SEC)
    );

    s->iface = NULL;
}

static int vmnet_start_with_mode(helper_vmnet_t *s, uint64_t mode)
{
    helper_vmnet_init(s);
    s->queue = dispatch_queue_create("vmnet-helper.queue", DISPATCH_QUEUE_SERIAL);
    s->start_sema = dispatch_semaphore_create(0);
    s->event_sema = dispatch_semaphore_create(0);
    s->stop_sema = dispatch_semaphore_create(0);

    xpc_object_t desc = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64(desc, vmnet_operation_mode_key, mode);

    char *desc_txt = xpc_copy_description(desc);
    if (desc_txt) {
        log_debug("HELPER: start descriptor=%s\n", desc_txt);
        free(desc_txt);
    }

    log_info("HELPER: calling vmnet_start_interface() mode=%llu\n", (unsigned long long)mode);
    s->iface = vmnet_start_interface(desc, s->queue, ^(vmnet_return_t status, xpc_object_t params) {
        s->start_status = status;
        if (status == VMNET_SUCCESS)
            log_info("HELPER: start callback status=%d\n", (int)status);
        else
            log_error("HELPER: start callback status=%d\n", (int)status);
        if (params) {
            char *params_txt = xpc_copy_description(params);
            if (params_txt) {
                log_debug("HELPER: start callback params=%s\n", params_txt);
                free(params_txt);
            }
        } else {
            log_debug("HELPER: start callback params=NULL\n");
        }
        dispatch_semaphore_signal(s->start_sema);
    });

    if (!s->iface) {
        log_error("HELPER: vmnet_start_interface returned NULL\n");
        return -2;
    }

    long wait_rc = dispatch_semaphore_wait(
        s->start_sema,
        dispatch_time(DISPATCH_TIME_NOW, 5LL * NSEC_PER_SEC)
    );
    if (wait_rc == 0 && s->start_status == VMNET_SUCCESS)
        log_info("HELPER: vmnet interface started successfully\n");
    else
        log_error("HELPER: start wait_rc=%ld start_status=%d\n", wait_rc, (int)s->start_status);

    if (wait_rc != 0) {
        vmnet_stop_sync(s);
        return -3;
    }
    if (s->start_status != VMNET_SUCCESS) {
        vmnet_stop_sync(s);
        return -4;
    }

    log_debug("HELPER: installing packets-available callback\n");
    vmnet_interface_set_event_callback(
        s->iface,
        VMNET_INTERFACE_PACKETS_AVAILABLE,
        s->queue,
        ^(interface_event_t event_id, xpc_object_t event) {
            (void)event_id;
            (void)event;
            if (!s->stopping && s->event_sema) {
                dispatch_semaphore_signal(s->event_sema);
            }
        }
    );
    return 0;
}

static int vmnet_start_shared(helper_vmnet_t *s)
{
    return vmnet_start_with_mode(s, VMNET_SHARED_MODE);
}

static int vmnet_start_host(helper_vmnet_t *s)
{
	(void)s;
#ifdef VMNET_HOST_MODE
    return vmnet_start_with_mode(s, VMNET_HOST_MODE);
#else
    log_info("HELPER: VMNET_HOST_MODE not available in this SDK");
    return -97;
#endif
}

static int vmnet_start_bridged(helper_vmnet_t *s)
{
	(void)s;
#ifdef VMNET_BRIDGED_MODE
    return vmnet_start_with_mode(s, VMNET_BRIDGED_MODE);
#else
    log_info("HELPER: VMNET_BRIDGED_MODE not available in this SDK");
    return -96;
#endif
}

static void vmnet_cleanup_published(helper_vmnet_t *s)
{
    char cmd[512];

    if (!s)
        return;

    run_cmd("/sbin/pfctl -a " HELPER_PF_ANCHOR " -F all >/dev/null 2>&1");
    unlink(HELPER_PF_RULES);

    if (s->published_iface[0] && s->published_ip[0]) {
        snprintf(cmd, sizeof(cmd),
                 "/sbin/ifconfig %s -alias %s >/dev/null 2>&1",
                 s->published_iface, s->published_ip);
        run_cmd(cmd);
    }

    s->published_active = false;
    s->published_iface[0] = 0;
    s->published_ip[0] = 0;
}

static int vmnet_setup_published(helper_vmnet_t *s, uint32_t published_ip)
{
    char ipbuf[INET_ADDRSTRLEN];
    char iface[32];
    char cmd[1024];
    FILE *fp;
    struct in_addr addr;

    if (!s) {
        log_error("HELPER: published mode requested with NULL state\n");
        return -95;
    }

    addr.s_addr = published_ip;
    if (published_ip == 0 || inet_ntop(AF_INET, &addr, ipbuf, sizeof(ipbuf)) == NULL) {
        log_error("HELPER: published mode requested but no valid published_ip supplied\n");
        return -95;
    }

    if (detect_default_interface(iface, sizeof(iface)) != 0) {
        log_error("HELPER: unable to detect default interface for published mode\n");
        return -94;
    }

    snprintf(s->published_iface, sizeof(s->published_iface), "%s", iface);
    snprintf(s->published_ip, sizeof(s->published_ip), "%s", ipbuf);

    snprintf(cmd, sizeof(cmd),
             "/sbin/ifconfig %s alias %s netmask 255.255.255.0",
             s->published_iface, s->published_ip);
    if (run_cmd(cmd) != 0) {
        log_error("HELPER: failed to add alias %s on %s\n", s->published_ip, s->published_iface);
        vmnet_cleanup_published(s);
        return -93;
    }

    if (run_cmd("/usr/sbin/sysctl -w net.inet.ip.forwarding=1 >/dev/null 2>&1") != 0) {
        log_error("HELPER: failed to enable IPv4 forwarding\n");
        vmnet_cleanup_published(s);
        return -92;
    }

    fp = fopen(HELPER_PF_RULES, "w");
    if (!fp) {
        log_error("HELPER: failed to open PF rules file %s\n", HELPER_PF_RULES);
        vmnet_cleanup_published(s);
        return -91;
    }

    fprintf(fp,
            "rdr pass on %s inet proto icmp from any to %s -> %s\n"
            "rdr pass on %s inet proto tcp from any to %s -> %s\n"
            "rdr pass on %s inet proto udp from any to %s -> %s\n"
            "nat on %s inet from %s to any -> (%s)\n",
            s->published_iface, s->published_ip, s->guest_ip,
            s->published_iface, s->published_ip, s->guest_ip,
            s->published_iface, s->published_ip, s->guest_ip,
            s->published_iface, s->guest_ip, s->published_iface);
    fclose(fp);

    run_cmd("/sbin/pfctl -E >/dev/null 2>&1");
    snprintf(cmd, sizeof(cmd),
             "/sbin/pfctl -a %s -f %s >/dev/null 2>&1",
             HELPER_PF_ANCHOR, HELPER_PF_RULES);
    if (run_cmd(cmd) != 0) {
        log_error("HELPER: failed to load PF rules for published mode\n");
        vmnet_cleanup_published(s);
        return -90;
    }

    s->published_active = true;
    log_info("HELPER: published mode active iface=%s published_ip=%s guest_ip=%s\n",
             s->published_iface, s->published_ip, s->guest_ip);
    return 0;
}

static int vmnet_send_frame(helper_vmnet_t *s, const uint8_t *frame, size_t len)
{
    struct iovec iov;
    iov.iov_base = (void *)frame;
    iov.iov_len = len;

    struct vmpktdesc pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.vm_pkt_iov = &iov;
    pkt.vm_pkt_iovcnt = 1;
    pkt.vm_pkt_size = len;

    int pkt_count = 1;
    vmnet_return_t rc = vmnet_write(s->iface, &pkt, &pkt_count);
    if (rc != VMNET_SUCCESS) {
        log_error("HELPER: vmnet_write rc=%d pkt_count=%d len=%zu\n", (int)rc, pkt_count, len);
        return -1;
    }
    return pkt_count;
}

static int vmnet_read_one(helper_vmnet_t *s, uint8_t *buf, size_t buf_size, size_t *out_len)
{
    struct iovec iov;
    iov.iov_base = buf;
    iov.iov_len = buf_size;

    struct vmpktdesc pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.vm_pkt_iov = &iov;
    pkt.vm_pkt_iovcnt = 1;
    pkt.vm_pkt_size = buf_size;

    int pkt_count = 1;
    vmnet_return_t rc = vmnet_read(s->iface, &pkt, &pkt_count);
    if (rc != VMNET_SUCCESS) {
        log_error("HELPER: vmnet_read rc=%d pkt_count=%d\n", (int)rc, pkt_count);
        return -1;
    }
    if (pkt_count <= 0) {
        *out_len = 0;
        return 0;
    }
    *out_len = (size_t)pkt.vm_pkt_size;
    return 1;
}

static int drain_vmnet(helper_vmnet_t *s, int fd)
{
    while (dispatch_semaphore_wait(s->event_sema, DISPATCH_TIME_NOW) == 0) {
        for (int i = 0; i < HELPER_DRAIN_LIMIT; i++) {
            uint8_t buf[HELPER_MAX_FRAME];
            size_t len = 0;
            int rc = vmnet_read_one(s, buf, sizeof(buf), &len);
            if (rc < 0) return -1;
            if (rc == 0) break;
            if (send_msg(fd, VMN_MSG_RX_FRAME, buf, (uint32_t)len) < 0) return -1;
        }
    }
    return 0;
}

static int make_server_socket(void)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, VMN_SOCK_PATH, sizeof(addr.sun_path) - 1);

    unlink(VMN_SOCK_PATH);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    chmod(VMN_SOCK_PATH, 0666);

    if (listen(fd, 8) < 0) {
        close(fd);
        unlink(VMN_SOCK_PATH);
        return -1;
    }

    return fd;
}

static void handle_client_session(int fd)
{
    helper_vmnet_t vmnet;
    helper_vmnet_init(&vmnet);

    bool running = true;
    bool started = false;

    log_info("HELPER: client connected\n");

    while (running) {
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;

        int prc = poll(&pfd, 1, 10);
        if (prc < 0) {
            log_error("HELPER: poll failed\n");
            break;
        }

        if (started) {
            if (drain_vmnet(&vmnet, fd) < 0) {
                log_error("HELPER: drain_vmnet failed\n");
                break;
            }
        }

        if (prc == 0) {
            continue;
        }

        vmn_msg_hdr_t hdr;
        if (read_full(fd, &hdr, sizeof(hdr)) < 0) {
            log_info("HELPER: peer closed connection\n");
            break;
        }

        if (hdr.type == VMN_MSG_START) {
            vmn_start_req_t req;
            uint8_t old_req[8];
            memset(&req, 0, sizeof(req));

            if (hdr.length == sizeof(req)) {
                if (read_full(fd, &req, sizeof(req)) < 0) {
                    log_error("HELPER: failed to read full START payload (%zu bytes)\n", sizeof(req));
                    break;
                }
            } else if (hdr.length == sizeof(old_req)) {
                if (read_full(fd, old_req, sizeof(old_req)) < 0) {
                    log_error("HELPER: failed to read legacy START payload (%zu bytes)\n", sizeof(old_req));
                    break;
                }
                memcpy(&req.mode, old_req, sizeof(old_req));
                req.guest_ip[0] = '\0';
                log_info("HELPER: accepted legacy START payload hdr.length=%u\n", hdr.length);
            } else {
                log_error("HELPER: bad START payload hdr.length=%u expected=%zu or %zu\n",
                          hdr.length, sizeof(req), sizeof(old_req));
                break;
            }
            {
                struct in_addr dbg_pub_addr;
                char dbg_pub_ip[INET_ADDRSTRLEN];
                dbg_pub_addr.s_addr = req.published_ip;
                dbg_pub_ip[0] = 0;
                if (req.published_ip != 0) {
                    if (inet_ntop(AF_INET, &dbg_pub_addr, dbg_pub_ip, sizeof(dbg_pub_ip)) == NULL)
                        snprintf(dbg_pub_ip, sizeof(dbg_pub_ip), "<inet_ntop failed>");
                } else {
                    snprintf(dbg_pub_ip, sizeof(dbg_pub_ip), "<none>");
                }
                log_info("HELPER: START req.mode=%u published_ip=0x%08x (%s) guest_ip=%s\n",
                         req.mode, req.published_ip, dbg_pub_ip,
                         req.guest_ip[0] ? req.guest_ip : "<none>");
                log_debug("HELPER: mode constants shared=%u host=%u bridged=%u published=%u\n",
                         (unsigned)VMN_MODE_SHARED,
                         (unsigned)VMN_MODE_HOST,
                         (unsigned)VMN_MODE_BRIDGED,
                         (unsigned)VMN_MODE_PUBLISHED);
            }

            helper_set_guest_ip(&vmnet, req.guest_ip);

            int rc = -99;
            switch (req.mode) {
                case VMN_MODE_SHARED:
                    log_info("HELPER: starting shared mode\n");
                    rc = vmnet_start_shared(&vmnet);
                    break;
                case VMN_MODE_HOST:
                    log_info("HELPER: starting host mode\n");
                    rc = vmnet_start_host(&vmnet);
                    break;
                case VMN_MODE_BRIDGED:
                    log_info("HELPER: starting bridged mode\n");
                    rc = vmnet_start_bridged(&vmnet);
                    break;
                case VMN_MODE_PUBLISHED: {
                    int prc;
                    log_info("HELPER: starting published mode\n");

                    rc = vmnet_start_shared(&vmnet);
                    if (rc == 0)
                        log_info("HELPER: shared mode ready\n");
                    else
                        log_error("HELPER: shared mode start failed rc=%d\n", rc);

                    if (rc != 0) {
                        log_error("HELPER: shared start failed\n");
                        break;
                    }

                    prc = vmnet_setup_published(&vmnet, req.published_ip);
                    if (prc == 0) {
                        log_info("HELPER: published mode ready iface=%s pub_ip=%s guest_ip=%s\n",
                                 vmnet.published_iface[0] ? vmnet.published_iface : "<none>",
                                 vmnet.published_ip[0] ? vmnet.published_ip : "<none>",
                                 vmnet.guest_ip[0] ? vmnet.guest_ip : "<none>");
                    } else {
                        log_error("HELPER: published setup failed rc=%d; continuing with shared vmnet only\n", prc);
                    }

                    /* IMPORTANT: keep rc = 0 */
                    rc = 0;
                    break;
                }

                default:
                    log_error("HELPER: unknown mode %u\n", req.mode);
                    rc = -98;
                    break;
            }
            if (rc == 0)
                log_info("HELPER: session started mode=%u\n", req.mode);
            else
                log_error("HELPER: start failed rc=%d mode=%u\n", rc, req.mode);

            if (rc == 0) {
                started = true;
                log_debug("HELPER: sending START_OK\n");
                send_msg(fd, VMN_MSG_START_OK, NULL, 0);
            } else {
                log_error("HELPER: sending START_ERR code=%d\n", rc);
                if (vmnet.iface)
                    vmnet_stop_sync(&vmnet);
                vmn_start_err_t err;
                err.code = rc;
                send_msg(fd, VMN_MSG_START_ERR, &err, sizeof(err));
            }
        } else if (hdr.type == VMN_MSG_SEND_FRAME) {
            if (!started || hdr.length == 0 || hdr.length > HELPER_MAX_FRAME) {
                if (hdr.length) {
                    uint8_t scratch[4096];
                    size_t remaining = hdr.length;
                    while (remaining > 0) {
                        size_t chunk = remaining > sizeof(scratch) ? sizeof(scratch) : remaining;
                        if (read_full(fd, scratch, chunk) < 0) break;
                        remaining -= chunk;
                    }
                }
                continue;
            }

            uint8_t buf[HELPER_MAX_FRAME];
            if (read_full(fd, buf, hdr.length) < 0) break;
            vmnet_send_frame(&vmnet, buf, hdr.length);
        } else if (hdr.type == VMN_MSG_STOP) {
            if (hdr.length) {
                uint8_t scratch[256];
                size_t remaining = hdr.length;
                while (remaining > 0) {
                    size_t chunk = remaining > sizeof(scratch) ? sizeof(scratch) : remaining;
                    if (read_full(fd, scratch, chunk) < 0) break;
                    remaining -= chunk;
                }
            }
            send_msg(fd, VMN_MSG_STOPPED, NULL, 0);
            running = false;
        } else {
            if (hdr.length) {
                uint8_t scratch[4096];
                size_t remaining = hdr.length;
                while (remaining > 0) {
                    size_t chunk = remaining > sizeof(scratch) ? sizeof(scratch) : remaining;
                    if (read_full(fd, scratch, chunk) < 0) break;
                    remaining -= chunk;
                }
            }
            log_error("HELPER: unknown msg type=%u\n", hdr.type);
        }
    }

    if (vmnet.published_active) {
        log_info("HELPER: cleaning up published state\n");
        vmnet_cleanup_published(&vmnet);
    }

    if (started) {
        log_info("HELPER: stopping vmnet session\n");
        vmnet_stop_sync(&vmnet);
    }

    close(fd);
    log_info("HELPER: client disconnected\n");
}

int main(void)
{
    log_info("HELPER: starting server on %s\n", VMN_SOCK_PATH);

    int listen_fd = make_server_socket();
    if (listen_fd < 0) {
        log_error("HELPER: failed to create listen socket\n");
        return 1;
    }

    for (;;) {
        int fd = accept(listen_fd, NULL, NULL);
        if (fd < 0) {
            log_error("HELPER: accept failed\n");
            sleep(1);
            continue;
        }

        handle_client_session(fd);
    }

    return 0;
}
