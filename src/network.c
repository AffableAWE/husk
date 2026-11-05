/* Optional privileged bridge networking over rtnetlink.
 *
 * The default remains the isolated network namespace created by clone. Bridge
 * mode requires an explicit bridge, container address, gateway, and lease
 * directory. The parent creates a veth pair, attaches the host end to the
 * existing bridge, moves the peer into the child netns, and records an
 * address lease. The child configures eth0, loopback, and the default route.
 * Cleanup deletes only the veth it created and its own lease file.
 */
#define _GNU_SOURCE

#include "husk.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <linux/if.h>
#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

extern unsigned int if_nametoindex(const char *ifname);

#ifndef VETH_INFO_PEER
#define VETH_INFO_PEER 1
#endif

static void set_err(char *err, size_t errlen, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static void set_err(char *err, size_t errlen, const char *fmt, ...)
{
    va_list ap;

    if (err == NULL || errlen == 0)
        return;
    va_start(ap, fmt);
    (void)vsnprintf(err, errlen, fmt, ap);
    va_end(ap);
}

static unsigned long long proc_starttime(pid_t pid)
{
    char path[64];
    char buf[4096];
    char *after;
    char *tok;
    int fd;
    int i;
    ssize_t n;

    (void)snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 0;
    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0)
        return 0;
    buf[n] = '\0';
    after = strrchr(buf, ')');
    if (after == NULL)
        return 0;
    tok = strtok(after + 1, " ");
    for (i = 0; tok != NULL && i < 19; i++)
        tok = strtok(NULL, " ");
    return tok != NULL ? strtoull(tok, NULL, 10) : 0;
}

static int owner_alive(pid_t pid, unsigned long long start)
{
    return pid > 1 && start > 0 && proc_starttime(pid) == start;
}

/* ---- rtnetlink helpers -------------------------------------------------- */

static int nl_open(char *err, size_t errlen)
{
    struct sockaddr_nl sa;
    int fd;

    fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) {
        set_err(err, errlen, "netlink socket: %s", strerror(errno));
        return -1;
    }
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        set_err(err, errlen, "bind netlink: %s", strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

static int addattr_l(struct nlmsghdr *n, size_t maxlen, int type,
                     const void *data, size_t alen)
{
    size_t len = RTA_LENGTH(alen);
    size_t newlen = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
    struct rtattr *rta;

    if (newlen > maxlen)
        return -1;
    rta = (struct rtattr *)((char *)n + NLMSG_ALIGN(n->nlmsg_len));
    rta->rta_type = (unsigned short)type;
    rta->rta_len = (unsigned short)len;
    if (alen != 0)
        memcpy(RTA_DATA(rta), data, alen);
    n->nlmsg_len = newlen;
    return 0;
}

static struct rtattr *addattr_nest(struct nlmsghdr *n, size_t maxlen, int type)
{
    struct rtattr *nest = (struct rtattr *)((char *)n + NLMSG_ALIGN(n->nlmsg_len));

    if (addattr_l(n, maxlen, type, NULL, 0) < 0)
        return NULL;
    return nest;
}

static void addattr_nest_end(struct nlmsghdr *n, struct rtattr *nest)
{
    nest->rta_len = (unsigned short)((char *)n + NLMSG_ALIGN(n->nlmsg_len) -
                                     (char *)nest);
}

static int nl_talk(int fd, struct nlmsghdr *n, char *err, size_t errlen)
{
    struct sockaddr_nl sa;
    struct iovec iov;
    struct msghdr msg;
    char buf[8192];

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    memset(&iov, 0, sizeof(iov));
    iov.iov_base = n;
    iov.iov_len = n->nlmsg_len;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &sa;
    msg.msg_namelen = sizeof(sa);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    if (sendmsg(fd, &msg, 0) < 0) {
        set_err(err, errlen, "netlink send: %s", strerror(errno));
        return -1;
    }
    for (;;) {
        ssize_t r = recv(fd, buf, sizeof(buf), 0);
        struct nlmsghdr *h;

        if (r < 0) {
            if (errno == EINTR)
                continue;
            set_err(err, errlen, "netlink recv: %s", strerror(errno));
            return -1;
        }
        for (h = (struct nlmsghdr *)buf; NLMSG_OK(h, (unsigned int)r);
             h = NLMSG_NEXT(h, r)) {
            if (h->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *e = NLMSG_DATA(h);

                if (e->error == 0)
                    return 0;
                set_err(err, errlen, "netlink: %s", strerror(-e->error));
                return -1;
            }
            if (h->nlmsg_type == NLMSG_DONE)
                return 0;
        }
    }
}

struct link_req {
    struct nlmsghdr n;
    struct ifinfomsg i;
    char buf[1024];
};

struct addr_req {
    struct nlmsghdr n;
    struct ifaddrmsg i;
    char buf[1024];
};

struct route_req {
    struct nlmsghdr n;
    struct rtmsg i;
    char buf[1024];
};

static int create_veth(int fd, const char *host, const char *peer, char *err,
                       size_t errlen)
{
    struct link_req req;
    struct rtattr *linkinfo;
    struct rtattr *infodata;
    struct rtattr *peerattr;
    struct ifinfomsg *pifi;
    size_t maxlen = sizeof(req);

    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.i));
    req.n.nlmsg_type = RTM_NEWLINK;
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    req.i.ifi_family = AF_UNSPEC;
    if (addattr_l(&req.n, maxlen, IFLA_IFNAME, host, strlen(host) + 1) < 0)
        return -1;
    linkinfo = addattr_nest(&req.n, maxlen, IFLA_LINKINFO);
    if (linkinfo == NULL ||
        addattr_l(&req.n, maxlen, IFLA_INFO_KIND, "veth", 5) < 0)
        return -1;
    infodata = addattr_nest(&req.n, maxlen, IFLA_INFO_DATA);
    if (infodata == NULL)
        return -1;
    peerattr = addattr_nest(&req.n, maxlen, VETH_INFO_PEER);
    if (peerattr == NULL)
        return -1;
    if (NLMSG_ALIGN(req.n.nlmsg_len) + NLMSG_ALIGN(sizeof(*pifi)) > maxlen)
        return -1;
    pifi = (struct ifinfomsg *)((char *)&req.n + NLMSG_ALIGN(req.n.nlmsg_len));
    memset(pifi, 0, sizeof(*pifi));
    pifi->ifi_family = AF_UNSPEC;
    req.n.nlmsg_len = NLMSG_ALIGN(req.n.nlmsg_len) + NLMSG_ALIGN(sizeof(*pifi));
    if (addattr_l(&req.n, maxlen, IFLA_IFNAME, peer, strlen(peer) + 1) < 0)
        return -1;
    addattr_nest_end(&req.n, peerattr);
    addattr_nest_end(&req.n, infodata);
    addattr_nest_end(&req.n, linkinfo);
    return nl_talk(fd, &req.n, err, errlen);
}

static int set_master(int fd, int ifindex, int master, char *err, size_t errlen)
{
    struct link_req req;

    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.i));
    req.n.nlmsg_type = RTM_SETLINK;
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.i.ifi_family = AF_UNSPEC;
    req.i.ifi_index = ifindex;
    if (addattr_l(&req.n, sizeof(req), IFLA_MASTER, &master, sizeof(master)) < 0)
        return -1;
    return nl_talk(fd, &req.n, err, errlen);
}

static int set_link_up(int fd, int ifindex, char *err, size_t errlen)
{
    struct link_req req;

    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.i));
    req.n.nlmsg_type = RTM_NEWLINK;
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.i.ifi_family = AF_UNSPEC;
    req.i.ifi_index = ifindex;
    req.i.ifi_flags = IFF_UP;
    req.i.ifi_change = IFF_UP;
    return nl_talk(fd, &req.n, err, errlen);
}

static int move_link(int fd, int ifindex, pid_t pid, char *err, size_t errlen)
{
    struct link_req req;
    int target = (int)pid;

    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.i));
    req.n.nlmsg_type = RTM_NEWLINK;
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.i.ifi_family = AF_UNSPEC;
    req.i.ifi_index = ifindex;
    if (addattr_l(&req.n, sizeof(req), IFLA_NET_NS_PID, &target,
                  sizeof(target)) < 0)
        return -1;
    return nl_talk(fd, &req.n, err, errlen);
}

static int delete_link(int fd, int ifindex, char *err, size_t errlen)
{
    struct link_req req;

    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.i));
    req.n.nlmsg_type = RTM_DELLINK;
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.i.ifi_family = AF_UNSPEC;
    req.i.ifi_index = ifindex;
    return nl_talk(fd, &req.n, err, errlen);
}

static int rename_link(int fd, int ifindex, const char *name, char *err,
                       size_t errlen)
{
    struct link_req req;

    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.i));
    req.n.nlmsg_type = RTM_NEWLINK;
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.i.ifi_family = AF_UNSPEC;
    req.i.ifi_index = ifindex;
    if (addattr_l(&req.n, sizeof(req), IFLA_IFNAME, name, strlen(name) + 1) < 0)
        return -1;
    return nl_talk(fd, &req.n, err, errlen);
}

static int add_address(int fd, int ifindex, unsigned int addr, int prefix,
                       char *err, size_t errlen)
{
    struct addr_req req;

    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.i));
    req.n.nlmsg_type = RTM_NEWADDR;
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE |
                        NLM_F_REPLACE;
    req.i.ifa_family = AF_INET;
    req.i.ifa_prefixlen = (unsigned char)prefix;
    req.i.ifa_scope = RT_SCOPE_UNIVERSE;
    req.i.ifa_index = (unsigned int)ifindex;
    if (addattr_l(&req.n, sizeof(req), IFA_LOCAL, &addr, sizeof(addr)) < 0 ||
        addattr_l(&req.n, sizeof(req), IFA_ADDRESS, &addr, sizeof(addr)) < 0)
        return -1;
    return nl_talk(fd, &req.n, err, errlen);
}

static int add_default_route(int fd, int ifindex, unsigned int gateway,
                             char *err, size_t errlen)
{
    struct route_req req;

    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.i));
    req.n.nlmsg_type = RTM_NEWROUTE;
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE |
                        NLM_F_REPLACE;
    req.i.rtm_family = AF_INET;
    req.i.rtm_table = RT_TABLE_MAIN;
    req.i.rtm_protocol = RTPROT_BOOT;
    req.i.rtm_scope = RT_SCOPE_UNIVERSE;
    req.i.rtm_type = RTN_UNICAST;
    req.i.rtm_dst_len = 0;
    if (addattr_l(&req.n, sizeof(req), RTA_GATEWAY, &gateway,
                  sizeof(gateway)) < 0 ||
        addattr_l(&req.n, sizeof(req), RTA_OIF, &ifindex, sizeof(ifindex)) < 0)
        return -1;
    return nl_talk(fd, &req.n, err, errlen);
}

/* ---- leases ------------------------------------------------------------- */

static int lease_name(const struct husk_config *cfg, char *name, size_t len)
{
    char addr[INET_ADDRSTRLEN];
    size_t i;

    if (inet_ntop(AF_INET, &cfg->container_addr, addr, sizeof(addr)) == NULL)
        return -1;
    if (snprintf(name, len, "%s_%d.lease", addr, cfg->container_prefix) >=
        (int)len)
        return -1;
    for (i = 0; name[i] != '\0'; i++) {
        if (name[i] == '/')
            name[i] = '_';
    }
    return 0;
}

static int lease_write(int fd, const struct husk_config *cfg, pid_t owner,
                       unsigned long long start)
{
    char buf[512];
    int n;

    n = snprintf(buf, sizeof(buf), "%ld %llu %s %d %s %s\n", (long)owner,
                 start, cfg->container_addr_text, cfg->container_prefix,
                 cfg->bridge, cfg->host_veth);
    if (n < 0 || (size_t)n >= sizeof(buf))
        return -1;
    if (ftruncate(fd, 0) < 0 || lseek(fd, 0, SEEK_SET) < 0)
        return -1;
    return write(fd, buf, (size_t)n) == n ? 0 : -1;
}

int husk_network_lease_acquire(struct husk_config *cfg, char *err,
                               size_t errlen)
{
    char name[128];
    char path[PATH_MAX];
    char buf[512];
    long pid = 0;
    unsigned long long start = 0;
    char addr[64];
    int prefix;
    char bridge[64];
    char veth[64];
    int fd;
    ssize_t n;

    if (!cfg->bridge_enabled)
        return 0;
    if (lease_name(cfg, name, sizeof(name)) < 0 ||
        snprintf(path, sizeof(path), "%s/%s", cfg->lease_dir, name) >=
            (int)sizeof(path)) {
        set_err(err, errlen, "lease path is too long");
        return -1;
    }
    fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0) {
        set_err(err, errlen, "open lease '%s': %s", path, strerror(errno));
        return -1;
    }
    if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
        if (errno == EWOULDBLOCK)
            set_err(err, errlen, "address %s is leased by a live container",
                    cfg->container_addr_text);
        else
            set_err(err, errlen, "lock lease '%s': %s", path, strerror(errno));
        close(fd);
        return -1;
    }
    memset(buf, 0, sizeof(buf));
    n = read(fd, buf, sizeof(buf) - 1);
    if (n > 0 &&
        sscanf(buf, "%ld %llu %63s %d %63s %63s", &pid, &start, addr, &prefix,
               bridge, veth) == 6) {
        if (owner_alive((pid_t)pid, start)) {
            set_err(err, errlen,
                    "address %s is owned by live process %ld; refusing reuse",
                    cfg->container_addr_text, pid);
            close(fd);
            return -1;
        }
        /* Stale lease: the previous owner is gone. Reuse the address. */
    }
    if (lease_write(fd, cfg, getpid(), proc_starttime(getpid())) < 0) {
        set_err(err, errlen, "write lease '%s': %s", path, strerror(errno));
        close(fd);
        return -1;
    }
    if (strlen(path) + 1 > sizeof(cfg->lease_path)) {
        set_err(err, errlen, "lease path is too long");
        close(fd);
        return -1;
    }
    strcpy(cfg->lease_path, path);
    cfg->lease_fd = fd;
    return 0;
}

static void lease_release(struct husk_config *cfg)
{
    if (cfg->lease_fd >= 0) {
        if (cfg->lease_path[0] != '\0')
            (void)unlink(cfg->lease_path);
        (void)close(cfg->lease_fd);
        cfg->lease_fd = -1;
        cfg->lease_path[0] = '\0';
    }
}

/* ---- validation and host setup ----------------------------------------- */

static int parse_cidr(const char *text, unsigned int *addr, int *prefix,
                      char *err, size_t errlen)
{
    char buf[64];
    char *slash;
    char *end;
    struct in_addr in;
    unsigned long p;

    if (strlen(text) + 1 > sizeof(buf)) {
        set_err(err, errlen, "container address is too long");
        return -1;
    }
    strcpy(buf, text);
    slash = strchr(buf, '/');
    if (slash == NULL) {
        set_err(err, errlen, "container address must be IPv4/PREFIX");
        return -1;
    }
    *slash = '\0';
    if (inet_pton(AF_INET, buf, &in) != 1) {
        set_err(err, errlen, "invalid container IPv4 address '%s'", buf);
        return -1;
    }
    errno = 0;
    p = strtoul(slash + 1, &end, 10);
    if (errno != 0 || end == slash + 1 || *end != '\0' || p < 1 || p > 32) {
        set_err(err, errlen, "invalid container prefix");
        return -1;
    }
    *addr = in.s_addr;
    *prefix = (int)p;
    return 0;
}

int husk_network_validate(struct husk_config *cfg, char *err, size_t errlen)
{
    struct in_addr gw;
    struct stat st;
    unsigned int mask;
    char check[PATH_MAX];

    if (!cfg->bridge_enabled)
        return 0;
    if (cfg->bridge == NULL || cfg->bridge[0] == '\0' ||
        strlen(cfg->bridge) >= IFNAMSIZ) {
        set_err(err, errlen, "invalid bridge name");
        return -1;
    }
    if (cfg->lease_dir == NULL || cfg->lease_dir[0] == '\0') {
        set_err(err, errlen, "--bridge requires --lease-dir");
        return -1;
    }
    if (stat(cfg->lease_dir, &st) < 0 || !S_ISDIR(st.st_mode)) {
        set_err(err, errlen, "invalid lease directory '%s': %s",
                cfg->lease_dir, strerror(errno));
        return -1;
    }
    if (access(cfg->lease_dir, W_OK | X_OK) < 0) {
        set_err(err, errlen, "lease directory '%s' is not writable: %s",
                cfg->lease_dir, strerror(errno));
        return -1;
    }
    if (if_nametoindex(cfg->bridge) == 0) {
        set_err(err, errlen, "bridge '%s' does not exist", cfg->bridge);
        return -1;
    }
    if (snprintf(check, sizeof(check), "/sys/class/net/%s/bridge",
                 cfg->bridge) >= (int)sizeof(check) ||
        access(check, F_OK) < 0) {
        set_err(err, errlen, "'%s' is not a Linux bridge", cfg->bridge);
        return -1;
    }
    if (parse_cidr(cfg->container_addr_text, &cfg->container_addr,
                   &cfg->container_prefix, err, errlen) < 0)
        return -1;
    if (cfg->gateway_text[0] == '\0' ||
        inet_pton(AF_INET, cfg->gateway_text, &gw) != 1) {
        set_err(err, errlen, "invalid gateway IPv4 address '%s'",
                cfg->gateway_text);
        return -1;
    }
    cfg->gateway_addr = gw.s_addr;
    mask = cfg->container_prefix == 32
               ? 0xffffffffU
               : (0xffffffffU << (32 - cfg->container_prefix));
    if ((ntohl(cfg->container_addr) & mask) !=
        (ntohl(cfg->gateway_addr) & mask)) {
        set_err(err, errlen, "gateway is not in the container subnet");
        return -1;
    }
    if (cfg->container_addr == cfg->gateway_addr) {
        set_err(err, errlen, "gateway must differ from the container address");
        return -1;
    }
    if ((ntohl(cfg->gateway_addr) >> 24) == 127 ||
        (ntohl(cfg->gateway_addr) >> 28) == 0xe) {
        set_err(err, errlen, "refusing loopback/multicast gateway");
        return -1;
    }
    {
        unsigned int a = ntohl(cfg->container_addr);
        unsigned int g = ntohl(cfg->gateway_addr);
        unsigned int maskh = cfg->container_prefix == 0
                                 ? 0
                                 : (0xffffffffU << (32 - cfg->container_prefix));

        if ((a >> 24) == 127 || (a >> 28) == 0xe) {
            set_err(err, errlen, "refusing loopback/multicast container address");
            return -1;
        }
        if (cfg->container_prefix < 31 &&
            ((a & ~maskh) == 0 || (a | maskh) == 0xffffffffU)) {
            set_err(err, errlen,
                    "container address is the network or broadcast address");
            return -1;
        }
        if (g == 0) {
            set_err(err, errlen, "gateway must not be 0.0.0.0");
            return -1;
        }
    }
    return 0;
}

int husk_network_parent_handshake(int ctrl_fd, pid_t child,
                                  struct husk_config *cfg, char *err,
                                  size_t errlen)
{
    struct husk_msg msg;
    struct pollfd pfd = {.fd = ctrl_fd, .events = POLLIN};
    int r;
    int fd;
    int host_idx;
    int peer_idx;
    int bridge_idx;
    int got;

    if (!cfg->bridge_enabled)
        return 0;
    r = poll(&pfd, 1, HUSK_MAP_TIMEOUT_MS);
    if (r <= 0) {
        set_err(err, errlen, "timed out waiting for network request");
        kill(child, SIGKILL);
        while (waitpid(child, NULL, 0) < 0 && errno == EINTR)
            ;
        return -1;
    }
    got = husk_recv_msg(ctrl_fd, &msg);
    if (got != 1 || msg.type != HUSK_MSG_NET_REQUEST) {
        set_err(err, errlen, "invalid network handshake message");
        kill(child, SIGKILL);
        while (waitpid(child, NULL, 0) < 0 && errno == EINTR)
            ;
        return -1;
    }
    fd = nl_open(err, errlen);
    if (fd < 0)
        goto fail;
    bridge_idx = (int)if_nametoindex(cfg->bridge);
    if (bridge_idx == 0) {
        set_err(err, errlen, "bridge '%s' disappeared", cfg->bridge);
        close(fd);
        goto fail;
    }
    if (create_veth(fd, cfg->host_veth, cfg->peer_veth, err, errlen) < 0) {
        close(fd);
        goto fail;
    }
    cfg->host_veth_created = true;
#ifdef HUSK_TEST_HOOKS
    if (husk_test_fail_if("network-after-veth")) {
        set_err(err, errlen, "injected failure after veth creation");
        close(fd);
        goto fail;
    }
#endif
    host_idx = (int)if_nametoindex(cfg->host_veth);
    peer_idx = (int)if_nametoindex(cfg->peer_veth);
    if (host_idx == 0 || peer_idx == 0) {
        set_err(err, errlen, "cannot find newly created veth interfaces");
        close(fd);
        goto fail;
    }
    if (set_master(fd, host_idx, bridge_idx, err, errlen) < 0 ||
        set_link_up(fd, host_idx, err, errlen) < 0 ||
        move_link(fd, peer_idx, child, err, errlen) < 0) {
        close(fd);
        goto fail;
    }
    close(fd);
    if (husk_send_msg(ctrl_fd, HUSK_MSG_NET_READY, 0, "ready") < 0) {
        set_err(err, errlen, "send network acknowledgement: %s",
                strerror(errno));
        goto fail;
    }
    return 0;

fail:
    (void)husk_send_msg(ctrl_fd, HUSK_MSG_NET_ERROR, HUSK_EXIT_SETUP, "%s",
                        err != NULL ? err : "network setup failed");
    kill(child, SIGKILL);
    while (waitpid(child, NULL, 0) < 0 && errno == EINTR)
        ;
    return -1;
}

int husk_network_child_wait(int ctrl_fd, char *err, size_t errlen)
{
    struct husk_msg msg;
    struct pollfd pfd = {.fd = ctrl_fd, .events = POLLIN};
    int r;
    int got;

    if (husk_send_msg(ctrl_fd, HUSK_MSG_NET_REQUEST, 0, "request") < 0) {
        set_err(err, errlen, "send network request: %s", strerror(errno));
        return -1;
    }
    r = poll(&pfd, 1, HUSK_MAP_TIMEOUT_MS);
    if (r <= 0) {
        set_err(err, errlen, "timed out waiting for network acknowledgement");
        return -1;
    }
    got = husk_recv_msg(ctrl_fd, &msg);
    if (got != 1) {
        set_err(err, errlen, "invalid network acknowledgement");
        return -1;
    }
    if (msg.type == HUSK_MSG_NET_READY)
        return 0;
    if (msg.type == HUSK_MSG_NET_ERROR) {
        set_err(err, errlen, "%s", msg.text[0] ? msg.text
                                               : "parent rejected network setup");
        return -1;
    }
    set_err(err, errlen, "unexpected network message %u", msg.type);
    return -1;
}

int husk_network_configure_child(const struct husk_config *cfg, char *err,
                                 size_t errlen)
{
    int fd;
    int lo;
    int eth;

    if (!cfg->bridge_enabled)
        return 0;
    fd = nl_open(err, errlen);
    if (fd < 0)
        return -1;
    lo = (int)if_nametoindex("lo");
    eth = (int)if_nametoindex(cfg->peer_veth);
    if (lo == 0 || eth == 0) {
        set_err(err, errlen, "container interfaces lo/%s missing",
                cfg->peer_veth);
        close(fd);
        return -1;
    }
    if (rename_link(fd, eth, "eth0", err, errlen) < 0) {
        close(fd);
        return -1;
    }
    eth = (int)if_nametoindex("eth0");
    if (set_link_up(fd, lo, err, errlen) < 0 ||
        add_address(fd, eth, cfg->container_addr, cfg->container_prefix, err,
                    errlen) < 0 ||
        set_link_up(fd, eth, err, errlen) < 0 ||
        add_default_route(fd, eth, cfg->gateway_addr, err, errlen) < 0) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

void husk_network_cleanup(struct husk_config *cfg)
{
    if (!cfg->bridge_enabled) {
        lease_release(cfg);
        return;
    }
    if (cfg->host_veth_created) {
        char err[HUSK_CTRL_TEXT];
        int fd = nl_open(err, sizeof(err));
        int idx = (int)if_nametoindex(cfg->host_veth);

        if (fd >= 0 && idx > 0)
            (void)delete_link(fd, idx, err, sizeof(err));
        if (fd >= 0)
            close(fd);
        cfg->host_veth_created = false;
    }
    lease_release(cfg);
}
