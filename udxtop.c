#include <assert.h>
#include <net/if.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>

#include "all.h"
#include "udx_conntrack.h"

// hw ethernet address
bool have_hw_addr;
char if_hw_addr[6];

// hw ip address
bool have_ip4_addr;
bool have_ip6_addr;
struct in_addr if_ip4_addr;
struct in6_addr if_ip6_addr;

// packet parsing
struct sockaddr_storage src;
struct sockaddr_storage dst;

eth_hdr_t *eth;
ip4_hdr_t *ip4;
ip6_hdr_t *ip6;
udp_hdr_t *udp;

history_t history_totals;
time_t last_timestamp;
int history_pos;
int history_len = 1;
pthread_mutex_t tick_mutex;

extern history_t history_totals;

pcap_t *pcap_handle;

sig_atomic_t signum;

static void sig_handler(int sig) {
    signum = sig;
}

#define FILTER_SZ 8192

char filter[FILTER_SZ];
int filter_sz;

option_t options;

pcap_handler packet_handler;

void init_history() {
    last_timestamp = time(NULL);
    memset(&history_totals, 0, sizeof(history_totals));
}

void history_rotate() {

    history_pos = (history_pos + 1) % HISTORY_LENGTH;

    for (int i = 0; i < nstreams; i++) {
        udx_stream_t *s = stream_table[i];

        if (s->history.last_write == history_pos) {
            remove_stream(s);
            i--; // hack for remove in place....
        } else {
            s->history.recv[history_pos] = 0;
            s->history.sent[history_pos] = 0;
        }
    }

    history_totals.sent[history_pos] = 0;
    history_totals.recv[history_pos] = 0;

    if (history_len < HISTORY_LENGTH) {
        history_len++;
    }
}

void tick(int print) {
    time_t t;
    pthread_mutex_lock(&tick_mutex);

    t = time(NULL);

    if (t - last_timestamp >= RESOLUTION) {
        analyze_data();
        ui_print();
        history_rotate();
        last_timestamp = t;
    } else {
        ui_tick(print);
    }

    pthread_mutex_unlock(&tick_mutex);
}

// returns: # of bytes of ip header,
// or -1 to drop packet
int parse_ipv4(const uint8_t *payload, int len) {
    ip4 = (ip4_hdr_t *)payload;
    ip6 = NULL;

    int version = ip4->v_and_hl >> 4;

    memset(&src, 0, sizeof(src));
    memset(&dst, 0, sizeof(dst));

    assert(version == 4);
    struct sockaddr_in *s = (struct sockaddr_in *)&src;
    struct sockaddr_in *d = (struct sockaddr_in *)&dst;
    s->sin_family = AF_INET;
    d->sin_family = AF_INET;
    s->sin_addr.s_addr = ip4->saddr;
    d->sin_addr.s_addr = ip4->daddr;

    int ip_header_len_bytes = (ip4->v_and_hl & 0xf) * 4;

    int flags_and_frag_offset = ntohs(ip4->frag_off);

    int flags = (flags_and_frag_offset >> 13) & 0x7;

    bool fragmented = flags & 0x1;

    if (fragmented) {
        ;
    }

    return ip_header_len_bytes;
}

int parse_ipv6(const uint8_t *payload, int len) {
    ip4 = NULL;
    ip6 = (ip6_hdr_t *)payload;

    memset(&src, 0, sizeof(src));
    memset(&dst, 0, sizeof(dst));

    struct sockaddr_in6 *s = (struct sockaddr_in6 *)&src;
    struct sockaddr_in6 *d = (struct sockaddr_in6 *)&dst;

    s->sin6_family = AF_INET6;
    d->sin6_family = AF_INET6;
    memcpy(&s->sin6_addr, &ip6->src, 16);
    memcpy(&d->sin6_addr, &ip6->dst, 16);

    return sizeof(ip6_hdr_t);
}

int parse_udp(const uint8_t *payload, int len) {
    udp = (udp_hdr_t *)payload;

    return sizeof(udp_hdr_t);
}

#define ENTERING 0
#define LEAVING 1

void handle_eth_packet(u_char *ctx, const struct pcap_pkthdr *header, const u_char *payload) {
    eth_hdr_t *eth = (eth_hdr_t *)payload;
    int proto = ntohs(eth->ether_type);
    payload = payload + sizeof(eth_hdr_t);

    tick(0);

    int len = header->len - sizeof(eth_hdr_t);
    int n = 0;

    int actual_len;

    if (proto == 0x800) {
        n = parse_ipv4(payload, len);
        if (ip4->protocol != 17) {
            return;
        }
        actual_len = ntohs(ip4->tot_len);
    } else if (proto == 0x86dd) {
        n = parse_ipv6(payload, len);
        if (ip6->next_header != 17) {
            return;
        }
        actual_len = ntohs(ip6->payload_len) + 40;
    } else {
        return;
    }

    payload += n;
    len -= n;
    n = parse_udp(payload, len);

    if (proto == 0x800) {
        struct sockaddr_in *s = (struct sockaddr_in *)&src;
        struct sockaddr_in *d = (struct sockaddr_in *)&dst;
        s->sin_port = udp->sport;
        d->sin_port = udp->dport;
    }
    if (proto == 0x86dd) {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&src;
        struct sockaddr_in6 *d = (struct sockaddr_in6 *)&dst;
        s->sin6_port = udp->sport;
        d->sin6_port = udp->dport;
    }
    int dir = -1;

    if (have_hw_addr && memcmp(eth->src, if_hw_addr, 6) == 0) {
        dir = 1; // leaving
    } else if (have_hw_addr && memcmp(eth->dst, if_hw_addr, 6) == 0) {
        dir = 0; // entering
    } else if (memcmp("\xff\xff\xff\xff\xff\xff", eth->dst, 6) == 0) {
        dir = 0; // broadcast, count as incoming
    }

    payload += n;
    len -= n;

    if (len >= 20 && payload[0] == 0xff && payload[1] == 1) {
        // is udx
        uint8_t *p = (uint8_t *)payload;

        int magic = *p++;
        assert(magic == 0xff);
        int udx_version = *p++;
        assert(udx_version == 1);
        int flags = *p++;
        int data_offset = *p++;
        (void)flags;
        (void)data_offset;

        uint32_t *i = (uint32_t *)p;

        uint32_t id = *i++;
        // uint32_t rwnd = *i++;
        // uint32_t seq = *i++;
        // uint32_t ack = *i++;
        struct sockaddr *_src;
        struct sockaddr *_dst;

        // flip src / dst ?

        // if (dir == 0) {
        _src = (struct sockaddr *)&src;
        _dst = (struct sockaddr *)&dst;
        // } else {
        //     _src = (struct sockaddr *)&dst;
        //     _dst = (struct sockaddr *)&src;
        // }

        udx_flow_t *f = upsert_flow(_src, _dst, id, dir);
        udx_stream_t *s = get_stream(f);

        s->history.last_write = history_pos;

        if (dir == LEAVING) {
            s->history.sent[history_pos] += actual_len;
            s->history.total_sent += actual_len;
            history_totals.sent[history_pos] += actual_len;
            history_totals.total_sent += actual_len;
        } else {
            s->history.recv[history_pos] += actual_len;
            s->history.total_recv += actual_len;
            history_totals.recv[history_pos] += actual_len;
            history_totals.total_recv += actual_len;
        }
    }
}

bool parse_args(int argc, char **argv) {
    int current_option = 0;

    for (int i = 1; i < argc; i++) {

        char *arg = argv[i];
        printf("arg %d %s\n", i, argv[i]);

        switch (current_option) {
        case 0:
            break;
        case 'i':
            options.interface = arg;
            current_option = 0;
            continue;
        case 'f':
            options.filter = arg;
            current_option = 0;
            continue;
        default:
            fprintf(stderr, "error: unknown option -%c %s\n", current_option, arg);
            return 1;
        }
        if (arg[0] == '-') {
            if (arg[1] == 'i') {
                current_option = 'i';
                continue;
            }
            if (arg[1] == 'f') {
                current_option = 'f';
                continue;
            }
        }
        fprintf(stderr, "unknown option '%s'\n", arg);
        return false;
    }

    return true;
}

void packet_loop(void *p) {
    pcap_loop(pcap_handle, -1, (pcap_handler)packet_handler, NULL);
}

int get_addrs_ioctl(char *interface, char if_hw_addr[],
                    struct in_addr *if_ip_addr, struct in6_addr *if_ip6_addr);

int main(int argc, char **argv) {

    int dlt = 0;
    pthread_t thread;
    struct sigaction sa = {};

    sa.sa_handler = sig_handler;

    // setlocale(LC_ALL, "");

    sigaction(SIGINT, &sa, NULL);

    if (!parse_args(argc, argv)) {
        return 1;
    }

    int rc;
    char errbuf[PCAP_ERRBUF_SIZE];

    rc = pcap_init(PCAP_CHAR_ENC_UTF_8, errbuf);
    if (rc != 0) {
        fprintf(stderr, "pcap_init: %s\n", errbuf);
        return 1;
    }

    if (options.interface) {

        int flags = get_addrs_ioctl(options.interface, if_hw_addr, &if_ip4_addr, &if_ip6_addr);

        have_hw_addr = flags & 0x01;
        have_ip4_addr = flags & 0x02;
        have_ip6_addr = flags & 0x04;

        if (!have_hw_addr) {
            __builtin_trap();
        }

        pcap_handle = pcap_open_live(options.interface, BUFSIZ, 1, 1000, errbuf);
        if (pcap_handle == NULL) {
            fprintf(stderr, "pcap_open_offline: %s\n", errbuf);
            return 1;
        }
    } else {
        pcap_if_t *alldevs = NULL;
        rc = pcap_findalldevs(&alldevs, errbuf);

        if (rc != 0 || alldevs == NULL /* no error but no devices */) {
            fprintf(stderr, "couldn't find default device. err=%s\n", errbuf);
            return 1;
        }

        pcap_if_t *dev = alldevs;

        int flags = get_addrs_ioctl(dev->name, if_hw_addr, &if_ip4_addr, &if_ip6_addr);

        have_hw_addr = flags & 0x01;
        have_ip4_addr = flags & 0x02;
        have_ip6_addr = flags & 0x04;

        pcap_handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);

        if (pcap_handle == NULL) {
            fprintf(stderr, "couldn't open device %s: %s\n", dev->name, errbuf);
            pcap_freealldevs(alldevs);
            return 1;
        }
        pcap_freealldevs(alldevs);
    }

    dlt = pcap_datalink(pcap_handle);
    if (dlt == DLT_EN10MB) {
        packet_handler = handle_eth_packet;
    } else {
        fprintf(stderr, "selected device doesn't provide ethernet headers, datalink type=%d", pcap_datalink(pcap_handle));
        return 1;
    }

    if (options.filter) {
        struct bpf_program fp;
        rc = pcap_compile(pcap_handle, &fp, options.filter, 0, PCAP_NETMASK_UNKNOWN);
        if (rc != 0) {
            fprintf(stderr, "couldn't compile filter %s: %s\n", options.filter, pcap_geterr(pcap_handle));
            return 1;
        }
        rc = pcap_setfilter(pcap_handle, &fp);

        if (rc != 0) {
            fprintf(stderr, "couldn't install filter %s: %s\n", options.filter, pcap_geterr(pcap_handle));
            return 1;
        }
    }
    // todo: more stuff from packet_init
    // e.g. DNS resolver thread?

    pthread_mutex_init(&tick_mutex, NULL);
    // packet_init(); // we initialize above

    init_history();

    ui_init();

    pthread_create(&thread, NULL, (void *)&packet_loop, NULL);

    ui_loop();

    pthread_cancel(thread);

    ui_finish();

    return 0;
}
