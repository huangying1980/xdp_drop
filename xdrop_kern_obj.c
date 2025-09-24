#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/if_ether.h>

#include "linux/bpf.h"
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "xdrop_common_kern_user.h"
#include "xdrop_kern_def.h"

#ifdef KERN_DEBUG
#define pdebug bpf_printk
#else
#define pdebug(fmt, ...) 
#endif

struct hdr_cursor {
    void    *pos;
    __u64    size;
    __u16    l3_proto;
    __u8     l4_proto;
};

union ipv4_key {
    __u32 b32[2];
    __u8  b8[8];
};

MAP_DEFINE(tcp_port) = MAP_INIT (
    BPF_MAP_TYPE_PERCPU_HASH,
    sizeof(__u32),
    sizeof(struct drop_statis),
    MAX_PORT_NUM
); 

MAP_DEFINE(udp_port) = MAP_INIT (
    BPF_MAP_TYPE_PERCPU_HASH,
    sizeof(__u32),
    sizeof(struct drop_statis),
    MAX_PORT_NUM
); 

MAP_DEFINE(layer3) = MAP_INIT (
    BPF_MAP_TYPE_PERCPU_HASH,
    sizeof(__u32),
    sizeof(struct drop_statis),
    MAX_LAYER3_NUM
);

MAP_DEFINE(layer4) = MAP_INIT (
    BPF_MAP_TYPE_PERCPU_HASH,
    sizeof(__u32),
    sizeof(struct drop_statis),
    MAX_LAYER4_NUM
);

MAP_DEFINE(ipv4) = MAP_INIT_NO_PREALLOC (
    BPF_MAP_TYPE_LPM_TRIE,
    8,
    sizeof(struct drop_statis),
    MAX_LPM_IPV4_NUM
);

MAP_DEFINE(ipv6) = MAP_INIT_NO_PREALLOC (
    BPF_MAP_TYPE_LPM_TRIE,
    20,
    sizeof(struct drop_statis),
    MAX_LPM_IPV6_NUM
);

MAP_DEFINE(statis) = MAP_INIT (
    BPF_MAP_TYPE_PERCPU_ARRAY,
    sizeof(__u32),
    sizeof(struct drop_statis),
    MAX_STATIS_NUM
);

XDROP_FILTER_DEFINE(layer3)
{
    __u32                 key;
    struct drop_statis   *statis;
    struct ethhdr        *eth;

    eth = cur->pos;
    if (eth + 1 > (struct ethhdr *)data_end) {
        pdebug("layer3 xdp aborted\n");
        return XDP_ABORTED;
    }

    cur->pos = eth + 1;
    cur->l3_proto = bpf_ntohs(eth->h_proto);
    key = eth->h_proto;
    statis = bpf_map_lookup_elem(MAP_REF(layer3), &key);
    if (!statis) {
        pdebug("layer3 xdp pass\n");
        return XDP_PASS;
    }

    XDROP_STATIS(statis);

    pdebug("layer3 xdp drop\n");
    return XDP_DROP;
}

XDROP_FILTER_DEFINE(ipv4) //layer3
{
    int           hdrsize;
    struct iphdr *iph = cur->pos;
    struct drop_statis *statis;
    __be32 src_ip = 0;
    union  ipv4_key key;

    if (iph + 1 > (struct iphdr *)data_end) {
        pdebug("ipv4 xdp aborted\n");
        return XDP_ABORTED;
    }

    hdrsize = iph->ihl * 4;
    if(hdrsize < sizeof(struct iphdr)) {
        pdebug("ipv4 xdp aborted\n");
        return XDP_ABORTED;
    }

    if (cur->pos + hdrsize > data_end) {
        pdebug("ipv4 xdp aborted\n");
        return XDP_ABORTED;
    }
    cur->pos += hdrsize; 
    cur->l4_proto = iph->protocol;
    src_ip = iph->saddr;
    key.b32[0] = 32;
    key.b8[4] = src_ip & 0xff;
    key.b8[5] = (src_ip >> 8) & 0xff;
    key.b8[6] = (src_ip >> 16) & 0xff;
    key.b8[7] = (src_ip >> 24) & 0xff;
    statis = bpf_map_lookup_elem(MAP_REF(ipv4), &key);
    if (!statis) {
        pdebug("ipv4 xdp pass");
        return XDP_PASS;
    }

    XDROP_STATIS_SAFE(statis);
    pdebug("ipv4 xdp drop\n");
    return XDP_DROP;
}

XDROP_FILTER_DEFINE(ipv6) //layer3
{
    struct ipv6hdr *ip6h = cur->pos;
    struct drop_statis *statis;

    if (ip6h + 1 > (struct ipv6hdr*)data_end) {
        pdebug("ipv6 xdp aborted\n");
        return XDP_ABORTED;
    }
    cur->pos = ip6h + 1;
    cur->l4_proto = ip6h->nexthdr;
    struct {
        __u32 prefixlen;
        struct in6_addr ipv6_addr;
    }key6 = {
        .prefixlen = 128,
        .ipv6_addr = ip6h->saddr
    };
    statis = bpf_map_lookup_elem(MAP_REF(ipv6), &key6);
   // statis = bpf_map_lookup_elem(MAP_REF(ipv6), ip6h->saddr.s6_addr);
    if (!statis) {
        pdebug("ipv6 xdp pass\n");
        return XDP_PASS;
    }

    XDROP_STATIS_SAFE(statis);
    pdebug("ipv6 xdp drop\n");
    return XDP_DROP;
}

XDROP_FILTER_DEFINE(layer4) //check tcp or udp
{
    __u32    key;
    struct drop_statis *statis;

    key = cur->l4_proto;
    statis = bpf_map_lookup_elem(MAP_REF(layer4), &key);
    if (!statis) {
        pdebug("layer4 xdp pass\n");
        return XDP_PASS;
    }

    XDROP_STATIS(statis);

    pdebug("layer4 xdp drop\n");
    return XDP_DROP;
}

XDROP_FILTER_DEFINE(tcp_port) //layer4
{
    int     len;
    __u32   port;
    struct  drop_statis *statis;
    struct tcphdr *h = cur->pos;

    if (h + 1 > (struct tcphdr *)data_end) {
        pdebug("tcp port xdp aborted\n");
        return XDP_ABORTED;
    }

    len = h->doff << 2;
    if(len < sizeof(h)) {
        pdebug("tcp port xdp aborted\n");
        return XDP_ABORTED;
    }
    if (cur->pos + len > data_end) {
        pdebug("tcp port xdp aborted\n");
        return XDP_ABORTED;
    }
    cur->pos += len;

    port = h->dest;
    statis = bpf_map_lookup_elem(MAP_REF(tcp_port), &port);
    if (!statis) {
        pdebug("tcp port xdp pass\n");
        return XDP_PASS;
    }

    XDROP_STATIS(statis); 

    pdebug("tcp port xdp drop\n");
    return XDP_DROP;

}

XDROP_FILTER_DEFINE(udp_port)
{
    int     len;
    __u32  port;
    struct udphdr *h = cur->pos;
    struct drop_statis *statis;

    if (h + 1 > (struct udphdr *)data_end) {
        pdebug("udp port xdp aborted\n");
        return XDP_ABORTED;
    }
    cur->pos  = h + 1;

    len = bpf_ntohs(h->len) - sizeof(struct udphdr);
    if (len < 0) {
        pdebug("udp port xdp aborted\n");
        return XDP_ABORTED;
    }

    port = h->dest;
    statis = bpf_map_lookup_elem(MAP_REF(udp_port), &port);
    if (!statis) {
        pdebug("udp port xdp pass\n");
        return XDP_PASS;
    }
    pdebug("upd_statis get-value: bytes:%llu, count:%llu\n", statis->byte, statis->count);

    XDROP_STATIS(statis);
    pdebug("upd_statis: bytes:%llu, count:%llu\n", statis->byte, statis->count);
    pdebug("udp port xdp drop\n");
    return XDP_DROP;
}

SEC("xdp_drop")
int drop_prog_main(struct xdp_md *ctx)
{
    __u32 action = XDP_PASS;
    struct drop_statis *statis;
    struct hdr_cursor cursor = {0, 0, 0, 0};
    struct hdr_cursor *cur;
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    cursor.pos = data;
    cursor.size = data_end - data;
    cur = &cursor;

    action = CALL_FILTER(layer3);
    if (action != XDP_PASS) {
        goto out;
    }
    
    switch (cur->l3_proto) {
        case ETH_P_IP:
            action = CALL_FILTER(ipv4);
            break;
        case ETH_P_IPV6:
            action = CALL_FILTER(ipv6);
            break;
        default:
            action = XDP_PASS;
            break;
    }

    if (action != XDP_PASS) {
        goto out;
    }

    action = CALL_FILTER(layer4);
    if (action != XDP_PASS) {
        goto out;
    }

    switch (cur->l4_proto) {
        case IPPROTO_UDP:
            action = CALL_FILTER(udp_port);
            break;
        case IPPROTO_TCP:
            action = CALL_FILTER(tcp_port);
            break;
        default:
            action = XDP_PASS;
            break;
    }

out:

#ifdef KERN_DEBUG
    bpf_printk("action %d\n", action);
#endif
    
    statis = bpf_map_lookup_elem(MAP_REF(statis), &action);
    if (statis) {
        XDROP_STATIS(statis);
    }
    
    return action;
}

char _license[] SEC("license") = "GPL";
