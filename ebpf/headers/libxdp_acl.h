#ifndef __LIBXDP_ACL_H_
#define __LIBXDP_ACL_H_

#include "vmlinux.h"

#include "bpf_helpers.h"
#include "bpf_endian.h"

#include "libxdp_map.h"

static volatile const __u32 ACL_RULE_NUM = 0;

static volatile const __u32 XDPACL_DEBUG = 0;

#define bpf_debug_printk(fmt, ...)          \
    do {                                    \
        if (XDPACL_DEBUG)                   \
            bpf_printk(fmt, ##__VA_ARGS__); \
    } while (0)

#define ETH_P_IP 0x0800 /* Internet Protocol packet	*/

struct rule_matching {
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
    __u8 protocol;

    __u16 pad;

    __u8 matched;
    struct rule_policy policy;
};

#define VALIDATE_HEADER(hdr, ctx)                               \
    do {                                                        \
        if ((void *)(hdr + 1) > (void *)(__u64)(ctx->data_end)) \
            return XDP_PASS;                                    \
    } while (0)

static __always_inline __u64
proto2key(__u8 protocol) {
    if (protocol == IPPROTO_TCP)
        return 1 << 0;

    if (protocol == IPPROTO_UDP)
        return 1 << 1;

    // ICMP
    return 1 << 2;
}

static int
matching_rule(struct bpf_map *map, const __u32 *key, struct rule_policy *value, struct rule_matching *match) {
    if (*key >= ACL_RULE_NUM)
        return 1;

    // protocol
    __u64 proto_key = proto2key(match->protocol);
    __u64 *proto;
    proto = (typeof(proto))bpf_map_lookup_elem(&acl_protocol, key);
    if (!proto || (*proto & proto_key) == 0)
        return 0;

    // sport
    struct port_range *pr;
    pr = (typeof(pr))bpf_map_lookup_elem(&acl_sport, key);
    if (!pr || !(pr->start <= match->sport && match->sport <= pr->end))
        return 0;

    // dport
    pr = (typeof(pr))bpf_map_lookup_elem(&acl_dport, key);
    if (!pr || !(pr->start <= match->dport && match->dport <= pr->end))
        return 0;

    // saddr
    void *m;
    m = (typeof(m))bpf_map_lookup_elem(&acl_saddr, key);
    if (!m)
        return 0;

    struct lpm_key k = {};
    k.prefixlen = LPM_PREFIXLEN;
    k.data = match->saddr;

    __u16 *val;
    val = (typeof(val))bpf_map_lookup_elem(m, &k);
    if (!val || *val == 0)
        return 0;

    // daddr
    m = (typeof(m))bpf_map_lookup_elem(&acl_daddr, key);
    if (!m)
        return 0;

    k.data = match->daddr;

    val = (typeof(val))bpf_map_lookup_elem(m, &k);
    if (!val || *val == 0)
        return 0;

    __builtin_memcpy(&match->policy, value, sizeof(*value));
    match->matched = 1;
    return 1;
}

static __always_inline int
match_acl_rules(struct xdp_md *ctx) {
    struct rule_matching match = {};

    struct ethhdr *eth;
    eth = (typeof(eth))((void *)(__u64)ctx->data);
    VALIDATE_HEADER(eth, ctx);

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph;
    iph = (typeof(iph))(eth + 1);
    VALIDATE_HEADER(iph, ctx);

    bool is_tcp_udp = (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP);
    bool is_icmp = (iph->protocol == IPPROTO_ICMP);

    if (is_tcp_udp) {
        struct udphdr *uh;
        uh = (typeof(uh))((void *)iph + iph->ihl * 4);
        VALIDATE_HEADER(uh, ctx);

        match.sport = uh->source;
        match.dport = uh->dest;

    } else if (is_icmp) {
        bpf_debug_printk("ICMP: %x -> %x\n", bpf_ntohl(iph->saddr), bpf_ntohl(iph->daddr));
    } else {
        return XDP_PASS;
    }

    match.saddr = iph->saddr;
    match.daddr = iph->daddr;
    match.protocol = iph->protocol;

    bpf_for_each_map_elem(&acl_rule_policy, matching_rule, &match, 0);

    if (match.matched == 0)
        return XDP_PASS;

    // stat
    __u64 *counter;
    counter = (typeof(counter))bpf_map_lookup_elem(&acl_stat, &match.policy.priority);
    if (counter)
        (*counter)++;

    return match.policy.action;
}

#endif // __LIBXDP_ACL_H_