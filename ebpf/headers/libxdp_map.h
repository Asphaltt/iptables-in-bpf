#ifndef __LIBXDP_MAP_H_
#define __LIBXDP_MAP_H_

#include "vmlinux.h"

#include "bpf_helpers.h"

#define LPM_PREFIXLEN 32

#define ACL_RULE_NUM_MAX 512
#define ACL_ADDR_NUM_MAX 64

struct lpm_key {
    __u32 prefixlen;
    __u32 data; /* network order */
} __attribute__((aligned(4)));

struct port_range {
    __u16 start;
    __u16 end;
};

struct rule_policy {
    __u32 priority;
    __u32 action;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_key);
    __type(value, __u16);
    __uint(max_entries, ACL_ADDR_NUM_MAX);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} acl_addr_inner SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, ACL_RULE_NUM_MAX);
} acl_saddr SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, ACL_RULE_NUM_MAX);
} acl_daddr SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct port_range);
    __uint(max_entries, ACL_RULE_NUM_MAX);
} acl_sport SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct port_range);
    __uint(max_entries, ACL_RULE_NUM_MAX);
} acl_dport SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, ACL_RULE_NUM_MAX);
} acl_protocol SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct rule_policy);
    __uint(max_entries, ACL_RULE_NUM_MAX);
} acl_rule_policy SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, ACL_RULE_NUM_MAX);
} acl_stat SEC(".maps");

#endif // __LIBXDP_MAP_H_