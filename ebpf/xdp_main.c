#include "vmlinux.h"

#include "bpf_helpers.h"

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} acl_progs SEC(".maps");

SEC("xdp_acl")
int xdp_acl_func(struct xdp_md *ctx) {
    bpf_tail_call_static(ctx, &acl_progs, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
