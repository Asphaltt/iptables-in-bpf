
#include "libxdp_acl.h"

SEC("xdp_acl")
int xdp_acl_func_imm(struct xdp_md *ctx) {
    return match_acl_rules(ctx);
}

char _license[] SEC("license") = "GPL";
