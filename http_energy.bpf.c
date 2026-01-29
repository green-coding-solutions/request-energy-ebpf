#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdbool.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef SK_PASS
#define SK_PASS 1
#endif

#define SCAN_MAX_BYTES   256
#define SCAN_LOOP_MAX    64

struct sock_key4 {
    __u32 sip4;
    __u32 dip4;
    __u32 sport;
    __u32 dport;
    __u32 family;
};

struct conn_state {
    __u64 opened_ns;
    __u64 last_req_end_ns;
    __u32 awaiting_resp;
    __u8  hdr_match;
    __u8  _pad[3];
};

struct { __uint(type, BPF_MAP_TYPE_SOCKHASH); __uint(max_entries, 16384); __type(key, struct sock_key4); __type(value, __u64); } sockhash SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536); __type(key, __u64); __type(value, struct conn_state); } conns SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536); __type(key, struct sock_key4); __type(value, __u64); } tuple_cookie SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1); __type(key, __u32); __type(value, __u64); } energy_cfg SEC(".maps");

static __always_inline int fill_key4_sockops(struct bpf_sock_ops *skops, struct sock_key4 *key)
{
    if (skops->family != AF_INET) return -1;
    key->family = AF_INET;
    key->sip4 = skops->local_ip4;
    key->dip4 = skops->remote_ip4;
    key->sport = skops->local_port;
    key->dport = skops->remote_port;
    return 0;
}

static __always_inline int fill_key4_msg(struct sk_msg_md *msg, struct sock_key4 *key, bool convert_ports)
{
    if (msg->family != AF_INET) return -1;
    key->family = AF_INET;
    key->sip4 = msg->local_ip4;
    key->dip4 = msg->remote_ip4;
    if (convert_ports) {
        key->sport = bpf_ntohl(msg->local_port);
        key->dport = bpf_ntohl(msg->remote_port);
    } else {
        key->sport = msg->local_port;
        key->dport = msg->remote_port;
    }
    return 0;
}

static __always_inline void advance_hdr_match(struct conn_state *st, __u8 c)
{
    if (st->hdr_match == 0) st->hdr_match = (c == '\r') ? 1 : 0;
    else if (st->hdr_match == 1) st->hdr_match = (c == '\n') ? 2 : (c == '\r' ? 1 : 0);
    else if (st->hdr_match == 2) st->hdr_match = (c == '\r') ? 3 : 0;
    else if (st->hdr_match == 3) st->hdr_match = (c == '\n') ? 4 : 0;
}

SEC("sockops")
int sockops_add_to_sockhash(struct bpf_sock_ops *skops)
{
    if (skops->op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB && skops->op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB)
        return 0;
    struct sock_key4 key = {};
    if (fill_key4_sockops(skops, &key) != 0) return 0;
    (void)bpf_sock_hash_update(skops, &sockhash, &key, BPF_ANY);
    __u64 cookie = bpf_get_socket_cookie(skops);
    bpf_map_update_elem(&tuple_cookie, &key, &cookie, BPF_ANY);

    // Also store a host-order copy in case other contexts report ports differently
    struct sock_key4 key_host = key;
    key_host.sport = bpf_ntohl(key.sport);
    key_host.dport = bpf_ntohl(key.dport);
    bpf_map_update_elem(&tuple_cookie, &key_host, &cookie, BPF_ANY);

    struct conn_state st = {};
    st.opened_ns = bpf_ktime_get_ns();
    bpf_map_update_elem(&conns, &cookie, &st, BPF_ANY);
    return 0;
}

SEC("sk_skb/stream_parser")
int parse_ingress(struct __sk_buff *skb)
{
    __u64 cookie = bpf_get_socket_cookie(skb);
    struct conn_state *st = bpf_map_lookup_elem(&conns, &cookie);
    if (!st) return skb->len;
    int len = skb->len;
    if (len > SCAN_MAX_BYTES) len = SCAN_MAX_BYTES;
    for (int i = 0; i < SCAN_MAX_BYTES; i++) {
        if (i >= len) break;
        __u8 c = 0;
        if (bpf_skb_load_bytes(skb, i, &c, 1) < 0) break;
        advance_hdr_match(st, c);
        if (st->hdr_match == 4) {
            st->hdr_match = 0;
            st->last_req_end_ns = bpf_ktime_get_ns();
            st->awaiting_resp = 1;
            break;
        }
    }
    return skb->len;
}

SEC("sk_skb/stream_verdict")
int verdict_allow(struct __sk_buff *skb)
{
    return SK_PASS;
}

SEC("sk_msg")
int inject_energy_header(struct sk_msg_md *msg)
{
    // Only operate if the entire msg payload is small and linear
    if (msg->size > SCAN_MAX_BYTES)
        return SK_PASS;
    if (bpf_msg_pull_data(msg, 0, msg->size, 0) != 0)
        return SK_PASS;

    char *data = (char *)(long)msg->data;
    char *data_end = (char *)(long)msg->data_end;
    if (data >= data_end)
        return SK_PASS;
    __u32 len = (__u32)((void *)data_end - (void *)data);
    if (len > msg->size) len = msg->size;
    if (len > SCAN_MAX_BYTES) len = SCAN_MAX_BYTES;

    int insert_off = -1;
#pragma clang loop unroll(disable)
    for (int i = 0; i < SCAN_LOOP_MAX; i++) {
        if (i + 1 >= (int)len)
            break;
        if (data + i + 2 > data_end)
            break;
        if (data[i] == '\r' && data[i + 1] == '\n') {
            insert_off = i + 2;
            break;
        }
    }
    if (insert_off < 0)
        return SK_PASS;

    // Lookup cookie via 4-tuple (sk_msg cannot use bpf_get_socket_cookie)
    struct sock_key4 key = {};
    if (fill_key4_msg(msg, &key, false) != 0)
        return SK_PASS;
    __u64 *cookie = bpf_map_lookup_elem(&tuple_cookie, &key);
    if (!cookie) {
        if (fill_key4_msg(msg, &key, true) != 0)
            return SK_PASS;
        cookie = bpf_map_lookup_elem(&tuple_cookie, &key);
        if (!cookie)
            return SK_PASS;
    }

    struct conn_state *st = bpf_map_lookup_elem(&conns, cookie);
    if (!st || st->opened_ns == 0)
        return SK_PASS;

    __u32 cfg_key = 0;
    __u64 *energy_per_ns = bpf_map_lookup_elem(&energy_cfg, &cfg_key);
    if (!energy_per_ns || *energy_per_ns == 0)
        return SK_PASS;

    __u64 now_ns = bpf_ktime_get_ns();
    __u64 energy_ns = now_ns - st->opened_ns;
    if (energy_ns > 10ULL * 1000000000ULL) // cap at 10s
        energy_ns = 10ULL * 1000000000ULL;
    __u64 energy_nj = energy_ns * (*energy_per_ns);
    if (energy_nj > 999999999999ULL) // cap digits (~12)
        energy_nj = 999999999999ULL;

    // Build header bytes with fixed max digits
    char hdr[40] = "X-Energy-nJ: ";
    int pos = 13; // strlen prefix
    char digits[12];
    int d = 0;
#pragma clang loop unroll(disable)
    for (int i = 0; i < 12; i++) {
        digits[d++] = '0' + (energy_nj % 10);
        energy_nj /= 10;
        if (energy_nj == 0)
            break;
    }
#pragma clang loop unroll(disable)
    for (int i = d - 1; i >= 0; i--) {
        hdr[pos++] = digits[i];
    }
    hdr[pos++] = '\r';
    hdr[pos++] = '\n';
    int hdr_len = pos;

    if (bpf_msg_push_data(msg, insert_off, hdr_len, 0) != 0)
        return SK_PASS;

    // refresh pointers
    if (bpf_msg_pull_data(msg, 0, insert_off + hdr_len, 0) != 0)
        return SK_PASS;
    data = (char *)(long)msg->data;
    data_end = (char *)(long)msg->data_end;
    if (data + insert_off + hdr_len > data_end)
        return SK_PASS;

#pragma clang loop unroll(disable)
    for (int i = 0; i < hdr_len; i++) {
        if (data + insert_off + i + 1 > data_end)
            return SK_PASS;
        *(volatile char *)(data + insert_off + i) = hdr[i];
    }

    return SK_PASS;
}
