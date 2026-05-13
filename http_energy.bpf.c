#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef SK_PASS
#define SK_PASS 1
#endif

#ifndef TCP_CLOSE
#define TCP_CLOSE 7
#endif

#define SCAN_MAX_BYTES   256
#define SCAN_LOOP_MAX    32
#define HDR_PREFIX       "X-Energy-Score: "
#define HDR_PREFIX_LEN   16
#define HDR_TEMPLATE     "X-Energy-Score:                     \r\n"
#define HDR_LEN          38
#define HDR_DEC_DIGITS   20
#define ENERGY_MODEL_SCALE 1000ULL
#define PSYS_SPLIT_SCALE 1000000ULL
#define PERF_MAP_MAX_CPUS 4096
#define ATTRIBUTION_MODE_PSYS 0ULL
#define ATTRIBUTION_MODE_MODEL 1ULL

struct sock_key4 {
    __u32 sip4;
    __u32 dip4;
    __u32 sport;
    __u32 dport;
    __u32 family;
};

struct conn_state {
    __u64 req_start_ns;
    __u64 current_req_id;
    __u32 awaiting_resp;
    __u8  hdr_match;
    __u8  _pad[3];
};

struct request_state {
    __u64 start_ns;
    __u64 cpu_ns;
    __u64 cycles;
    __u64 instructions;
    __u64 cache_misses;
    __u64 energy_score;
    __u64 attributed_score;
    __u64 energy_uj;
    __u64 sched_in_count;
    __u64 last_sched_in_ns;
    __u64 wakeup_count;
    __u64 migration_count;
    __u64 last_cycles;
    __u64 last_instructions;
    __u64 last_cache_misses;
    __u64 sock_cookie;
    __u32 owner_tgid;
    __u32 owner_tid;
};

struct process_freq_key {
    __u32 tgid;
    __u32 cpu_khz;
};

struct energy_model_config {
    __u64 attribution_mode;
    __u64 default_freq_multiplier;
    __u64 wakeup_penalty;
    __u64 cycles_weight;
    __u64 instructions_weight;
    __u64 cache_miss_weight;
    __u64 migration_penalty;
};

struct psys_reading {
    __u64 counter_raw;
    __u64 enabled;
    __u64 running;
    __u64 read_count;
    __u64 read_errors;
};

struct psys_split_state {
    __u64 uj_per_score_scaled;
    __u64 interval_score;
    __u64 interval_psys_uj;
    __u64 interval_active_psys_uj;
    __u64 interval_idle_uj;
    __u64 update_count;
};

#define ACCUMULATE_U64_MAP(map_name, key_value, delta_value)                     \
    do {                                                                        \
        __u32 __key = (key_value);                                              \
        __u64 __delta = (delta_value);                                          \
        __u64 *__value = bpf_map_lookup_elem(&(map_name), &__key);              \
        if (__value)                                                            \
            __sync_fetch_and_add(__value, __delta);                             \
        else                                                                    \
            bpf_map_update_elem(&(map_name), &__key, &__delta, BPF_ANY);        \
    } while (0)

struct { __uint(type, BPF_MAP_TYPE_SOCKHASH); __uint(max_entries, 16384); __type(key, struct sock_key4); __type(value, __u64); } sockhash SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536); __type(key, __u64); __type(value, struct conn_state); } conns SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536); __type(key, struct sock_key4); __type(value, __u64); } tuple_cookie SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1); __type(key, __u32); __type(value, struct energy_model_config); } model_cfg SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096); __type(key, __u32); __type(value, __u64); } freq_multipliers SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536); __type(key, __u64); __type(value, __u64); } active_reqs SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY); __uint(max_entries, 1); __type(key, __u32); __type(value, __u32); } psys_events SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY); __uint(max_entries, PERF_MAP_MAX_CPUS); __type(key, __u32); __type(value, __u32); } cycles_events SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY); __uint(max_entries, PERF_MAP_MAX_CPUS); __type(key, __u32); __type(value, __u32); } instructions_events SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY); __uint(max_entries, PERF_MAP_MAX_CPUS); __type(key, __u32); __type(value, __u32); } cache_miss_events SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536); __type(key, __u64); __type(value, struct request_state); } reqs SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536); __type(key, __u32); __type(value, __u64); } thread_reqs SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1); __type(key, __u32); __type(value, __u64); } req_seq SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096); __type(key, __u32); __type(value, __u32); } cpu_khz SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 262144); __type(key, struct process_freq_key); __type(value, __u64); } process_freq_runtime SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536); __type(key, __u32); __type(value, __u64); } process_wakeup_count SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536); __type(key, __u32); __type(value, __u64); } process_cycles SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536); __type(key, __u32); __type(value, __u64); } process_instructions SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536); __type(key, __u32); __type(value, __u64); } process_cache_misses SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536); __type(key, __u32); __type(value, __u64); } process_migrations SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536); __type(key, __u32); __type(value, __u64); } process_attributed_energy_uj SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1); __type(key, __u32); __type(value, struct psys_reading); } psys_last_reading SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1); __type(key, __u32); __type(value, struct psys_split_state); } psys_split_state SEC(".maps");

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

static __always_inline int fill_key4_msg(struct sk_msg_md *msg, struct sock_key4 *key)
{
    if (msg->family != AF_INET) return -1;
    key->family = AF_INET;
    key->sip4 = msg->local_ip4;
    key->dip4 = msg->remote_ip4;
    key->sport = msg->local_port;
    key->dport = msg->remote_port;
    return 0;
}

static __always_inline void advance_hdr_match(struct conn_state *st, __u8 c)
{
    if (st->hdr_match == 0) st->hdr_match = (c == '\r') ? 1 : 0;
    else if (st->hdr_match == 1) st->hdr_match = (c == '\n') ? 2 : (c == '\r' ? 1 : 0);
    else if (st->hdr_match == 2) st->hdr_match = (c == '\r') ? 3 : 0;
    else if (st->hdr_match == 3) st->hdr_match = (c == '\n') ? 4 : 0;
}

static __always_inline void clear_pending_request(struct conn_state *st)
{
    st->req_start_ns = 0;
    st->current_req_id = 0;
    st->awaiting_resp = 0;
    st->hdr_match = 0;
}

static __always_inline __u64 next_request_id(void)
{
    __u32 key = 0;
    __u64 *seq = bpf_map_lookup_elem(&req_seq, &key);

    if (!seq)
        return 0;
    return __sync_add_and_fetch(seq, 1);
}

static __always_inline void delete_request_tracking(__u64 cookie)
{
    __u64 *req_id = bpf_map_lookup_elem(&active_reqs, &cookie);
    if (!req_id)
        return;

    struct request_state *req = bpf_map_lookup_elem(&reqs, req_id);
    if (req && req->owner_tid) {
        __u32 tid = req->owner_tid;
        bpf_map_delete_elem(&thread_reqs, &tid);
    }

    bpf_map_delete_elem(&reqs, req_id);
    bpf_map_delete_elem(&active_reqs, &cookie);
}

static __always_inline void delete_conn_tracking(struct sock_key4 *key, __u64 cookie)
{
    delete_request_tracking(cookie);
    bpf_map_delete_elem(&sockhash, key);
    bpf_map_delete_elem(&tuple_cookie, key);
    bpf_map_delete_elem(&conns, &cookie);
}

static __always_inline void finish_request(struct conn_state *st, __u64 cookie)
{
    delete_request_tracking(cookie);
    if (st)
        clear_pending_request(st);
}

static __always_inline int looks_like_http_response(char *data, char *data_end, __u32 len)
{
    if (len < 8 || data + 8 > data_end)
        return 0;
    return data[0] == 'H' && data[1] == 'T' && data[2] == 'T' && data[3] == 'P' &&
           data[4] == '/' && data[5] == '1' && data[6] == '.';
}

static __always_inline __u32 current_cpu_clock_khz(void)
{
    __u32 cpu = bpf_get_smp_processor_id();
    __u32 *khz = bpf_map_lookup_elem(&cpu_khz, &cpu);

    return khz ? *khz : 0;
}

static __always_inline __u64 read_perf_counter(void *events)
{
    __u64 value = bpf_perf_event_read(events, BPF_F_CURRENT_CPU);

    return (__s64)value < 0 ? 0 : value;
}

static __always_inline void sample_psys_energy(void)
{
    __u32 key = 0;
    struct psys_reading *reading = bpf_map_lookup_elem(&psys_last_reading, &key);
    struct bpf_perf_event_value value = {};
    long ret;

    if (!reading)
        return;

    ret = bpf_perf_event_read_value(&psys_events, 0, &value, sizeof(value));
    if (ret) {
        reading->read_errors += 1;
        return;
    }

    reading->counter_raw = value.counter;
    reading->enabled = value.enabled;
    reading->running = value.running;
    reading->read_count += 1;
}

static __always_inline void snapshot_request_counters(struct request_state *req)
{
    if (!req)
        return;

    req->last_cycles = read_perf_counter(&cycles_events);
    req->last_instructions = read_perf_counter(&instructions_events);
    req->last_cache_misses = read_perf_counter(&cache_miss_events);
}

static __always_inline __u64 scale_weighted_score(__u64 value, __u64 weight)
{
    return (value / ENERGY_MODEL_SCALE) * weight +
           ((value % ENERGY_MODEL_SCALE) * weight) / ENERGY_MODEL_SCALE;
}

static __always_inline __u64 scale_psys_energy(__u64 score, __u64 uj_per_score_scaled)
{
    return (score / PSYS_SPLIT_SCALE) * uj_per_score_scaled +
           ((score % PSYS_SPLIT_SCALE) * uj_per_score_scaled) / PSYS_SPLIT_SCALE;
}

static __always_inline struct energy_model_config *get_model_config(void)
{
    __u32 key = 0;

    return bpf_map_lookup_elem(&model_cfg, &key);
}

static __always_inline struct psys_split_state *get_psys_split_state(void)
{
    __u32 key = 0;

    return bpf_map_lookup_elem(&psys_split_state, &key);
}

static __always_inline __u64 freq_multiplier_for_khz(__u32 cpu_khz)
{
    struct energy_model_config *cfg = get_model_config();
    __u64 multiplier = cfg ? cfg->default_freq_multiplier : ENERGY_MODEL_SCALE;
    __u64 *override;

    override = bpf_map_lookup_elem(&freq_multipliers, &cpu_khz);
    if (override)
        multiplier = *override;
    return multiplier;
}

static __always_inline void charge_request_signal(struct request_state *req, __u64 delta_score)
{
    struct energy_model_config *cfg;
    struct psys_split_state *split;

    if (!req || !delta_score)
        return;

    req->energy_score += delta_score;

    cfg = get_model_config();
    if (cfg && cfg->attribution_mode == ATTRIBUTION_MODE_MODEL) {
        req->energy_uj += delta_score;
        req->attributed_score += delta_score;
        if (req->owner_tgid)
            ACCUMULATE_U64_MAP(process_attributed_energy_uj, req->owner_tgid, delta_score);
        return;
    }

    split = get_psys_split_state();
    if (!split || !split->uj_per_score_scaled)
        return;

    req->energy_uj += scale_psys_energy(delta_score, split->uj_per_score_scaled);
    req->attributed_score += delta_score;
}

static __always_inline void flush_pending_request_energy(struct request_state *req)
{
    struct psys_split_state *split;
    __u64 pending_score;

    if (!req || req->attributed_score >= req->energy_score)
        return;

    split = get_psys_split_state();
    if (!split || !split->uj_per_score_scaled)
        return;

    pending_score = req->energy_score - req->attributed_score;
    req->energy_uj += scale_psys_energy(pending_score, split->uj_per_score_scaled);
    req->attributed_score = req->energy_score;
}

static __always_inline void account_sched_out(struct request_state *req, __u32 tid, __u64 now_ns)
{
    if (!req || req->owner_tid != tid || !req->last_sched_in_ns)
        return;

    __u64 delta_ns = now_ns - req->last_sched_in_ns;
    __u32 cpu_khz = current_cpu_clock_khz();
    __u64 multiplier = freq_multiplier_for_khz(cpu_khz);
    __u64 cycles_now = read_perf_counter(&cycles_events);
    __u64 instructions_now = read_perf_counter(&instructions_events);
    __u64 cache_misses_now = read_perf_counter(&cache_miss_events);
    __u64 cycles_delta = cycles_now >= req->last_cycles ? cycles_now - req->last_cycles : 0;
    __u64 instructions_delta = instructions_now >= req->last_instructions ?
                               instructions_now - req->last_instructions : 0;
    __u64 cache_misses_delta = cache_misses_now >= req->last_cache_misses ?
                               cache_misses_now - req->last_cache_misses : 0;
    struct energy_model_config *cfg = get_model_config();
    __u64 score_delta = scale_weighted_score(delta_ns, multiplier);

    req->cpu_ns += delta_ns;
    req->cycles += cycles_delta;
    req->instructions += instructions_delta;
    req->cache_misses += cache_misses_delta;
    if (cfg) {
        score_delta += scale_weighted_score(cycles_delta, cfg->cycles_weight);
        score_delta += scale_weighted_score(instructions_delta, cfg->instructions_weight);
        score_delta += scale_weighted_score(cache_misses_delta, cfg->cache_miss_weight);
    }
    charge_request_signal(req, score_delta);
    req->last_sched_in_ns = 0;
    req->last_cycles = 0;
    req->last_instructions = 0;
    req->last_cache_misses = 0;

    if (req->owner_tgid) {
        ACCUMULATE_U64_MAP(process_cycles, req->owner_tgid, cycles_delta);
        ACCUMULATE_U64_MAP(process_instructions, req->owner_tgid, instructions_delta);
        ACCUMULATE_U64_MAP(process_cache_misses, req->owner_tgid, cache_misses_delta);
    }

    if (req->owner_tgid && cpu_khz) {
        struct process_freq_key key = {
            .tgid = req->owner_tgid,
            .cpu_khz = cpu_khz,
        };
        __u64 *runtime_ns = bpf_map_lookup_elem(&process_freq_runtime, &key);

        if (runtime_ns) {
            __sync_fetch_and_add(runtime_ns, delta_ns);
        } else {
            bpf_map_update_elem(&process_freq_runtime, &key, &delta_ns, BPF_ANY);
        }
    }
}

static __always_inline void account_process_wakeup(void)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u32 tgid = pid_tgid >> 32;
    __u64 init = 1;
    __u64 *count;

    if (!tgid)
        return;

    count = bpf_map_lookup_elem(&process_wakeup_count, &tgid);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        bpf_map_update_elem(&process_wakeup_count, &tgid, &init, BPF_ANY);
    }

    __u64 *req_id = bpf_map_lookup_elem(&thread_reqs, &tid);
    if (!req_id)
        return;

    struct request_state *req = bpf_map_lookup_elem(&reqs, req_id);
    if (!req) {
        bpf_map_delete_elem(&thread_reqs, &tid);
        return;
    }
    if (req->owner_tid != tid || req->owner_tgid != tgid)
        return;

    req->wakeup_count += 1;
    struct energy_model_config *cfg = get_model_config();
    if (cfg)
        charge_request_signal(req, cfg->wakeup_penalty);
}

SEC("tracepoint/power/cpu_frequency")
int track_cpu_frequency(struct trace_event_raw_cpu *ctx)
{
    __u32 cpu = ctx->cpu_id;
    __u32 khz = ctx->state;

    bpf_map_update_elem(&cpu_khz, &cpu, &khz, BPF_ANY);
    return 0;
}

SEC("tracepoint/sched/sched_wakeup")
int track_sched_wakeup(struct trace_event_raw_sched_wakeup_template *ctx)
{
    (void)ctx;
    account_process_wakeup();
    return 0;
}

SEC("tracepoint/sched/sched_wakeup_new")
int track_sched_wakeup_new(struct trace_event_raw_sched_wakeup_template *ctx)
{
    (void)ctx;
    account_process_wakeup();
    return 0;
}

SEC("tp_btf/sched_migrate_task")
int BPF_PROG(track_sched_migrate_task, struct task_struct *p, int dest_cpu)
{
    __u32 tgid;
    __u32 pid;

    (void)dest_cpu;
    if (!p)
        return 0;

    tgid = BPF_CORE_READ(p, tgid);
    pid = BPF_CORE_READ(p, pid);

    if (tgid)
        ACCUMULATE_U64_MAP(process_migrations, tgid, 1);

    __u64 *req_id = bpf_map_lookup_elem(&thread_reqs, &pid);
    if (!req_id)
        return 0;

    struct request_state *req = bpf_map_lookup_elem(&reqs, req_id);
    if (!req) {
        bpf_map_delete_elem(&thread_reqs, &pid);
        return 0;
    }
    if (req->owner_tid == pid) {
        req->migration_count += 1;
        struct energy_model_config *cfg = get_model_config();
        if (cfg)
            charge_request_signal(req, cfg->migration_penalty);
    }

    return 0;
}

SEC("sockops")
int sockops_add_to_sockhash(struct bpf_sock_ops *skops)
{
    struct sock_key4 key = {};
    __u64 cookie;

    if (skops->op == BPF_SOCK_OPS_STATE_CB) {
        if (skops->args[1] != TCP_CLOSE)
            return 0;
        if (fill_key4_sockops(skops, &key) != 0)
            return 0;
        cookie = bpf_get_socket_cookie(skops);
        delete_conn_tracking(&key, cookie);
        return 0;
    }

    if (skops->op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB &&
        skops->op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB)
        return 0;

    if (fill_key4_sockops(skops, &key) != 0)
        return 0;
    if (bpf_sock_hash_update(skops, &sockhash, &key, BPF_ANY) != 0)
        return 0;

    cookie = bpf_get_socket_cookie(skops);
    if (bpf_map_update_elem(&tuple_cookie, &key, &cookie, BPF_ANY) != 0) {
        bpf_map_delete_elem(&sockhash, &key);
        return 0;
    }

    struct conn_state st = {};
    if (bpf_map_update_elem(&conns, &cookie, &st, BPF_ANY) != 0) {
        bpf_map_delete_elem(&tuple_cookie, &key);
        bpf_map_delete_elem(&sockhash, &key);
        return 0;
    }

    bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_STATE_CB_FLAG);
    return 0;
}

SEC("cgroup_skb/ingress")
int track_ingress(struct __sk_buff *skb)
{
    if (skb->protocol != bpf_htons(ETH_P_IP))
        return 1;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct iphdr *iph = data;
    if ((void *)(iph + 1) > data_end)
        return 1;
    if (iph->protocol != IPPROTO_TCP)
        return 1;

    __u32 ip_hdr_len = iph->ihl * 4;
    if (ip_hdr_len < sizeof(*iph))
        return 1;
    struct tcphdr *tcph = data + ip_hdr_len;
    if ((void *)(tcph + 1) > data_end)
        return 1;

    __u32 tcp_hdr_len = tcph->doff * 4;
    if (tcp_hdr_len < sizeof(*tcph))
        return 1;

    __u32 payload_off = ip_hdr_len + tcp_hdr_len;
    if (data + payload_off > data_end)
        return 1;

    __u64 cookie = bpf_get_socket_cookie(skb);
    if (cookie == 0)
        return 1;
    struct conn_state *st = bpf_map_lookup_elem(&conns, &cookie);
    if (!st)
        return 1;

    int len = skb->len - payload_off;
    if (len <= 0)
        return 1;
    if (len > SCAN_MAX_BYTES)
        len = SCAN_MAX_BYTES;
    if (len > 0 && !st->awaiting_resp && st->req_start_ns == 0)
        st->req_start_ns = bpf_ktime_get_ns();

#pragma clang loop unroll(disable)
    for (int i = 0; i < SCAN_MAX_BYTES; i++) {
        if (i >= len)
            break;
        __u8 c = 0;
        if (bpf_skb_load_bytes(skb, payload_off + i, &c, 1) < 0)
            break;
        advance_hdr_match(st, c);
        if (st->hdr_match == 4) {
            st->hdr_match = 0;
            if (!st->awaiting_resp && st->current_req_id == 0) {
                __u64 req_id = next_request_id();
                if (req_id == 0)
                    break;

                __u64 start_ns = st->req_start_ns;
                if (start_ns == 0)
                    start_ns = bpf_ktime_get_ns();

                struct request_state req = {};
                req.start_ns = start_ns;
                req.sock_cookie = cookie;
                /* sample_psys_energy() removed: bpf_perf_event_read_value
                 * is not permitted in cgroup_skb programs. PSYS is sampled
                 * from userspace and from the fentry/tcp_sendmsg hook. */
                if (bpf_map_update_elem(&reqs, &req_id, &req, BPF_ANY) != 0)
                    break;
                if (bpf_map_update_elem(&active_reqs, &cookie, &req_id, BPF_ANY) != 0) {
                    bpf_map_delete_elem(&reqs, &req_id);
                    break;
                }

                st->current_req_id = req_id;
                if (st->req_start_ns == 0)
                    st->req_start_ns = bpf_ktime_get_ns();
                st->awaiting_resp = 1;
            }
            break;
        }
    }
    return 1;
}

SEC("fexit/tcp_recvmsg")
int BPF_PROG(bind_request_owner, struct sock *sk, struct msghdr *msg, size_t len,
             int flags, int *addr_len, int ret)
{
    if (!sk || ret <= 0)
        return 0;

    __u64 cookie = bpf_get_socket_cookie(sk);
    if (!cookie)
        return 0;

    __u64 *req_id = bpf_map_lookup_elem(&active_reqs, &cookie);
    if (!req_id)
        return 0;

    struct request_state *req = bpf_map_lookup_elem(&reqs, req_id);
    if (!req) {
        bpf_map_delete_elem(&active_reqs, &cookie);
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u32 tgid = pid_tgid >> 32;

    if (req->owner_tid && req->owner_tid != tid)
        return 0;

    req->owner_tid = tid;
    req->owner_tgid = tgid;
    bpf_map_update_elem(&thread_reqs, &tid, req_id, BPF_ANY);
    return 0;
}

/* Finalise the request's current scheduling slice from a context that is
 * permitted to call bpf_perf_event_read{,_value}. fentry/tcp_bpf_sendmsg
 * fires when the kernel enters the sockmap send path, which is BEFORE the
 * sk_msg verdict program (inject_energy_header) runs on the outgoing
 * response bytes. So req->energy_uj is up to date by the time the header
 * is built. (Plain tcp_sendmsg is called by tcp_bpf_sendmsg *after* the
 * verdict, so attaching there would be too late.) */
SEC("fentry/tcp_bpf_sendmsg")
int BPF_PROG(finalize_request_energy, struct sock *sk, struct msghdr *msg, size_t size)
{
    if (!sk)
        return 0;

    __u64 cookie = bpf_get_socket_cookie(sk);
    if (!cookie)
        return 0;

    __u64 *req_id = bpf_map_lookup_elem(&active_reqs, &cookie);
    if (!req_id)
        return 0;

    struct request_state *req = bpf_map_lookup_elem(&reqs, req_id);
    if (!req)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u64 now_ns = bpf_ktime_get_ns();

    if (req->owner_tid == tid)
        account_sched_out(req, tid, now_ns);
    sample_psys_energy();
    return 0;
}

SEC("tracepoint/sched/sched_switch")
int account_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
    __u64 now_ns = bpf_ktime_get_ns();
    __u32 prev_tid = ctx->prev_pid;
    __u32 next_tid = ctx->next_pid;

    if (prev_tid) {
        __u64 *req_id = bpf_map_lookup_elem(&thread_reqs, &prev_tid);
        if (req_id) {
            struct request_state *req = bpf_map_lookup_elem(&reqs, req_id);
            if (!req) {
                bpf_map_delete_elem(&thread_reqs, &prev_tid);
            } else {
                account_sched_out(req, prev_tid, now_ns);
            }
        }
    }

    if (next_tid) {
        __u64 *req_id = bpf_map_lookup_elem(&thread_reqs, &next_tid);
        if (req_id) {
            struct request_state *req = bpf_map_lookup_elem(&reqs, req_id);
            if (!req) {
                bpf_map_delete_elem(&thread_reqs, &next_tid);
            } else if (req->owner_tid == next_tid) {
                req->sched_in_count += 1;
                req->last_sched_in_ns = now_ns;
                snapshot_request_counters(req);
            }
        }
    }

    return 0;
}

SEC("sk_msg")
int inject_energy_header(struct sk_msg_md *msg)
{
    struct sock_key4 key = {};
    __u64 cookie_val;
    bool have_request = false;
    char *data;
    char *data_end;
    __u32 len;
    int insert_off = -1;

    if (fill_key4_msg(msg, &key) != 0)
        return SK_PASS;
    __u64 *cookie = bpf_map_lookup_elem(&tuple_cookie, &key);
    if (!cookie)
        return SK_PASS;
    cookie_val = *cookie;

    struct conn_state *st = bpf_map_lookup_elem(&conns, cookie);
    if (!st || !st->awaiting_resp || st->req_start_ns == 0)
        return SK_PASS;
    __u64 req_id = st->current_req_id;
    if (req_id == 0)
        return SK_PASS;
    have_request = true;

    struct request_state *req = bpf_map_lookup_elem(&reqs, &req_id);
    if (!req)
        goto out_finish;

    __u32 pull_len = msg->size;
    if (pull_len > SCAN_MAX_BYTES)
        pull_len = SCAN_MAX_BYTES;
    if (pull_len == 0)
        goto out_finish;
    if (bpf_msg_pull_data(msg, 0, pull_len, 0) != 0)
        goto out_finish;

    data = (char *)(long)msg->data;
    data_end = (char *)(long)msg->data_end;
    if (data >= data_end)
        goto out_finish;
    len = (__u32)((void *)data_end - (void *)data);
    if (len > pull_len) len = pull_len;
    if (!looks_like_http_response(data, data_end, len))
        goto out_finish;

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
        goto out_finish;

    /* sk_msg programs are not allowed to call bpf_perf_event_read{,_value}.
     * The current request slice was already accounted in fentry/tcp_sendmsg
     * (finalize_request_energy), so we only need to convert any pending
     * PSYS score into microjoules here. */
    flush_pending_request_energy(req);

    __u64 energy_uj = req->energy_uj;
    char hdr[HDR_LEN] = HDR_TEMPLATE;
    int digit_pos = HDR_PREFIX_LEN + HDR_DEC_DIGITS - 1;

    if (energy_uj == 0) {
        hdr[digit_pos] = '0';
    } else {
#pragma clang loop unroll(disable)
        for (int i = 0; i < HDR_DEC_DIGITS; i++) {
            if (energy_uj == 0)
                break;
            hdr[digit_pos - i] = '0' + (energy_uj % 10);
            energy_uj /= 10;
        }
    }

    if (bpf_msg_push_data(msg, insert_off, HDR_LEN, 0) != 0)
        goto out_finish;

    // refresh pointers
    if (bpf_msg_pull_data(msg, 0, insert_off + HDR_LEN, 0) != 0)
        goto out_finish;
    data = (char *)(long)msg->data;
    data_end = (char *)(long)msg->data_end;
    if (data + insert_off + HDR_LEN > data_end)
        goto out_finish;

#pragma clang loop unroll(disable)
    for (int i = 0; i < HDR_LEN; i++) {
        if (data + insert_off + i + 1 > data_end)
            goto out_finish;
        *(volatile char *)(data + insert_off + i) = hdr[i];
    }

out_finish:
    if (have_request)
        finish_request(st, cookie_val);
    return SK_PASS;
}
