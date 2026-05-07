// http_energy.c
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>
#include <linux/perf_event.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define ENERGY_MODEL_SCALE 1000ULL
#define PSYS_SPLIT_SCALE 1000000ULL
#define ATTRIBUTION_MODE_PSYS 0ULL
#define ATTRIBUTION_MODE_MODEL 1ULL

static volatile sig_atomic_t g_stop = 0;

struct energy_model_config {
    __u64 attribution_mode;
    __u64 default_freq_multiplier;
    __u64 wakeup_penalty;
    __u64 cycles_weight;
    __u64 instructions_weight;
    __u64 cache_miss_weight;
    __u64 migration_penalty;
};

struct runtime_model_config {
    __u64 idle_power_uw;
    __u32 psys_interval_ms;
};

struct collection_options {
    const char *csv_path;
    const char *label;
    FILE *fp;
};

struct loaded_energy_model {
    struct energy_model_config bpf_cfg;
    struct runtime_model_config runtime_cfg;
    struct freq_multiplier_entry *freq_entries;
    size_t freq_count;
    size_t freq_cap;
};

struct freq_multiplier_entry {
    __u32 khz;
    __u64 multiplier;
};

struct process_freq_key {
    __u32 tgid;
    __u32 cpu_khz;
};

struct psys_split_state {
    __u64 uj_per_score_scaled;
    __u64 interval_score;
    __u64 interval_psys_uj;
    __u64 interval_active_psys_uj;
    __u64 interval_idle_uj;
    __u64 update_count;
};

struct process_counter_snapshot {
    __u32 tgid;
    __u64 value;
};

struct freq_counter_snapshot {
    struct process_freq_key key;
    __u64 value;
};

struct process_score_accumulator {
    __u32 tgid;
    __u64 score;
};

struct interval_freq_total {
    __u32 khz;
    __u64 runtime_ns;
};

struct interval_stats {
    __u64 runtime_ns;
    __u64 wakeups;
    __u64 cycles;
    __u64 instructions;
    __u64 cache_misses;
    __u64 migrations;
    struct interval_freq_total *freq_totals;
    size_t freq_count;
    size_t freq_cap;
};

struct attribution_state {
    struct process_counter_snapshot *wakeup_prev;
    size_t wakeup_prev_count;
    size_t wakeup_prev_cap;
    struct process_counter_snapshot *cycles_prev;
    size_t cycles_prev_count;
    size_t cycles_prev_cap;
    struct process_counter_snapshot *instructions_prev;
    size_t instructions_prev_count;
    size_t instructions_prev_cap;
    struct process_counter_snapshot *cache_miss_prev;
    size_t cache_miss_prev_count;
    size_t cache_miss_prev_cap;
    struct process_counter_snapshot *migration_prev;
    size_t migration_prev_count;
    size_t migration_prev_cap;
    struct freq_counter_snapshot *freq_prev;
    size_t freq_prev_count;
    size_t freq_prev_cap;
    __u64 last_psys_raw;
    struct timespec last_sample_ts;
    bool have_last_psys;
};

static void on_sigint(int signo)
{
    (void)signo;
    g_stop = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *fmt, va_list args)
{
    // show INFO/WARN; hide DEBUG unless you want it
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, fmt, args);
}

static int bump_memlock_rlimit(void)
{
    struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        fprintf(stderr, "setrlimit(RLIMIT_MEMLOCK) failed: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

static int open_cgroup(const char *path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        fprintf(stderr, "Failed to open cgroup %s: %s\n", path, strerror(errno));
    return fd;
}

static int read_text_file(const char *path, char *buf, size_t size)
{
    FILE *fp;

    if (!path || !buf || size == 0)
        return -1;

    fp = fopen(path, "r");
    if (!fp)
        return -1;
    if (!fgets(buf, (int)size, fp)) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

static int read_u32_file(const char *path, __u32 *out)
{
    char buf[64];
    char *end = NULL;
    unsigned long value;

    if (!out || read_text_file(path, buf, sizeof(buf)) != 0)
        return -1;

    errno = 0;
    value = strtoul(buf, &end, 0);
    if (errno || end == buf)
        return -1;
    *out = (__u32)value;
    return 0;
}

static int read_cpu_freq_khz(int cpu, __u32 *out)
{
    static const char *const candidates[] = {
        "scaling_cur_freq",
        "cpuinfo_cur_freq",
        "cpuinfo_avg_freq",
    };
    char path[PATH_MAX];

    if (!out || cpu < 0)
        return -1;

    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        int n = snprintf(path, sizeof(path),
                         "/sys/devices/system/cpu/cpu%d/cpufreq/%s",
                         cpu, candidates[i]);
        if (n <= 0 || (size_t)n >= sizeof(path))
            return -1;
        if (read_u32_file(path, out) == 0 && *out)
            return 0;
    }

    return -1;
}

static int refresh_cpu_khz_map(int map_fd, long cpu_count)
{
    int updated = 0;

    if (map_fd < 0 || cpu_count <= 0)
        return -1;

    for (int cpu = 0; cpu < cpu_count; cpu++) {
        __u32 key = (__u32)cpu;
        __u32 khz;

        if (read_cpu_freq_khz(cpu, &khz) != 0)
            continue;
        if (bpf_map_update_elem(map_fd, &key, &khz, BPF_ANY) != 0) {
            fprintf(stderr, "Failed to update cpu_khz[%d]: %s\n",
                    cpu, strerror(errno));
            return -1;
        }
        updated++;
    }

    return updated;
}

static int read_long_double_file(const char *path, long double *out)
{
    char buf[128];
    char *end = NULL;
    long double value;

    if (!out || read_text_file(path, buf, sizeof(buf)) != 0)
        return -1;

    errno = 0;
    value = strtold(buf, &end);
    if (errno || end == buf)
        return -1;
    *out = value;
    return 0;
}

static int parse_event_config(const char *text, __u64 *out)
{
    const char *event;
    char *end = NULL;
    unsigned long long value;

    if (!text || !out)
        return -1;

    event = strstr(text, "event=");
    if (!event)
        return -1;
    event += 6;

    errno = 0;
    value = strtoull(event, &end, 0);
    if (errno || end == event)
        return -1;
    *out = value;
    return 0;
}

static int parse_first_cpu(const char *cpumask, int *cpu_out)
{
    char *end = NULL;
    long cpu;

    if (!cpumask || !cpu_out)
        return -1;

    errno = 0;
    cpu = strtol(cpumask, &end, 10);
    if (errno || end == cpumask || cpu < 0)
        return -1;
    *cpu_out = (int)cpu;
    return 0;
}

static long get_cpu_count(void)
{
    long cpu_count = sysconf(_SC_NPROCESSORS_CONF);

    return cpu_count > 0 ? cpu_count : -1;
}

static int perf_event_open_cpu(__u64 config, int cpu)
{
    struct perf_event_attr attr = {};

    attr.type = PERF_TYPE_HARDWARE;
    attr.size = sizeof(attr);
    attr.config = config;
    attr.disabled = 0;
    attr.exclude_hv = 1;
    attr.inherit = 0;

    return syscall(__NR_perf_event_open, &attr, -1, cpu, -1, 0);
}

static int perf_event_open_dynamic(__u32 type, __u64 config, int cpu)
{
    struct perf_event_attr attr = {};

    attr.type = type;
    attr.size = sizeof(attr);
    attr.config = config;
    attr.disabled = 0;

    return syscall(__NR_perf_event_open, &attr, -1, cpu, -1, 0);
}

static int populate_psys_perf_event(int map_fd, long double *scale_uj_out)
{
    static const char *type_path = "/sys/bus/event_source/devices/power/type";
    static const char *event_path = "/sys/bus/event_source/devices/power/events/energy-psys";
    static const char *scale_path = "/sys/bus/event_source/devices/power/events/energy-psys.scale";
    static const char *cpumask_path = "/sys/bus/event_source/devices/power/cpumask";
    char event_buf[128];
    char cpumask_buf[128];
    __u32 type;
    __u64 config;
    long double scale_joules;
    int cpu = 0;
    int fd;
    __u32 key = 0;

    if (!scale_uj_out)
        return -1;
    if (read_u32_file(type_path, &type) != 0)
        return -1;
    if (read_text_file(event_path, event_buf, sizeof(event_buf)) != 0)
        return -1;
    if (read_long_double_file(scale_path, &scale_joules) != 0)
        return -1;
    if (parse_event_config(event_buf, &config) != 0)
        return -1;
    if (read_text_file(cpumask_path, cpumask_buf, sizeof(cpumask_buf)) == 0)
        (void)parse_first_cpu(cpumask_buf, &cpu);

    fd = perf_event_open_dynamic(type, config, cpu);
    if (fd < 0) {
        fprintf(stderr, "perf_event_open(energy-psys, cpu=%d) failed: %s\n",
                cpu, strerror(errno));
        return -1;
    }
    if (bpf_map_update_elem(map_fd, &key, &fd, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to populate psys perf event map: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    *scale_uj_out = scale_joules * 1000000.0L;
    return fd;
}

static int populate_perf_event_array(int map_fd, __u64 config, const char *name,
                                     long cpu_count, int **fds_out)
{
    int *fds;

    if (!fds_out || cpu_count <= 0)
        return -1;

    fds = calloc((size_t)cpu_count, sizeof(*fds));
    if (!fds) {
        fprintf(stderr, "calloc failed for %s perf fds\n", name);
        return -1;
    }
    for (int cpu = 0; cpu < cpu_count; cpu++)
        fds[cpu] = -1;

    for (int cpu = 0; cpu < cpu_count; cpu++) {
        int fd = perf_event_open_cpu(config, cpu);
        __u32 key = cpu;

        if (fd < 0) {
            fprintf(stderr, "perf_event_open(%s, cpu=%d) failed: %s\n",
                    name, cpu, strerror(errno));
            goto fail;
        }
        if (bpf_map_update_elem(map_fd, &key, &fd, BPF_ANY) != 0) {
            fprintf(stderr, "Failed to populate %s perf array for cpu %d: %s\n",
                    name, cpu, strerror(errno));
            close(fd);
            goto fail;
        }
        fds[cpu] = fd;
    }

    *fds_out = fds;
    return 0;

fail:
    for (int cpu = 0; cpu < cpu_count; cpu++) {
        if (fds[cpu] >= 0)
            close(fds[cpu]);
    }
    free(fds);
    return -1;
}

static void close_perf_event_array(int *fds, long cpu_count)
{
    if (!fds || cpu_count <= 0)
        return;

    for (int cpu = 0; cpu < cpu_count; cpu++) {
        if (fds[cpu] >= 0)
            close(fds[cpu]);
    }
    free(fds);
}

static char *trim(char *s)
{
    while (*s && isspace((unsigned char)*s))
        s++;
    if (*s == '\0')
        return s;

    char *end = s + strlen(s) - 1;
    while (end >= s && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
    }
    return s;
}

static int parse_scaled_multiplier(const char *text, __u64 *out)
{
    char *end = NULL;
    double value;

    if (!text || !out)
        return -1;

    errno = 0;
    value = strtod(text, &end);
    if (errno || end == text || value < 0)
        return -1;
    while (*end && isspace((unsigned char)*end))
        end++;
    if (*end != '\0')
        return -1;

    *out = (__u64)(value * (double)ENERGY_MODEL_SCALE + 0.5);
    return 0;
}

static int parse_u64_value(const char *text, __u64 *out)
{
    char *end = NULL;
    unsigned long long value;

    if (!text || !out)
        return -1;

    errno = 0;
    value = strtoull(text, &end, 0);
    if (errno || end == text)
        return -1;
    while (*end && isspace((unsigned char)*end))
        end++;
    if (*end != '\0')
        return -1;

    *out = value;
    return 0;
}

static __u64 mul_div_u64(__u64 value, __u64 multiplier, __u64 divisor)
{
    __uint128_t scaled;

    if (!divisor)
        return 0;

    scaled = (__uint128_t)value * (__uint128_t)multiplier;
    return (__u64)(scaled / divisor);
}

static __u64 scale_weighted_score(__u64 value, __u64 weight)
{
    return mul_div_u64(value, weight, ENERGY_MODEL_SCALE);
}

static __u64 freq_multiplier_for_khz(const struct loaded_energy_model *model, __u32 cpu_khz)
{
    if (!model)
        return ENERGY_MODEL_SCALE;

    for (size_t i = 0; i < model->freq_count; i++) {
        if (model->freq_entries[i].khz == cpu_khz)
            return model->freq_entries[i].multiplier;
    }

    return model->bpf_cfg.default_freq_multiplier;
}

static int upsert_freq_multiplier(struct loaded_energy_model *model, __u32 khz, __u64 multiplier)
{
    struct freq_multiplier_entry *entries;

    if (!model)
        return -1;

    for (size_t i = 0; i < model->freq_count; i++) {
        if (model->freq_entries[i].khz == khz) {
            model->freq_entries[i].multiplier = multiplier;
            return 0;
        }
    }

    if (model->freq_count == model->freq_cap) {
        size_t new_cap = model->freq_cap ? model->freq_cap * 2 : 16;

        entries = realloc(model->freq_entries, new_cap * sizeof(*entries));
        if (!entries)
            return -1;
        model->freq_entries = entries;
        model->freq_cap = new_cap;
    }

    model->freq_entries[model->freq_count].khz = khz;
    model->freq_entries[model->freq_count].multiplier = multiplier;
    model->freq_count++;
    return 0;
}

static void free_loaded_energy_model(struct loaded_energy_model *model)
{
    if (!model)
        return;

    free(model->freq_entries);
    model->freq_entries = NULL;
    model->freq_count = 0;
    model->freq_cap = 0;
}

static const char *attribution_mode_name(__u64 mode)
{
    return mode == ATTRIBUTION_MODE_MODEL ? "model" : "psys";
}

static int parse_attribution_mode(const char *text, __u64 *out)
{
    if (!text || !out)
        return -1;
    if (strcmp(text, "psys") == 0) {
        *out = ATTRIBUTION_MODE_PSYS;
        return 0;
    }
    if (strcmp(text, "model") == 0) {
        *out = ATTRIBUTION_MODE_MODEL;
        return 0;
    }

    return -1;
}

static void free_interval_stats(struct interval_stats *stats)
{
    if (!stats)
        return;

    free(stats->freq_totals);
    memset(stats, 0, sizeof(*stats));
}

static int ensure_interval_freq_capacity(struct interval_stats *stats, size_t needed)
{
    struct interval_freq_total *new_freqs;
    size_t new_cap;

    if (!stats)
        return -1;
    if (needed <= stats->freq_cap)
        return 0;

    new_cap = stats->freq_cap ? stats->freq_cap * 2 : 16;
    while (new_cap < needed)
        new_cap *= 2;

    new_freqs = realloc(stats->freq_totals, new_cap * sizeof(*new_freqs));
    if (!new_freqs)
        return -1;

    stats->freq_totals = new_freqs;
    stats->freq_cap = new_cap;
    return 0;
}

static int add_interval_freq_runtime(struct interval_stats *stats, __u32 khz, __u64 runtime_ns)
{
    if (!stats || !khz || !runtime_ns)
        return 0;

    for (size_t i = 0; i < stats->freq_count; i++) {
        if (stats->freq_totals[i].khz == khz) {
            stats->freq_totals[i].runtime_ns += runtime_ns;
            return 0;
        }
    }

    if (ensure_interval_freq_capacity(stats, stats->freq_count + 1) != 0)
        return -1;

    stats->freq_totals[stats->freq_count].khz = khz;
    stats->freq_totals[stats->freq_count].runtime_ns = runtime_ns;
    stats->freq_count++;
    return 0;
}

static __u64 timespec_to_ns(const struct timespec *ts)
{
    if (!ts)
        return 0;
    return (__u64)ts->tv_sec * 1000000000ULL + (__u64)ts->tv_nsec;
}

static int open_collection_output(struct collection_options *options)
{
    struct stat st = {};
    bool write_header = true;

    if (!options || !options->csv_path)
        return 0;

    if (stat(options->csv_path, &st) == 0 && st.st_size > 0)
        write_header = false;

    options->fp = fopen(options->csv_path, "a");
    if (!options->fp) {
        fprintf(stderr, "Failed to open collection CSV %s: %s\n",
                options->csv_path, strerror(errno));
        return -1;
    }

    if (write_header) {
        fprintf(options->fp,
                "sample_time_ns,label,mode,interval_ns,interval_psys_uj,active_psys_uj,"
                "idle_uj,total_score,runtime_ns,wakeups,cycles,instructions,"
                "cache_misses,migrations,freq_runtime_ns\n");
        fflush(options->fp);
    }

    return 0;
}

static void close_collection_output(struct collection_options *options)
{
    if (!options || !options->fp)
        return;

    fclose(options->fp);
    options->fp = NULL;
}

static int write_interval_sample(FILE *fp, const char *label, __u64 mode,
                                 const struct timespec *sample_ts, __u64 interval_ns,
                                 __u64 interval_psys_uj, __u64 active_psys_uj, __u64 idle_uj,
                                 __u64 total_score, const struct interval_stats *stats)
{
    if (!fp || !sample_ts || !stats)
        return -1;

    fprintf(fp,
            "%llu,%s,%s,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,\"",
            (unsigned long long)timespec_to_ns(sample_ts),
            label ? label : "default",
            attribution_mode_name(mode),
            (unsigned long long)interval_ns,
            (unsigned long long)interval_psys_uj,
            (unsigned long long)active_psys_uj,
            (unsigned long long)idle_uj,
            (unsigned long long)total_score,
            (unsigned long long)stats->runtime_ns,
            (unsigned long long)stats->wakeups,
            (unsigned long long)stats->cycles,
            (unsigned long long)stats->instructions,
            (unsigned long long)stats->cache_misses,
            (unsigned long long)stats->migrations);

    for (size_t i = 0; i < stats->freq_count; i++) {
        if (i)
            fputc(';', fp);
        fprintf(fp, "%u:%llu",
                stats->freq_totals[i].khz,
                (unsigned long long)stats->freq_totals[i].runtime_ns);
    }
    fprintf(fp, "\"\n");
    fflush(fp);
    return ferror(fp) ? -1 : 0;
}

static int ensure_process_score_capacity(struct process_score_accumulator **scores,
                                         size_t *cap, size_t needed)
{
    struct process_score_accumulator *new_scores;
    size_t new_cap;

    if (!scores || !cap)
        return -1;
    if (needed <= *cap)
        return 0;

    new_cap = *cap ? *cap * 2 : 32;
    while (new_cap < needed)
        new_cap *= 2;

    new_scores = realloc(*scores, new_cap * sizeof(**scores));
    if (!new_scores)
        return -1;

    *scores = new_scores;
    *cap = new_cap;
    return 0;
}

static int add_process_score(struct process_score_accumulator **scores, size_t *count,
                             size_t *cap, __u32 tgid, __u64 delta_score)
{
    if (!scores || !count || !cap || !tgid || !delta_score)
        return 0;

    for (size_t i = 0; i < *count; i++) {
        if ((*scores)[i].tgid == tgid) {
            (*scores)[i].score += delta_score;
            return 0;
        }
    }

    if (ensure_process_score_capacity(scores, cap, *count + 1) != 0)
        return -1;

    (*scores)[*count].tgid = tgid;
    (*scores)[*count].score = delta_score;
    (*count)++;
    return 0;
}

static int ensure_counter_snapshot_capacity(struct process_counter_snapshot **entries,
                                            size_t *cap, size_t needed)
{
    struct process_counter_snapshot *new_entries;
    size_t new_cap;

    if (!entries || !cap)
        return -1;
    if (needed <= *cap)
        return 0;

    new_cap = *cap ? *cap * 2 : 64;
    while (new_cap < needed)
        new_cap *= 2;

    new_entries = realloc(*entries, new_cap * sizeof(**entries));
    if (!new_entries)
        return -1;

    *entries = new_entries;
    *cap = new_cap;
    return 0;
}

static ssize_t find_counter_snapshot(const struct process_counter_snapshot *entries,
                                     size_t count, __u32 tgid)
{
    for (size_t i = 0; i < count; i++) {
        if (entries[i].tgid == tgid)
            return (ssize_t)i;
    }

    return -1;
}

static int upsert_counter_snapshot(struct process_counter_snapshot **entries, size_t *count,
                                   size_t *cap, __u32 tgid, __u64 value)
{
    ssize_t idx;

    if (!entries || !count || !cap)
        return -1;

    idx = find_counter_snapshot(*entries, *count, tgid);
    if (idx >= 0) {
        (*entries)[idx].value = value;
        return 0;
    }

    if (ensure_counter_snapshot_capacity(entries, cap, *count + 1) != 0)
        return -1;

    (*entries)[*count].tgid = tgid;
    (*entries)[*count].value = value;
    (*count)++;
    return 0;
}

static int ensure_freq_snapshot_capacity(struct freq_counter_snapshot **entries,
                                         size_t *cap, size_t needed)
{
    struct freq_counter_snapshot *new_entries;
    size_t new_cap;

    if (!entries || !cap)
        return -1;
    if (needed <= *cap)
        return 0;

    new_cap = *cap ? *cap * 2 : 128;
    while (new_cap < needed)
        new_cap *= 2;

    new_entries = realloc(*entries, new_cap * sizeof(**entries));
    if (!new_entries)
        return -1;

    *entries = new_entries;
    *cap = new_cap;
    return 0;
}

static bool same_process_freq_key(struct process_freq_key a, struct process_freq_key b)
{
    return a.tgid == b.tgid && a.cpu_khz == b.cpu_khz;
}

static ssize_t find_freq_snapshot(const struct freq_counter_snapshot *entries, size_t count,
                                  struct process_freq_key key)
{
    for (size_t i = 0; i < count; i++) {
        if (same_process_freq_key(entries[i].key, key))
            return (ssize_t)i;
    }

    return -1;
}

static int upsert_freq_snapshot(struct freq_counter_snapshot **entries, size_t *count,
                                size_t *cap, struct process_freq_key key, __u64 value)
{
    ssize_t idx;

    if (!entries || !count || !cap)
        return -1;

    idx = find_freq_snapshot(*entries, *count, key);
    if (idx >= 0) {
        (*entries)[idx].value = value;
        return 0;
    }

    if (ensure_freq_snapshot_capacity(entries, cap, *count + 1) != 0)
        return -1;

    (*entries)[*count].key = key;
    (*entries)[*count].value = value;
    (*count)++;
    return 0;
}

static __u64 raw_psys_to_uj(__u64 delta_raw, long double scale_uj)
{
    long double energy = (long double)delta_raw * scale_uj;

    if (energy <= 0.0L)
        return 0;
    if (energy >= (long double)~(__u64)0)
        return ~(__u64)0;
    return (__u64)(energy + 0.5L);
}

static __u64 interval_idle_uj(__u64 idle_power_uw, const struct timespec *prev,
                              const struct timespec *now)
{
    time_t sec_delta;
    long nsec_delta;
    __u64 delta_ns;

    if (!idle_power_uw || !prev || !now)
        return 0;
    if (now->tv_sec < prev->tv_sec ||
        (now->tv_sec == prev->tv_sec && now->tv_nsec <= prev->tv_nsec))
        return 0;

    sec_delta = now->tv_sec - prev->tv_sec;
    nsec_delta = now->tv_nsec - prev->tv_nsec;
    if (nsec_delta < 0) {
        sec_delta -= 1;
        nsec_delta += 1000000000L;
    }
    if (sec_delta < 0)
        return 0;

    delta_ns = (__u64)sec_delta * 1000000000ULL + (__u64)nsec_delta;
    return mul_div_u64(idle_power_uw, delta_ns, 1000000000ULL);
}

static int read_perf_counter_value(int fd, __u64 *value_out)
{
    __u64 value;
    ssize_t nread;

    if (fd < 0 || !value_out)
        return -1;

    nread = read(fd, &value, sizeof(value));
    if (nread != (ssize_t)sizeof(value))
        return -1;

    *value_out = value;
    return 0;
}

static int collect_weighted_process_counters(int map_fd,
                                             struct process_counter_snapshot **prev_entries,
                                             size_t *prev_count, size_t *prev_cap,
                                             __u64 weight, bool fixed_point_weight,
                                             struct process_score_accumulator **scores,
                                             size_t *score_count, size_t *score_cap,
                                             __u64 *total_score, __u64 *raw_total_out)
{
    __u32 key = 0;
    __u32 next_key;
    int err;

    if (map_fd < 0 || !prev_entries || !prev_count || !prev_cap ||
        !scores || !score_count || !score_cap || !total_score)
        return -1;

    if (raw_total_out)
        *raw_total_out = 0;

    err = bpf_map_get_next_key(map_fd, NULL, &next_key);
    while (err == 0) {
        __u64 current_value;
        __u64 prev_value = 0;
        __u64 delta = 0;
        __u64 delta_score = 0;
        ssize_t idx;

        if (bpf_map_lookup_elem(map_fd, &next_key, &current_value) != 0)
            return -1;

        idx = find_counter_snapshot(*prev_entries, *prev_count, next_key);
        if (idx >= 0)
            prev_value = (*prev_entries)[idx].value;
        if (current_value >= prev_value)
            delta = current_value - prev_value;

        if (delta) {
            if (raw_total_out)
                *raw_total_out += delta;
            delta_score = fixed_point_weight ? scale_weighted_score(delta, weight)
                                             : delta * weight;
            if (delta_score) {
                if (add_process_score(scores, score_count, score_cap, next_key, delta_score) != 0)
                    return -1;
                *total_score += delta_score;
            }
        }

        if (upsert_counter_snapshot(prev_entries, prev_count, prev_cap, next_key, current_value) != 0)
            return -1;

        key = next_key;
        err = bpf_map_get_next_key(map_fd, &key, &next_key);
    }

    return (err != 0 && errno == ENOENT) ? 0 : -1;
}

static int collect_freq_runtime_scores(int map_fd, const struct loaded_energy_model *model,
                                       struct freq_counter_snapshot **prev_entries,
                                       size_t *prev_count, size_t *prev_cap,
                                       struct process_score_accumulator **scores,
                                       size_t *score_count, size_t *score_cap,
                                       __u64 *total_score, struct interval_stats *stats)
{
    struct process_freq_key key = {};
    struct process_freq_key next_key;
    int err;

    if (map_fd < 0 || !model || !prev_entries || !prev_count || !prev_cap ||
        !scores || !score_count || !score_cap || !total_score)
        return -1;

    if (stats)
        stats->runtime_ns = 0;

    err = bpf_map_get_next_key(map_fd, NULL, &next_key);
    while (err == 0) {
        __u64 current_value;
        __u64 prev_value = 0;
        __u64 delta = 0;
        __u64 delta_score = 0;
        __u64 multiplier;
        ssize_t idx;

        if (bpf_map_lookup_elem(map_fd, &next_key, &current_value) != 0)
            return -1;

        idx = find_freq_snapshot(*prev_entries, *prev_count, next_key);
        if (idx >= 0)
            prev_value = (*prev_entries)[idx].value;
        if (current_value >= prev_value)
            delta = current_value - prev_value;

        if (delta) {
            if (stats) {
                stats->runtime_ns += delta;
                if (add_interval_freq_runtime(stats, next_key.cpu_khz, delta) != 0)
                    return -1;
            }
            multiplier = freq_multiplier_for_khz(model, next_key.cpu_khz);
            delta_score = scale_weighted_score(delta, multiplier);
            if (delta_score) {
                if (add_process_score(scores, score_count, score_cap, next_key.tgid, delta_score) != 0)
                    return -1;
                *total_score += delta_score;
            }
        }

        if (upsert_freq_snapshot(prev_entries, prev_count, prev_cap, next_key, current_value) != 0)
            return -1;

        key = next_key;
        err = bpf_map_get_next_key(map_fd, &key, &next_key);
    }

    return (err != 0 && errno == ENOENT) ? 0 : -1;
}

static int seed_counter_snapshot(int map_fd, struct process_counter_snapshot **entries,
                                 size_t *count, size_t *cap)
{
    __u32 key = 0;
    __u32 next_key;
    int err;

    if (map_fd < 0 || !entries || !count || !cap)
        return -1;

    err = bpf_map_get_next_key(map_fd, NULL, &next_key);
    while (err == 0) {
        __u64 value;

        if (bpf_map_lookup_elem(map_fd, &next_key, &value) != 0)
            return -1;
        if (upsert_counter_snapshot(entries, count, cap, next_key, value) != 0)
            return -1;

        key = next_key;
        err = bpf_map_get_next_key(map_fd, &key, &next_key);
    }

    return (err != 0 && errno == ENOENT) ? 0 : -1;
}

static int seed_freq_snapshot(int map_fd, struct freq_counter_snapshot **entries,
                              size_t *count, size_t *cap)
{
    struct process_freq_key key = {};
    struct process_freq_key next_key;
    int err;

    if (map_fd < 0 || !entries || !count || !cap)
        return -1;

    err = bpf_map_get_next_key(map_fd, NULL, &next_key);
    while (err == 0) {
        __u64 value;

        if (bpf_map_lookup_elem(map_fd, &next_key, &value) != 0)
            return -1;
        if (upsert_freq_snapshot(entries, count, cap, next_key, value) != 0)
            return -1;

        key = next_key;
        err = bpf_map_get_next_key(map_fd, &key, &next_key);
    }

    return (err != 0 && errno == ENOENT) ? 0 : -1;
}

static void free_attribution_state(struct attribution_state *state)
{
    if (!state)
        return;

    free(state->wakeup_prev);
    free(state->cycles_prev);
    free(state->instructions_prev);
    free(state->cache_miss_prev);
    free(state->migration_prev);
    free(state->freq_prev);
    memset(state, 0, sizeof(*state));
}

static int load_energy_model_config(const char *path, int model_cfg_fd, int freq_multipliers_fd,
                                    struct loaded_energy_model *model)
{
    FILE *fp = fopen(path, "r");
    char *line = NULL;
    size_t cap = 0;
    ssize_t nread;
    int line_no = 0;
    int ret = -1;
    __u32 cfg_key = 0;
    struct loaded_energy_model loaded = {
        .bpf_cfg = {
            .attribution_mode = ATTRIBUTION_MODE_PSYS,
            .default_freq_multiplier = ENERGY_MODEL_SCALE,
            .wakeup_penalty = 0,
            .cycles_weight = 0,
            .instructions_weight = 0,
            .cache_miss_weight = 0,
            .migration_penalty = 0,
        },
        .runtime_cfg = {
            .idle_power_uw = 0,
            .psys_interval_ms = 200,
        },
    };

    if (!model) {
        if (fp)
            fclose(fp);
        return -1;
    }
    if (!fp) {
        fprintf(stderr, "Failed to open config file %s: %s\n", path, strerror(errno));
        return -1;
    }

    while ((nread = getline(&line, &cap, fp)) != -1) {
        char *cursor;

        (void)nread;
        line_no++;

        cursor = line;
        while (*cursor) {
            if (*cursor == '#') {
                *cursor = '\0';
                break;
            }
            cursor++;
        }

        cursor = trim(line);
        if (*cursor == '\0')
            continue;

        if (strncmp(cursor, "attribution_mode=", 17) == 0) {
            if (parse_attribution_mode(cursor + 17, &loaded.bpf_cfg.attribution_mode) != 0) {
                fprintf(stderr, "Invalid attribution_mode at %s:%d\n", path, line_no);
                goto out;
            }
            continue;
        }

        if (strncmp(cursor, "default_multiplier=", 19) == 0) {
            if (parse_scaled_multiplier(cursor + 19, &loaded.bpf_cfg.default_freq_multiplier) != 0) {
                fprintf(stderr, "Invalid default_multiplier at %s:%d\n", path, line_no);
                goto out;
            }
            continue;
        }

        if (strncmp(cursor, "wakeup_penalty=", 15) == 0) {
            if (parse_u64_value(cursor + 15, &loaded.bpf_cfg.wakeup_penalty) != 0) {
                fprintf(stderr, "Invalid wakeup_penalty at %s:%d\n", path, line_no);
                goto out;
            }
            continue;
        }

        if (strncmp(cursor, "cycles_weight=", 14) == 0) {
            if (parse_scaled_multiplier(cursor + 14, &loaded.bpf_cfg.cycles_weight) != 0) {
                fprintf(stderr, "Invalid cycles_weight at %s:%d\n", path, line_no);
                goto out;
            }
            continue;
        }

        if (strncmp(cursor, "instructions_weight=", 20) == 0) {
            if (parse_scaled_multiplier(cursor + 20, &loaded.bpf_cfg.instructions_weight) != 0) {
                fprintf(stderr, "Invalid instructions_weight at %s:%d\n", path, line_no);
                goto out;
            }
            continue;
        }

        if (strncmp(cursor, "cache_miss_weight=", 18) == 0) {
            if (parse_scaled_multiplier(cursor + 18, &loaded.bpf_cfg.cache_miss_weight) != 0) {
                fprintf(stderr, "Invalid cache_miss_weight at %s:%d\n", path, line_no);
                goto out;
            }
            continue;
        }

        if (strncmp(cursor, "migration_penalty=", 18) == 0) {
            if (parse_u64_value(cursor + 18, &loaded.bpf_cfg.migration_penalty) != 0) {
                fprintf(stderr, "Invalid migration_penalty at %s:%d\n", path, line_no);
                goto out;
            }
            continue;
        }

        if (strncmp(cursor, "idle_power_uw=", 14) == 0) {
            if (parse_u64_value(cursor + 14, &loaded.runtime_cfg.idle_power_uw) != 0) {
                fprintf(stderr, "Invalid idle_power_uw at %s:%d\n", path, line_no);
                goto out;
            }
            continue;
        }

        if (strncmp(cursor, "psys_interval_ms=", 17) == 0) {
            __u64 interval_ms;

            if (parse_u64_value(cursor + 17, &interval_ms) != 0 || interval_ms == 0 || interval_ms > 60000) {
                fprintf(stderr, "Invalid psys_interval_ms at %s:%d\n", path, line_no);
                goto out;
            }
            loaded.runtime_cfg.psys_interval_ms = (__u32)interval_ms;
            continue;
        }

        if (strncmp(cursor, "freq_khz=", 9) == 0) {
            __u32 khz;
            __u64 multiplier;
            char *value = trim(cursor + 9);
            char *sep = value;
            char *end = NULL;

            while (*sep && !isspace((unsigned char)*sep))
                sep++;
            if (*sep == '\0') {
                fprintf(stderr, "Invalid freq_khz entry at %s:%d\n", path, line_no);
                goto out;
            }
            *sep++ = '\0';
            sep = trim(sep);
            if (*sep == '\0') {
                fprintf(stderr, "Invalid freq_khz entry at %s:%d\n", path, line_no);
                goto out;
            }

            errno = 0;
            khz = strtoul(value, &end, 0);
            if (errno || end == value || *trim(end) != '\0') {
                fprintf(stderr, "Invalid frequency key at %s:%d\n", path, line_no);
                goto out;
            }
            if (parse_scaled_multiplier(sep, &multiplier) != 0) {
                fprintf(stderr, "Invalid frequency multiplier at %s:%d\n", path, line_no);
                goto out;
            }
            if (bpf_map_update_elem(freq_multipliers_fd, &khz, &multiplier, BPF_ANY) != 0) {
                fprintf(stderr, "Failed to write freq multiplier for %u kHz: %s\n",
                        khz, strerror(errno));
                goto out;
            }
            if (upsert_freq_multiplier(&loaded, khz, multiplier) != 0) {
                fprintf(stderr, "Failed to store freq multiplier for %u kHz in userspace\n", khz);
                goto out;
            }
            continue;
        }

        fprintf(stderr, "Unknown config key at %s:%d: %s\n", path, line_no, cursor);
        goto out;
    }

    if (bpf_map_update_elem(model_cfg_fd, &cfg_key, &loaded.bpf_cfg, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to write model config: %s\n", strerror(errno));
        goto out;
    }

    *model = loaded;
    loaded.freq_entries = NULL;
    loaded.freq_count = 0;
    loaded.freq_cap = 0;
    ret = 0;

out:
    free(loaded.freq_entries);
    free(line);
    fclose(fp);
    return ret;
}

static int seed_attribution_state(struct attribution_state *state, int process_freq_runtime_fd,
                                  int process_wakeup_fd, int process_cycles_fd,
                                  int process_instructions_fd, int process_cache_miss_fd,
                                  int process_migrations_fd, int psys_fd)
{
    if (!state || psys_fd < 0)
        return -1;

    if (seed_freq_snapshot(process_freq_runtime_fd, &state->freq_prev,
                           &state->freq_prev_count, &state->freq_prev_cap) != 0)
        return -1;
    if (seed_counter_snapshot(process_wakeup_fd, &state->wakeup_prev,
                              &state->wakeup_prev_count, &state->wakeup_prev_cap) != 0)
        return -1;
    if (seed_counter_snapshot(process_cycles_fd, &state->cycles_prev,
                              &state->cycles_prev_count, &state->cycles_prev_cap) != 0)
        return -1;
    if (seed_counter_snapshot(process_instructions_fd, &state->instructions_prev,
                              &state->instructions_prev_count, &state->instructions_prev_cap) != 0)
        return -1;
    if (seed_counter_snapshot(process_cache_miss_fd, &state->cache_miss_prev,
                              &state->cache_miss_prev_count, &state->cache_miss_prev_cap) != 0)
        return -1;
    if (seed_counter_snapshot(process_migrations_fd, &state->migration_prev,
                              &state->migration_prev_count, &state->migration_prev_cap) != 0)
        return -1;
    if (read_perf_counter_value(psys_fd, &state->last_psys_raw) != 0)
        return -1;
    if (clock_gettime(CLOCK_MONOTONIC, &state->last_sample_ts) != 0)
        return -1;

    state->have_last_psys = true;
    return 0;
}

static int update_process_attributed_energy(int map_fd,
                                            const struct process_score_accumulator *scores,
                                            size_t score_count, __u64 interval_energy_uj,
                                            __u64 total_score)
{
    if (map_fd < 0 || !scores || !score_count || !interval_energy_uj || !total_score)
        return 0;

    for (size_t i = 0; i < score_count; i++) {
        __u32 tgid = scores[i].tgid;
        __u64 current_value = 0;
        __u64 delta_energy = mul_div_u64(interval_energy_uj, scores[i].score, total_score);
        __u64 new_value;

        if (!tgid || !delta_energy)
            continue;

        if (bpf_map_lookup_elem(map_fd, &tgid, &current_value) != 0)
            current_value = 0;
        new_value = current_value + delta_energy;
        if (bpf_map_update_elem(map_fd, &tgid, &new_value, BPF_ANY) != 0)
            return -1;
    }

    return 0;
}

static int run_psys_split_update(const struct loaded_energy_model *model,
                                 struct attribution_state *state, long double psys_scale_uj,
                                 int psys_fd, int psys_split_fd,
                                 int process_freq_runtime_fd, int process_wakeup_fd,
                                 int process_cycles_fd, int process_instructions_fd,
                                 int process_cache_miss_fd, int process_migrations_fd,
                                 int process_attributed_energy_fd,
                                 const struct collection_options *collection)
{
    struct process_score_accumulator *scores = NULL;
    size_t score_count = 0;
    size_t score_cap = 0;
    struct psys_split_state split = {};
    struct interval_stats stats = {};
    struct timespec now_ts;
    __u64 raw_now;
    __u64 delta_raw = 0;
    __u64 total_score = 0;
    __u64 interval_ns = 0;
    __u64 interval_psys_uj = 0;
    __u64 idle_uj = 0;
    __u64 active_psys_uj = 0;
    __u64 uj_per_score_scaled = 0;
    __u32 key = 0;
    int ret = -1;

    if (!model || !state || psys_fd < 0 || psys_split_fd < 0)
        return -1;
    if (!state->have_last_psys)
        return -1;
    if (clock_gettime(CLOCK_MONOTONIC, &now_ts) != 0)
        return -1;
    if (read_perf_counter_value(psys_fd, &raw_now) != 0)
        return -1;

    if (collect_freq_runtime_scores(process_freq_runtime_fd, model, &state->freq_prev,
                                    &state->freq_prev_count, &state->freq_prev_cap,
                                    &scores, &score_count, &score_cap, &total_score,
                                    &stats) != 0)
        goto out;
    if (collect_weighted_process_counters(process_wakeup_fd, &state->wakeup_prev,
                                          &state->wakeup_prev_count, &state->wakeup_prev_cap,
                                          model->bpf_cfg.wakeup_penalty, false,
                                          &scores, &score_count, &score_cap, &total_score,
                                          &stats.wakeups) != 0)
        goto out;
    if (collect_weighted_process_counters(process_cycles_fd, &state->cycles_prev,
                                          &state->cycles_prev_count, &state->cycles_prev_cap,
                                          model->bpf_cfg.cycles_weight, true,
                                          &scores, &score_count, &score_cap, &total_score,
                                          &stats.cycles) != 0)
        goto out;
    if (collect_weighted_process_counters(process_instructions_fd, &state->instructions_prev,
                                          &state->instructions_prev_count, &state->instructions_prev_cap,
                                          model->bpf_cfg.instructions_weight, true,
                                          &scores, &score_count, &score_cap, &total_score,
                                          &stats.instructions) != 0)
        goto out;
    if (collect_weighted_process_counters(process_cache_miss_fd, &state->cache_miss_prev,
                                          &state->cache_miss_prev_count, &state->cache_miss_prev_cap,
                                          model->bpf_cfg.cache_miss_weight, true,
                                          &scores, &score_count, &score_cap, &total_score,
                                          &stats.cache_misses) != 0)
        goto out;
    if (collect_weighted_process_counters(process_migrations_fd, &state->migration_prev,
                                          &state->migration_prev_count, &state->migration_prev_cap,
                                          model->bpf_cfg.migration_penalty, false,
                                          &scores, &score_count, &score_cap, &total_score,
                                          &stats.migrations) != 0)
        goto out;

    interval_ns = timespec_to_ns(&now_ts) - timespec_to_ns(&state->last_sample_ts);
    if (raw_now >= state->last_psys_raw)
        delta_raw = raw_now - state->last_psys_raw;
    interval_psys_uj = raw_psys_to_uj(delta_raw, psys_scale_uj);
    idle_uj = interval_idle_uj(model->runtime_cfg.idle_power_uw, &state->last_sample_ts, &now_ts);
    active_psys_uj = interval_psys_uj > idle_uj ? interval_psys_uj - idle_uj : 0;
    if (total_score && active_psys_uj)
        uj_per_score_scaled = mul_div_u64(active_psys_uj, PSYS_SPLIT_SCALE, total_score);

    if (model->bpf_cfg.attribution_mode == ATTRIBUTION_MODE_PSYS) {
        if (update_process_attributed_energy(process_attributed_energy_fd, scores, score_count,
                                             active_psys_uj, total_score) != 0)
            goto out;
    }

    if (bpf_map_lookup_elem(psys_split_fd, &key, &split) != 0)
        memset(&split, 0, sizeof(split));
    split.uj_per_score_scaled = uj_per_score_scaled;
    split.interval_score = total_score;
    split.interval_psys_uj = interval_psys_uj;
    split.interval_active_psys_uj = active_psys_uj;
    split.interval_idle_uj = idle_uj;
    split.update_count += 1;
    if (bpf_map_update_elem(psys_split_fd, &key, &split, BPF_ANY) != 0)
        goto out;

    if (collection && collection->fp) {
        if (write_interval_sample(collection->fp, collection->label,
                                  model->bpf_cfg.attribution_mode, &now_ts,
                                  interval_ns, interval_psys_uj, active_psys_uj,
                                  idle_uj, total_score, &stats) != 0) {
            fprintf(stderr, "Failed to write interval sample to %s\n", collection->csv_path);
            goto out;
        }
    }

    state->last_psys_raw = raw_now;
    state->last_sample_ts = now_ts;
    ret = 0;

out:
    free_interval_stats(&stats);
    free(scores);
    return ret;
}

int main(int argc, char **argv)
{
    int ret = 1;
    int argi = 1;
    int cg_fd = -1;
    int psys_fd = -1;
    long cpu_count = -1;
    long double psys_scale_uj = 0.0L;
    bool sockops_attached = false;
    bool ingress_attached = false;
    bool skmsg_attached = false;
    bool need_psys = false;
    struct loaded_energy_model model = {};
    struct attribution_state attribution = {};
    struct collection_options collection = {};
    struct bpf_object *obj = NULL;
    struct bpf_link *recvmsg_link = NULL;
    struct bpf_link *sched_link = NULL;
    struct bpf_link *freq_link = NULL;
    struct bpf_link *wakeup_link = NULL;
    struct bpf_link *wakeup_new_link = NULL;
    struct bpf_link *migrate_link = NULL;
    int *cycles_fds = NULL;
    int *instructions_fds = NULL;
    int *cache_miss_fds = NULL;

    while (argi < argc && strncmp(argv[argi], "--", 2) == 0) {
        if (strcmp(argv[argi], "--collect-csv") == 0) {
            argi++;
            if (argi >= argc) {
                fprintf(stderr, "--collect-csv requires a path\n");
                return 1;
            }
            collection.csv_path = argv[argi++];
            continue;
        }
        if (strcmp(argv[argi], "--collect-label") == 0) {
            argi++;
            if (argi >= argc) {
                fprintf(stderr, "--collect-label requires a value\n");
                return 1;
            }
            collection.label = argv[argi++];
            continue;
        }

        fprintf(stderr, "Unknown option: %s\n", argv[argi]);
        return 1;
    }

    if (argc - argi != 3) {
        fprintf(stderr,
                "Usage: %s [--collect-csv path] [--collect-label label] "
                "/sys/fs/cgroup/<cg> ./http_energy.bpf.o ./energy_model.conf\n",
                argv[0]);
        return 1;
    }

    const char *cg_path = argv[argi];
    const char *obj_path = argv[argi + 1];
    const char *config_path = argv[argi + 2];

    libbpf_set_print(libbpf_print_fn);

    if (bump_memlock_rlimit() != 0)
        return 1;

    cpu_count = get_cpu_count();
    if (cpu_count <= 0) {
        fprintf(stderr, "Failed to determine CPU count\n");
        return 1;
    }

    cg_fd = open_cgroup(cg_path);
    if (cg_fd < 0)
        goto cleanup;

    obj = bpf_object__open_file(obj_path, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "bpf_object__open_file(%s) failed\n", obj_path);
        obj = NULL;
        goto cleanup;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "bpf_object__load failed\n");
        goto cleanup;
    }

    struct bpf_program *p_sockops = bpf_object__find_program_by_name(obj, "sockops_add_to_sockhash");
    struct bpf_program *p_ingress = bpf_object__find_program_by_name(obj, "track_ingress");
    struct bpf_program *p_recvmsg = bpf_object__find_program_by_name(obj, "bind_request_owner");
    struct bpf_program *p_sched   = bpf_object__find_program_by_name(obj, "account_sched_switch");
    struct bpf_program *p_freq    = bpf_object__find_program_by_name(obj, "track_cpu_frequency");
    struct bpf_program *p_wakeup  = bpf_object__find_program_by_name(obj, "track_sched_wakeup");
    struct bpf_program *p_wakeup_new = bpf_object__find_program_by_name(obj, "track_sched_wakeup_new");
    struct bpf_program *p_migrate = bpf_object__find_program_by_name(obj, "track_sched_migrate_task");
    struct bpf_program *p_skmsg   = bpf_object__find_program_by_name(obj, "inject_energy_header");

    if (!p_sockops || !p_ingress || !p_recvmsg || !p_sched || !p_freq ||
        !p_wakeup || !p_wakeup_new || !p_migrate || !p_skmsg) {
        fprintf(stderr, "Failed to find one or more programs in object\n");
        goto cleanup;
    }

    struct bpf_map *m_sockhash = bpf_object__find_map_by_name(obj, "sockhash");
    if (!m_sockhash) {
        fprintf(stderr, "Failed to find map 'sockhash'\n");
        goto cleanup;
    }
    struct bpf_map *m_model_cfg = bpf_object__find_map_by_name(obj, "model_cfg");
    if (!m_model_cfg) {
        fprintf(stderr, "Failed to find map 'model_cfg'\n");
        goto cleanup;
    }
    struct bpf_map *m_psys_events = bpf_object__find_map_by_name(obj, "psys_events");
    if (!m_psys_events) {
        fprintf(stderr, "Failed to find map 'psys_events'\n");
        goto cleanup;
    }
    struct bpf_map *m_psys_split = bpf_object__find_map_by_name(obj, "psys_split_state");
    if (!m_psys_split) {
        fprintf(stderr, "Failed to find map 'psys_split_state'\n");
        goto cleanup;
    }
    struct bpf_map *m_cpu_khz = bpf_object__find_map_by_name(obj, "cpu_khz");
    if (!m_cpu_khz) {
        fprintf(stderr, "Failed to find map 'cpu_khz'\n");
        goto cleanup;
    }
    struct bpf_map *m_freq_multipliers = bpf_object__find_map_by_name(obj, "freq_multipliers");
    if (!m_freq_multipliers) {
        fprintf(stderr, "Failed to find map 'freq_multipliers'\n");
        goto cleanup;
    }
    struct bpf_map *m_process_freq_runtime = bpf_object__find_map_by_name(obj, "process_freq_runtime");
    struct bpf_map *m_process_wakeup_count = bpf_object__find_map_by_name(obj, "process_wakeup_count");
    struct bpf_map *m_process_cycles = bpf_object__find_map_by_name(obj, "process_cycles");
    struct bpf_map *m_process_instructions = bpf_object__find_map_by_name(obj, "process_instructions");
    struct bpf_map *m_process_cache_misses = bpf_object__find_map_by_name(obj, "process_cache_misses");
    struct bpf_map *m_process_migrations = bpf_object__find_map_by_name(obj, "process_migrations");
    struct bpf_map *m_process_attributed_energy = bpf_object__find_map_by_name(obj, "process_attributed_energy_uj");
    if (!m_process_freq_runtime || !m_process_wakeup_count || !m_process_cycles ||
        !m_process_instructions || !m_process_cache_misses || !m_process_migrations ||
        !m_process_attributed_energy) {
        fprintf(stderr, "Failed to find one or more process attribution maps\n");
        goto cleanup;
    }
    struct bpf_map *m_cycles_events = bpf_object__find_map_by_name(obj, "cycles_events");
    if (!m_cycles_events) {
        fprintf(stderr, "Failed to find map 'cycles_events'\n");
        goto cleanup;
    }
    struct bpf_map *m_instructions_events = bpf_object__find_map_by_name(obj, "instructions_events");
    if (!m_instructions_events) {
        fprintf(stderr, "Failed to find map 'instructions_events'\n");
        goto cleanup;
    }
    struct bpf_map *m_cache_miss_events = bpf_object__find_map_by_name(obj, "cache_miss_events");
    if (!m_cache_miss_events) {
        fprintf(stderr, "Failed to find map 'cache_miss_events'\n");
        goto cleanup;
    }

    int sockhash_fd = bpf_map__fd(m_sockhash);
    int model_cfg_fd = bpf_map__fd(m_model_cfg);
    int psys_events_fd = bpf_map__fd(m_psys_events);
    int psys_split_fd = bpf_map__fd(m_psys_split);
    int cpu_khz_fd = bpf_map__fd(m_cpu_khz);
    int freq_multipliers_fd = bpf_map__fd(m_freq_multipliers);
    int process_freq_runtime_fd = bpf_map__fd(m_process_freq_runtime);
    int process_wakeup_fd = bpf_map__fd(m_process_wakeup_count);
    int process_cycles_fd = bpf_map__fd(m_process_cycles);
    int process_instructions_fd = bpf_map__fd(m_process_instructions);
    int process_cache_miss_fd = bpf_map__fd(m_process_cache_misses);
    int process_migrations_fd = bpf_map__fd(m_process_migrations);
    int process_attributed_energy_fd = bpf_map__fd(m_process_attributed_energy);
    int cycles_events_fd = bpf_map__fd(m_cycles_events);
    int instructions_events_fd = bpf_map__fd(m_instructions_events);
    int cache_miss_events_fd = bpf_map__fd(m_cache_miss_events);

    int sockops_fd = bpf_program__fd(p_sockops);
    int ingress_fd = bpf_program__fd(p_ingress);
    int skmsg_fd   = bpf_program__fd(p_skmsg);

    if (load_energy_model_config(config_path, model_cfg_fd, freq_multipliers_fd, &model) != 0)
        goto cleanup;
    need_psys = collection.csv_path != NULL || model.bpf_cfg.attribution_mode == ATTRIBUTION_MODE_PSYS;
    if (collection.csv_path) {
        if (open_collection_output(&collection) != 0)
            goto cleanup;
    }
    psys_fd = -1;
    if (need_psys) {
        psys_fd = populate_psys_perf_event(psys_events_fd, &psys_scale_uj);
        if (psys_fd < 0) {
            fprintf(stderr, "PSYS perf event unavailable; mode=%s collection=%s\n",
                    attribution_mode_name(model.bpf_cfg.attribution_mode),
                    collection.csv_path ? "enabled" : "disabled");
            goto cleanup;
        }
    }
    if (populate_perf_event_array(cycles_events_fd, PERF_COUNT_HW_CPU_CYCLES,
                                  "cpu-cycles", cpu_count, &cycles_fds) != 0)
        goto cleanup;
    if (populate_perf_event_array(instructions_events_fd, PERF_COUNT_HW_INSTRUCTIONS,
                                  "instructions", cpu_count, &instructions_fds) != 0)
        goto cleanup;
    if (populate_perf_event_array(cache_miss_events_fd, PERF_COUNT_HW_CACHE_MISSES,
                                  "cache-misses", cpu_count, &cache_miss_fds) != 0)
        goto cleanup;

    if (bpf_prog_attach(sockops_fd, cg_fd, BPF_CGROUP_SOCK_OPS, 0)) {
        fprintf(stderr, "attach(sockops) failed: %s\n", strerror(errno));
        goto cleanup;
    }
    sockops_attached = true;

    if (bpf_prog_attach(ingress_fd, cg_fd, BPF_CGROUP_INET_INGRESS, 0)) {
        fprintf(stderr, "attach(cgroup_ingress) failed: %s\n", strerror(errno));
        goto cleanup;
    }
    ingress_attached = true;

    recvmsg_link = bpf_program__attach(p_recvmsg);
    if (libbpf_get_error(recvmsg_link)) {
        fprintf(stderr, "attach(fexit tcp_recvmsg) failed\n");
        recvmsg_link = NULL;
        goto cleanup;
    }

    sched_link = bpf_program__attach(p_sched);
    if (libbpf_get_error(sched_link)) {
        fprintf(stderr, "attach(tracepoint sched_switch) failed\n");
        sched_link = NULL;
        goto cleanup;
    }

    freq_link = bpf_program__attach(p_freq);
    if (libbpf_get_error(freq_link)) {
        fprintf(stderr, "attach(tracepoint power cpu_frequency) failed\n");
        freq_link = NULL;
        goto cleanup;
    }
    ret = refresh_cpu_khz_map(cpu_khz_fd, cpu_count);
    if (ret < 0)
        goto cleanup;

    wakeup_link = bpf_program__attach(p_wakeup);
    if (libbpf_get_error(wakeup_link)) {
        fprintf(stderr, "attach(tracepoint sched_wakeup) failed\n");
        wakeup_link = NULL;
        goto cleanup;
    }

    wakeup_new_link = bpf_program__attach(p_wakeup_new);
    if (libbpf_get_error(wakeup_new_link)) {
        fprintf(stderr, "attach(tracepoint sched_wakeup_new) failed\n");
        wakeup_new_link = NULL;
        goto cleanup;
    }

    migrate_link = bpf_program__attach(p_migrate);
    if (libbpf_get_error(migrate_link)) {
        fprintf(stderr, "attach(tp_btf sched_migrate_task) failed\n");
        migrate_link = NULL;
        goto cleanup;
    }

    if (bpf_prog_attach(skmsg_fd, sockhash_fd, BPF_SK_MSG_VERDICT, 0)) {
        fprintf(stderr, "attach(sk_msg) failed: %s\n", strerror(errno));
        goto cleanup;
    }
    skmsg_attached = true;

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    if (need_psys) {
        if (seed_attribution_state(&attribution, process_freq_runtime_fd, process_wakeup_fd,
                                   process_cycles_fd, process_instructions_fd,
                                   process_cache_miss_fd, process_migrations_fd,
                                   psys_fd) != 0) {
            fprintf(stderr, "Failed to seed PSYS attribution state\n");
            goto cleanup;
        }
    }

    printf("Attached OK.\n");
    printf("Put your HTTP server into cgroup: %s\n", cg_path);
    printf("Energy model config loaded from: %s\n", config_path);
    printf("Attribution mode: %s\n", attribution_mode_name(model.bpf_cfg.attribution_mode));
    printf("Responses will include X-Energy-Score as attributed microjoules for plaintext HTTP/1.x.\n");
    if (model.bpf_cfg.attribution_mode == ATTRIBUTION_MODE_PSYS)
        printf("PSYS machine energy is sampled through perf and split across processes using the logged signals.\n");
    else
        printf("Direct model mode is active: the configured coefficients are applied as microjoule weights in-kernel.\n");
    printf("Attribution update interval: %u ms; configured idle baseline: %llu uW.\n",
           model.runtime_cfg.psys_interval_ms,
           (unsigned long long)model.runtime_cfg.idle_power_uw);
    printf("Per-process runtime by CPU frequency is accumulated in the BPF map 'process_freq_runtime'; the cpu_khz map is refreshed from power:cpu_frequency and sysfs.\n");
    printf("Per-process wakeup counts are accumulated in the BPF map 'process_wakeup_count' from sched_wakeup events.\n");
    printf("Per-process cycles, instructions, cache misses, migrations, and attributed energy are accumulated in 'process_cycles', 'process_instructions', 'process_cache_misses', 'process_migrations', and 'process_attributed_energy_uj'.\n");
    if (collection.csv_path)
        printf("Interval signal collection is enabled: %s\n", collection.csv_path);
    printf("Ctrl-C to stop.\n");

    while (!g_stop) {
        struct timespec req = {
            .tv_sec = model.runtime_cfg.psys_interval_ms / 1000,
            .tv_nsec = (long)(model.runtime_cfg.psys_interval_ms % 1000) * 1000000L,
        };

        while (!g_stop && nanosleep(&req, &req) != 0) {
            if (errno != EINTR)
                break;
        }
        if (g_stop)
            break;

        ret = refresh_cpu_khz_map(cpu_khz_fd, cpu_count);
        if (ret < 0)
            goto cleanup;

        if (need_psys) {
            if (run_psys_split_update(&model, &attribution, psys_scale_uj, psys_fd, psys_split_fd,
                                      process_freq_runtime_fd, process_wakeup_fd, process_cycles_fd,
                                      process_instructions_fd, process_cache_miss_fd,
                                      process_migrations_fd, process_attributed_energy_fd,
                                      &collection) != 0) {
                fprintf(stderr, "PSYS attribution update failed\n");
                goto cleanup;
            }
        }
    }

    ret = 0;

cleanup:
    if (skmsg_attached)
        bpf_prog_detach2(skmsg_fd, sockhash_fd, BPF_SK_MSG_VERDICT);
    if (migrate_link)
        bpf_link__destroy(migrate_link);
    if (wakeup_new_link)
        bpf_link__destroy(wakeup_new_link);
    if (wakeup_link)
        bpf_link__destroy(wakeup_link);
    if (freq_link)
        bpf_link__destroy(freq_link);
    if (sched_link)
        bpf_link__destroy(sched_link);
    if (recvmsg_link)
        bpf_link__destroy(recvmsg_link);
    if (ingress_attached)
        bpf_prog_detach2(ingress_fd, cg_fd, BPF_CGROUP_INET_INGRESS);
    if (sockops_attached)
        bpf_prog_detach2(sockops_fd, cg_fd, BPF_CGROUP_SOCK_OPS);
    if (psys_fd >= 0)
        close(psys_fd);
    close_perf_event_array(cache_miss_fds, cpu_count);
    close_perf_event_array(instructions_fds, cpu_count);
    close_perf_event_array(cycles_fds, cpu_count);
    close_collection_output(&collection);
    free_attribution_state(&attribution);
    free_loaded_energy_model(&model);
    if (obj)
        bpf_object__close(obj);
    if (cg_fd >= 0)
        close(cg_fd);
    return ret;
}
