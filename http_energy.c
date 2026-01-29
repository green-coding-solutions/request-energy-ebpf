// http_energy.c
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static volatile sig_atomic_t g_stop = 0;

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

int main(int argc, char **argv)
{
    if (argc < 3 || argc > 4) {
        fprintf(stderr, "Usage: %s /sys/fs/cgroup/<cg> ./http_energy.bpf.o [energy_per_ns]\n", argv[0]);
        return 1;
    }

    const char *cg_path = argv[1];
    const char *obj_path = argv[2];
    __u64 energy_per_ns = 5;
    if (argc == 4)
        energy_per_ns = strtoull(argv[3], NULL, 0);

    libbpf_set_print(libbpf_print_fn);

    if (bump_memlock_rlimit() != 0)
        return 1;

    int cg_fd = open_cgroup(cg_path);
    if (cg_fd < 0)
        return 1;

    struct bpf_object *obj = bpf_object__open_file(obj_path, NULL);
    fprintf(stderr, "After open_file\n"); fflush(stderr);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "bpf_object__open_file(%s) failed\n", obj_path);
        return 1;
    }

    fprintf(stderr, "Before bpf_object__load\n"); fflush(stderr);
    if (bpf_object__load(obj)) {
        fprintf(stderr, "bpf_object__load failed\n");
        return 1;
    }
    fprintf(stderr, "After bpf_object__load\n"); fflush(stderr);

    fprintf(stderr, "Finding programs...\n"); fflush(stderr);
    struct bpf_program *p_sockops = bpf_object__find_program_by_name(obj, "sockops_add_to_sockhash");
    fprintf(stderr, "Found sockops_add_to_sockhash\n"); fflush(stderr);
    struct bpf_program *p_parser  = bpf_object__find_program_by_name(obj, "parse_ingress");
    fprintf(stderr, "Found parse_ingress\n"); fflush(stderr);
    struct bpf_program *p_verdict = bpf_object__find_program_by_name(obj, "verdict_allow");
    fprintf(stderr, "Found verdict_allow\n"); fflush(stderr);
    struct bpf_program *p_skmsg   = bpf_object__find_program_by_name(obj, "inject_energy_header");
    fprintf(stderr, "Found inject_energy_header\n"); fflush(stderr);

    if (!p_sockops || !p_parser || !p_verdict || !p_skmsg) {
        fprintf(stderr, "Failed to find one or more programs in object\n");
        return 1;
    }

    struct bpf_map *m_sockhash = bpf_object__find_map_by_name(obj, "sockhash");
    if (!m_sockhash) {
        fprintf(stderr, "Failed to find map 'sockhash'\n");
        return 1;
    }
    struct bpf_map *m_cfg = bpf_object__find_map_by_name(obj, "energy_cfg");
    if (!m_cfg) {
        fprintf(stderr, "Failed to find map 'energy_cfg'\n");
        return 1;
    }

    int sockhash_fd = bpf_map__fd(m_sockhash);
    int cfg_fd = bpf_map__fd(m_cfg);

    int sockops_fd = bpf_program__fd(p_sockops);
    int parser_fd  = bpf_program__fd(p_parser);
    int verdict_fd = bpf_program__fd(p_verdict);
    int skmsg_fd   = bpf_program__fd(p_skmsg);

    fprintf(stderr, "Setting energy_per_ns=%llu...\n", (unsigned long long)energy_per_ns); fflush(stderr);
    __u32 cfg_key = 0;
    if (bpf_map_update_elem(cfg_fd, &cfg_key, &energy_per_ns, BPF_ANY)) {
        fprintf(stderr, "Failed to write energy_per_ns: %s\n", strerror(errno));
        return 1;
    }

    fprintf(stderr, "Attaching sockops...\n"); fflush(stderr);
    if (bpf_prog_attach(sockops_fd, cg_fd, BPF_CGROUP_SOCK_OPS, 0)) {
        fprintf(stderr, "attach(sockops) failed: %s\n", strerror(errno));
        return 1;
    }
    // Keep only sk_msg attached for header injection; stream_* remain disabled.
    fprintf(stderr, "Attaching sk_msg (header injector)...\n"); fflush(stderr);
    if (bpf_prog_attach(skmsg_fd, sockhash_fd, BPF_SK_MSG_VERDICT, 0)) {
        fprintf(stderr, "attach(sk_msg) failed: %s\n", strerror(errno));
        return 1;
    }

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    printf("Attached OK.\n");
    printf("Put your HTTP server into cgroup: %s\n", cg_path);
    printf("Responses will include X-Energy-nJ for plaintext HTTP/1.x.\n");
    printf("Ctrl-C to stop.\n");

    while (!g_stop)
        sleep(1);

    bpf_prog_detach2(sockops_fd, cg_fd, BPF_CGROUP_SOCK_OPS);
    // bpf_prog_detach2(parser_fd, sockhash_fd, BPF_SK_SKB_STREAM_PARSER);
    // bpf_prog_detach2(verdict_fd, sockhash_fd, BPF_SK_SKB_STREAM_VERDICT);
    bpf_prog_detach2(skmsg_fd, sockhash_fd, BPF_SK_MSG_VERDICT);

    bpf_object__close(obj);
    close(cg_fd);
    return 0;
}
