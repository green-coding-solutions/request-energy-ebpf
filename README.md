# request-energy-ebpf

Tiny eBPF experiment that attaches to a cgroup, tracks HTTP requests, and injects an `X-Energy-nJ` header on responses.

## Prerequisites
- `clang` (for both userland and BPF)
- libbpf headers/libs (`libbpf-devel` on Fedora) and `pkg-config`
- A cgroup you can write to (examples below use `/sys/fs/cgroup/httpdemo`)

## Build
```
make
```
This produces:
- `http_energy.bpf.o` – the BPF program
- `http_energy` – the user-space loader/attacher

Clean up:
```
make clean
```

## Run (example)
1. Start a server in the target cgroup (adjust the path to your cgroup):
   ```bash
   sudo bash -c 'echo $$ > /sys/fs/cgroup/httpdemo/cgroup.procs; python3 -m http.server 8080'
   ```
2. In another shell, load the programs (optional third arg sets energy-per-nanosecond; default 5):
   ```bash
   sudo ./http_energy /sys/fs/cgroup/httpdemo ./http_energy.bpf.o 5
   ```
3. Curl the server and check for the `X-Energy-nJ` header:
   ```bash
   curl -v http://127.0.0.1:8080/
   ```

### How energy is computed
- On connection establish (sockops), the program records `opened_ns = ktime_get_ns()`.
- When the first response chunk (sk_msg) is seen, it computes `energy_nj = (now - opened_ns) * energy_per_ns`, capping the interval at 10s and the printed value at 12 digits. The header is injected only when the message payload is small (≤256 bytes) and linear; otherwise it is left untouched.

If you hit verifier or permission issues, ensure the cgroup path is correct and that your kernel supports SK_MSG programs. Use `make clean && make` after code changes.
