# request-energy-ebpf

Tiny eBPF experiment that attaches to a cgroup, tracks HTTP requests, attributes CPU work to the thread serving each request, injects an `X-Energy-Score` header on responses, and supports two attribution modes:
- `psys`: distribute sampled PSYS interval energy across the tracked work
- `model`: apply fitted per-signal coefficients directly in-kernel as microjoule weights

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
1. Create the target cgroup:
   ```bash
   sudo mkdir -p /sys/fs/cgroup/httpdemo
   ```
2. Start a server in that cgroup (adjust the path to your cgroup):
   ```bash
   sudo bash -c 'echo $$ > /sys/fs/cgroup/httpdemo/cgroup.procs; exec ./scripts/workload_server.py --port 8080'
   ```
3. Review or edit the energy model config:
   ```bash
   sed -n '1,120p' ./energy_model.conf
   ```
4. In another shell, load the programs:
   ```bash
   sudo ./http_energy /sys/fs/cgroup/httpdemo ./http_energy.bpf.o ./energy_model.conf
   ```
5. Curl the server and check for the `X-Energy-Score` header:
   ```bash
   curl -v http://127.0.0.1:8080/
   ```
   The header value is emitted as a decimal microjoule count.

### How energy is computed
- On connection establish (sockops), the program adds the socket to a sockhash and enables TCP state callbacks so per-connection state can be cleaned up on close.
- On inbound plaintext HTTP traffic, a cgroup ingress program detects the end of the request headers, creates a request ID, and marks the connection as awaiting a response.
- When the server thread reads from the TCP socket, an `fexit/tcp_recvmsg` program binds that thread to the active request for the connection.
- A `power/cpu_frequency` tracepoint updates a per-CPU clock map whenever the kernel reports a CPU frequency transition.
- Userspace opens the `power/energy-psys` perf event, reads its scale from sysfs, and samples total machine energy every `psys_interval_ms`.
- A `sched_switch` tracepoint charges on-CPU runtime to the currently bound request whenever that thread is scheduled in and out, and also accumulates a `(tgid, cpu_khz) -> runtime_ns` mapping in the `process_freq_runtime` map.
- `sched_wakeup` and `sched_wakeup_new` tracepoints count wakeup events by waking process in the `process_wakeup_count` map keyed by `tgid`, and also charge a wakeup penalty when the request-owning thread triggers a wakeup while the request is active.
- Per-CPU PMU counters attribute cycles, instructions, and cache misses to the active request on each sched-in/sched-out slice, and aggregate them into `process_cycles`, `process_instructions`, and `process_cache_misses` maps keyed by `tgid`.
- A `sched_migrate_task` hook counts migrations in the `process_migrations` map keyed by `tgid`.
- Userspace computes an interval score for every process from the logged signals, subtracts the configured idle baseline from the PSYS interval, and derives a live `uJ / score` factor from `active_psys_uj / total_interval_score`.
- That live factor is written back into the `psys_split_state` map. BPF converts each request’s incremental score into attributed microjoules as work is observed, and also exports cumulative per-process attributed energy in `process_attributed_energy_uj`.
- On the first outbound `HTTP/1.x` response write, the `sk_msg` program injects `X-Energy-Score` using the PSYS-attributed request energy in microjoules.
- If the first response write cannot be rewritten safely, the response is left untouched and the pending request state is cleared so later responses are not corrupted.

### Energy model config
- `attribution_mode=psys|model` selects either live PSYS interval splitting or direct in-kernel model evaluation.
- `default_multiplier=<float>` sets the fallback score multiplier when there is no exact `freq_khz` entry for the current CPU frequency.
- `wakeup_penalty=<integer>` adds that many score units whenever the request-owning thread triggers a scheduler wakeup.
- `cycles_weight=<float>` adds `cycles * cycles_weight` to the score on each accounted slice.
- `instructions_weight=<float>` adds `instructions * instructions_weight` to the score on each accounted slice.
- `cache_miss_weight=<float>` adds `cache_misses * cache_miss_weight` to the score on each accounted slice.
- `migration_penalty=<integer>` adds that many score units whenever the request-owning thread is migrated.
- `idle_power_uw=<integer>` subtracts that idle baseline from each sampled PSYS interval before energy is distributed across processes.
- `psys_interval_ms=<integer>` controls how often userspace samples PSYS and recomputes the live `uJ / score` factor.
- `freq_khz=<khz> <float>` sets an exact-match multiplier for a specific CPU frequency in kHz.
- Float weights are fixed-point scalars with `1.0` meaning `delta += signal_value`, `2.0` meaning `delta += 2 * signal_value`, and so on.
- In `psys` mode those deltas are intermediate score units that are converted to microjoules through the live PSYS split factor.
- In `model` mode those deltas are interpreted directly as microjoules, so the fitted config coefficients must already be in energy units.

## Collection, Fitting, And Model Mode

The intended workflow is:
1. Run collection in `attribution_mode=psys` so each interval has a PSYS energy target.
2. Fit a direct model from the collected CSV.
3. Switch to the generated config with `attribution_mode=model` for direct in-kernel energy estimation.

### 0. Measure an idle baseline

Before collecting data, measure the host's idle platform power and copy the suggested value into `energy_model.conf`:

```bash
sudo ./scripts/measure_idle_power.py --duration 5 --samples 7
```

The script reads `power/energy-psys`, reports the observed idle power distribution, and prints a final line such as `idle_power_uw=123456`. By default it reports a robust fluctuation score based on median absolute deviation, keeps the raw range in the JSON for visibility, and still prints the suggested baseline even when the host is noisy. Add `--strict` if you want the command to exit nonzero when the fluctuation limit is exceeded.

### 1. Collect interval signals with PSYS

The loader can emit one CSV row per PSYS update interval:

```bash
sudo ./http_energy --collect-csv ./samples.csv --collect-label baseline \
  /sys/fs/cgroup/httpdemo ./http_energy.bpf.o ./energy_model.conf
```

The CSV includes:
- PSYS interval energy (`interval_psys_uj`, `active_psys_uj`, `idle_uj`)
- aggregate interval features (`runtime_ns`, `wakeups`, `cycles`, `instructions`, `cache_misses`, `migrations`)
- per-frequency runtime encoded as `freq_runtime_ns="800000:123;2200000:456"`

The bundled workload server exposes endpoints with materially different behavior:
- `/cpu?iters=...`
- `/json?items=...`
- `/compress?kb=...`
- `/file?kb=...`
- `/post?kb=...`

To automate collection against that server with a mixed request profile:

```bash
sudo ./scripts/collect_signals.py \
  --cgroup /sys/fs/cgroup/httpdemo \
  --use-workload-server \
  --workload-port 8080 \
  --output-csv ./samples.csv \
  --benchmark-json ./benchmark.json \
  --duration 20 \
  --concurrency 8
```

That script:
- starts the server in the target cgroup
- starts `http_energy` with CSV collection enabled
- runs the bundled HTTP benchmark with a mixed endpoint profile
- writes the benchmark summary and collected signal CSV

If you want to specify the mix manually, repeat `--path` or pass a JSON `--mix-file` through `collect_signals.py` or `benchmark_http.py`.

The standalone benchmark driver is also available directly:

```bash
./scripts/benchmark_http.py \
  --url http://127.0.0.1:8080/ \
  --profile mixed \
  --duration 15 \
  --concurrency 4
```

### 2. Fit and evaluate a direct energy model

Fit the collected CSV against PSYS energy and emit a ready-to-use `energy_model.conf`:

```bash
./scripts/fit_energy_model.py \
  --input-csv ./samples.csv \
  --output-config ./energy_model.fitted.conf \
  --report-json ./energy_model.report.json
```

The fitter:
- uses `active_psys_uj` as the default target
- fits per-frequency runtime coefficients plus wakeup/cycle/instruction/cache-miss/migration coefficients
- writes evaluation metrics for train/test splits (`MAE`, `RMSE`, `MAPE`, `R²`)
- generates a config with `attribution_mode=model`
- writes `psys_interval_ms=200` by default in the generated config

### 3. Run the fitted model in-kernel

After fitting, launch the loader with the generated config:

```bash
sudo ./http_energy /sys/fs/cgroup/httpdemo ./http_energy.bpf.o ./energy_model.fitted.conf
```

In `model` mode the request datapath no longer needs PSYS to estimate per-request energy for the response header. Collection still uses PSYS, so `--collect-csv` should be run with a PSYS-based config.

### Current limitations
- In `psys` mode the request header value represents PSYS-attributed microjoules, and the attribution accuracy still depends on how well the chosen signal weights explain whole-machine energy on your target host.
- In `psys` mode the live split factor is interval-based. Very short requests that finish before the first PSYS update after startup may still report `0` until the first calibrated factor is available.
- In `model` mode the output quality depends entirely on the host-specific dataset used to fit the coefficients.
- This works best for blocking or thread-per-request servers where one worker thread handles one request at a time.
- It does not attempt to attribute background work or async work that moves across threads.

If you hit verifier, perf permission, or attachment issues, ensure the cgroup path is correct, that your kernel supports SK_MSG and the tracepoints used here, and that hardware perf counters are available. `power/energy-psys` is now required for live attribution. Use `make clean && make` after code changes.
