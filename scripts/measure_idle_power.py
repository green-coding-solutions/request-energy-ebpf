#!/usr/bin/env python3
import argparse
import ctypes
import json
import os
import platform
import statistics
import struct
import sys
import time


SYSFS_POWER = "/sys/bus/event_source/devices/power"
SYS_perf_event_open = {
    "x86_64": 298,
    "amd64": 298,
    "aarch64": 241,
    "arm64": 241,
}.get(platform.machine().lower())


class PerfEventAttr(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_uint32),
        ("size", ctypes.c_uint32),
        ("config", ctypes.c_uint64),
        ("sample_period", ctypes.c_uint64),
        ("sample_type", ctypes.c_uint64),
        ("read_format", ctypes.c_uint64),
        ("flags", ctypes.c_uint64),
        ("wakeup_events", ctypes.c_uint32),
        ("bp_type", ctypes.c_uint32),
        ("config1", ctypes.c_uint64),
        ("config2", ctypes.c_uint64),
        ("branch_sample_type", ctypes.c_uint64),
        ("sample_regs_user", ctypes.c_uint64),
        ("sample_stack_user", ctypes.c_uint32),
        ("clockid", ctypes.c_int32),
        ("sample_regs_intr", ctypes.c_uint64),
        ("aux_watermark", ctypes.c_uint32),
        ("sample_max_stack", ctypes.c_uint16),
        ("__reserved_2", ctypes.c_uint16),
        ("aux_sample_size", ctypes.c_uint32),
        ("aux_action", ctypes.c_uint32),
        ("sig_data", ctypes.c_uint64),
        ("config3", ctypes.c_uint64),
        ("config4", ctypes.c_uint64),
    ]


def parse_args():
    parser = argparse.ArgumentParser(description="Measure idle platform power using power/energy-psys.")
    parser.add_argument("--duration", type=float, default=5.0, help="Seconds per idle sample.")
    parser.add_argument("--samples", type=int, default=5, help="Number of idle samples.")
    parser.add_argument("--warmup", type=float, default=2.0, help="Warmup idle seconds before sampling.")
    parser.add_argument("--max-fluctuation-percent", type=float, default=10.0,
                        help="Maximum allowed median-absolute-deviation spread as a percent of median power.")
    parser.add_argument("--strict", action="store_true",
                        help="Exit nonzero when the fluctuation limit is exceeded.")
    parser.add_argument("--json", help="Optional JSON output path.")
    return parser.parse_args()


def read_text(path):
    with open(path, encoding="utf-8") as fp:
        return fp.read().strip()


def parse_event_config(text):
    for part in text.split(","):
        if part.startswith("event="):
            return int(part.split("=", 1)[1], 0)
    raise ValueError(f"Unsupported perf event description: {text}")


def parse_first_cpu(cpumask):
    return int(cpumask.split(",")[0].split("-")[0], 10)


def open_psys_event():
    if SYS_perf_event_open is None:
        raise RuntimeError(f"Unsupported architecture for perf_event_open: {platform.machine()}")

    source_type = int(read_text(os.path.join(SYSFS_POWER, "type")), 0)
    config = parse_event_config(read_text(os.path.join(SYSFS_POWER, "events", "energy-psys")))
    scale_uj = float(read_text(os.path.join(SYSFS_POWER, "events", "energy-psys.scale"))) * 1_000_000.0
    cpu = parse_first_cpu(read_text(os.path.join(SYSFS_POWER, "cpumask")))

    attr = PerfEventAttr()
    attr.type = source_type
    attr.size = ctypes.sizeof(PerfEventAttr)
    attr.config = config

    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_int
    fd = libc.syscall(SYS_perf_event_open, ctypes.byref(attr), -1, cpu, -1, 0)
    if fd < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))

    return fd, scale_uj


def read_counter(fd):
    raw = os.read(fd, 8)
    if len(raw) != 8:
        raise RuntimeError("Failed to read PSYS counter")
    return struct.unpack("Q", raw)[0]


def sample_idle_power(fd, scale_uj, duration_s):
    start_raw = read_counter(fd)
    start_ns = time.monotonic_ns()
    time.sleep(duration_s)
    end_raw = read_counter(fd)
    end_ns = time.monotonic_ns()

    delta_raw = max(0, end_raw - start_raw)
    delta_ns = max(1, end_ns - start_ns)
    delta_uj = delta_raw * scale_uj
    avg_uw = delta_uj * 1_000_000.0 / delta_ns
    return {
        "duration_s": delta_ns / 1_000_000_000.0,
        "energy_uj": delta_uj,
        "avg_power_uw": avg_uw,
    }


def median_absolute_deviation(values):
    center = statistics.median(values)
    deviations = [abs(value - center) for value in values]
    return statistics.median(deviations)


def summarize_powers(powers, max_fluctuation_percent):
    median_power = statistics.median(powers)
    min_power = min(powers)
    max_power = max(powers)
    range_fluctuation_percent = 0.0
    fluctuation_percent = 0.0
    if median_power > 0:
        range_fluctuation_percent = (max_power - min_power) * 100.0 / median_power
        fluctuation_percent = median_absolute_deviation(powers) * 100.0 / median_power

    within_limit = fluctuation_percent <= max_fluctuation_percent
    return {
        "mean_idle_power_uw": statistics.mean(powers),
        "median_idle_power_uw": median_power,
        "min_idle_power_uw": min_power,
        "max_idle_power_uw": max_power,
        "fluctuation_method": "median_absolute_deviation",
        "fluctuation_percent": fluctuation_percent,
        "range_fluctuation_percent": range_fluctuation_percent,
        "max_allowed_fluctuation_percent": max_fluctuation_percent,
        "within_fluctuation_limit": within_limit,
        "suggested_idle_power_uw": round(median_power),
    }


def estimate_counter_power_quantum_uw(scale_uj, duration_s):
    if duration_s <= 0:
        return 0.0
    return scale_uj / duration_s


def main():
    args = parse_args()
    fd, scale_uj = open_psys_event()
    try:
        time.sleep(args.warmup)
        samples = [sample_idle_power(fd, scale_uj, args.duration) for _ in range(args.samples)]
    finally:
        os.close(fd)

    powers = [sample["avg_power_uw"] for sample in samples]
    report = {"samples": samples}
    report.update(summarize_powers(powers, args.max_fluctuation_percent))
    median_duration_s = statistics.median(sample["duration_s"] for sample in samples)
    counter_power_quantum_uw = estimate_counter_power_quantum_uw(scale_uj, median_duration_s)
    allowed_spread_uw = report["median_idle_power_uw"] * args.max_fluctuation_percent / 100.0
    report["energy_counter_quantum_uj"] = scale_uj
    report["estimated_counter_power_quantum_uw"] = counter_power_quantum_uw

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fp:
            json.dump(report, fp, indent=2, sort_keys=True)
            fp.write("\n")

    print(json.dumps(report, indent=2, sort_keys=True))
    print(f"idle_power_uw={report['suggested_idle_power_uw']}")
    if counter_power_quantum_uw > allowed_spread_uw:
        print(
            "energy-psys counter resolution is too coarse for this sampling window: "
            f"about {counter_power_quantum_uw:.2f} uW per counter tick at {median_duration_s:.3f}s, "
            f"but the allowed spread is only {allowed_spread_uw:.2f} uW. "
            "Increase --duration to reduce quantization noise.",
            file=sys.stderr,
        )
    if not report["within_fluctuation_limit"]:
        message = (
            "Idle power fluctuation exceeded "
            f"{args.max_fluctuation_percent:.2f}% using {report['fluctuation_method']}: "
            f"observed {report['fluctuation_percent']:.2f}% "
            f"(raw range {report['range_fluctuation_percent']:.2f}%). "
            "Suggested baseline was still printed; consider longer samples or a quieter host."
        )
        if args.strict:
            raise SystemExit(message)
        print(message, file=sys.stderr)


if __name__ == "__main__":
    main()
