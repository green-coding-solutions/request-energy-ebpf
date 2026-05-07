#!/usr/bin/env python3
import argparse
import http.client
import json
import random
import socket
import threading
import time
import urllib.parse


BUILTIN_PROFILES = {
    "mixed": [
        {"path": "/cpu?iters=20000", "weight": 2},
        {"path": "/cpu?iters=120000", "weight": 1},
        {"path": "/json?items=128", "weight": 2},
        {"path": "/json?items=4096", "weight": 1},
        {"path": "/compress?kb=64", "weight": 2},
        {"path": "/compress?kb=1024", "weight": 1},
        {"path": "/file?kb=64", "weight": 2},
        {"path": "/file?kb=2048", "weight": 1},
        {"path": "/post?kb=32", "weight": 2},
        {"path": "/post?kb=512", "weight": 1},
    ],
}


def parse_args():
    parser = argparse.ArgumentParser(description="Simple HTTP benchmark for request-energy collection.")
    parser.add_argument("--url", required=True,
                        help="Base target URL, for example http://127.0.0.1:8080/ or a single request URL.")
    parser.add_argument("--duration", type=float, default=15.0, help="Benchmark duration in seconds.")
    parser.add_argument("--concurrency", type=int, default=4, help="Number of worker threads.")
    parser.add_argument("--timeout", type=float, default=5.0, help="Per-request timeout in seconds.")
    parser.add_argument("--method", default="GET", help="HTTP method to use.")
    parser.add_argument("--body", default="", help="Optional request body.")
    parser.add_argument("--path", action="append", default=[],
                        help="Relative path to benchmark. Repeat to build a request mix.")
    parser.add_argument("--mix-file",
                        help="JSON file with [{'path': '/cpu?iters=1000', 'weight': 2}, ...].")
    parser.add_argument("--profile", choices=sorted(BUILTIN_PROFILES.keys()),
                        help="Built-in request mix profile.")
    return parser.parse_args()


class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.completed = 0
        self.failures = 0
        self.bytes_read = 0
        self.latencies = []
        self.status_codes = {}

    def record_success(self, latency_s, status, bytes_read):
        with self.lock:
            self.completed += 1
            self.bytes_read += bytes_read
            self.latencies.append(latency_s)
            self.status_codes[status] = self.status_codes.get(status, 0) + 1

    def record_failure(self):
        with self.lock:
            self.failures += 1


def make_connection(parsed, timeout):
    scheme = parsed.scheme.lower()
    if scheme == "http":
        conn = http.client.HTTPConnection(parsed.hostname, parsed.port or 80, timeout=timeout)
    elif scheme == "https":
        conn = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443, timeout=timeout)
    else:
        raise ValueError(f"Unsupported URL scheme: {parsed.scheme}")
    return conn


def load_plan(args, parsed):
    if args.mix_file:
        with open(args.mix_file, encoding="utf-8") as fp:
            raw_plan = json.load(fp)
    elif args.profile:
        raw_plan = BUILTIN_PROFILES[args.profile]
    elif args.path:
        raw_plan = [{"path": path, "weight": 1} for path in args.path]
    else:
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        raw_plan = [{"path": path, "weight": 1}]

    plan = []
    for entry in raw_plan:
        path = entry["path"]
        weight = max(1, int(entry.get("weight", 1)))
        plan.append((path, weight))

    if not plan:
        raise ValueError("Benchmark plan is empty.")

    return plan


def choose_path(plan):
    total_weight = sum(weight for _, weight in plan)
    target = random.uniform(0, total_weight)
    running = 0.0
    for path, weight in plan:
        running += weight
        if target <= running:
            return path
    return plan[-1][0]


def worker(deadline, parsed, plan, method, body, timeout, stats):
    conn = None
    while time.monotonic() < deadline:
        if conn is None:
            try:
                conn = make_connection(parsed, timeout)
            except Exception:
                stats.record_failure()
                continue

        start = time.perf_counter()
        try:
            path = choose_path(plan)
            conn.request(method, path, body=body)
            resp = conn.getresponse()
            payload = resp.read()
            latency_s = time.perf_counter() - start
            stats.record_success(latency_s, resp.status, len(payload))
        except (http.client.HTTPException, OSError, socket.error):
            stats.record_failure()
            try:
                conn.close()
            except Exception:
                pass
            conn = None

    if conn is not None:
        try:
            conn.close()
        except Exception:
            pass


def percentile(sorted_values, p):
    if not sorted_values:
        return 0.0
    idx = max(0, min(len(sorted_values) - 1, int(round((len(sorted_values) - 1) * p))))
    return sorted_values[idx]


def main():
    args = parse_args()
    parsed = urllib.parse.urlparse(args.url)
    plan = load_plan(args, parsed)
    deadline = time.monotonic() + args.duration
    stats = Stats()
    threads = []

    for _ in range(args.concurrency):
        thread = threading.Thread(
            target=worker,
            args=(deadline, parsed, plan, args.method, args.body, args.timeout, stats),
            daemon=True,
        )
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    latencies = sorted(stats.latencies)
    result = {
        "url": args.url,
        "plan": [{"path": path, "weight": weight} for path, weight in plan],
        "duration_s": args.duration,
        "concurrency": args.concurrency,
        "completed_requests": stats.completed,
        "failed_requests": stats.failures,
        "bytes_read": stats.bytes_read,
        "requests_per_second": stats.completed / args.duration if args.duration > 0 else 0.0,
        "latency_ms_avg": (sum(latencies) / len(latencies) * 1000.0) if latencies else 0.0,
        "latency_ms_p50": percentile(latencies, 0.50) * 1000.0,
        "latency_ms_p95": percentile(latencies, 0.95) * 1000.0,
        "latency_ms_p99": percentile(latencies, 0.99) * 1000.0,
        "status_codes": stats.status_codes,
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
