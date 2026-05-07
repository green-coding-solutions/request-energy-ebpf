#!/usr/bin/env python3
import argparse
import json
import os
import pathlib
import shlex
import signal
import subprocess
import sys
import time


def parse_args():
    parser = argparse.ArgumentParser(description="Run a server, collect interval signals, and benchmark it.")
    parser.add_argument("--cgroup", required=True, help="Target cgroup path, for example /sys/fs/cgroup/httpdemo")
    parser.add_argument("--server-cmd",
                        help="Server command started inside the cgroup, for example 'python3 -m http.server 8080'")
    parser.add_argument("--use-workload-server", action="store_true",
                        help="Start the bundled workload server instead of requiring --server-cmd.")
    parser.add_argument("--workload-port", type=int, default=8080,
                        help="Port used by --use-workload-server.")
    parser.add_argument("--url", help="Benchmark URL.")
    parser.add_argument("--output-csv", required=True, help="Collection CSV output path.")
    parser.add_argument("--config", default="./energy_model.conf", help="Config passed to http_energy.")
    parser.add_argument("--loader-bin", default="./http_energy", help="Path to the loader binary.")
    parser.add_argument("--bpf-object", default="./http_energy.bpf.o", help="Path to the BPF object.")
    parser.add_argument("--label", default="benchmark", help="Collection label written into the CSV.")
    parser.add_argument("--duration", type=float, default=15.0, help="Benchmark duration in seconds.")
    parser.add_argument("--concurrency", type=int, default=4, help="Benchmark concurrency.")
    parser.add_argument("--warmup-seconds", type=float, default=2.0, help="Delay before and after loader start.")
    parser.add_argument("--benchmark-json", help="Optional path for benchmark results.")
    parser.add_argument("--path", action="append", default=[],
                        help="Relative path to include in the benchmark mix. Repeat to add more paths.")
    parser.add_argument("--mix-file", help="JSON benchmark mix file passed through to benchmark_http.py.")
    parser.add_argument("--profile", help="Built-in benchmark profile passed through to benchmark_http.py.")
    return parser.parse_args()


def terminate_process(proc, name):
    if proc is None or proc.poll() is not None:
        return
    proc.send_signal(signal.SIGINT)
    try:
        proc.wait(timeout=5)
        return
    except subprocess.TimeoutExpired:
        pass

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
    print(f"{name} did not exit cleanly; forced shutdown", file=sys.stderr)


def main():
    args = parse_args()
    repo_root = pathlib.Path(__file__).resolve().parents[1]
    benchmark_script = repo_root / "scripts" / "benchmark_http.py"
    workload_server_script = repo_root / "scripts" / "workload_server.py"

    if not args.server_cmd and not args.use_workload_server:
        raise SystemExit("Either --server-cmd or --use-workload-server is required.")

    if args.use_workload_server:
        args.server_cmd = f"{shlex.quote(str(workload_server_script))} --port {args.workload_port}"
        if not args.url:
            args.url = f"http://127.0.0.1:{args.workload_port}/"
        if not args.path and not args.mix_file and not args.profile:
            args.profile = "mixed"
    elif not args.url:
        raise SystemExit("--url is required unless --use-workload-server is set.")

    os.makedirs(os.path.dirname(os.path.abspath(args.output_csv)), exist_ok=True)
    if args.benchmark_json:
        os.makedirs(os.path.dirname(os.path.abspath(args.benchmark_json)), exist_ok=True)

    os.makedirs(args.cgroup, exist_ok=True)

    server_shell = f"echo $$ > {shlex.quote(args.cgroup)}/cgroup.procs; exec {args.server_cmd}"
    server_proc = subprocess.Popen(["bash", "-lc", server_shell], cwd=repo_root)
    loader_proc = None
    benchmark_result = None

    try:
        time.sleep(args.warmup_seconds)
        if server_proc.poll() is not None:
            raise RuntimeError("Server exited before collection started.")

        loader_cmd = [
            os.path.abspath(args.loader_bin),
            "--collect-csv", os.path.abspath(args.output_csv),
            "--collect-label", args.label,
            args.cgroup,
            os.path.abspath(args.bpf_object),
            os.path.abspath(args.config),
        ]
        loader_proc = subprocess.Popen(loader_cmd, cwd=repo_root)
        time.sleep(args.warmup_seconds)
        if loader_proc.poll() is not None:
            raise RuntimeError("http_energy exited before the benchmark started.")

        benchmark_cmd = [
            sys.executable,
            str(benchmark_script),
            "--url", args.url,
            "--duration", str(args.duration),
            "--concurrency", str(args.concurrency),
        ]
        if args.mix_file:
            benchmark_cmd.extend(["--mix-file", args.mix_file])
        if args.profile:
            benchmark_cmd.extend(["--profile", args.profile])
        for path in args.path:
            benchmark_cmd.extend(["--path", path])
        benchmark_run = subprocess.run(
            benchmark_cmd,
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=False,
        )
        if benchmark_run.returncode != 0:
            raise RuntimeError(
                f"Benchmark failed with code {benchmark_run.returncode}\n"
                f"stdout:\n{benchmark_run.stdout}\n\nstderr:\n{benchmark_run.stderr}"
            )

        benchmark_result = json.loads(benchmark_run.stdout)
        if args.benchmark_json:
            with open(args.benchmark_json, "w", encoding="utf-8") as fp:
                json.dump(benchmark_result, fp, indent=2, sort_keys=True)
                fp.write("\n")

        print(json.dumps({
            "collection_csv": os.path.abspath(args.output_csv),
            "benchmark": benchmark_result,
        }, indent=2, sort_keys=True))

    finally:
        terminate_process(loader_proc, "http_energy")
        terminate_process(server_proc, "server")


if __name__ == "__main__":
    main()
