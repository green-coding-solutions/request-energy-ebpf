#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import pathlib
import threading
import urllib.parse
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


FILE_SIZES_KB = [64, 256, 1024, 2048, 4096]


def parse_args():
    parser = argparse.ArgumentParser(description="HTTP workload server with variable CPU/memory/IO endpoints.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address.")
    parser.add_argument("--port", type=int, default=8080, help="Bind port.")
    parser.add_argument("--data-dir", default="./workload_data", help="Directory for generated file workloads.")
    return parser.parse_args()


def ensure_workload_files(data_dir):
    os.makedirs(data_dir, exist_ok=True)
    seed = hashlib.sha256(b"request-energy-ebpf-workload").digest()
    for size_kb in FILE_SIZES_KB:
        path = pathlib.Path(data_dir) / f"blob_{size_kb}kb.bin"
        if path.exists() and path.stat().st_size == size_kb * 1024:
            continue

        block = bytearray(seed)
        while len(block) < size_kb * 1024:
            seed = hashlib.sha256(seed).digest()
            block.extend(seed)
        path.write_bytes(bytes(block[: size_kb * 1024]))


class WorkloadHandler(BaseHTTPRequestHandler):
    server_version = "workload-server/1.0"

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)

        if parsed.path == "/":
            self._write_json({
                "endpoints": ["/cpu", "/json", "/compress", "/file", "/post"],
                "thread": threading.get_ident(),
            })
            return
        if parsed.path == "/cpu":
            iters = self._get_int(query, "iters", 50000, 1, 5_000_000)
            digest = self._cpu_work(iters)
            self._write_json({"endpoint": "cpu", "iters": iters, "digest": digest})
            return
        if parsed.path == "/json":
            items = self._get_int(query, "items", 512, 1, 100_000)
            payload = self._json_work(items)
            self._write_bytes(payload, "application/json")
            return
        if parsed.path == "/compress":
            size_kb = self._get_int(query, "kb", 64, 1, 16_384)
            payload = self._compress_work(size_kb)
            self._write_bytes(payload, "application/octet-stream")
            return
        if parsed.path == "/file":
            size_kb = self._get_int(query, "kb", 64, 1, 16_384)
            payload = self._file_work(size_kb)
            self._write_bytes(payload, "application/octet-stream")
            return

        self.send_error(404, "Not Found")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        if parsed.path != "/post":
            self.send_error(404, "Not Found")
            return

        size_kb = self._get_int(query, "kb", 32, 1, 4096)
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        if not body:
            body = b"x" * (size_kb * 1024)

        digest = hashlib.sha256(body).hexdigest()
        transformed = zlib.compress(body * 2, level=6)
        self._write_json({
            "endpoint": "post",
            "input_bytes": len(body),
            "digest": digest,
            "compressed_bytes": len(transformed),
        })

    def log_message(self, fmt, *args):
        return

    def _get_int(self, query, key, default, lower, upper):
        raw = query.get(key, [str(default)])[0]
        try:
            value = int(raw)
        except ValueError:
            value = default
        return max(lower, min(upper, value))

    def _cpu_work(self, iters):
        data = b"seed"
        for idx in range(iters):
            data = hashlib.sha256(data + idx.to_bytes(8, "little")).digest()
        return data.hex()

    def _json_work(self, items):
        rows = []
        for idx in range(items):
            rows.append({
                "id": idx,
                "value": (idx * 2654435761) % 1_000_003,
                "text": f"row-{idx:06d}",
            })
        encoded = json.dumps({"items": rows}, separators=(",", ":")).encode("utf-8")
        return encoded

    def _compress_work(self, size_kb):
        raw = (b"abcdefghijklmnopqrstuvwxyz012345" * ((size_kb * 1024 // 32) + 1))[: size_kb * 1024]
        return zlib.compress(raw, level=6)

    def _file_work(self, size_kb):
        available = min(FILE_SIZES_KB, key=lambda existing: abs(existing - size_kb))
        path = pathlib.Path(self.server.data_dir) / f"blob_{available}kb.bin"
        return path.read_bytes()

    def _write_json(self, payload):
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self._write_bytes(data, "application/json")

    def _write_bytes(self, payload, content_type):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def main():
    args = parse_args()
    ensure_workload_files(args.data_dir)

    server = ThreadingHTTPServer((args.host, args.port), WorkloadHandler)
    server.data_dir = args.data_dir
    print(f"Serving workload endpoints on http://{args.host}:{args.port} from {args.data_dir}")
    server.serve_forever()


if __name__ == "__main__":
    main()
