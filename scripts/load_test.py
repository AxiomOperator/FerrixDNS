#!/usr/bin/env python3
"""Measures a release build of ferrixdns under load, and reports throughput, latency and memory.

The load generator, upstream and node all share this machine and compete for its CPU, so these are
conservative numbers for this hardware, not a published benchmark (spec section 8.6).

  scripts/load_test.py [--list-size 1000000] [--seconds 10]
"""

import argparse
import hashlib
import json
import os
import platform
import re
import resource
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FX = ROOT / "target/release/ferrixdns"
DNSLOAD = ROOT / "target/release/dnsload"
PASSWORD = "load test password"
OVERLOAD_CLIENTS = 6000
OPEN_FILES_SPARE = 200
# The installed service runs with LimitNOFILE=65536, so this matches it.
OPEN_FILES_WANTED = 65536


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def write_state(state: Path, list_size: int):
    """Writes a policy revision pinning a generated blocklist, as the API would."""
    lines = sorted(f"host{i}.ads{i % 997}.load.test" for i in range(list_size))
    artifact = "".join(f"e {name}\n" for name in lines).encode()
    sha = hashlib.sha256(artifact).hexdigest()
    (state / "lists").mkdir(parents=True)
    (state / "lists" / f"{sha}.list").write_bytes(artifact)

    policy = (
        "schema_version = 1\n[[lists]]\nid = \"generated\"\naction = \"deny\"\n"
        f"url = \"https://load.test/list\"\nformat = \"domains\"\nartifact_sha256 = \"{sha}\"\n"
    ).encode()
    revision = hashlib.sha256(policy).hexdigest()
    (state / "policy").mkdir()
    (state / "policy" / f"{revision}.rev").write_bytes(policy)
    (state / "policy" / "HISTORY").write_text(revision + "\n")
    return len(artifact)


class Node:
    def __init__(self, state, upstream_port, cache_mib=64, extra=()):
        self.dns_port = free_port()
        self.web_port = free_port()
        self.log = tempfile.TemporaryFile(mode="w+")
        self.process = subprocess.Popen(
            [
                str(FX), "serve",
                "--listen", f"127.0.0.1:{self.dns_port}",
                "--upstream", f"127.0.0.1:{upstream_port}",
                "--state-dir", str(state),
                "--web-listen", f"127.0.0.1:{self.web_port}",
                "--cache-mib", str(cache_mib),
                *extra,
            ],
            stderr=self.log,
            env={**os.environ, "NO_COLOR": "1", "RUST_LOG": "warn,ferrixdns=info"},
        )
        started = time.monotonic()
        self.ready_seconds = None
        while time.monotonic() - started < 120:
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{self.web_port}/api/v1/health/live", timeout=1)
                self.ready_seconds = time.monotonic() - started
                break
            except OSError:
                time.sleep(0.05)
        if self.ready_seconds is None:
            raise RuntimeError("ferrixdns didn't start")
        self.cookie = None
        self.csrf = None
        self.sign_in()

    def _request(self, path, body=None):
        headers = {"Content-Type": "application/json"}
        if self.cookie:
            headers["Cookie"] = self.cookie
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.web_port}/api/v1{path}", data=data, headers=headers
        )
        return urllib.request.urlopen(request, timeout=10)

    def patch(self, path, body):
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.web_port}/api/v1{path}",
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json", "Cookie": self.cookie, "X-CSRF-Token": self.csrf},
            method="PATCH",
        )
        return urllib.request.urlopen(request, timeout=60)

    def sign_in(self):
        self.log.seek(0)
        match = re.search(r"setup_token=([0-9a-f]+)", self.log.read())
        path, body = (
            ("/auth/setup", {"token": match.group(1), "username": "admin", "password": PASSWORD})
            if match
            else ("/auth/login", {"username": "admin", "password": PASSWORD})
        )
        response = self._request(path, body)
        self.cookie = response.headers["Set-Cookie"].split(";")[0]
        self.csrf = json.load(response)["data"]["csrf_token"]

    def system(self):
        return json.load(self._request("/system/status"))["data"]

    def cache(self):
        return json.load(self._request("/dns/cache"))["data"]

    def memory_mib(self):
        status = Path(f"/proc/{self.process.pid}/status").read_text()
        field = lambda name: int(re.search(rf"{name}:\s+(\d+)", status).group(1)) / 1024
        return field("VmRSS"), field("VmHWM")

    def threads_and_fds(self):
        status = Path(f"/proc/{self.process.pid}/status").read_text()
        threads = int(re.search(r"Threads:\s+(\d+)", status).group(1))
        return threads, len(os.listdir(f"/proc/{self.process.pid}/fd"))

    def stop(self):
        self.process.terminate()
        self.process.wait(timeout=20)


def raise_open_file_limit():
    """The overload stage opens a socket per client, which is more than most shells allow."""
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    wanted = OPEN_FILES_WANTED if hard == resource.RLIM_INFINITY else min(hard, OPEN_FILES_WANTED)
    if wanted < OVERLOAD_CLIENTS + OPEN_FILES_SPARE:
        sys.exit(
            f"The overload stage needs {OVERLOAD_CLIENTS + OPEN_FILES_SPARE:,} open files, but this "
            f"shell's hard limit is {hard:,}. Raise it with: ulimit -Hn {OPEN_FILES_WANTED}"
        )
    if soft == resource.RLIM_INFINITY or soft >= wanted:
        return
    # Child processes inherit this.
    resource.setrlimit(resource.RLIMIT_NOFILE, (wanted, hard))


def load(node, seconds, **options):
    arguments = [str(DNSLOAD), "run", "--server", f"127.0.0.1:{node.dns_port}", "--seconds", str(seconds)]
    for key, value in options.items():
        arguments += [f"--{key.replace('_', '-')}", str(value)]
    finished = subprocess.run(arguments, capture_output=True, text=True)
    if finished.returncode != 0:
        sys.exit(f"dnsload failed: {finished.stderr.strip()}")
    return json.loads(finished.stdout)


def report(name, result, node):
    rss, peak = node.memory_mib()
    print(
        f"{name:<44} {result['qps']:>8,.0f} {result['p50_us'] / 1000:>7.2f} "
        f"{result['p95_us'] / 1000:>7.2f} {result['p99_us'] / 1000:>7.2f} "
        f"{result['timeouts']:>8,} {result['other']:>8,} {rss:>6.0f} {peak:>6.0f}"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list-size", type=int, default=1_000_000)
    parser.add_argument("--seconds", type=int, default=10)
    args = parser.parse_args()
    raise_open_file_limit()

    subprocess.run(
        ["cargo", "build", "--release", "-q", "-p", "node-bin", "-p", "performance"],
        cwd=ROOT,
        check=True,
    )
    print(f"{platform.platform()}, {os.cpu_count()} CPUs. Generator, upstream and node share them.")

    work = Path(tempfile.mkdtemp(prefix="ferrix-load-"))
    upstream_port = free_port()
    slow_port = free_port()
    helpers = [
        subprocess.Popen([str(DNSLOAD), "upstream", "--listen", f"127.0.0.1:{upstream_port}"]),
        subprocess.Popen(
            [str(DNSLOAD), "upstream", "--listen", f"127.0.0.1:{slow_port}", "--delay-ms", "500"]
        ),
    ]
    time.sleep(0.2)
    node = None
    try:
        artifact_bytes = write_state(work / "state", args.list_size)
        print(f"Blocklist: {args.list_size:,} entries, {artifact_bytes / 1_048_576:.0f} MiB artifact.")
        node = Node(work / "state", upstream_port)
        print(f"Started and ready in {node.ready_seconds:.2f} s, including compiling the list.\n")
        print(
            f"{'Scenario':<44} {'QPS':>8} {'p50 ms':>7} {'p95 ms':>7} {'p99 ms':>7} "
            f"{'Timeouts':>8} {'SERVFAIL':>8} {'RSS':>6} {'Peak':>6}"
        )
        common = {"list_size": args.list_size}
        report(
            "Max rate: 95% cacheable, 5% unique",
            load(node, args.seconds, repeat_percent=95, **common), node,
        )
        report(
            "Max rate: 50% blocked, 45% cacheable",
            load(node, args.seconds, blocked_percent=50, repeat_percent=45, **common), node,
        )
        report(
            "Max rate: all unique (no cache hits)",
            load(node, args.seconds, repeat_percent=0, **common), node,
        )
        report(
            "Paced 10,000 QPS: mixed (10% blocked)",
            load(node, args.seconds, rate=10_000, clients=128, blocked_percent=10, repeat_percent=85, **common),
            node,
        )
        report(
            "Paced 1,000 QPS: mixed (10% blocked)",
            load(node, args.seconds, rate=1_000, clients=32, blocked_percent=10, repeat_percent=85, **common),
            node,
        )
        before = node.system()["events_dropped"]
        report(
            "Paced 10,000 QPS again: telemetry drops",
            load(node, args.seconds, rate=10_000, clients=128, blocked_percent=10, repeat_percent=85, **common),
            node,
        )
        print(f"  Events dropped at 10,000 QPS: {node.system()['events_dropped'] - before:,}")

        # Recompiling the list competes for CPU, so this shows what DNS sees during a list update.
        stop = threading.Event()
        def toggle():
            enabled = False
            while not stop.is_set():
                node.patch("/lists/generated", {"enabled": enabled})
                enabled = not enabled
                time.sleep(0.2)
        toggler = threading.Thread(target=toggle)
        toggler.start()
        report(
            "Paced 10,000 QPS: list recompiling throughout",
            load(node, args.seconds, rate=10_000, clients=128, blocked_percent=0, repeat_percent=90, **common),
            node,
        )
        stop.set()
        toggler.join()
        # Toggling can stop either way, and later stages need the list on.
        node.patch("/lists/generated", {"enabled": True})

        system = node.system()
        print(
            f"\nTelemetry: {system['queries_recorded']:,} recorded, "
            f"{system['events_dropped']:,} dropped, {system['telemetry_write_errors']} write errors, "
            f"{system['query_history_bytes'] / 1_048_576:.0f} MiB on disk."
        )
        cache = node.cache()
        print(
            f"Cache: {cache['hits']:,} hits, {cache['misses']:,} misses, {cache['entries']:,} entries, "
            f"{cache['bytes'] / 1_048_576:.0f} of {cache['max_bytes'] / 1_048_576:.0f} MiB."
        )
        node.stop()

        print("\nOverload: a 500 ms upstream, more demand than the 4,096 in-flight limit.")
        node = Node(work / "state", slow_port, cache_mib=0)
        result = load(node, args.seconds, clients=OVERLOAD_CLIENTS, repeat_percent=0, timeout_ms=3000, **common)
        threads, fds = node.threads_and_fds()
        report("Flood during slow upstream", result, node)
        print(f"After the flood: {threads} threads, {fds} open files.")
        healthy = load(node, 2, clients=1, blocked_percent=100, repeat_percent=0, **common)
        print(f"Blocked queries during recovery: {healthy['nxdomain']:,} answered, {healthy['timeouts']} timed out.")
        node.stop()
    finally:
        # A failed stage must not leave a node running.
        if node is not None:
            node.stop()
        for helper in helpers:
            helper.kill()
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
