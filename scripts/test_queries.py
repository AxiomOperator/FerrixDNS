#!/usr/bin/env python3
"""Sends DNS lookups for a variety of sites to a FerrixDNS node, and summarizes the answers.

These are DNS lookups only. No request is made to the sites themselves. Each lookup shows up in the
dashboard, so this is also a quick way to watch it update. A built-in mix of ordinary sites and
ad and tracker domains is used, unless --urls names a file with your own.

  scripts/test_queries.py 100                            100 lookups to this machine's address
  scripts/test_queries.py 100 --server 192.168.1.10      to another node
  scripts/test_queries.py 100 --server 127.0.0.1:5300    to scripts/start.sh's default address
  scripts/test_queries.py 100 --urls my-sites.txt        one URL or domain per line, # for comments
  scripts/test_queries.py 500 --delay 0.2 --parallel 1   spread out over time

Exits with an error if no lookup got an answer.
"""

import argparse
import random
import socket
import statistics
import struct
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlsplit

DEFAULT_SITES = """
https://www.google.com https://www.youtube.com https://www.wikipedia.org https://github.com
https://www.amazon.com https://www.reddit.com https://www.microsoft.com https://www.apple.com
https://www.cloudflare.com https://www.nytimes.com https://www.bbc.com https://stackoverflow.com
https://www.netflix.com https://www.spotify.com https://www.linkedin.com https://www.weather.gov
https://doubleclick.net https://ad.doubleclick.net https://googleadservices.com
https://www.googletagmanager.com https://google-analytics.com https://adservice.google.com
https://ads.yahoo.com https://pixel.facebook.com https://app-measurement.com
https://this-name-does-not-exist.example
""".split()

RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
QTYPES = {"A": 1, "AAAA": 28}
TIMEOUT_SECONDS = 2.0


def domain_of(text):
    """Accepts a URL or a bare domain."""
    text = text.strip()
    host = urlsplit(text if "://" in text else f"//{text}").hostname
    if not host:
        raise ValueError(f"not a URL or domain: {text!r}")
    return host.rstrip(".")


def read_domains(path):
    domains = []
    for line in Path(path).read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            domains.append(domain_of(line))
    if not domains:
        raise ValueError(f"{path} has no URLs or domains")
    return domains


def main_address():
    """This machine's address on its default route. Nothing is sent to find it."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect(("1.1.1.1", 53))
        return probe.getsockname()[0]


def parse_server(text):
    host, separator, port = text.rpartition(":")
    return (host, int(port)) if separator else (text, 53)


def build_query(query_id, domain, qtype):
    question = b"".join(
        bytes([len(label)]) + label for label in domain.encode("idna").split(b".")
    )
    header = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    return header + question + b"\0" + struct.pack(">HH", QTYPES[qtype], 1)


def look_up(server, domain, qtype, delay):
    """Returns the domain, the answer's status, and the seconds it took, or None for no answer."""
    if delay:
        time.sleep(delay)
    query_id = random.randrange(0x10000)
    query = build_query(query_id, domain, qtype)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(TIMEOUT_SECONDS)
        started = time.monotonic()
        try:
            sock.sendto(query, server)
            while True:
                reply = sock.recv(4096)
                if len(reply) >= 12 and reply[:2] == query[:2]:
                    took = time.monotonic() - started
                    code = reply[3] & 0x0f
                    return domain, RCODES.get(code, f"RCODE{code}"), took
        except TimeoutError:
            return domain, "NO ANSWER", None
        except OSError as error:
            return domain, f"ERROR ({error.strerror})", None


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("n", type=int, help="how many lookups to send")
    parser.add_argument("--server", help="address[:port] of the node (default: this machine's address, port 53)")
    parser.add_argument("--urls", help="file of URLs or domains to use instead of the built-in mix")
    parser.add_argument("--parallel", type=int, default=5, help="lookups at once (default: 5)")
    parser.add_argument("--delay", type=float, default=0.0, help="seconds to wait before each lookup")
    parser.add_argument("--verbose", action="store_true", help="print every lookup")
    args = parser.parse_args()

    if args.n < 1:
        parser.error("n must be at least 1")
    if args.parallel < 1:
        parser.error("--parallel must be at least 1")
    if args.delay < 0:
        parser.error("--delay can't be negative")
    try:
        domains = read_domains(args.urls) if args.urls else [domain_of(site) for site in DEFAULT_SITES]
        server = parse_server(args.server) if args.server else (main_address(), 53)
    except (OSError, ValueError) as error:
        parser.error(str(error))

    # Go through every domain before repeating any, in a different order each time around.
    work = []
    while len(work) < args.n:
        round_of_domains = random.sample(domains, len(domains))
        work += [(domain, random.choice(list(QTYPES))) for domain in round_of_domains]
    work = work[: args.n]

    print(f"Sending {args.n} lookups for {len(set(d for d, _ in work))} domains to {server[0]}:{server[1]}")
    statuses = Counter()
    by_domain = {}
    times = []
    started = time.monotonic()
    with ThreadPoolExecutor(args.parallel) as pool:
        lookups = [pool.submit(look_up, server, domain, qtype, args.delay) for domain, qtype in work]
        for (domain, qtype), lookup in zip(work, lookups):
            name, status, took = lookup.result()
            statuses[status] += 1
            by_domain.setdefault(name, Counter())[status] += 1
            if took is not None:
                times.append(took)
            if args.verbose:
                shown = f"{took * 1000:.1f} ms" if took is not None else "-"
                print(f"  {qtype:<4} {name:<40} {status:<10} {shown}")
    elapsed = time.monotonic() - started

    print(f"\nFinished in {elapsed:.1f} s ({args.n / elapsed:.0f} lookups per second)\n")
    for status, count in statuses.most_common():
        print(f"  {status:<12} {count:>7}  {count * 100 / args.n:5.1f}%")
    if times:
        ordered = sorted(times)
        p95 = ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))]
        print(f"\n  Response time: median {statistics.median(ordered) * 1000:.1f} ms, 95% under {p95 * 1000:.1f} ms")

    not_found = sorted(d for d, seen in by_domain.items() if seen["NXDOMAIN"])
    if not_found:
        print(f"\n  Blocked or not found ({len(not_found)}): {', '.join(not_found)}")
    if statuses["REFUSED"]:
        print(
            "\n  REFUSED means this address isn't in the node's allowed networks, or went over its "
            "query limit.\n  The limit is under Settings, Blocking and logs. Try a --delay if it's the limit."
        )
    if not times:
        print("\nNo lookup got an answer. Is the node running at that address?", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
