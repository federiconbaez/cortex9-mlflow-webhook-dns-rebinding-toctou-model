#!/usr/bin/env python3
"""Independent derivation of fixtures/expected.tsv.

Written from the saved diff (CVE-2026-64849_mlflow_ba949522477c.diff) and
the GHSA text, NOT from src/. It does not import the model or the ipaddress
module: addresses are parsed with socket.inet_pton (parsing only, no
network) and classified with a hand-written table of non-public ranges.
The table only has to be right for the fixture addresses; the tests check
it against the model on every one of them.
"""
import json
import socket
import sys
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent.parent

V4_NOT_PUBLIC = [  # (network, prefix)
    ("0.0.0.0", 8), ("10.0.0.0", 8), ("100.64.0.0", 10), ("127.0.0.0", 8),
    ("169.254.0.0", 16), ("172.16.0.0", 12), ("192.0.0.0", 24),
    ("192.0.2.0", 24), ("192.168.0.0", 16), ("198.18.0.0", 15),
    ("198.51.100.0", 24), ("203.0.113.0", 24), ("240.0.0.0", 4),
]
V6_NOT_PUBLIC = [
    ("::", 128), ("::1", 128), ("100::", 64), ("2001:db8::", 32),
    ("2002::", 16), ("fc00::", 7), ("fe80::", 10),
]
MAPPED = bytes(10) + b"\xff\xff"   # ::ffff:0:0/96 -> classify the IPv4 part


def _bits(b):
    return int.from_bytes(b, "big"), len(b) * 8


def _in(addr, fam, net, plen):
    a, n = _bits(addr)
    m, _ = _bits(socket.inet_pton(fam, net))
    return (a >> (n - plen)) == (m >> (n - plen))


def parse(ip):
    for fam in (socket.AF_INET, socket.AF_INET6):
        try:
            return fam, socket.inet_pton(fam, ip)
        except OSError:
            pass
    return None, None


def public(ip):
    fam, b = parse(ip)
    if fam is None:
        raise ValueError(ip)
    if fam == socket.AF_INET6 and b[:12] == MAPPED:
        fam, b = socket.AF_INET, b[12:]
    table = V4_NOT_PUBLIC if fam == socket.AF_INET else V6_NOT_PUBLIC
    return not any(_in(b, fam, n, p) for n, p in table)


def simulate(version, s):
    counters, log = {}, []

    def lookup(host):
        if parse(host)[0] is not None:
            log.append(host)
            return [host]
        k = counters.get(host, 0)
        counters[host] = k + 1
        answers = s["resolver"][host]
        log.append(host)
        return answers[k] if k < len(answers) else answers[-1]

    peers = []

    def out(label, check=""):
        return [label, str(len(peers)), check, ";".join(peers), str(len(log))]

    # _validate_webhook_url (both versions): scheme, then every address public.
    if urlsplit(s["url"]).scheme != "https":
        return out("REJECT_SCHEME")
    check = ""
    if not s["allow_private"]:
        ips = lookup(urlsplit(s["url"]).hostname)
        check = ",".join(ips)
        if not all(public(i) for i in ips):
            return out("REJECT_VALIDATION", check)
    url, hit_private = s["url"], False
    for _ in range(10):
        if s["explicit_proxy"]:
            peer = s["explicit_proxy"]
        elif s["env_proxy"] and version == "pre":   # post: trust_env = False
            peer = s["env_proxy"]
        else:
            peer = lookup(urlsplit(url).hostname)[0]
        peers.append(peer)
        if version == "post" and not s["allow_private"]:
            # _assert_public_peer: getpeername, parse, is_global
            if s["getpeername_fails"] or parse(peer)[0] is None or not public(peer):
                return out("SSRF_ERROR", check)
        hit_private = hit_private or not public(peer)
        if url not in s["redirects"]:
            break
        url = s["redirects"][url]
    else:
        return out("TOO_MANY_HOPS", check)
    if hit_private:
        return out("ALLOWED_BY_ENV" if s["allow_private"] else "REACHED_PRIVATE", check)
    return out("DELIVERED", check)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else HERE / "fixtures" / "scenarios.json"
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    lines = ["\t".join(["id", "version", "label", "hops", "check_ips", "peers", "resolutions"])]
    for s in data["scenarios"]:
        for v, hand in (("pre", s["hand_pre"]), ("post", s["hand_post"])):
            row = simulate(v, s)
            if row[0] != hand:
                sys.exit(f"{s['id']}/{v}: derived {row[0]} != hand label {hand}")
            lines.append("\t".join([s["id"], v] + row))
    sys.stdout.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
