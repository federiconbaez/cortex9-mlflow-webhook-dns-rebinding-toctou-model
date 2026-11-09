"""Check-then-use model of MLflow webhook delivery before and after commit
ba949522477c (PR #24258).

Diff lines cited refer to
sources/cve2026/diffs/CVE-2026-64849_mlflow_ba949522477c.diff
(sha256 f825a17c5d6bba836db2cfd6451b403eaa369cc8a110d71634b8532a8655dbfe).

No socket is ever opened. Name resolution goes through FakeResolver, a
deterministic table; "connecting" means taking the first address of a fresh
resolution. The model has no requests/urllib3 code in it.

pre  : _validate_webhook_url resolves the host and requires every address to
       be public (GHSA text; restated in the new module docstring, diff lines
       45-46), then the request re-resolves the host (diff lines 47-50) and
       connects with a plain HTTPAdapter (diff line 25, removed). Env proxies
       are honoured (trust_env default).
post : same validation, then SSRFProtectedHTTPAdapter (diff line 29) checks
       the peer IP of every connected socket (diff lines 82-115, 127-131,
       137-152, 162-186) and env proxies are ignored (diff line 33).
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from urllib.parse import urlsplit

VERSIONS = ("pre", "post")
ALLOWED_SCHEMES = ("https",)      # default per the GHSA text, not in the diff
MAX_HOPS = 10                     # model bound on redirect chains


class SSRFProtectionError(Exception):
    """Mirrors diff lines 74-79: not retried, delivery fails closed.

    .rule holds the diff lines of the check that raised it."""

    def __init__(self, msg, rule):
        super().__init__(msg)
        self.rule = rule


class FakeResolver:
    """Deterministic stand-in for socket.getaddrinfo.

    table maps a hostname to a list of answers; each call returns the next
    answer and the last one repeats. IP literals resolve to themselves.
    """

    def __init__(self, table):
        self.table = {h: [list(a) for a in answers] for h, answers in table.items()}
        for h, answers in self.table.items():
            if not answers or any(not a for a in answers):
                raise ValueError(f"empty answer for {h!r}")
        self.calls = {}
        self.log = []

    def resolve(self, host):
        try:
            ipaddress.ip_address(host)
            self.log.append((host, [host]))
            return [host]
        except ValueError:
            pass
        if host not in self.table:
            raise LookupError(f"NXDOMAIN {host}")
        n = self.calls.get(host, 0)
        self.calls[host] = n + 1
        answers = self.table[host]
        ans = answers[min(n, len(answers) - 1)]
        self.log.append((host, list(ans)))
        return list(ans)


def is_public(ip: str) -> bool:
    """The classifier both versions use: ipaddress ... is_global
    (GHSA quote of _validate_webhook_url; diff lines 96 and 103)."""
    return ipaddress.ip_address(ip).is_global


def assert_public_peer(peer, allow_private=False, getpeername_fails=False):
    """Model of _assert_public_peer (diff lines 82-108)."""
    if allow_private:                                  # diff 83-84
        return
    if getpeername_fails:                              # diff 88-94
        raise SSRFProtectionError("Could not determine webhook connection peer address",
                                  "88-94")
    try:
        ip = ipaddress.ip_address(peer)                # diff 95-101
    except ValueError as e:
        raise SSRFProtectionError(f"invalid IP address: {peer!r}", "95-101") from e
    if not ip.is_global:                               # diff 103-108
        raise SSRFProtectionError(f"{ip} is not a public IP address", "103-108")


@dataclass
class Scenario:
    url: str
    resolver: dict
    redirects: dict = field(default_factory=dict)     # url -> Location
    allow_private: bool = False
    env_proxy: str | None = None                       # HTTP(S)_PROXY address
    explicit_proxy: str | None = None                  # session.proxies address
    getpeername_fails: bool = False


@dataclass
class Result:
    version: str
    label: str
    hops: int
    check_ips: str          # what validation saw (first resolution)
    peers: str              # peer of each connection, ';'-joined
    resolutions: int
    rule: str               # diff lines that decide the outcome


def _host(url):
    h = urlsplit(url).hostname
    if not h:
        raise ValueError(f"no host in {url!r}")
    return h


def deliver(version: str, sc: Scenario) -> Result:
    if version not in VERSIONS:
        raise ValueError(f"unknown version {version!r}")
    res = FakeResolver(sc.resolver)
    peers = []

    def done(label, rule, check=""):
        return Result(version, label, len(peers), check, ";".join(peers),
                      len(res.log), rule)

    # 1. _validate_webhook_url on the ORIGINAL url only (both versions).
    if urlsplit(sc.url).scheme not in ALLOWED_SCHEMES:
        return done("REJECT_SCHEME", "ghsa:validate")
    check = []
    if not sc.allow_private:
        check = res.resolve(_host(sc.url))
        if not all(is_public(ip) for ip in check):
            return done("REJECT_VALIDATION", "ghsa:validate", ",".join(check))
    check_s = ",".join(check)

    # 2. requests.post: resolve again and connect, following redirects.
    trust_env = version == "pre"                       # diff 31-33
    url = sc.url
    private_seen = False
    for _ in range(MAX_HOPS):
        if sc.explicit_proxy is not None:
            peer = sc.explicit_proxy                   # diff 175-186 (post)
        elif sc.env_proxy is not None and trust_env:
            peer = sc.env_proxy
        else:
            peer = res.resolve(_host(url))[0]          # re-resolution, diff 47-50
        peers.append(peer)
        if version == "post":
            try:
                assert_public_peer(peer, sc.allow_private, sc.getpeername_fails)
            except SSRFProtectionError as e:
                return done("SSRF_ERROR", _post_rule(sc, e.rule), check_s)
        if not is_public(peer):
            private_seen = True
        nxt = sc.redirects.get(url)
        if nxt is None:
            break
        url = nxt                                      # no re-validation (GHSA)
    else:
        return done("TOO_MANY_HOPS", "model", check_s)

    if private_seen:
        label = "ALLOWED_BY_ENV" if sc.allow_private else "REACHED_PRIVATE"
        rule = "83-84" if sc.allow_private else "25;45-50"
    else:
        label = "DELIVERED"
        rule = "25;45-50" if version == "pre" else _post_rule(sc, "103")
    return done(label, rule, check_s)


def _post_rule(sc, check_rule):
    """Diff lines behind a post-fix outcome."""
    parts = ["29", check_rule]
    if sc.env_proxy is not None:
        parts.append("33")
    if sc.explicit_proxy is not None:
        parts.append("175-186")
    return ";".join(parts)
