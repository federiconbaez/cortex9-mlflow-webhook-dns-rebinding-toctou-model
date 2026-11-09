# cortex9-mlflow-webhook-dns-rebinding-toctou-model

Check-then-use model of **CVE-2026-64849** (GHSA-7gwp-5pfp-969j), the SSRF
in MLflow webhook delivery: `_validate_webhook_url` resolved the webhook
host and required public addresses, but the request resolved the host
**again** and connected without re-checking, so a rebinding DNS answer (or a
redirect) could reach `169.254.169.254`, `127.0.0.1` or RFC 1918 space. Fixed
in MLflow 3.15.0 by commit ba949522477c (PR #24258): `pre` = before,
`post` = after.

Educational, offline, deterministic, Python stdlib only. MLflow, requests
and urllib3 are not installed. Name resolution is a **deterministic fake
resolver** (a table of answers per host, consumed in order); no socket is
ever opened, and a test patches `socket` to fail on any call.
`11.0.0.1`/`11.0.0.2` are stand-in public addresses that are never contacted.

Spanish: [README.es.md](README.es.md). Exercises: [PRACTICE.md](PRACTICE.md).

## What the fix changes (lines of the saved diff)

| Diff lines | Change | Model |
|---|---|---|
| 25 (removed) / 29 (added) | `HTTPAdapter` → `SSRFProtectedHTTPAdapter` | `pre` connects unchecked; `post` checks every connection |
| 31-33 (added) | `session.trust_env = False` | `post` ignores env proxies |
| 45-50 (docstring) | names the TOCTOU: validation resolves, `requests.post` re-resolves | two independent resolutions |
| 82-108 | `_assert_public_peer`: env opt-out (83-84), `getpeername` failure (88-94), invalid IP (95-101), `not ip.is_global` (103-108) | `assert_public_peer` |
| 111-131, 137-152 | protected connection and pool classes for http and https | every hop, including redirects, is checked |
| 162-186 | protected pool manager and `proxy_manager_for` | explicit proxy peer is checked |

`_validate_webhook_url` itself is not in the diff; its behaviour (https only
by default, every resolved address must be `is_global`) is taken from the
GHSA text.

## Differential evidence (`results/differential.csv`)

| Sequence `[validation, connection]` | pre | post |
|---|---|---|
| `[11.0.0.1, 169.254.169.254]` | `REACHED_PRIVATE` | `SSRF_ERROR` (29;103-108) |
| `[11.0.0.1, 127.0.0.1]` | `REACHED_PRIVATE` | `SSRF_ERROR` |
| `[11.0.0.1, ::ffff:10.0.0.1]` | `REACHED_PRIVATE` | `SSRF_ERROR` |
| 302 from a public host to `http://169.254.169.254/...` | `REACHED_PRIVATE` (hop 2) | `SSRF_ERROR` (hop 2) |
| always `11.0.0.1` (negative) | `DELIVERED` | `DELIVERED` |
| `127.0.0.1` from the start (negative) | `REJECT_VALIDATION` | `REJECT_VALIDATION` |

All 8 positives reach a non-public peer `pre` and fail closed `post`; all 5
negatives keep their label. On a grid of 23 × 23 `[validation, connection]`
pairs, `post` never reaches a non-public peer.

**Beyond the diff:** `64:ff9b::a9fe:a9fe` (NAT64 form of 169.254.169.254) is
`is_global` to Python's `ipaddress`, so `post` as in this diff lets it through
(`a07`). The GHSA itself says IPv6-transition bypasses were fixed later
(PR 25568, MLflow 3.16.0); that follow-up is **not** modelled. The GHSA also
names `::ffff:100.64.0.0/10`; on Python 3.10.22, 3.11.18, 3.12.16 and
3.13.5 `ipaddress` already rejects `::ffff:100.64.0.1` (`a09`), so that
part is not reproduced here.

## Run

```sh
python3 tests/run.py                                   # any skip = failure
python3 scripts/derive_expected.py | diff - fixtures/expected.tsv
PYTHONPATH=src python3 -m mlflow_ssrf_model results fixtures/scenarios.json /tmp/r && diff -r results /tmp/r
PYTHONPATH=src python3 -m mlflow_ssrf_model case pre 11.0.0.1 169.254.169.254
```

`fixtures/scenarios.json` holds hand-derived labels;
`scripts/derive_expected.py` re-simulates the flow with `socket.inet_pton`
and a hand-written range table (no `ipaddress`, no model code) and writes
`fixtures/expected.tsv`; the tests compare all three.

See [LIMITATIONS.md](LIMITATIONS.md) and [SOURCES.md](SOURCES.md).
License: Apache-2.0.
