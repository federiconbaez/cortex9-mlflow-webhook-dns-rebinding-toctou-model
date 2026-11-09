# Limitations

- **A model is not a finding.** This repo re-states public behaviour from
  CVE-2026-64849, its advisory and the fix commit. Nothing was reproduced
  against a real MLflow server.
- **No network, no HTTP.** "Connecting" means taking the first address of a
  fresh fake resolution. Real urllib3 may try several addresses in order,
  use happy-eyeballs or reuse pooled connections; none of that is modelled
  (cases `a05`/`a06` show the first-address assumption).
- **Validation from the GHSA, not the diff.** `_validate_webhook_url` (https
  only by default, every resolved address `is_global`, skipped resolution
  when `MLFLOW_WEBHOOK_ALLOW_PRIVATE_IPS` is set) is taken from the advisory
  text; the diff does not contain it.
- **Redirects.** Following redirects without re-validation (`pre`), and one
  new checked connection per hop (`post`), follow the GHSA text and the
  pool classes in the diff (lines 127-140). Status codes, method changes
  (302 vs 307/308) and requests' own redirect limit are not modelled; the
  model stops at 10 hops (`TOO_MANY_HOPS`).
- **IPv6 edge cases beyond the diff are not verified.** The classifier is
  Python's `ipaddress ... is_global` as in diff line 103, and its answers
  can change between Python versions. Fixture addresses were checked on
  Python 3.10.22, 3.11.18, 3.12.16 and 3.13.5 only. NAT64 (`a07`) passes;
  the GHSA follow-up (PR 25568, 3.16.0) that normalises such addresses is
  not modelled. The GHSA's `::ffff:100.64.0.0/10` claim is not reproduced
  with these Python versions (`a09`), which may depend on the Python patch
  level; unverified.
- **Proxies.** Env proxy handling (`trust_env`) is reduced to "connect to
  the proxy address". Whether an operator's env proxy is attacker-relevant
  is out of scope; `a03` only shows the effect of diff line 33.
- **TLS, timeouts, retries** (`SSRFProtectionError` is not retried, diff
  lines 74-79) and the `/test` endpoint's response reflection are not
  modelled.
- **Stand-in addresses.** `11.0.0.1` and `11.0.0.2` are used only because
  `is_global` needs a globally routable address; they are never contacted.
- **Grid** in the tests is a fixed list, not a proof.
