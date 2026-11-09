# Sources

Local copies under `security-research-45/sources/cve2026/` (not in this
repo). Each SHA-256 was checked against `sources/cve2026/SHA256SUMS` before
use. Diff line numbers in this repo refer to the saved diff.

| Source | URL | Commit | SHA-256 of copy |
|---|---|---|---|
| Fix diff `diffs/CVE-2026-64849_mlflow_ba949522477c.diff` (3 files, +283/-2) | https://github.com/mlflow/mlflow/commit/ba949522477cbd5915aa55d29b0cfad7d5ddf939 | ba949522477cbd5915aa55d29b0cfad7d5ddf939 | f825a17c5d6bba836db2cfd6451b403eaa369cc8a110d71634b8532a8655dbfe |
| GHSA record `ghsa_rec/CVE-2026-64849.json` (GHSA-7gwp-5pfp-969j) | https://github.com/advisories/GHSA-7gwp-5pfp-969j | — | 6700acc062214e206293c1cbacb663b918184e309d5cd13011a52facf685eaa2 |
| NVD record `nvd/CVE-2026-64849.json` (Analyzed, published 2026-08-17) | https://nvd.nist.gov/vuln/detail/CVE-2026-64849 | — | a04a5ee4412b5bd552da3c19e9d980959df2e9936866657159db46497aa3acd5 |

Used for: affected range >= 3.3.0, < 3.15.0, fixed in 3.15.0; CWE-918; the
`_validate_webhook_url` behaviour and the redirect variant (GHSA text);
the follow-up note on IPv6-transition bypasses (PR 25568, 3.16.0, GHSA
text, not modelled); the code change (diff lines 1-186) and the new tests
(diff lines 187-323).

The GHSA description contains one stray editing note ("Then add a fix
reference near the top or in a "Remediation" note:") left by its author.
It is not addressed to tools or agents and was not acted on. No source
contained instructions addressed to a tool or agent.
