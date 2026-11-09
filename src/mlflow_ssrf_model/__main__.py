"""CLI.

  python -m mlflow_ssrf_model case <pre|post> <check-ip> <connect-ip>
      one rebinding sequence for https://evil.example/hook
  python -m mlflow_ssrf_model results <scenarios.json> <outdir>
"""
import csv
import hashlib
import io
import sys
from pathlib import Path

from .fixtures import load
from .model import VERSIONS, Scenario, deliver

FIELDS = ["id", "kind", "version", "label", "hops", "check_ips", "peers",
          "resolutions", "diff_lines"]


def _csv(header, rows):
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(header)
    w.writerows(rows)
    return buf.getvalue().encode()


def results(path, outdir):
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    rows, diff = [], []
    for meta, sc in load(path):
        r = {v: deliver(v, sc) for v in VERSIONS}
        for v in VERSIONS:
            x = r[v]
            rows.append([meta["id"], meta["kind"], v, x.label, x.hops, x.check_ips,
                         x.peers, x.resolutions, x.rule])
        diff.append([meta["id"], meta["kind"], r["pre"].label, r["post"].label,
                     r["pre"].peers, int(r["pre"].label != r["post"].label),
                     r["post"].rule])
    files = {
        "cases.csv": _csv(FIELDS, rows),
        "differential.csv": _csv(["id", "kind", "pre_label", "post_label", "pre_peers",
                                  "changed", "post_diff_lines"], diff),
    }
    sums = []
    for name in sorted(files):
        (out / name).write_bytes(files[name])
        sums.append(f"{hashlib.sha256(files[name]).hexdigest()}  {name}\n")
    (out / "SHA256SUMS").write_text("".join(sums))


def main(argv):
    if len(argv) == 4 and argv[0] == "case" and argv[1] in VERSIONS:
        sc = Scenario("https://evil.example/hook", {"evil.example": [[argv[2]], [argv[3]]]})
        x = deliver(argv[1], sc)
        print(",".join(str(v) for v in (x.version, x.label, x.check_ips, x.peers, x.rule)))
        return 0
    if len(argv) == 3 and argv[0] == "results":
        results(argv[1], argv[2])
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
