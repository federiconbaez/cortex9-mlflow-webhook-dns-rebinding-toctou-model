"""Reader for fixtures/scenarios.json."""
import json

from .model import Scenario

FIELDS = ("url", "resolver", "redirects", "allow_private", "env_proxy",
          "explicit_proxy", "getpeername_fails")


def load(path):
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    out = []
    for s in data["scenarios"]:
        out.append((s, Scenario(**{k: s[k] for k in FIELDS})))
    return out
