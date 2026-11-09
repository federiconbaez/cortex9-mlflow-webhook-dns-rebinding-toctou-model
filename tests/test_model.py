import importlib.util
import itertools
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from mlflow_ssrf_model import FakeResolver, Scenario, assert_public_peer, deliver
from mlflow_ssrf_model.fixtures import load
from mlflow_ssrf_model.model import SSRFProtectionError, is_public

REPO = Path(__file__).resolve().parent.parent
SCEN = load(REPO / "fixtures" / "scenarios.json")

spec = importlib.util.spec_from_file_location("derive", REPO / "scripts" / "derive_expected.py")
DERIVE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(DERIVE)

PUBLIC = ["11.0.0.1", "11.0.0.2", "2a00::1", "::ffff:11.0.0.1", "64:ff9b::a9fe:a9fe"]
NOT_PUBLIC = ["169.254.169.254", "127.0.0.1", "10.0.0.5", "172.16.0.1", "192.168.1.1",
              "100.64.0.1", "0.0.0.0", "::1", "::", "fe80::1", "fd00::1",
              "::ffff:10.0.0.1", "::ffff:169.254.169.254", "::ffff:100.64.0.1",
              "2002:a9fe:a9fe::1", "192.0.2.10", "198.51.100.7", "203.0.113.5"]


def rebind(check, connect, **kw):
    return Scenario("https://evil.example/hook", {"evil.example": [[check], [connect]]}, **kw)


def _expected():
    lines = (REPO / "fixtures" / "expected.tsv").read_text(encoding="utf-8").splitlines()
    return {(f[0], f[1]): f[2:] for f in (l.split("\t") for l in lines[1:])}


class Fixtures(unittest.TestCase):
    def test_fixture_count(self):
        kinds = [m["kind"] for m, _ in SCEN]
        self.assertGreaterEqual(kinds.count("pos"), 8)
        self.assertGreaterEqual(kinds.count("neg"), 5)
        self.assertGreaterEqual(kinds.count("adv"), 12)
        self.assertEqual(len({m["id"] for m, _ in SCEN}), len(SCEN))

    def test_model_matches_independent_expected(self):
        exp = _expected()
        self.assertEqual(len(exp), 2 * len(SCEN))
        for m, sc in SCEN:
            for v in ("pre", "post"):
                with self.subTest(case=m["id"], version=v):
                    r = deliver(v, sc)
                    self.assertEqual([r.label, str(r.hops), r.check_ips, r.peers,
                                      str(r.resolutions)], exp[(m["id"], v)])

    def test_model_matches_hand_labels(self):
        for m, sc in SCEN:
            with self.subTest(case=m["id"]):
                self.assertEqual(deliver("pre", sc).label, m["hand_pre"])
                self.assertEqual(deliver("post", sc).label, m["hand_post"])

    def test_expected_tsv_is_what_derive_produces(self):
        out = subprocess.run([sys.executable, str(REPO / "scripts" / "derive_expected.py")],
                             check=True, capture_output=True, text=True).stdout
        self.assertEqual(out, (REPO / "fixtures" / "expected.tsv").read_text(encoding="utf-8"))


class Differential(unittest.TestCase):
    def test_acceptance(self):
        reached = 0
        for m, sc in SCEN:
            if m["kind"] == "pos":
                pre, post = deliver("pre", sc), deliver("post", sc)
                reached += pre.label == "REACHED_PRIVATE"
                self.assertEqual(post.label, "SSRF_ERROR", m["id"])
            if m["kind"] == "neg":
                self.assertEqual(deliver("pre", sc).label, deliver("post", sc).label, m["id"])
        self.assertGreaterEqual(reached, 3)

    def test_rebinding_grid(self):
        n = 0
        for check, connect in itertools.product(PUBLIC + NOT_PUBLIC, repeat=2):
            pre, post = deliver("pre", rebind(check, connect)), deliver("post", rebind(check, connect))
            n += 1
            if not is_public(check):
                self.assertEqual(pre.label, "REJECT_VALIDATION")
                self.assertEqual(post.label, "REJECT_VALIDATION")
                continue
            self.assertEqual(pre.label, "DELIVERED" if is_public(connect) else "REACHED_PRIVATE")
            self.assertEqual(post.label, "DELIVERED" if is_public(connect) else "SSRF_ERROR")
            self.assertNotEqual(post.label, "REACHED_PRIVATE")
        self.assertEqual(n, len(PUBLIC + NOT_PUBLIC) ** 2)

    def test_two_resolutions_one_check(self):
        # The TOCTOU: validation and connection resolve independently (diff 45-50).
        r = deliver("pre", rebind("11.0.0.1", "169.254.169.254"))
        self.assertEqual((r.check_ips, r.peers, r.resolutions), ("11.0.0.1", "169.254.169.254", 2))

    def test_post_check_uses_connected_peer_not_validation(self):
        # Even with an identical validation answer, post decides on the peer (diff 89, 103).
        a = deliver("post", rebind("11.0.0.1", "11.0.0.1"))
        b = deliver("post", rebind("11.0.0.1", "127.0.0.1"))
        self.assertEqual((a.label, b.label), ("DELIVERED", "SSRF_ERROR"))

    def test_rule_points_at_diff_lines(self):
        self.assertEqual(deliver("post", rebind("11.0.0.1", "127.0.0.1")).rule, "29;103-108")
        sc = Scenario("https://ok.example/", {"ok.example": [["11.0.0.1"]]}, getpeername_fails=True)
        self.assertEqual(deliver("post", sc).rule, "29;88-94")
        self.assertEqual(deliver("pre", rebind("11.0.0.1", "127.0.0.1")).rule, "25;45-50")


class Classifier(unittest.TestCase):
    def test_model_and_derivation_agree(self):
        for ip in PUBLIC:
            self.assertTrue(is_public(ip), ip)
            self.assertTrue(DERIVE.public(ip), ip)
        for ip in NOT_PUBLIC:
            self.assertFalse(is_public(ip), ip)
            self.assertFalse(DERIVE.public(ip), ip)

    def test_nat64_passes_is_global(self):
        # Beyond the diff: NAT64 of 169.254.169.254 is global to ipaddress.
        # GHSA: fixed later (PR 25568, MLflow 3.16.0); not modelled.
        self.assertEqual(deliver("post", rebind("11.0.0.1", "64:ff9b::a9fe:a9fe")).label, "DELIVERED")


class PeerCheck(unittest.TestCase):
    def test_invalid_ip_fails_closed(self):
        with self.assertRaises(SSRFProtectionError) as cm:
            assert_public_peer("999.1.1.1")
        self.assertEqual(cm.exception.rule, "95-101")

    def test_getpeername_fails_closed(self):
        with self.assertRaises(SSRFProtectionError) as cm:
            assert_public_peer("11.0.0.1", getpeername_fails=True)
        self.assertEqual(cm.exception.rule, "88-94")

    def test_allow_private_short_circuits(self):
        self.assertIsNone(assert_public_peer("127.0.0.1", allow_private=True))
        self.assertIsNone(assert_public_peer("999.1.1.1", allow_private=True, getpeername_fails=True))

    def test_not_global(self):
        with self.assertRaises(SSRFProtectionError) as cm:
            assert_public_peer("169.254.169.254")
        self.assertEqual(cm.exception.rule, "103-108")


class Resolver(unittest.TestCase):
    def test_sequence_then_repeat_last(self):
        r = FakeResolver({"h.example": [["11.0.0.1"], ["127.0.0.1"]]})
        self.assertEqual([r.resolve("h.example") for _ in range(4)],
                         [["11.0.0.1"], ["127.0.0.1"], ["127.0.0.1"], ["127.0.0.1"]])

    def test_literals_and_nxdomain(self):
        r = FakeResolver({})
        self.assertEqual(r.resolve("::1"), ["::1"])
        with self.assertRaises(LookupError):
            r.resolve("missing.example")
        with self.assertRaises(ValueError):
            FakeResolver({"h.example": [[]]})

    def test_bad_version(self):
        with self.assertRaises(ValueError):
            deliver("master", rebind("11.0.0.1", "11.0.0.1"))

    def test_no_network_is_touched(self):
        def boom(*a, **k):
            raise AssertionError("network call")
        with mock.patch.object(socket, "socket", boom), \
             mock.patch.object(socket, "create_connection", boom), \
             mock.patch.object(socket, "getaddrinfo", boom), \
             mock.patch.object(socket, "gethostbyname", boom):
            for _, sc in SCEN:
                for v in ("pre", "post"):
                    deliver(v, sc)

    def test_deterministic(self):
        for _, sc in SCEN:
            self.assertEqual(deliver("pre", sc), deliver("pre", sc))
            self.assertEqual(deliver("post", sc), deliver("post", sc))


class Practice(unittest.TestCase):
    def test_practice_level_1(self):
        self.assertEqual(deliver("pre", rebind("11.0.0.1", "11.0.0.1")).label, "DELIVERED")

    def test_practice_level_2(self):
        self.assertEqual(deliver("pre", rebind("127.0.0.1", "127.0.0.1")).label, "REJECT_VALIDATION")

    def test_practice_level_3(self):
        self.assertEqual(deliver("pre", rebind("11.0.0.1", "169.254.169.254")).label, "REACHED_PRIVATE")

    def test_practice_level_4(self):
        r = deliver("post", rebind("11.0.0.1", "169.254.169.254"))
        self.assertEqual((r.label, r.rule), ("SSRF_ERROR", "29;103-108"))

    def test_practice_level_5(self):
        self.assertEqual(deliver("post", rebind("11.0.0.1", "::ffff:10.0.0.1")).label, "SSRF_ERROR")

    def test_practice_level_6(self):
        sc = Scenario("https://ok.example/", {"ok.example": [["11.0.0.1"]]}, env_proxy="127.0.0.1")
        self.assertEqual((deliver("pre", sc).label, deliver("post", sc).label),
                         ("REACHED_PRIVATE", "DELIVERED"))

    def test_practice_level_7(self):
        self.assertEqual(deliver("post", rebind("11.0.0.1", "64:ff9b::a9fe:a9fe")).label, "DELIVERED")


class Results(unittest.TestCase):
    def test_results_regenerate_byte_identical(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            env = dict(os.environ, PYTHONPATH=str(REPO / "src"))
            for d in (a, b):
                subprocess.run([sys.executable, "-m", "mlflow_ssrf_model", "results",
                                str(REPO / "fixtures" / "scenarios.json"), d], check=True, env=env)
            for name in ("cases.csv", "differential.csv", "SHA256SUMS"):
                ba = Path(a, name).read_bytes()
                self.assertEqual(ba, Path(b, name).read_bytes())
                self.assertEqual(ba, (REPO / "results" / name).read_bytes(), name)


if __name__ == "__main__":
    unittest.main()
