import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from firmware.pq_scanner import (  # noqa: E402
    FIXTURES,
    SSH_TRANSCRIPTS,
    TLS_TRANSCRIPTS,
    classify_transcript,
    classify_weak,
    main,
    quantum_readiness_score,
    rsa_bits_to_security,
    scan,
)


class RsaSecurityTest(unittest.TestCase):
    def test_1024_is_weak(self):
        self.assertLess(rsa_bits_to_security(1024), 100)

    def test_3072_is_strong(self):
        self.assertGreaterEqual(rsa_bits_to_security(3072), 128)

    def test_2048_is_below_128(self):
        self.assertLess(rsa_bits_to_security(2048), 128)


class ClassifyWeakTest(unittest.TestCase):
    def test_webapi_rsa_1024_tls12_flagged(self):
        fs = classify_weak(FIXTURES["web-api"], "web-api")
        types = [f["type"] for f in fs if f["weak"]]
        self.assertIn("rsa_key_size", types)
        self.assertIn("tls_version", types)

    def test_gateway_hybrid_not_flagged_as_protocol_weak(self):
        fs = classify_weak(FIXTURES["gateway"], "gateway")
        types = [f["type"] for f in fs if f["weak"]]
        # hybrid key exchange is present, but the RSA-2048 cert is still below
        # the NIST 3072 initial-migration threshold -> only rsa_key_size is weak
        self.assertNotIn("tls_version", types)
        self.assertNotIn("ecc_short_curve", types)
        self.assertIn("rsa_key_size", types)

    def test_legacy_vpn_short_dh_flagged(self):
        fs = classify_weak(FIXTURES["legacy-vpn"], "legacy-vpn")
        types = [f["type"] for f in fs if f["weak"]]
        self.assertIn("dh_short_group", types)

    def test_ssh_group23_ok_group14_flagged(self):
        ok = classify_weak({"ssh": True, "kex": "diffie-hellman-group14-sha256",
                            "host_key_alg": "ed25519", "host_key_bits": 256},
                           "x")[0]
        self.assertTrue(ok["weak"])


class ClassifyTranscriptTest(unittest.TestCase):
    def test_tls_12_transcript_flagged(self):
        fs = classify_transcript(TLS_TRANSCRIPTS["web-api"], "web-api")
        types = [f["type"] for f in fs if f["weak"]]
        self.assertIn("transcript_tls12", types)

    def test_pqc_hybrid_transcript_detected(self):
        fs = classify_transcript(TLS_TRANSCRIPTS["gateway"], "gateway")
        self.assertTrue(any(f["type"] == "transcript_pqc_hybrid" for f in fs))

    def test_ssh_transcript_group14_flagged_by_rsa_threshold(self):
        fs = classify_transcript(SSH_TRANSCRIPTS["ssh-gateway"], "ssh-gateway")
        self.assertTrue(fs)


class ScanTest(unittest.TestCase):
    def test_scan_finds_weak_in_fixtures(self):
        findings = scan(FIXTURES, TLS_TRANSCRIPTS, SSH_TRANSCRIPTS)
        self.assertTrue(any(f["weak"] for f in findings))
        self.assertTrue(any(f["type"] == "transcript_pqc_hybrid"
                            for f in findings))

    def test_score_drops_with_weak_findings(self):
        findings = scan(FIXTURES, TLS_TRANSCRIPTS, SSH_TRANSCRIPTS)
        score = quantum_readiness_score(findings)
        self.assertLess(score, 100)
        self.assertGreaterEqual(score, 0)


class CliTest(unittest.TestCase):
    def test_demo_exit_zero_report_written(self):
        with tempfile.TemporaryDirectory() as td:
            rp = os.path.join(td, "r.md")
            code = main(["--report", rp])
            self.assertEqual(code, 0)  # demo run exits 0 by contract
            self.assertIn("POST-QUANTUM", open(rp).read())

    def test_strict_exits_one_when_weak(self):
        with tempfile.TemporaryDirectory() as td:
            rp = os.path.join(td, "r.md")
            code = main(["--report", rp, "--strict"])
            self.assertEqual(code, 1)

    def test_json_report(self):
        with tempfile.TemporaryDirectory() as td:
            rp = os.path.join(td, "r.json")
            code = main(["--report", rp])
            self.assertEqual(code, 0)
            data = json.loads(open(rp).read())
            self.assertIn("score", data)
            self.assertTrue(data["weak"])


if __name__ == "__main__":
    unittest.main()