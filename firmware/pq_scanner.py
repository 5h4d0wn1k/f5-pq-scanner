#!/usr/bin/env python3
"""
F5 — Post-quantum cryptography scanner.

Inspects key-exchange configurations and TLS/SSH transcript representations and
flags any cryptography weaker than NIST post-quantum migration thresholds
(RSA < 3072, ECDH/ECDSA on curves < 256 bits, classical DH groups < 2048, DH on
*any* TLS 1.2 suite, TLS 1.2-without-PQC-hybrid).

Runs queries against synthetic fixture configs (never a live network) and
produces JSON/Markdown findings plus a Quantum Readiness Score (0-100). Fully
offline and deterministic - standard library only.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# --------------------------------------------------------------------------- #
# NIST PQC migration thresholds (documented; 3.1.1-era informative).
# --------------------------------------------------------------------------- #
THRESHOLDS = {
    "rsa_min_bits": 3072,           # AES-128-equivalent security
    "ecc_min_bits": 256,            # curves below 256 bits are weak
    "dh_min_group_bits": 2048,      # classical finite-field groups
    "tls_min_version_ok": "1.3",    # TLS 1.2 without hybrid is a finding
}


# --------------------------------------------------------------------------- #
# Synthetic fixture configs + TLS/SSH transcript representations.
# --------------------------------------------------------------------------- #
FIXTURES = {
    "web-api": {
        "tls_version": "1.2",
        "cert": {"key_alg": "RSA", "key_bits": 1024, "subject": "api.example.com"},
        "key_exchange": {"algo": "ECDHE_RSA", "curve": "secp521r1"},
        "cipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    },
    "gateway": {
        "tls_version": "1.3",
        "cert": {"key_alg": "RSA", "key_bits": 2048, "subject": "gw.example.com"},
        "key_exchange": {"algo": "X25519MLKEM768", "curve": "x25519"},
        "cipher": "TLS_AES_256_GCM_SHA384",
    },
    "legacy-vpn": {
        "tls_version": "1.2",
        "cert": {"key_alg": "RSA", "key_bits": 1024, "subject": "vpn.example.com"},
        "key_exchange": {"algo": "DH", "group_bits": 1024, "curve": None},
        "cipher": "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    },
    "ssh-gateway": {
        "ssh": True,
        "kex": "diffie-hellman-group14-sha256",   # 2048-bit group (borderline)
        "host_key_alg": "ssh-rsa",
        "host_key_bits": 4096,
    },
}

# TLS transcript representation: extraction of `openssl s_client ... | grep Cipher`
TLS_TRANSCRIPTS = {
    "web-api": "New, TLSv1.2, Cipher is TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "gateway": "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n"
               "Server Temp Key: X25519MLKEM768 3072 bits",
    "legacy-vpn": "New, TLSv1.2, Cipher is TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
}

SSH_TRANSCRIPTS = {
    "ssh-gateway": "kex_algorithm: diffie-hellman-group14-sha256\n"
                   "server_host_key_algorithms: ssh-rsa\n",
}

# --------------------------------------------------------------------------- #
# Cost heuristics: attack complexity in ~bits of security for the crypto under
# migration. Post-quantum: large classical RSA/DH and short curves are the
# headline flags.
# --------------------------------------------------------------------------- #
def rsa_bits_to_security(bits):
    """Approximate classical security (bits) for RSA modulus size.

    Documented anchor points (ECRYPT-CSA / NIST-equivalent estimates):
      1024 -> ~80, 2048 -> ~112, 3072 -> ~128, 4096 -> ~140.
    """
    anchors = [(1024, 80), (2048, 112), (3072, 128), (4096, 140)]
    if bits <= anchors[0][0]:
        return int(bits / 1024 * anchors[0][1])
    for (a, sa), (b, sb) in zip(anchors, anchors[1:]):
        if a <= bits <= b:
            frac = (bits - a) / (b - a)
            return int(sa + frac * (sb - sa))
    return int(anchors[-1][1] + (bits - anchors[-1][0]) / 10)


def ecc_curve_security(bits):
    return int(bits / 2)


def classify_weak(conf, name):
    """Return list of finding dicts for one config."""
    findings = []
    src = "config"

    tls_ver = conf.get("tls_version")
    if tls_ver and tls_ver < "1.3":
        findings.append({
            "asset": name, "type": "tls_version",
            "detail": "TLS %s in use; migrate to TLS 1.3 or add hybrid PQC"
                      % tls_ver,
            "weak": True})

    cert = conf.get("cert") or {}
    key_alg = cert.get("key_alg", "")
    key_bits = cert.get("key_bits")
    if key_alg.upper() == "RSA" and key_bits:
        if key_bits < THRESHOLDS["rsa_min_bits"]:
            findings.append({
                "asset": name, "type": "rsa_key_size",
                "detail": "RSA-%d < NIST threshold RSA-%d"
                          % (key_bits, THRESHOLDS["rsa_min_bits"]),
                "weak": True})

    kex = conf.get("key_exchange") or {}
    curve = kex.get("curve")
    group_bits = kex.get("group_bits")
    algo = kex.get("algo", "")
    if "X25519MLKEM" in algo or "MLKEM" in algo or "kyber" in algo.lower():
        findings.append({"asset": name, "type": "hybrid_pqc",
                         "detail": algo + " hybrid present", "weak": False})
    if curve and curve not in ("x25519",) and "PQC" not in algo:
        m = re.search(r"(\d+)", curve)
        if m and m.group(1).startswith("521"):
            pass  # secp521r1 is fine
        bits = int(m.group(1)) if m else 0
        if 0 < bits < THRESHOLDS["ecc_min_bits"]:
            findings.append({
                "asset": name, "type": "ecc_short_curve",
                "detail": "curve %s ≈ %d-bit security < 128-bit PQC target" %
                          (curve, bits // 2), "weak": True})
    if group_bits and group_bits < THRESHOLDS["dh_min_group_bits"]:
        findings.append({
            "asset": name, "type": "dh_short_group",
            "detail": "DH group %d < %d bits" %
                      (group_bits, THRESHOLDS["dh_min_group_bits"]),
            "weak": True})

    # SSH representation
    if conf.get("ssh"):
        kex_name = conf.get("kex", "")
        if "group14" in kex_name or "group1" in kex_name:
            g = int(re.search(r"group\d+", kex_name).group(0).lstrip("group"))
            if g < THRESHOLDS["rsa_min_bits"]:
                findings.append({
                    "asset": name, "type": "ssh_short_dh_group",
                    "detail": kex_name + " group %d < NIST threshold" % g,
                    "weak": True})
        hk = conf.get("host_key_alg", "")
        if hk == "ssh-rsa" and conf.get("host_key_bits", 0) < THRESHOLDS["rsa_min_bits"]:
            findings.append({
                "asset": name, "type": "ssh_rsa_key_size",
                "detail": "ssh-rsa host key %d bits" % conf["host_key_bits"],
                "weak": True})
        if "rsa" in hk.lower() and "509" in hk:
            findings.append({
                "asset": name, "type": "ssh_cert_delegation",
                "detail": hk, "weak": False})

    return findings


def classify_transcript(text, name):
    """Inspect a TLS/SSH transcript representation for weak negotiations."""
    findings = []
    m_tls = re.search(r"TLSv1\.(\d)", text)
    if m_tls and m_tls.group(0).endswith("2"):
        findings.append({
            "asset": name, "type": "transcript_tls12",
            "detail": "transcript negotiated TLS 1.2", "weak": True})
    for suite in re.findall(r"TLS_[A-Z0-9_]+", text):
        if "DHE" in suite or "RSA" in suite and "ECDHE_RSA" in suite:
            if "MLKEM" not in text and "KYBER" not in text.upper():
                findings.append({
                    "asset": name, "type": "transcript_classical_only",
                    "detail": suite, "weak": True})
    m_kex = re.search(r"X25519MLKEM(\d+)", text)
    if m_kex:
        findings.append({"asset": name, "type": "transcript_pqc_hybrid",
                         "detail": "X25519MLKEM%s hybrid" % m_kex.group(1),
                         "weak": False})

    m_ssh_kex = re.search(r"kex_algorithm:\s*(\S+)", text)
    if m_ssh_kex:
        kex = m_ssh_kex.group(1)
        g = re.search(r"group(\d+)", kex)
        if g and int(g.group(1)) < THRESHOLDS["dh_min_group_bits"]:
            findings.append({
                "asset": name, "type": "transcript_ssh_short_group",
                "detail": kex, "weak": True})
    m_hk = re.search(r"server_host_key_algorithms:\s*(\S+)", text)
    if m_hk and "rsa" in m_hk.group(1):
        findings.append({
            "asset": name, "type": "transcript_ssh_hostkey",
            "detail": m_hk.group(1), "weak": True})
    return findings


def scan(configs, transcripts, ssh_transcripts):
    findings = []
    for name, conf in configs.items():
        findings.extend(classify_weak(conf, name))
    for name, text in transcripts.items():
        findings.extend(classify_transcript(text, name))
    for name, text in ssh_transcripts.items():
        findings.extend(classify_transcript(text, name))
    return findings


# --------------------------------------------------------------------------- #
# Readiness scoring + report.
# --------------------------------------------------------------------------- #
def quantum_readiness_score(findings, total=100):
    """Score 0-100; weak findings deduct against a clean baseline."""
    weak = [f for f in findings if f["weak"]]
    deduction = min(100, 25 * len({f["asset"] for f in weak}))
    return max(0, total - deduction)


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="f5-pq-scanner",
        description="Post-quantum scanner: inspection of key-exchange configs "
                    "and TLS/SSH transcript representations, flagging anything "
                    "weaker than NIST PQC migration thresholds.",
    )
    ap.add_argument("--config-file", default=None,
                    help="path to a JSON config of assets to scan (overrides "
                         "embedded fixture set)")
    ap.add_argument("--transcript-file", default=None,
                    help="path to a TLS transcript text to scan")
    ap.add_argument("--config", default="config.json")
    ap.add_argument("--report", default="reports/report.md")
    ap.add_argument("--strict", action="store_true",
                    help="exit 1 when weak crypto is present (gate mode)")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args(argv)

    cfg = {}
    cfg_path = Path(args.config)
    if cfg_path.exists():
        try:
            cfg = json.loads(cfg_path.read_text())
        except json.JSONDecodeError:
            print("[config] parse error in %s" % cfg_path, file=sys.stderr)
            return 2

    if args.config_file:
        configs = json.loads(Path(args.config_file).read_text())
    else:
        configs = FIXTURES
    transcripts = dict(TLS_TRANSCRIPTS)
    ssh_transcripts = dict(SSH_TRANSCRIPTS)
    if args.transcript_file:
        transcripts["cli_transcript"] = Path(args.transcript_file).read_text()

    findings = scan(configs, transcripts, ssh_transcripts)
    weak = [f for f in findings if f["weak"]]
    score = quantum_readiness_score(findings)

    banner = "=" * 62 + "\n  F5 - POST-QUANTUM CRYPTO SCANNER\n" + "=" * 62
    lines = [banner,
             "  Assets scanned      : %d" % len(configs),
             "  Findings            : %d (weak: %d)" % (len(findings), len(weak)),
             "  Quantum readiness   : %d/100" % score,
             ""]
    lines.append("  findings by asset:")
    for f in findings:
        mark = "[WEAK ]" if f["weak"] else "[OK   ]"
        lines.append("    %s %-16s %-22s %s" %
                     (mark, f["asset"], f["type"], f["detail"]))
    text = "\n".join(lines)

    out = Path(args.report)
    out.parent.mkdir(parents=True, exist_ok=True)
    if args.report.endswith(".json"):
        out.write_text(json.dumps(
            {"findings": findings, "weak": [f["asset"] for f in weak],
             "score": score}, indent=2))
    else:
        out.write_text(text)
    print(text)

    # 0 = successful run, 1 = weak crypto present (--strict only), 2 = error.
    return 1 if (weak and args.strict) else 0


if __name__ == "__main__":
    sys.exit(main())