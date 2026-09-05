#!/usr/bin/env python3
"""
F5 — Post-quantum readiness scanner
Inventories weak-in-2035 cryptography (RSA/ECDSA/ECDH) across source trees,
parses TLS/SSH cipher-probe output, emits a CycloneDX-ish CBOM JSON, and grades
the estate against seven government/framework migration timelines, producing a
framework-divergence table and a Quantum Readiness Score.

Educational / authorized use only. See README legal section.

Usage:
    python3 pq_scanner.py            # run the offline self-test demo (exit 0)
"""

import hashlib
import json
import os
import re
import sys
from collections import defaultdict, Counter

# ---------------------------------------------------------------------------
# Static source scanning: patterns that reveal weak-in-2035 algorithm usage
# ---------------------------------------------------------------------------

RSA_RE = re.compile(r"\bRSA(?:/)?(?:OAEP|PSS|PKCS1|SHA\d{3})?\b", re.IGNORECASE)
ECDSA_RE = re.compile(r"\b(?:ECDSA|ECDH|secp256r1|secp384r1|P-256|P-384)\b", re.IGNORECASE)
KEY_LEN_RE = re.compile(r"\b(?:RSA|bits|key_size|key_length)\s*[=:]\s*(\d{4})", re.IGNORECASE)

# Approximate year each key length / curve becomes tractable for a quantum
# adversary (Shor's algorithm). Used for the weak-by-2035 cutoff.
GENERIC_BITS_YEAR = {
    1024: 2020,
    2048: 2030,
    3072: 2035,
    4096: 2040,
}


def scan_source_tree(root, file_exts=(".py", ".c", ".h", ".cpp", ".hpp", ".go", ".rs", ".js", ".conf", ".json", ".env")):
    """Walk an embedded sample tree and collect crypto-usage findings."""
    findings = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in filenames:
            if not any(fn.endswith(e) for e in file_exts):
                continue
            path = os.path.join(dirpath, fn)
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    lines = fh.readlines()
            except OSError:
                continue
            for idx, line in enumerate(lines, 1):
                low = line.lower()
                if "rsa" in low:
                    findings.append(_finding(path, idx, "rsa", "RSA/public-key (Shor-vulnerable)", line))
                if "ecdsa" in low or "ecdh" in low or "secp256r1" in low or "secp384r1" in low:
                    findings.append(_finding(path, idx, "ecc", "ECDSA/ECDH on non-PQC curve", line))
                for bits, year in GENERIC_BITS_YEAR.items():
                    if f"{bits}" in low and year <= 2035:
                        findings.append(_finding(path, idx, "key_size", f"{bits}-bit key (weak-by-{year})", line))
    return findings


def _finding(path, line_no, kind, desc, snippet):
    return {
        "file": os.path.relpath(path),
        "line": line_no,
        "kind": kind,
        "description": desc,
        "weak_by_2035": True,
        "sha256_of_line": hashlib.sha256(snippet.strip().encode("utf-8", "replace")).hexdigest()[:16],
    }


# ---------------------------------------------------------------------------
# TLS/SSH cipher-probe output parser
# ---------------------------------------------------------------------------
#
# Consumes the text a client like `openssl s_client` / `ssh -Q kex` would emit:
#   TLS_AES_128_GCM_SHA256          TLSv1.3 Kx=any  Au=any    Enc=AESGCM(128)
#   TLS_ECDHE_RSA_WITH_AES_GCM_SHA256  TLSv1.2 Kx=ECDH  Au=RSA  Enc=AESGCM(128)
#   KEX: sntrup761x25519-sha512
#   KEX: curve25519-sha256
# and maps each negotiated suite/cipher/curve to its quantum robustness.

KNOWN_WEAK_TOKEN = ["rsa", "ecdsa", "ecdh", "secp256", "p-256", "p-384", "p-521", "curve25519", "x25519", "nistp"]

# Curve name -> weak? (all elliptic curves used for key exchange are broken by
# Shor's algorithm unless ML-KEM/other PQC is combined with them).
CURVE_WEAK = {
    "secp256r1": True, "secp384r1": True, "secp521r1": True,
    "prime256v1": True, "x25519": True, "curve25519": True,
    "x448": True, "curve448": True,
}
# Composite / hybrid PQC offerings that are acceptable heading toward 2035.
PQC_TOKENS = ["mlkem", "kyber", "sntrup", "frodo", "classic-mceliece", "x25519mlkem768", "p256_kyber", "mlkem768x25519"]


def parse_probe_output(text, source="embedded-probe.txt"):
    """Parse cipher-probe text into a structured list of negotiated entries."""
    entries = []
    seen = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        low = line.lower()

        if low.startswith("kx:") or re.match(r"^\s*(tls|sslv[23]|x25519|curve|secp|aes|chacha|mlkem|kyber)", low):
            entries.append(_classify_probe_line(line, source))

        # openssl s_client style lines that contain cipher + Kx= + Au= + Enc=
        elif "kx=" in low or "au=" in low:
            entries.append(_classify_probe_line(line, source))
    # de-duplicate by normalized line
    uniq = []
    for e in entries:
        key = (e["line"],)
        if key not in seen:
            seen.add(key)
            uniq.append(e)
    return uniq


def _classify_probe_line(line, source):
    low = line.lower()
    weak = False
    pqc = False
    detail = "unknown"
    for t in PQC_TOKENS:
        if t in low:
            pqc = True
    for t in KNOWN_WEAK_TOKEN:
        if t in low:
            weak = True
    if any(c in low for c in ["aesgcm", "chacha20", "sha256", "sha384", "tls1.3", "tls1.2", "tls1.3"]):
        detail = "bulk-encryption/suite"
    if weak and pqc:
        detail = "hybrid (PQC + classically-weak)"
    elif pqc:
        detail = "pure-PQC"
    elif weak:
        detail = "classically-weak (Shor-vulnerable)"
    status = "compliant" if (pqc and not weak) else "hybrid" if (pqc and weak) else "weak"
    return {
        "source": source,
        "line": line,
        "weak": weak,
        "pqc": pqc,
        "detail": detail,
        "status": status,
        "recommend": "replace-with-ML-KEM" if status == "weak" else "monitor" if status == "hybrid" else "ok",
    }


# ---------------------------------------------------------------------------
# Framework migration timelines (timelines for when crypto must be migrated)
# ---------------------------------------------------------------------------

FRAMEWORKS = {
    "CNSA 2.0 (US NSA)":        {"software-2035": True, "deploy_by": 2035, "target": "ML-KEM/ML-DSA"},
    "NIST IR 8547 (US)":        {"software-2035": True, "deploy_by": 2035, "target": "PQC standalone"},
    "BSI (Germany)":            {"software-2035": True, "deploy_by": 2030, "target": "hybrid optional"},
    "NCSC (UK)":                {"software-2035": True, "deploy_by": 2033, "target": "hybrid/standard"},
    "ASD (Australia)":          {"software-2035": True, "deploy_by": 2030, "target": "PQC hybrid"},
    "ANSSI (France)":           {"software-2035": True, "deploy_by": 2035, "target": "PQC (2025-2030 first)"},
    "KCMSP (S. Korea KISA)":    {"software-2035": True, "deploy_by": 2030, "target": "KCMSP with PQC"},
}

# The extra "one more" beyond the six named is KCMSP (Korea KISA). CNSA 2.0,
# NIST IR 8547, BSI, NCSC, ASD, ANSSI are the other six.


def grade_frameworks(findings, probe_entries):
    """Produce per-framework readiness status + a divergence table."""
    total_weak = len(findings) + sum(1 for p in probe_entries if p["status"] == "weak")
    overall = _readiness_grade(total_weak)
    rows = []
    for name, spec in FRAMEWORKS.items():
        compliant = total_weak == 0
        status = "compliant" if compliant else "at-risk"
        rows.append({
            "framework": name,
            "deploy_by": spec["deploy_by"],
            "target": spec["target"],
            "weak_assets": total_weak,
            "status": status,
            "migrate_required": spec["deploy_by"] <= 2035,
        })
    return rows, overall


def _readiness_grade(weak_count):
    if weak_count == 0:
        return 100
    if weak_count <= 2:
        return 75
    if weak_count <= 5:
        return 50
    return 25


# ---------------------------------------------------------------------------
# CycloneDX-ish CBOM JSON builder
# ---------------------------------------------------------------------------

def build_cbom(findings, probe_entries, framework_rows):
    weak_components = []
    for f in findings:
        weak_components.append({
            "type": "cryptographic-asset",
            "name": f["file"],
            "bom-ref": f"crypto-{f['sha256_of_line']}",
            "description": f["description"],
            "properties": [{"name": "weak-by-2035", "value": "true"}],
        })
    for p in probe_entries:
        if p["status"] == "weak":
            weak_components.append({
                "type": "cryptographic-asset",
                "name": p["line"],
                "description": p["detail"],
                "properties": [{"name": "status", "value": p["status"]}],
            })
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:f5pq-scan-" + hashlib.sha1(str(len(findings)).encode()).hexdigest()[:8],
        "metadata": {"component": {"type": "application", "name": "f5-pq-scanner", "version": "1.0"}},
        "components": weak_components,
        "services": [],
        "quantumReadiness": {
            "score": _readiness_grade(len(findings) + sum(1 for p in probe_entries if p["status"] == "weak")),
            "frameworks": framework_rows,
        },
    }


# ---------------------------------------------------------------------------
# EMBEDDED SAMPLE DATA (offline demo tree + probe output)
# ---------------------------------------------------------------------------

SAMPLE_TREE = {
    "service-auth": {
        "auth.go": [
            "func login() error {\n",
            "    // RSA2048 used for session ticket signing\n",
            "    key, _ := rsa.GenerateKey(rand.Reader, 2048)\n",
            "    sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)\n",
            "}\n",
        ],
        "config.json": [
            "{\n",
            '  "tls": {"cert":"server.crt", "key_size": 2048, "curve":"secp256r1"},\n',
            "}\n",
        ],
    },
    "edge-proxy": {
        "crypto.c": [
            "/* ECDHE handshake, P-256 */\n",
            "EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);\n",
            "/* hash for signature */\n",
        ],
        "proxy.go": [
            "package edge\n",
            "// RSA-1024 legacy fallback retained for old clients\n",
            "func legacy() { tls.Config{CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}} }\n",
        ],
    },
    "device-agent": {
        "agent.py": [
            "import ssl\n",
            "# BLE transport uses ECDH (P-384) for session establishment\n",
            "curve = ssl.ECDH_AUTO\n",
        ],
        ".env": [
            "PAYLOAD_ENCRYPTION=rsa\n",
            "KEY_BITS=3072\n",
        ],
    },
}

PROBE_OUTPUT = """\
TLS_AES_128_GCM_SHA256                    TLSv1.3 Kx=any      Au=any    Enc=AESGCM(128)  Mac=AEAD
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256     TLSv1.2 Kx=ECDH     Au=RSA    Enc=AESGCM(128)  Mac=AEAD
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256   TLSv1.2 Kx=ECDH     Au=ECDSA  Enc=AESGCM(128)  Mac=AEAD
KEX: curve25519-sha256
KEX: sntrup761x25519-sha512
KEX: X25519MLKEM768
"""


def _materialize_tree(root):
    """Write the embedded sample tree to disk so the scanner can walk it."""
    os.makedirs(root, exist_ok=True)
    for sub, files in SAMPLE_TREE.items():
        d = os.path.join(root, sub)
        os.makedirs(d, exist_ok=True)
        for fn, lines in files.items():
            with open(os.path.join(d, fn), "w", encoding="utf-8") as fh:
                fh.writelines(lines)


# ---------------------------------------------------------------------------
# Demo / self-test
# ---------------------------------------------------------------------------

def main(argv=None):
    print("=" * 60)
    print("  F5 — Post-quantum readiness scanner")
    print("=" * 60)

    import tempfile
    workdir = tempfile.mkdtemp(prefix="f5-pq-")
    tree_root = os.path.join(workdir, "codebase")
    _materialize_tree(tree_root)

    print("\n[1/4] Static source scan (RSA/ECDSA/ECDH, key-size detection) ...")
    findings = scan_source_tree(tree_root)
    print(f"  findings: {len(findings)}")
    by_kind = Counter(f["kind"] for f in findings)
    print(f"  by kind : {dict(by_kind)}")
    for f in findings[:5]:
        print(f"    - {f['file']}:{f['line']}  [{f['description']}]")

    print("\n[2/4] TLS/SSH cipher-probe output parser ...")
    entries = parse_probe_output(PROBE_OUTPUT)
    print(f"  negotiated entries: {len(entries)}")
    for e in entries:
        print(f"    - {e['line']:<60} -> {e['status']} ({e['detail']})")

    print("\n[3/4] Framework timeline grading (7 frameworks)...")
    rows, score = grade_frameworks(findings, entries)
    print(f"  Quantum Readiness Score: {score}/100")
    print(f"  {'framework':<22} {'deploy_by':<9} {'weak':<5} status")
    print("  " + "-" * 55)
    for r in rows:
        print(f"  {r['framework']:<22} {r['deploy_by']:<9} {r['weak_assets']:<5} {r['status']}")

    print("\n[4/4] CycloneDX-ish CBOM JSON ...")
    cbom = build_cbom(findings, entries, rows)
    js = json.dumps(cbom, indent=2)
    cbom_path = os.path.join(workdir, "cbom.json")
    with open(cbom_path, "w", encoding="utf-8") as fh:
        fh.write(js)
    print(f"  wrote CBOM -> {cbom_path}")
    print(f"  CBOM weak components: {len(cbom['components'])}")

    print("\nFramework-divergence (which frameworks demand action by when):")
    for r in rows:
        if r["migrate_required"] and r["status"] == "at-risk":
            print(f"    - {r['framework']}: migrate by {r['deploy_by']} -> target {r['target']}")

    print("\nDemo complete (exit 0).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
