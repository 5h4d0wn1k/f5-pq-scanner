# F5 — Post-quantum readiness scanner

Inventories weak-in-2035 cryptography (RSA/ECDSA/ECDH) and grades the estate against seven government migration timelines with a Quantum Readiness Score.

## Overview

- **Weak-in-2035 crypto inventory**: Static source scan for RSA/ECDSA/ECDH usage with key-size detection across config/env/bundle files from an embedded sample tree
- **Cipher-probe output parser**: Consumes TLS/SSH handshake/test output naming ciphers and curves (x25519, secp256r1, RSA2048, X25519MLKEM768) and maps each to quantum robustness
- **CBOM JSON**: Emits a CycloneDX-ish Cryptographic Bill of Materials enumerating weak components
- **Framework grading**: Scores readiness against seven frameworks' timelines (CNSA 2.0, NIST IR 8547, BSI, NCSC, ASD, ANSSI, KCMSP) producing a framework-divergence table
- **Fully offline**: Runs against an embedded sample "codebase" and canned probe output

## Features

- **Static source scan** for `RSA`, `ECDSA`, `ECDH`, curves `secp256r1`/`P-256`/`P-384`
- **Key-size detection** (1024/2048/3072/4096) tagged with the year they become quantum-tractable
- **Cipher-probe parser** that classifies negotiated suites as weak / hybrid / compliant
- **Hybrid PQC detection** for ML-KEM/Kyber/sntrup combined suites (e.g. `X25519MLKEM768`)
- **CycloneDX 1.5 CBOM** output with per-asset weak-by-2035 properties
- **Seven-framework divergence table** with clear migrate-by deadlines
- **Quantum Readiness Score** (0-100)

## Installation

```bash
# No third-party dependencies. Python 3.8+ standard library only.
pip install -r requirements.txt   # (empty; nothing required)
```

## Usage

```python
from pq_scanner import parse_probe_output, scan_source_tree, grade_frameworks, build_cbom

findings = scan_source_tree("path/to/source")
entries = parse_probe_output(probe_text)
rows, score = grade_frameworks(findings, entries)
cbom = build_cbom(findings, entries, rows)
```

### Running the Demo

```bash
python3 firmware/pq_scanner.py
```

## Example Output

```
============================================================
  F5 — Post-quantum readiness scanner
============================================================

[1/4] Static source scan (RSA/ECDSA/ECDH, key-size detection) ...
  findings: 7
  by kind : {'rsa': 3, 'ecc': 3, 'key_size': 1}
[2/4] TLS/SSH cipher-probe output parser ...
  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   -> weak (classically-weak)
  KEX: X25519MLKEM768                     -> hybrid (PQC + classically-weak)
[3/4] Framework timeline grading (7 frameworks)...
  Quantum Readiness Score: 25/100
```

## IMPORTANT: Read before use.

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission before scanning an organization's cryptographic estate
- Unauthorized scanning of systems or network service cipher suites may violate computer fraud laws
- This tool should ONLY be used on systems you own or have written authorization to assess

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Penetration Testing / Security Research Laws**: Some jurisdictions exempt authorized security research; others do not
- **State Laws**: Many states have additional computer crime statutes
- **Contractual Terms**: Scanning may breach acceptable-use policies or software license terms

### Acceptable Use
- Assessing the cryptographic posture of your own systems
- Authorized readiness assessments with a written scope and budget
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Scanning systems you do not own without authorization
- Using output to access or exfiltrate data beyond the assessment scope
- Any activity that violates applicable laws or regulations
- Facilitating unauthorized penetration of third-party infrastructure

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover cryptographic weaknesses using this tool, follow responsible disclosure practices:
1. Report to the system owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
