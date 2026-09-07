# F5 — Post-Quantum Crypto Scanner

A deterministic, offline, standard-library-only scanner that inspects
**key-exchange configurations** and **TLS/SSH transcript representations** and
flags anything weaker than NIST post-quantum migration thresholds.

## Overview

- **Thresholds documented**: RSA < 3072 is weak; ECDH/ECDSA curves < 256 bits
  are weak; classical DH groups < 2048 bits are weak; TLS 1.2 without a hybrid
  PQC suite is weak. Source: NIST IR 8547 / IETF hybrid key-share direction.
- **Config inspection** — parses synthetic asset configs (cert key algorithm +
  size, KEX algorithm + curve/group, TLS version, SSH kex/host-key).
- **Transcript inspection** — parses canned `openssl s_client`/SSH output text
  and detects negotiated TLS 1.2, classical-only suites, weak DH groups,
  ssh-rsa host keys, and **hybrid PQC** agreements (`X25519MLKEM768`).
- **Quantum Readiness Score** — 0–100, deducting per weak asset.
- Clean exit codes: `0` = successful run, `1` = weak crypto present with
  `--strict` (gate mode), `2` = config error. The default demo run always exits
  `0`. Reports to `reports/` (Markdown or JSON), gitignored.

## CLI

```bash
python3 firmware/pq_scanner.py --help
python3 firmware/pq_scanner.py
python3 firmware/pq_scanner.py --config-file assets.json --report reports/r.md
python3 firmware/pq_scanner.py --transcript-file tls.log --report reports/r.json
```

Config lives in `config.json` (thresholds). All scans run against synthetic
fixtures or files you supply; nothing ever queries a live network.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## IMPORTANT: Read before use.

Provided **exclusively** for authorized security research, academic study, and
readiness assessment of systems you own or are authorized to assess.

### Authorization Requirements

You MUST have explicit written permission before scanning any organization's
cryptographic estate. This tool inspects config files and canned transcripts
only; do not point it at systems you do not own or lack written authorization
to assess.

### Legal Framework

Unauthorized access to or interference with computer systems is governed by the
**Computer Fraud and Abuse Act (CFAA)** (18 U.S.C. § 1030), the **EU Directive
on Attacks Against Information Systems** (2013/40/EU), and equivalent
legislation in other jurisdictions. Penalties include imprisonment and
significant fines. Some jurisdictions exempt authorized security research, but
that must still be documented and scoped.

### Acceptable Use

- Assessing the cryptographic posture of your own systems and configurations
- Authorized readiness assessments with a written scope and budget
- Academic research in controlled lab environments
- Security education and training (fixtures use only RFC 5737/doc names)

### Prohibited Use

- Scanning systems you do not own without authorization
- Probing live endpoints or networks with this scanner
- Using output to access or exfiltrate data beyond the assessment scope
- Facilitating unauthorized penetration of third-party infrastructure

### No Warranty

This software is provided "as is" without warranty of any kind. The authors
assume no liability for damages arising from use or misuse of this tool,
including incorrect cryptographic classification against evolving standards.

### Responsible Disclosure

If you discover cryptographic weaknesses using this tool, follow coordinated
disclosure: report privately to the system owner, allow reasonable time for
remediation, and do not exploit beyond proof of concept.

## Live Lab Test Plan

1. **Demo run** — `python3 firmware/pq_scanner.py` scans 4 assets + 5
   transcripts, prints the banner and findings, writes the report, and exits `0`.
2. **Gate mode** — `--strict` exits `1` because weak crypto is present.
2. **Threshold sanity** — `rsa_bits_to_security(1024) < 100 < 128 <=
   rsa_bits_to_security(3072)` (unit-tested).
3. **Hybrid detection** — the gateway fixture's `X25519MLKEM768` appears as
   `hybrid_pqc` / `transcript_pqc_hybrid`, never flagged weak.
4. **Honest partial** — the same gateway is flagged for its RSA-2048
   certificate (below the 3072 threshold) — no false "all clean".
5. **Determinism** — identical fixture run yields identical findings.
6. **Offline guarantee** — stdlib only; no network; fixed fixtures + RFC 5737.

## Metrics

| Metric | Definition |
|--------|-----------|
| Assets scanned | fixtures or `--config-file` entries |
| Findings | total issues, split weak vs informative (hybrid PQC) |
| Weak types | rsa_key_size / tls_version / dh_short_group / ecc_short_curve / ssh_* / transcript_* |
| Quantum Readiness Score | 100 − 25 × (distinct weak assets), floor 0 |
| Exit codes | 0 successful demo, 1 weak findings in --strict mode, 2 config error |

Verified offline: 4 assets → 15 findings (13 weak), readiness score 0/100.

## License

MIT License