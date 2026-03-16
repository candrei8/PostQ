# Quant-Scan -- Post-Quantum Cryptography Scanner

[![Build Status](https://img.shields.io/github/actions/workflow/status/eydcompany/quant-scan/ci.yml?branch=main)](https://github.com/eydcompany/quant-scan/actions)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://python.org)
[![PyPI](https://img.shields.io/pypi/v/quant-scan.svg)](https://pypi.org/project/quant-scan/)

**Detect quantum-vulnerable cryptography before it becomes a liability.**

Quant-Scan is a static analysis tool that inventories every cryptographic algorithm in your codebase, certificates, server configurations, and dependency tree -- then tells you exactly which ones will break when large-scale quantum computers arrive. It maps findings to real compliance deadlines (EU PQC Roadmap 2026/2030, NIST SP 800-208, Spain's ENS), assigns a 0-100 risk score, and recommends concrete post-quantum replacements. Run it locally, run it in CI, and stay ahead of the migration timeline.

---

## Features

- **Multi-language source scanning** -- Python, Java, JavaScript/TypeScript, Go, C/C++, C#
- **Certificate scanning** -- X.509 file parsing (PEM, DER, CRT) and live TLS endpoint probing
- **Configuration scanning** -- SSH, nginx, Apache, HAProxy, and cloud provider configs
- **Dependency scanning** -- pip, npm, Maven, Go modules
- **Compliance mapping** -- NIST SP 800-208, EU PQC Roadmap, ENS, CCN-STIC, DORA
- **Multiple output formats** -- Rich console tables, machine-readable JSON, branded HTML reports
- **Scoring system** -- 0-100 risk score with Grade A-F for executive communication
- **PQC readiness metric** -- percentage of cryptography already migrated to post-quantum algorithms
- **YAML-driven rules** -- extend detection without writing Python code

---

## Quick Start

### Install

```bash
pip install quant-scan
```

### Scan a project

```bash
quant-scan scan /path/to/project
```

That's it. Quant-Scan walks the directory tree, detects cryptographic usage across source files, certificates, configs, and dependencies, and prints a scored report to the terminal.

---

## Usage Examples

### Full scan with JSON output

```bash
quant-scan scan /path/to/project --format json -o report.json
```

### Source-only scan for Python and Java

```bash
quant-scan source /path/to/project --languages python,java
```

### Certificate scan including a live TLS probe

```bash
quant-scan certificate /path/to/certs --check-tls api.example.com:443
```

### Configuration audit

```bash
quant-scan config /etc/ssh /etc/nginx
```

### Dependency check

```bash
quant-scan dependencies /path/to/project
```

### Filter by severity

```bash
quant-scan scan /path/to/project --severity critical,high
```

### Exclude test directories

```bash
quant-scan scan /path/to/project --exclude "tests/**" --exclude "**/node_modules/**"
```

---

## CLI Reference

```
quant-scan <command> <target> [options]
```

### Commands

| Command        | Description                                    |
|----------------|------------------------------------------------|
| `scan`         | Full scan (source + certificates + config + deps) |
| `source`       | Source code analysis only                      |
| `certificate`  | Certificate and TLS analysis only              |
| `config`       | Configuration file analysis only               |
| `dependencies` | Dependency manifest analysis only              |

### Global Options

| Option              | Description                                      |
|---------------------|--------------------------------------------------|
| `--format`          | Output format: `console`, `json`, `html`         |
| `--severity`        | Minimum severity filter: `critical`, `high`, `medium`, `low`, `info` |
| `-o`, `--output`    | Write report to file instead of stdout           |
| `--exclude`         | Gitignore-style exclusion patterns (repeatable)  |
| `--no-color`        | Disable colored output                           |

---

## Supported Algorithms

### Quantum-Vulnerable (Shor's algorithm breaks these)

| Algorithm | Family | Quantum Risk | PQC Replacement |
|-----------|--------|-------------|-----------------|
| RSA (all key sizes) | Asymmetric | Vulnerable | ML-KEM, ML-DSA |
| ECDSA / ECC | Asymmetric | Vulnerable | ML-DSA, SLH-DSA |
| DSA | Asymmetric | Vulnerable | ML-DSA |
| DH / ECDH | Key Exchange | Vulnerable | ML-KEM |
| Ed25519 / Ed448 | Signature | Vulnerable | ML-DSA, SLH-DSA |

### Quantum-Weakened (Grover's algorithm halves effective key length)

| Algorithm | Family | Quantum Risk | Recommendation |
|-----------|--------|-------------|----------------|
| AES-128 | Symmetric | Weakened | Upgrade to AES-256 |
| AES-256 | Symmetric | Safe | No action needed |
| SHA-256 | Hash | Weakened | Consider SHA-3 or SHA-512 |
| SHA-1 | Hash | Weakened + classically weak | Migrate immediately |

### Classically Broken (vulnerable today, no quantum computer needed)

| Algorithm | Family | Quantum Risk | Action |
|-----------|--------|-------------|--------|
| DES / 3DES | Symmetric | Vulnerable | Replace with AES-256 |
| MD5 | Hash | Vulnerable | Replace with SHA-3 or SHA-512 |
| RC4 | Stream cipher | Vulnerable | Replace with ChaCha20 or AES-GCM |
| Blowfish | Symmetric | Weakened | Replace with AES-256 |

### Post-Quantum Safe

| Algorithm | Standard | Status |
|-----------|----------|--------|
| ML-KEM (Kyber) | FIPS 203 | Standardized |
| ML-DSA (Dilithium) | FIPS 204 | Standardized |
| SLH-DSA (SPHINCS+) | FIPS 205 | Standardized |
| XMSS | NIST SP 800-208 | Standardized |

---

## Adding Custom Rules

Detection rules are defined in YAML. Drop a new file into the `rules/` directory and Quant-Scan picks it up automatically -- no Python code required.

```yaml
# rules/custom_legacy_crypto.yaml
rules:
  - id: CUSTOM-001
    severity: high
    quantum_risk: vulnerable
    algorithm:
      name: "MyLegacyCipher"
      family: RSA
      pqc_replacements: ["ML-KEM-768"]
    pattern:
      type: function_call
      regex: "legacy_encrypt\\("
    languages: [python, java]
    message: "Usage of MyLegacyCipher detected — quantum vulnerable"
    recommendation: "Migrate to ML-KEM-768 for key encapsulation"
    compliance_refs:
      - "NIST SP 800-208"
      - "EU PQC Roadmap 2026"
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full rule schema reference.

---

## Contributing

We welcome contributions. Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on setting up the development environment, adding rules, writing analyzers, and submitting pull requests.

---

## License

Quant-Scan is released under the [Apache License 2.0](LICENSE).

---

## About

Built by **[EYD Company](https://eydcompany.com)** (Madrid, Spain) -- a consulting firm at the intersection of legal compliance and technology. As the EU mandates post-quantum cryptographic inventories by Q4 2026 and full migration of critical infrastructure by 2030, organizations need automated tooling to understand their exposure. Quant-Scan is that tooling: open-source, extensible, and built for the European regulatory landscape.

Questions or enterprise support inquiries: **info@eydcompany.com**
