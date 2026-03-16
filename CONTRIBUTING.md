# Contributing to Quant-Scan

Thank you for your interest in contributing. This document explains how to set up your development environment, add detection rules, write new language analyzers, and submit changes.

---

## Development Setup

1. **Clone the repository**

   ```bash
   git clone https://github.com/eydcompany/quant-scan.git
   cd quant-scan
   ```

2. **Install uv** (if you don't have it)

   ```bash
   pip install uv
   ```

3. **Create a virtual environment and install dependencies**

   ```bash
   uv venv
   source .venv/bin/activate   # Linux/macOS
   .venv\Scripts\activate      # Windows
   uv pip install -e ".[dev]"
   ```

4. **Verify the setup**

   ```bash
   pytest
   quant-scan --help
   ```

---

## Adding New Detection Rules

Detection rules are defined in YAML files under the `rules/` directory. You can add new rules without writing any Python code.

### Rule schema

```yaml
rules:
  - id: LANG-NNN            # Unique identifier (e.g., PY-005, JAVA-012)
    severity: critical       # critical | high | medium | low | info
    quantum_risk: vulnerable # vulnerable | weakened | safe | unknown
    algorithm:
      name: "RSA"
      family: RSA            # Must match an AlgorithmFamily enum value
      key_size: 2048         # Optional
      pqc_replacements:
        - "ML-KEM-768"
    pattern:
      type: import           # import | function_call | constant | regex
      regex: "from\\s+Crypto\\.PublicKey\\s+import\\s+RSA"
    languages: [python]
    message: "RSA key generation detected — quantum vulnerable"
    recommendation: "Migrate to ML-KEM for key encapsulation or ML-DSA for signatures"
    compliance_refs:
      - "NIST SP 800-208"
      - "EU PQC Roadmap 2026"
```

### Guidelines for rules

- Use a clear, descriptive `message` that states what was found and why it matters.
- Always include at least one `pqc_replacement`.
- Reference specific compliance frameworks in `compliance_refs` when applicable.
- Test your rule against sample files before submitting.

---

## Adding a New Language Analyzer

Language analyzers live under `src/quant_scan/scanners/source/`. Each analyzer is a Python module that scans files of a particular language.

### Steps

1. Create a new file: `src/quant_scan/scanners/source/lang_<language>.py`

2. Implement the file scanner. It should:
   - Accept a file path and the loaded rule set
   - Return a list of `Finding` objects
   - Read lines with context (a few lines before and after each match)

3. Register the language in the source scanner's language map so it gets picked up for the appropriate file extensions.

4. Add YAML rules for the language under `rules/`.

5. Add test fixtures under `tests/fixtures/` and corresponding test cases.

---

## Code Style

- **Formatter/linter:** We use [ruff](https://docs.astral.sh/ruff/) for both linting and formatting.
- **Type hints:** All public functions and methods must have type annotations.
- **Docstrings:** Use Google-style or NumPy-style docstrings for public APIs.
- **Imports:** Use `from __future__ import annotations` at the top of every module.

Run the linter before committing:

```bash
ruff check src/ tests/
ruff format src/ tests/
```

---

## Pull Request Process

1. **Fork** the repository and create a feature branch from `main`.
2. Make your changes with clear, atomic commits.
3. Ensure all tests pass: `pytest`
4. Ensure the linter is clean: `ruff check src/ tests/`
5. Open a pull request against `main` with:
   - A clear title describing the change
   - A description of what was changed and why
   - Any relevant issue numbers
6. A maintainer will review your PR. Please respond to feedback promptly.

For larger changes (new scanner types, architectural changes), please open an issue first to discuss the approach before investing significant effort.

---

## Questions?

Open an issue or reach out at **info@eydcompany.com**.
