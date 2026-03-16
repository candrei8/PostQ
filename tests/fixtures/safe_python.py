"""Fixture: Python code with quantum-safe or no cryptography.

This file should produce ZERO findings.
"""

import json
import os
import sys
from pathlib import Path

# Normal string operations — not crypto
data = "hello world"
encoded = data.encode("utf-8")
decoded = encoded.decode("utf-8")

# File operations
config_path = Path("/etc/config.json")
if config_path.exists():
    config = json.loads(config_path.read_text())

# Math operations (not crypto)
result = 2 ** 256
values = list(range(100))
total = sum(values)

# os.urandom is fine — cryptographically secure
token = os.urandom(32)

# String that mentions crypto in comments but doesn't use it
# This function processes RSA tokens from the API
# MD5 is mentioned here but not actually called


def process_data(items: list[dict]) -> dict:
    """Process items — nothing crypto here."""
    return {item["key"]: item["value"] for item in items}


class DataProcessor:
    """Regular business logic."""

    def __init__(self, name: str):
        self.name = name

    def run(self) -> None:
        print(f"Processing {self.name}")
