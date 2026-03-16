"""Fixture: Python code with quantum-vulnerable cryptography.

Every import/usage here should trigger at least one finding.
"""

import hashlib
import random

from Crypto.Cipher import DES, DES3
from Crypto.PublicKey import RSA as RSA_Key
from cryptography.hazmat.primitives.asymmetric import ec, rsa

# RSA key generation — quantum vulnerable
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# RSA with small key
small_key = RSA_Key.generate(1024)

# ECC — quantum vulnerable
ec_key = ec.generate_private_key(ec.SECP256R1())

# MD5 — broken hash
md5_hash = hashlib.md5(b"data").hexdigest()

# SHA-1 — broken hash
sha1_hash = hashlib.sha1(b"data").hexdigest()

# DES — broken cipher
des_cipher = DES.new(b"12345678", DES.MODE_ECB)

# 3DES — deprecated
triple_des = DES3.new(b"0123456789abcdef01234567", DES3.MODE_CBC, iv=b"12345678")

# Weak random for crypto — insecure
crypto_key = random.randint(0, 2**128)

# ECB mode — insecure
from cryptography.hazmat.primitives.ciphers import modes  # noqa: E402

ecb = modes.ECB()
