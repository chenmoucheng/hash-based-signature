"""Independent stdlib oracle; never use these public deterministic keys outside tests.

Run from the repository root: python3 test/generate-fixture.py
The Haskell suite reads the committed output; Python is not needed for normal tests.
"""
import hashlib
from pathlib import Path


def sha(data):
    return hashlib.sha256(data).digest()


def walk(value, count):
    for _ in range(count):
        value = sha(value)
    return value


# Independent expression of base-16 encoding using hex strings and integer parsing.
secret = bytes(i % 256 for i in range(67 * 32))
parts = [secret[i:i + 32] for i in range(0, len(secret), 32)]
message = b"abc"
digits = [int(c, 16) for c in sha(message).hex()]
checksum = 64 * 15 - sum(digits)
digits += [int(c, 16) for c in f"{checksum:03x}"]
public = b"".join(walk(part, 15) for part in parts)
signature = b"".join(walk(part, digit) for part, digit in zip(parts, digits))
Path("test/fixtures/wots.txt").write_text(public.hex() + "\n" + signature.hex() + "\n")

# One-byte message digest: two digits plus two checksum digits (maximum 30).
short_digits = [int(c, 16) for c in sha(message)[:1].hex()]
short_digits += [int(c, 16) for c in f"{30 - sum(short_digits):02x}"]
short_public = b"".join(walk(part, 15) for part in parts[:4])
short_signature = b"".join(walk(part, digit) for part, digit in zip(parts, short_digits))
Path("test/fixtures/wots-1-byte.txt").write_text(short_public.hex() + "\n" + short_signature.hex() + "\n")
