"""Evidence integrity helpers for the NEXUS prototype.

The prototype hashes uploaded evidence locally with SHA-256, records the hash
in the tamper-evident local audit chain, and exposes verification metadata.
The Soroban contract in contracts/audit_log remains the on-chain integration
path; deployment is intentionally not performed here.
"""

import hashlib
from pathlib import Path


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_bytes(data: bytes, expected_hash: str) -> dict:
    actual = sha256_bytes(data)
    return {
        "expected_hash": expected_hash,
        "actual_hash": actual,
        "match": actual == expected_hash,
        "status": "VERIFIED" if actual == expected_hash else "INTEGRITY_FAILURE",
    }
