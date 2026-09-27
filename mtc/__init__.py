"""Blinded Merkle-tree commitment.

SHA-256 and the Merkle tree are implemented in this package.
No hashlib and no third-party Merkle-tree library is used.
"""

from mtc.merkle import Commitment, Decommitment, Opening, Scheme
from mtc.sha256 import sha256

__all__ = [
    "Commitment",
    "Decommitment",
    "Opening",
    "Scheme",
    "sha256",
]
