"""Blinded Merkle-tree vector commitment.

For messages D[0..n):

  blind r_i is sampled uniformly from {0,1}^256
  leaf_i  = H(0x00 || r_i || <i> || <|D_i|> || D_i)
  pad_j   = H(0x02 || <j>)                         for j >= n, up to 2^k
  node    = H(0x01 || left || right)
  commit  = H(0x03 || root || <n>)

The first byte separates leaves, internal nodes, padding, and the
length-binding header, so a collision between those roles is a
collision of H. The blind r_i is what makes an unopened leaf hiding;
without it the scheme is only binding, which is the gap pointed out
for the plain hash commitment H(x).

`hash_fn` defaults to the SHA-256 implemented in this project. Tests
that show binding failure pass a deliberately weak hash instead.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable

from mtc.sha256 import sha256

HashFn = Callable[[bytes], bytes]

DOMAIN_LEAF = b"\x00"
DOMAIN_NODE = b"\x01"
DOMAIN_PAD = b"\x02"
DOMAIN_COMMIT = b"\x03"

BLIND_LEN = 32


def _u64(value: int) -> bytes:
    if value < 0 or value >= 2**64:
        raise ValueError("integer does not fit in uint64")
    return value.to_bytes(8, "big")


def next_pow2(n: int) -> int:
    if n <= 0:
        raise ValueError("n must be positive")
    size = 1
    while size < n:
        size <<= 1
    return size


@dataclass(frozen=True)
class Commitment:
    """Public commitment. `digest` binds both the Merkle root and n."""

    digest: bytes
    n: int

    def hex(self) -> str:
        return self.digest.hex()


@dataclass
class Decommitment:
    """Secret state kept by the committer. Not sent before opening."""

    messages: list[bytes]
    blinds: list[bytes]
    layers: list[list[bytes]]

    @property
    def n(self) -> int:
        return len(self.messages)


@dataclass(frozen=True)
class AuthStep:
    sibling: bytes
    current_is_left: bool


@dataclass(frozen=True)
class Opening:
    index: int
    data: bytes
    blind: bytes
    path: tuple[AuthStep, ...]
    n: int

    @property
    def proof_bytes(self) -> int:
        """Size of the sibling hashes. The blind and the message are extra."""
        return sum(len(step.sibling) for step in self.path)


class Scheme:
    def __init__(
        self,
        hash_fn: HashFn = sha256,
        digest_size: int = 32,
        blind_len: int = BLIND_LEN,
    ) -> None:
        self.hash_fn = hash_fn
        self.digest_size = digest_size
        self.blind_len = blind_len

    def leaf_hash(self, index: int, blind: bytes, data: bytes) -> bytes:
        if len(blind) != self.blind_len:
            raise ValueError(f"blind must be {self.blind_len} bytes")
        body = DOMAIN_LEAF + blind + _u64(index) + _u64(len(data)) + data
        return self.hash_fn(body)

    def pad_hash(self, index: int) -> bytes:
        return self.hash_fn(DOMAIN_PAD + _u64(index))

    def node_hash(self, left: bytes, right: bytes) -> bytes:
        return self.hash_fn(DOMAIN_NODE + left + right)

    def commit_hash(self, root: bytes, n: int) -> bytes:
        return self.hash_fn(DOMAIN_COMMIT + root + _u64(n))

    def commit(
        self,
        messages: list[bytes],
        blinds: list[bytes] | None = None,
    ) -> tuple[Commitment, Decommitment]:
        n = len(messages)
        if n == 0:
            raise ValueError("cannot commit to an empty vector")
        if blinds is None:
            blinds = [os.urandom(self.blind_len) for _ in range(n)]
        if len(blinds) != n:
            raise ValueError("one blind is required per message")
        for blind in blinds:
            if len(blind) != self.blind_len:
                raise ValueError(f"blind must be {self.blind_len} bytes")

        width = next_pow2(n)
        level = [
            self.leaf_hash(i, blinds[i], messages[i]) if i < n else self.pad_hash(i)
            for i in range(width)
        ]
        layers = [level]
        while len(level) > 1:
            level = [
                self.node_hash(level[i], level[i + 1])
                for i in range(0, len(level), 2)
            ]
            layers.append(level)

        digest = self.commit_hash(level[0], n)
        commitment = Commitment(digest=digest, n=n)
        decommitment = Decommitment(
            messages=list(messages),
            blinds=list(blinds),
            layers=layers,
        )
        return commitment, decommitment

    def open(self, decommitment: Decommitment, index: int) -> Opening:
        if index < 0 or index >= decommitment.n:
            raise IndexError("opening index out of range")
        path: list[AuthStep] = []
        cursor = index
        for layer in decommitment.layers[:-1]:
            sibling_index = cursor ^ 1
            path.append(
                AuthStep(
                    sibling=layer[sibling_index],
                    current_is_left=(cursor % 2 == 0),
                )
            )
            cursor //= 2
        return Opening(
            index=index,
            data=decommitment.messages[index],
            blind=decommitment.blinds[index],
            path=tuple(path),
            n=decommitment.n,
        )

    def verify(self, commitment: Commitment, opening: Opening) -> bool:
        if opening.n != commitment.n:
            return False
        if opening.index < 0 or opening.index >= commitment.n:
            return False
        if len(opening.blind) != self.blind_len:
            return False
        height = next_pow2(commitment.n).bit_length() - 1
        if len(opening.path) != height:
            return False

        try:
            node = self.leaf_hash(opening.index, opening.blind, opening.data)
        except ValueError:
            return False

        cursor = opening.index
        for step in opening.path:
            if len(step.sibling) != self.digest_size:
                return False
            # The side bit is a function of the index. An opener cannot
            # retarget the same siblings at a different position by
            # flipping it.
            if step.current_is_left != (cursor % 2 == 0):
                return False
            if step.current_is_left:
                node = self.node_hash(node, step.sibling)
            else:
                node = self.node_hash(step.sibling, node)
            cursor //= 2

        return self.commit_hash(node, opening.n) == commitment.digest
