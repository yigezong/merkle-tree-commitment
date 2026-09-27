"""SHA-256, implemented from FIPS 180-4.

The padding, message schedule, and compression function follow the
standard directly. This file does not import hashlib or any other
hash implementation.

References in the standard:
  §4.2.2  SHA-256 constants
  §5.1.1  padding
  §5.3.3  initial hash value
  §6.2.2  compression function
"""

from __future__ import annotations

MASK = 0xFFFFFFFF

# §4.2.2: first 32 bits of the fractional parts of the cube roots
# of the first 64 primes.
K = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)

# §5.3.3: first 32 bits of the fractional parts of the square roots
# of the first 8 primes.
_IV = (
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
)


def _rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & MASK


def compress(state: tuple[int, ...], block: bytes) -> tuple[int, ...]:
    """One SHA-256 compression of a 64-byte block. FIPS 180-4 §6.2.2."""
    if len(block) != 64:
        raise ValueError("SHA-256 block must be 64 bytes")

    w = [int.from_bytes(block[i : i + 4], "big") for i in range(0, 64, 4)]
    for i in range(16, 64):
        x = w[i - 15]
        s0 = _rotr(x, 7) ^ _rotr(x, 18) ^ (x >> 3)
        x = w[i - 2]
        s1 = _rotr(x, 17) ^ _rotr(x, 19) ^ (x >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & MASK)

    a, b, c, d, e, f, g, h = state
    for i in range(64):
        s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
        ch = (e & f) ^ ((MASK ^ e) & g)
        temp1 = (h + s1 + ch + K[i] + w[i]) & MASK
        s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (s0 + maj) & MASK
        h = g
        g = f
        f = e
        e = (d + temp1) & MASK
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & MASK

    mixed = (a, b, c, d, e, f, g, h)
    return tuple((state[i] + mixed[i]) & MASK for i in range(8))


class SHA256:
    """Incremental SHA-256. `digest` does not modify the object."""

    digest_size = 32
    block_size = 64

    def __init__(self, data: bytes = b"") -> None:
        self._state = _IV
        self._buffer = bytearray()
        self._nbits = 0
        if data:
            self.update(data)

    def update(self, data: bytes) -> "SHA256":
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("SHA-256 input must be bytes")
        self._nbits += len(data) * 8
        self._buffer.extend(data)
        while len(self._buffer) >= 64:
            block = bytes(self._buffer[:64])
            del self._buffer[:64]
            self._state = compress(self._state, block)
        return self

    def digest(self) -> bytes:
        # §5.1.1: append a 1 bit, then zeros, then the 64-bit length,
        # so that the padded length is a multiple of 512 bits.
        state = self._state
        buf = bytearray(self._buffer)
        buf.append(0x80)
        while (len(buf) % 64) != 56:
            buf.append(0)
        length = self._nbits & ((1 << 64) - 1)
        buf.extend(length.to_bytes(8, "big"))
        for offset in range(0, len(buf), 64):
            state = compress(state, bytes(buf[offset : offset + 64]))
        return b"".join(word.to_bytes(4, "big") for word in state)

    def hexdigest(self) -> str:
        return self.digest().hex()


def sha256(data: bytes) -> bytes:
    return SHA256(data).digest()
