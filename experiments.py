"""Correctness checks, security experiments, and performance measurement.

Run from the project root:

    python experiments.py

Nothing in this file imports hashlib or a Merkle-tree library.
SHA-256 is checked against the published FIPS 180-4 test vectors.
"""

from __future__ import annotations

import json
import os
import statistics
import time
from pathlib import Path

from mtc.merkle import Scheme, next_pow2
from mtc.sha256 import SHA256, sha256

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"

# FIPS 180-4 / NIST known-answer tests. These are published outputs,
# not values computed by calling another hash implementation.
SHA256_VECTORS = (
    (
        b"",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        b"abc",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    ),
    (
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    ),
)


class CountingHash:
    def __init__(self, inner, digest_size: int) -> None:
        self.inner = inner
        self.digest_size = digest_size
        self.calls = 0

    def __call__(self, data: bytes) -> bytes:
        self.calls += 1
        return self.inner(data)


def toy16(data: bytes) -> bytes:
    """Deliberately weak 16-bit checksum.

    Used only to show that binding disappears when collision resistance
    disappears. This is not a cryptographic hash.
    """
    state = 0xA5A5
    for byte in data:
        state ^= byte
        state = ((state << 5) | (state >> 11)) & 0xFFFF
        state = (state + 0x9E37) & 0xFFFF
    return state.to_bytes(2, "big")


def hamming(left: bytes, right: bytes) -> int:
    return sum((a ^ b).bit_count() for a, b in zip(left, right))


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def test_sha256() -> dict:
    for message, expected in SHA256_VECTORS:
        got = sha256(message).hex()
        check(got == expected, f"SHA-256 mismatch for {message!r}: {got}")

    # Padding boundary: 55 bytes fits in one block, 56 bytes needs two.
    # Incremental hashing must match one-shot hashing.
    for size in (0, 1, 55, 56, 63, 64, 65, 128):
        data = bytes((i * 17 + 3) & 0xFF for i in range(size))
        one_shot = sha256(data)
        incremental = SHA256()
        incremental.update(data[: size // 3])
        incremental.update(data[size // 3 :])
        check(incremental.digest() == one_shot, f"incremental mismatch at {size}")
        check(incremental.digest() == one_shot, "digest() must be repeatable")

    million = b"a" * 1_000_000
    started = time.perf_counter()
    digest = sha256(million).hex()
    elapsed = time.perf_counter() - started
    expected_million = (
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    )
    check(digest == expected_million, f"million-a mismatch: {digest}")
    return {"million_a_seconds": elapsed, "million_a_mib_per_s": 1_000_000 / elapsed / (1024 * 1024)}


def test_correctness() -> None:
    scheme = Scheme()
    for n in (1, 2, 3, 4, 5, 7, 8, 17):
        messages = [f"record-{i}".encode() for i in range(n)]
        messages[0] = b""
        if n > 2:
            messages[2] = b"x" * 10_000
        commitment, decommitment = scheme.commit(messages)
        check(len(commitment.digest) == 32, "commitment must be 32 bytes")
        for index in range(n):
            opening = scheme.open(decommitment, index)
            check(scheme.verify(commitment, opening), f"honest open failed n={n} i={index}")
            check(
                len(opening.path) == next_pow2(n).bit_length() - 1,
                "unexpected proof height",
            )

    # Same messages with the same blinds are the same commitment.
    messages = [b"a", b"b", b"c"]
    blinds = [b"\x11" * 32, b"\x22" * 32, b"\x33" * 32]
    first, _ = scheme.commit(messages, blinds)
    second, _ = scheme.commit(messages, blinds)
    check(first.digest == second.digest, "commit must be deterministic given blinds")

    # A different blind changes the commitment even when messages do not.
    other_blinds = [b"\x11" * 32, b"\x22" * 32, b"\x44" * 32]
    third, _ = scheme.commit(messages, other_blinds)
    check(first.digest != third.digest, "blind must affect the commitment")

    try:
        scheme.commit([])
        raise AssertionError("empty vector should be rejected")
    except ValueError:
        pass


def test_tamper() -> None:
    scheme = Scheme()
    messages = [f"m{i}".encode() for i in range(6)]
    commitment, decommitment = scheme.commit(messages)

    def flipped(opening, *, data=False, blind=False, sibling=False, index=None, n=None):
        path = opening.path
        if sibling:
            raw = bytearray(path[0].sibling)
            raw[0] ^= 0x01
            path = (type(path[0])(bytes(raw), path[0].current_is_left),) + path[1:]
        new_data = bytearray(opening.data)
        if data:
            if not new_data:
                new_data = bytearray(b"\x00")
            new_data[0] ^= 0x01
        new_blind = bytearray(opening.blind)
        if blind:
            new_blind[0] ^= 0x01
        return type(opening)(
            index=opening.index if index is None else index,
            data=bytes(new_data),
            blind=bytes(new_blind),
            path=path,
            n=opening.n if n is None else n,
        )

    opening = scheme.open(decommitment, 3)
    check(not scheme.verify(commitment, flipped(opening, data=True)), "tampered data accepted")
    check(not scheme.verify(commitment, flipped(opening, blind=True)), "tampered blind accepted")
    check(not scheme.verify(commitment, flipped(opening, sibling=True)), "tampered sibling accepted")
    check(not scheme.verify(commitment, flipped(opening, index=2)), "wrong index accepted")
    check(not scheme.verify(commitment, flipped(opening, n=8)), "wrong length accepted")

    # An opening for position 3 must not verify as position 1.
    other = scheme.open(decommitment, 1)
    swapped = type(opening)(
        index=other.index,
        data=opening.data,
        blind=opening.blind,
        path=other.path,
        n=opening.n,
    )
    check(not scheme.verify(commitment, swapped), "cross-position opening accepted")

    # Padding positions are not messages.
    try:
        scheme.open(decommitment, 6)
        raise AssertionError("padding index should not open")
    except IndexError:
        pass


def test_hash_call_count() -> None:
    counter = CountingHash(sha256, 32)
    scheme = Scheme(hash_fn=counter, digest_size=32)
    for n in (1, 2, 3, 5, 8, 100):
        counter.calls = 0
        messages = [b"x" for _ in range(n)]
        scheme.commit(messages, blinds=[b"\x00" * 32 for _ in range(n)])
        width = next_pow2(n)
        # W leaves-or-pads, W-1 internal nodes, 1 length-binding header.
        check(counter.calls == 2 * width, f"commit hashes for n={n}: {counter.calls}")


def experiment_hiding(trials: int = 200) -> dict:
    """Show why the blind is required, then measure that it works."""
    scheme = Scheme()
    space = [bytes([i]) for i in range(32)]
    secret = space[7]
    zero = b"\x00" * 32

    # No entropy in the blind: the leaf is a deterministic function of the
    # message, so a 32-element space is recovered by exhaustive search.
    naked, _ = scheme.commit([secret], blinds=[zero])
    recovered = None
    for candidate in space:
        guess, _ = scheme.commit([candidate], blinds=[zero])
        if guess.digest == naked.digest:
            recovered = candidate
            break
    check(recovered == secret, "unblinded low-entropy message should be recoverable")

    blinded, _ = scheme.commit([secret])
    false_hits = 0
    for candidate in space:
        guess, _ = scheme.commit([candidate], blinds=[zero])
        if guess.digest == blinded.digest:
            false_hits += 1
    check(false_hits == 0, "blinded commitment should not match a zero-blind guess")

    distances_different = []
    distances_same = []
    for _ in range(trials):
        left, _ = scheme.commit([b"yes"])
        right, _ = scheme.commit([b"no"])
        again, _ = scheme.commit([b"yes"])
        distances_different.append(hamming(left.digest, right.digest))
        distances_same.append(hamming(left.digest, again.digest))

    return {
        "message_space": len(space),
        "unblinded_recovered": True,
        "blinded_false_hits": false_hits,
        "trials": trials,
        "hamming_different_mean": statistics.mean(distances_different),
        "hamming_same_message_mean": statistics.mean(distances_same),
        "hamming_ideal": 128,
    }


def experiment_binding() -> dict:
    """Break binding of the same scheme instantiated with a 16-bit hash.

    A birthday search looks for two different leaf inputs with the same
    digest. That pair is a concrete witness for the reduction in the design
    document: two accepting openings of different messages are a collision of H.
    """
    weak = Scheme(hash_fn=toy16, digest_size=2, blind_len=4)
    yes = b"yes"
    no = b"no"
    seen: dict[bytes, bytes] = {}
    found_yes = found_no = None
    trials = 0
    # 16-bit output: after a few hundred yes-leaves, a no-leaf hits one of
    # them with overwhelming probability. Cap the search anyway.
    for trials in range(1, 100_001):
        blind = trials.to_bytes(4, "big")
        if trials % 2 == 1:
            digest = weak.leaf_hash(0, blind, yes)
            seen.setdefault(digest, blind)
        else:
            digest = weak.leaf_hash(0, blind, no)
            if digest in seen:
                found_yes = seen[digest]
                found_no = blind
                break
    check(found_yes is not None and found_no is not None, "expected a 16-bit collision")

    leaf_yes = weak.leaf_hash(0, found_yes, yes)
    leaf_no = weak.leaf_hash(0, found_no, no)
    check(leaf_yes == leaf_no, "searched pair is not a collision")
    check(yes != no, "messages must differ")

    commitment, decommitment_yes = weak.commit([yes], blinds=[found_yes])
    _, decommitment_no = weak.commit([no], blinds=[found_no])
    opening_yes = weak.open(decommitment_yes, 0)
    opening_no = weak.open(decommitment_no, 0)
    check(weak.verify(commitment, opening_yes), "honest weak opening should verify")
    check(weak.verify(commitment, opening_no), "colliding opening should verify")
    check(opening_yes.data != opening_no.data, "the two opened messages differ")

    # The same attack does not succeed against SHA-256 for a small search.
    real = Scheme()
    real_blind = b"\x10" * 32
    real_commitment, real_decommitment = real.commit([yes], blinds=[real_blind])
    real_opening = real.open(real_decommitment, 0)
    sha_breaks = 0
    for i in range(4096):
        bad_blind = i.to_bytes(32, "big")
        forged = type(real_opening)(
            index=0,
            data=b"no",
            blind=bad_blind,
            path=real_opening.path,
            n=1,
        )
        if real.verify(real_commitment, forged):
            sha_breaks += 1
    check(sha_breaks == 0, "SHA-256 binding failed inside the search bound")
    return {
        "toy_digest_bits": 16,
        "toy_trials": trials,
        "toy_binding_broken": True,
        "yes_blind": found_yes.hex(),
        "no_blind": found_no.hex(),
        "colliding_leaf": leaf_yes.hex(),
        "sha256_search": 4096,
        "sha256_binding_breaks": sha_breaks,
    }


def _median_time(fn, repeats: int, loops: int = 1) -> float:
    """Median per-call time. `loops` batches short calls so the clock can see them."""
    samples = []
    for _ in range(repeats):
        started = time.perf_counter()
        for _ in range(loops):
            fn()
        samples.append((time.perf_counter() - started) / loops)
    return statistics.median(samples)


def experiment_performance() -> dict:
    scheme = Scheme()
    rows = []
    leaf_sizes = (1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096)
    for n in leaf_sizes:
        messages = [f"tx-{i:08d}".encode() for i in range(n)]
        repeats = 7 if n <= 256 else 3
        commitment, decommitment = scheme.commit(messages)
        target = n // 2

        commit_s = _median_time(lambda: scheme.commit(messages), repeats)
        opening = scheme.open(decommitment, target)
        # Open is a few index operations; verify is only log n hashes.
        # Batch them so the median is not one scheduling quantum.
        open_s = _median_time(lambda: scheme.open(decommitment, target), 5, loops=200)
        verify_s = _median_time(lambda: scheme.verify(commitment, opening), 5, loops=40)

        # Cost of checking one leaf by rebuilding the whole tree.
        rebuild_s = commit_s
        width = next_pow2(n)
        rows.append(
            {
                "n": n,
                "width": width,
                "commit_ms": commit_s * 1e3,
                "open_ms": open_s * 1e3,
                "verify_ms": verify_s * 1e3,
                "rebuild_ms": rebuild_s * 1e3,
                "speedup_vs_rebuild": commit_s / verify_s if verify_s else None,
                "proof_bytes": opening.proof_bytes,
                "opening_bytes": opening.proof_bytes + len(opening.blind) + len(opening.data),
                "commit_hashes": 2 * width,
                "verify_hashes": width.bit_length() - 1 + 2,
            }
        )

    throughput = []
    for size in (64, 1024, 4096, 32 * 1024, 256 * 1024):
        data = os.urandom(size)
        # Warm the interpreter, then take the median of enough work to
        # smooth out scheduling noise.
        sha256(data)
        repeats = 5 if size >= 32 * 1024 else 11
        elapsed = _median_time(lambda: sha256(data), repeats)
        throughput.append(
            {
                "bytes": size,
                "ms": elapsed * 1e3,
                "mib_per_s": size / elapsed / (1024 * 1024),
            }
        )
    return {"trees": rows, "sha256": throughput}


def write_svg(rows: list[dict], path: Path) -> None:
    import math

    width, height = 760, 420
    left, right, top, bottom = 70, 24, 36, 56
    plot_w = width - left - right
    plot_h = height - top - bottom
    xs = [row["n"] for row in rows]
    commit = [row["commit_ms"] for row in rows]
    verify = [row["verify_ms"] for row in rows]
    log_min = math.log10(0.2)
    log_max = math.log10(max(commit) * 1.4)

    def px(n: int) -> float:
        return left + (xs.index(n) / (len(xs) - 1)) * plot_w

    def py(value: float) -> float:
        value = max(value, 10**log_min)
        t = (math.log10(value) - log_min) / (log_max - log_min)
        return top + plot_h - t * plot_h

    def polyline(values: list[float]) -> str:
        return " ".join(f"{px(n):.1f},{py(v):.1f}" for n, v in zip(xs, values))

    x_labels = []
    for n in xs:
        x_labels.append(
            f'<text x="{px(n):.1f}" y="{height - 28}" text-anchor="middle" '
            f'font-size="11" fill="#334155">{n}</text>'
        )
    y_labels = []
    grid = []
    tick = 10 ** math.floor(log_min)
    while tick <= 10**log_max:
        if tick >= 10**log_min:
            y = py(tick)
            grid.append(
                f'<line x1="{left}" y1="{y:.1f}" x2="{width - right}" y2="{y:.1f}" '
                f'stroke="#e2e8f0"/>'
            )
            label = f"{tick:.1f}" if tick < 1 else f"{tick:.0f}"
            y_labels.append(
                f'<text x="{left - 10}" y="{y + 4:.1f}" text-anchor="end" '
                f'font-size="11" fill="#334155">{label}</text>'
            )
        tick *= 10

    path.write_text(
        f'''<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
  <style>text {{ font-family: "PingFang SC", sans-serif; }}</style>
  <rect width="100%" height="100%" fill="#ffffff"/>
  <text x="{left}" y="18" font-size="14" font-family="sans-serif" fill="#0f172a">叶子数量与 commit、verify 耗时（对数坐标）</text>
  {''.join(grid)}
  {''.join(y_labels)}
  {''.join(x_labels)}
  <polyline fill="none" stroke="#1d4ed8" stroke-width="2" points="{polyline(commit)}"/>
  <polyline fill="none" stroke="#c2410c" stroke-width="2" points="{polyline(verify)}"/>
  <text x="{width / 2:.0f}" y="{height - 6}" text-anchor="middle" font-size="12" fill="#334155">叶子数 n</text>
  <text x="16" y="{top + plot_h / 2:.0f}" transform="rotate(-90 16 {top + plot_h / 2:.0f})" font-size="12" fill="#334155">毫秒</text>
  <rect x="{width - 210}" y="36" width="12" height="12" fill="#1d4ed8"/>
  <text x="{width - 192}" y="47" font-size="12" fill="#0f172a">commit</text>
  <rect x="{width - 130}" y="36" width="12" height="12" fill="#c2410c"/>
  <text x="{width - 112}" y="47" font-size="12" fill="#0f172a">verify</text>
</svg>
''',
        encoding="utf-8",
    )


def write_summary(report: dict, path: Path) -> None:
    lines = ["# 实验原始结果", ""]
    lines.append("## SHA-256")
    lines.append("")
    sha = report["sha256_selftest"]
    lines.append(
        f"- 100 万个 `a` 的哈希耗时 {sha['million_a_seconds']:.3f} s，"
        f"约 {sha['million_a_mib_per_s']:.2f} MiB/s。"
    )
    lines.append("")
    lines.append("| 消息长度 (B) | 耗时 (ms) | 吞吐 (MiB/s) |")
    lines.append("|---:|---:|---:|")
    for row in report["performance"]["sha256"]:
        lines.append(f"| {row['bytes']} | {row['ms']:.3f} | {row['mib_per_s']:.3f} |")
    lines.append("")
    lines.append("## Merkle 承诺")
    lines.append("")
    lines.append(
        "| n | commit (ms) | open (ms) | verify (ms) | 证明 (B) | commit 哈希次数 | verify 哈希次数 |"
    )
    lines.append("|---:|---:|---:|---:|---:|---:|---:|")
    for row in report["performance"]["trees"]:
        lines.append(
            f"| {row['n']} | {row['commit_ms']:.3f} | {row['open_ms']:.4f} | "
            f"{row['verify_ms']:.3f} | {row['proof_bytes']} | {row['commit_hashes']} | "
            f"{row['verify_hashes']} |"
        )
    lines.append("")
    hiding = report["hiding"]
    lines.append("## Hiding")
    lines.append("")
    lines.append(
        f"- 不盲化时，32 个候选消息被穷举恢复：{hiding['unblinded_recovered']}。"
    )
    lines.append(
        f"- 盲化后，用零盲化因子穷举的命中数：{hiding['blinded_false_hits']}。"
    )
    lines.append(
        f"- 不同消息的承诺汉明距离均值：{hiding['hamming_different_mean']:.2f} "
        f"（理想值 {hiding['hamming_ideal']}）。"
    )
    lines.append(
        f"- 相同消息、独立盲化因子的承诺汉明距离均值："
        f"{hiding['hamming_same_message_mean']:.2f}。"
    )
    lines.append("")
    binding = report["binding"]
    lines.append("## Binding")
    lines.append("")
    lines.append(
        f"- 16-bit 弱哈希在 {binding['toy_trials']} 次尝试后找到碰撞，"
        f"两条不同消息的 opening 都通过验证。"
    )
    lines.append(
        f"- SHA-256 上 {binding['sha256_search']} 次替换盲化因子，"
        f"伪造成功次数：{binding['sha256_binding_breaks']}。"
    )
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def experiment_example() -> dict:
    """A fully reproducible 4-leaf opening, using fixed blinds."""
    scheme = Scheme()
    messages = [b"Alice", b"Bob", b"Carol", b"Dave"]
    blinds = [bytes([i + 1]) * 32 for i in range(4)]
    commitment, decommitment = scheme.commit(messages, blinds)
    opening = scheme.open(decommitment, 2)
    tampered = type(opening)(
        index=opening.index,
        data=b"Eve",
        blind=opening.blind,
        path=opening.path,
        n=opening.n,
    )
    check(scheme.verify(commitment, opening), "example opening should verify")
    check(not scheme.verify(commitment, tampered), "tampered example should fail")
    return {
        "messages": [m.decode() for m in messages],
        "blinds": [b.hex() for b in blinds],
        "commitment": commitment.hex(),
        "n": commitment.n,
        "open_index": 2,
        "open_message": opening.data.decode(),
        "open_blind": opening.blind.hex(),
        "siblings": [step.sibling.hex() for step in opening.path],
        "sides_current_is_left": [step.current_is_left for step in opening.path],
        "verify": True,
        "tampered_message": "Eve",
        "tampered_verify": False,
    }


def main() -> None:
    RESULTS.mkdir(exist_ok=True)
    print("SHA-256 known-answer tests...")
    sha = test_sha256()
    print(f"  million-a: {sha['million_a_seconds']:.3f}s")
    print("correctness...")
    test_correctness()
    print("tamper...")
    test_tamper()
    print("hash-call counts...")
    test_hash_call_count()
    print("hiding...")
    hiding = experiment_hiding()
    print(
        f"  hamming different={hiding['hamming_different_mean']:.2f} "
        f"same={hiding['hamming_same_message_mean']:.2f}"
    )
    print("binding...")
    binding = experiment_binding()
    print(f"  toy collision after {binding['toy_trials']} trials")
    print("performance...")
    performance = experiment_performance()
    print("example...")
    example = experiment_example()
    report = {
        "sha256_selftest": sha,
        "hiding": hiding,
        "binding": binding,
        "performance": performance,
        "example": example,
    }
    (RESULTS / "metrics.json").write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )
    write_summary(report, RESULTS / "summary.md")
    write_svg(performance["trees"], RESULTS / "timing.svg")
    print("wrote results/metrics.json, results/summary.md, results/timing.svg")


if __name__ == "__main__":
    main()
