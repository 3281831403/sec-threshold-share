"""Threshold secret sharing over GF(256).

A share is encoded as one coordinate byte, one payload byte per secret byte,
and one checksum trailer byte.  The field is GF(256) with the irreducible
polynomial x^8 + x^4 + x^3 + x + 1, represented as 0x11B.
"""
from __future__ import annotations

import random

_IRREDUCIBLE = 283
_MASK = 255
_REDUCER = _IRREDUCIBLE & _MASK  # low byte of the polynomial, 0x1B
_HIGH_BIT = 0x80
_FIELD_ORDER = 256


# --- defect 1: field multiplication with proper polynomial reduction --------
def gf_mul(a: int, b: int) -> int:
    """Multiply a and b in GF(256) and return one byte.

    Russian-peasant multiplication: every left shift that overflows the byte
    is reduced by XOR-ing the low part (0x1B) of the irreducible polynomial,
    instead of truncating an ordinary integer product to its low eight bits.
    """
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        overflow = a & _HIGH_BIT
        a = (a << 1) & _MASK
        if overflow:
            a ^= _REDUCER
        b >>= 1
    return result


def _gf_pow(a: int, n: int) -> int:
    """Raise a to a nonnegative integer power in GF(256)."""
    result = 1
    base = a
    while n > 0:
        if n & 1:
            result = gf_mul(result, base)
        base = gf_mul(base, base)
        n >>= 1
    return result


# --- defect 2: exact multiplicative inverse, no floating point --------------
def gf_inv(a: int) -> int:
    """Return the multiplicative inverse of a nonzero field element.

    The nonzero elements form a group of order 255, so by Lagrange's theorem
    a ** 254 == a ** -1 exactly.  All arithmetic stays in GF(256); there is no
    floating-point reciprocal to drift on small field elements.
    """
    if a == 0:
        raise ZeroDivisionError("zero has no multiplicative inverse in GF(256)")
    return _gf_pow(a, _FIELD_ORDER - 2)


# --- defect 5: Horner evaluation with low-degree-first coefficients ---------
def eval_poly(coeffs, x: int) -> int:
    """Evaluate a polynomial whose coefficients are ordered low degree first."""
    acc = 0
    # Horner consumes the highest-degree coefficient first, so walk the
    # low-degree-first list backwards; otherwise the polynomial is reversed.
    for coeff in reversed(coeffs):
        acc = gf_mul(acc, x) ^ coeff
    return acc


def _checksum(coord: int, payload: bytes) -> int:
    """One-byte integrity tag covering both the coordinate and the payload.

    A rolling GF(256) hash: a single changed byte changes the tag because
    multiplication by the nonzero constant 0x03 is a field bijection, so the
    perturbation can never cancel on later positions.
    """
    acc = 0
    for byte in (coord, *payload):
        acc = gf_mul(acc, 0x03) ^ byte
    return acc


# --- defect 6: shares get deterministic nonzero coordinates 1..shares -------
def split(secret: bytes, threshold: int, shares: int, seed: int) -> list[bytes]:
    """Split secret into shares shares with the given reconstruction threshold."""
    if threshold < 1:
        raise ValueError("threshold must be at least 1")
    if shares < threshold:
        raise ValueError("shares must be at least the threshold")
    if shares > _MASK:
        raise ValueError("at most 255 shares fit in one coordinate byte")

    rng = random.Random(seed)
    payloads = [bytearray() for _ in range(shares)]
    for secret_byte in secret:
        # The constant term is the secret byte; the rest are random field
        # elements.  For threshold == 1 the polynomial is just the constant.
        coeffs = [secret_byte] + [
            rng.randrange(_FIELD_ORDER) for _ in range(threshold - 1)
        ]
        for index in range(shares):
            coord = index + 1  # always in 1..255, never zero
            payloads[index].append(eval_poly(coeffs, coord))

    result = []
    for index in range(shares):
        coord = index + 1
        payload = bytes(payloads[index])
        # --- defect 8: checksum commits to coordinate AND payload ----------
        result.append(bytes([coord]) + payload + bytes([_checksum(coord, payload)]))
    return result


def combine(shares, threshold: int) -> bytes:
    """Reconstruct the secret from shares using Lagrange interpolation at zero."""
    if threshold < 1:
        raise ValueError("threshold must be at least 1")
    if len(shares) < threshold:
        raise ValueError("not enough shares to meet the threshold")

    # --- defect 7: repeated coordinates are rejected, never silently merged -
    coords = [share[0] for share in shares]
    if len(set(coords)) != len(coords):
        raise ValueError("duplicate share coordinates")

    # --- defect 9: threshold one is the constant polynomial, take it direct -
    if threshold == 1:
        return bytes(shares[0][1:-1])

    # --- defect 10: order-independent reconstruction ------------------------
    ordered = sorted(shares, key=lambda share: share[0])
    points = [(share[0], share[1:-1]) for share in ordered]
    width = len(ordered[0]) - 2
    secret = bytearray(width)

    for position in range(width):
        reconstructed = 0
        for i, (x_i, payload_i) in enumerate(points):
            numerator = 1
            denominator = 1
            for m, (x_m, _) in enumerate(points):
                if m == i:
                    continue
                # Evaluating at x = 0: (0 - x_m) == x_m in characteristic 2.
                numerator = gf_mul(numerator, x_m)
                # Subtraction equals addition (XOR) in GF(2^8).
                denominator = gf_mul(denominator, x_m ^ x_i)
            # --- defect 3: the denominator is actually inverted -------------
            lagrange = gf_mul(numerator, gf_inv(denominator))
            # --- defect 4: GF addition (XOR) keeps the accumulator mod 256 --
            reconstructed ^= gf_mul(payload_i[position], lagrange)
        secret[position] = reconstructed
    return bytes(secret)


def verify_share(share) -> bool:
    """Check one share in isolation."""
    if not isinstance(share, (bytes, bytearray)) or len(share) < 2:
        return False
    coord = share[0]
    if coord == 0:  # a zero coordinate would degenerate interpolation
        return False
    payload = bytes(share[1:-1])
    return share[-1] == _checksum(coord, payload)


def reconstruct(shares, threshold: int) -> dict:
    """Validate shares, reconstruct the secret, and report the shares used."""
    if len(shares) < threshold:
        raise ValueError("not enough shares to meet the threshold")
    for share in shares:
        if not verify_share(share):
            raise ValueError("share failed integrity verification")
    secret = combine(shares, threshold)
    return {"secret": secret, "used": set(shares)}
