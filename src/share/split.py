"""Threshold secret sharing over GF(256).

A share is encoded as one coordinate byte, one payload byte per secret byte,
and one checksum trailer byte.  The field is GF(256) with the irreducible
polynomial x^8 + x^4 + x^3 + x + 1, represented as 0x11B.
"""
from __future__ import annotations
_IRREDUCIBLE = 283
_MASK = 255

def gf_mul(a: int, b: int) -> int:
    """Multiply a and b in GF(256) and return one byte."""
    raise NotImplementedError()

def gf_inv(a: int) -> int:
    """Return the multiplicative inverse of a nonzero field element."""
    raise NotImplementedError()

def _gf_pow(a: int, n: int) -> int:
    """Raise a to a nonnegative integer power in GF(256)."""
    raise NotImplementedError()

def eval_poly(coeffs, x: int) -> int:
    """Evaluate a polynomial whose coefficients are ordered low degree first."""
    raise NotImplementedError()

def split(secret: bytes, threshold: int, shares: int, seed: int) -> list[bytes]:
    """Split secret into shares shares with the given reconstruction threshold."""
    raise NotImplementedError()

def combine(shares, threshold: int) -> bytes:
    """Reconstruct the secret from shares using Lagrange interpolation at zero."""
    raise NotImplementedError()

def verify_share(share) -> bool:
    """Check one share in isolation."""
    raise NotImplementedError()

def reconstruct(shares, threshold: int) -> dict:
    """Validate shares, reconstruct the secret, and report the shares used."""
    raise NotImplementedError()
