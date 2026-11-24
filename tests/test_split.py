from __future__ import annotations

import pytest

from share.split import (
    _gf_pow,
    combine,
    eval_poly,
    gf_inv,
    gf_mul,
    reconstruct,
    split,
    verify_share,
)

SECRET = bytes.fromhex("000102030405060708090a0b0c0d0e0f")


def test_gf_mul_reduces_with_the_irreducible_polynomial():
    assert gf_mul(0x57, 0x83) == 0xC1
    assert gf_mul(0x80, 0x02) == 0x1B
    assert gf_mul(0xFF, 0x01) == 0xFF


def test_gf_inv_is_a_true_modular_inverse():
    assert gf_inv(0x53) == 0xCA
    assert gf_inv(0x01) == 0x01
    assert gf_mul(0x53, gf_inv(0x53)) == 0x01
    with pytest.raises((ValueError, ZeroDivisionError)):
        gf_inv(0)


def test_lagrange_denominator_uses_inverted_differences():
    shares = split(SECRET, 2, 3, 101)
    assert combine([shares[1], shares[2]], 2) == SECRET


def test_interpolation_accumulator_is_reduced_modulo_256():
    shares = split(SECRET, 3, 4, 202)
    assert combine(shares[:3], 3) == SECRET


def test_eval_poly_uses_low_degree_first_coefficient_order():
    assert eval_poly([0x01, 0x02, 0x03], 0x02) == 0x09
    assert eval_poly([0x00, 0x01], 0x02) == 0x02
    assert eval_poly([0x05], 0x7B) == 0x05


def test_split_assigns_nonzero_coordinates():
    shares = split(SECRET, 2, 4, 303)
    assert [share[0] for share in shares] == [1, 2, 3, 4]
    assert verify_share(shares[0]) is True


def test_duplicate_share_cannot_lower_the_threshold():
    shares = split(SECRET, 3, 4, 404)
    with pytest.raises(ValueError):
        combine([shares[0], shares[0], shares[1]], 3)


def test_verify_share_covers_the_payload_against_tampering():
    shares = split(SECRET, 2, 3, 505)
    good = shares[1]
    bad = bytearray(good)
    bad[1] ^= 0x01
    assert verify_share(good) is True
    assert verify_share(bytes(bad)) is False


def test_threshold_one_reconstructs_from_a_single_share():
    shares = split(SECRET, 1, 3, 606)
    share = shares[1]
    assert verify_share(share) is True
    result = reconstruct([share], 1)
    assert result["secret"] == SECRET
    assert result["used"] == {share}


def test_share_order_does_not_change_reconstruction():
    shares = split(SECRET, 2, 4, 707)
    ordered = [shares[0], shares[2]]
    reversed_order = list(reversed(ordered))
    forward = combine(ordered, 2)
    backward = combine(reversed_order, 2)
    assert forward == backward
    assert forward == SECRET


def test_known_gf_vectors():
    assert gf_mul(0x57, 0x83) == 0xC1
    assert gf_inv(0x53) == 0xCA
    assert _gf_pow(0x53, 0) == 0x01
    assert _gf_pow(0x02, 8) == 0x1B


def test_threshold_two_any_pair_restores_and_single_share_is_rejected():
    shares = split(SECRET, 2, 4, 808)
    for i in range(4):
        for j in range(i + 1, 4):
            result = reconstruct([shares[i], shares[j]], 2)
            assert result["secret"] == SECRET
            assert result["used"] == {shares[i], shares[j]}
    with pytest.raises(ValueError):
        reconstruct([shares[0]], 2)


def test_share_count_equal_to_threshold_restores_exact_bytes():
    shares = split(SECRET, 3, 3, 909)
    result = reconstruct(shares, 3)
    assert result["secret"] == SECRET
    assert len(result["secret"]) == len(SECRET)
    assert result["used"] == set(shares)


def test_duplicate_coordinates_are_rejected():
    shares = split(SECRET, 2, 3, 1001)
    assert verify_share(shares[0]) is True
    assert verify_share(shares[1]) is True
    with pytest.raises(ValueError):
        combine([shares[0], shares[1], shares[0]], 2)


def test_two_independent_batches_match_single_batch():
    batch_a = split(SECRET, 2, 3, 1102)
    batch_b = split(SECRET, 2, 4, 1203)
    secret_a = reconstruct(batch_a[:2], 2)["secret"]
    secret_b = reconstruct(batch_b[:2], 2)["secret"]
    assert secret_a == SECRET
    assert secret_b == SECRET
    assert secret_a == secret_b