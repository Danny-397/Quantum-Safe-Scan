"""Tests for risk scoring and recommendations."""

import pytest

from quantumsafe.recommender import recommend
from quantumsafe.scanner import RISK_HIGH, RISK_LOW, RISK_MEDIUM, Finding
from quantumsafe.scorer import (
    calculate_score,
    count_by_severity,
    risk_band,
)


def _f(level, family="rsa"):
    return Finding("f.py", 1, "X", level, "why", family)


def test_score_formula():
    findings = [_f(RISK_HIGH), _f(RISK_MEDIUM), _f(RISK_LOW)]  # 15 + 5 + 1
    assert calculate_score(findings) == 21


def test_score_is_capped_at_100():
    findings = [_f(RISK_HIGH) for _ in range(20)]  # 300 -> capped
    assert calculate_score(findings) == 100


def test_empty_score_is_zero():
    assert calculate_score([]) == 0


@pytest.mark.parametrize("score,band", [
    (0, "Low"), (30, "Low"), (31, "Medium"), (60, "Medium"),
    (61, "High"), (80, "High"), (81, "Critical"), (100, "Critical"),
])
def test_risk_band_boundaries(score, band):
    assert risk_band(score) == band


def test_count_by_severity():
    findings = [_f(RISK_HIGH), _f(RISK_HIGH), _f(RISK_MEDIUM), _f(RISK_LOW)]
    counts = count_by_severity(findings)
    assert counts == {RISK_HIGH: 2, RISK_MEDIUM: 1, RISK_LOW: 1}


def test_recommend_known_family():
    rec = recommend("rsa")
    assert "Kyber" in rec.replacement or "ML-KEM" in rec.replacement
    assert "FIPS 203" in rec.nist_reference


def test_recommend_unknown_family_falls_back():
    rec = recommend("does-not-exist")
    assert rec.replacement and rec.nist_reference
