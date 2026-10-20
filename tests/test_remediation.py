"""Tests for call-site-specific remediation.

`cli/remediation.py` was the one module in `cli/` with no tests of its own,
and it is the module whose output an engineer acts on directly: it tells them
what to change on the line in front of them.

The invariant worth protecting is the cross-check against
`recommender.RECOMMENDATIONS`. `remediate()` ends in a catch-all that returns
"Review against current NIST PQC guidance" for anything it does not recognise.
That is the right behaviour for an unknown family, but it means a family added
to the scanner and *not* to this module degrades silently into useless advice
rather than failing. The two tables are therefore pinned to each other.
"""

import pytest

from quantumsafe.recommender import RECOMMENDATIONS
from quantumsafe.remediation import Fix, remediate

# Families with no like-for-like replacement: these need a PQC migration.
ASYMMETRIC = {"rsa", "ecc", "dsa", "dh"}
# Families where a direct swap exists.
DROP_IN = set(RECOMMENDATIONS) - ASYMMETRIC

LANGUAGES = ["python", "javascript", "java", "go", "", "cobol"]

GENERIC_ACTION = "Review against current NIST PQC guidance."


# --------------------------------------------------------------------------- #
# Every known family must be handled
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("family", sorted(RECOMMENDATIONS))
def test_every_recommended_family_has_a_specific_fix(family):
    """No family the scanner can report may fall through to the catch-all."""
    fix = remediate(family, "python")
    assert fix.action != GENERIC_ACTION, (
        f"{family!r} is in RECOMMENDATIONS but has no branch in remediate(); "
        "it silently degrades to generic advice"
    )
    assert fix.action.strip()
    assert fix.guidance.strip()


def test_unknown_family_falls_back_rather_than_raising():
    """An unrecognised family must degrade politely, not crash the scan."""
    fix = remediate("not-a-real-family", "python")
    assert fix.action == GENERIC_ACTION
    assert fix.drop_in is False


# --------------------------------------------------------------------------- #
# Drop-in vs migration — getting this backwards is the dangerous failure
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("family", sorted(ASYMMETRIC))
def test_asymmetric_families_are_not_advertised_as_drop_in(family):
    """RSA/ECC/DSA/DH have no like-for-like swap.

    Marking one drop_in=True would tell an engineer a key-exchange migration
    is a one-line change, which is the most expensive wrong answer this tool
    could give.
    """
    fix = remediate(family, "python")
    assert fix.drop_in is False
    assert "design change" in fix.action or "design change" in fix.guidance
    assert fix.library, "a migration needs somewhere to migrate to"
    assert "hybrid" in fix.guidance.lower()


@pytest.mark.parametrize("family", sorted(DROP_IN))
def test_drop_in_families_are_marked_drop_in(family):
    fix = remediate(family, "python")
    assert fix.drop_in is True


@pytest.mark.parametrize("family", sorted(DROP_IN - {"sha256"}))
def test_drop_in_families_show_a_before_and_an_after(family):
    """A drop-in fix is only useful if it shows the actual swap."""
    fix = remediate(family, "python")
    assert fix.before.strip(), f"{family} has no 'before' pattern"
    assert fix.after.strip(), f"{family} has no 'after' pattern"
    assert fix.before != fix.after


def test_sha256_is_reported_as_already_safe():
    """SHA-256 is the one family whose correct advice is 'change nothing'."""
    fix = remediate("sha256")
    assert fix.drop_in is True
    assert "no change required" in fix.action.lower()
    assert not fix.before and not fix.after


# --------------------------------------------------------------------------- #
# Language handling
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("family", sorted(RECOMMENDATIONS))
@pytest.mark.parametrize("language", LANGUAGES)
def test_every_family_language_pair_resolves(family, language):
    """_pick falls back to the "" entry, so no pairing may raise KeyError."""
    fix = remediate(family, language)
    assert isinstance(fix, Fix)
    assert fix.action.strip()


def test_unknown_language_uses_the_agnostic_fallback():
    agnostic = remediate("md5", "")
    cobol = remediate("md5", "cobol")
    assert (cobol.before, cobol.after) == (agnostic.before, agnostic.after)


def test_language_specific_snippets_actually_differ():
    """Otherwise the per-language tables are doing nothing."""
    py = remediate("md5", "python")
    js = remediate("md5", "javascript")
    assert py.before != js.before
    assert "hashlib" in py.before
    assert "crypto" in js.before


def test_pqc_library_pointer_is_language_aware():
    py = remediate("rsa", "python")
    js = remediate("rsa", "javascript")
    assert py.library and js.library
    assert py.library != js.library


# --------------------------------------------------------------------------- #
# Shape
# --------------------------------------------------------------------------- #
def test_snippet_is_echoed_into_before_for_migrations_and_truncated():
    """The caller's own line is shown back, bounded so a minified file can't
    drag a 50KB 'snippet' into the report."""
    long_line = "x" * 500
    fix = remediate("rsa", "python", snippet=long_line)
    assert fix.before
    assert len(fix.before) <= 120


def test_snippet_is_stripped():
    fix = remediate("ecc", "python", snippet="   key = ec.generate()   ")
    assert fix.before == "key = ec.generate()"


def test_to_dict_round_trips_every_field():
    fix = remediate("rsa", "python", snippet="k = rsa.generate(2048)")
    d = fix.to_dict()
    assert set(d) == {"action", "drop_in", "before", "after", "guidance", "library"}
    assert d["drop_in"] is False
    assert d["action"] == fix.action
