"""Tests for Mosca's inequality in cli/horizon.py.

The module makes a claim the rest of the tool does not: not "how much bad
crypto is here" but "will you finish in time". That makes two things worth
pinning hard -- the inequality itself (X + Y > Z), and the honesty properties:
that no Z is invented, that a missing Z yields no verdict rather than a guess,
and that every coefficient is surfaced so a reader can disagree with it.
"""

import datetime

import pytest

from quantumsafe.horizon import (
    ASYMMETRIC_WORKSTREAM_MONTHS,
    DISCOVERY_MONTHS,
    DROP_IN_FAMILY_MONTHS,
    MAX_SITE_MULTIPLIER,
    VERDICT_AT_RISK,
    VERDICT_LATE,
    VERDICT_ON_TRACK,
    VERDICT_UNKNOWN,
    assess,
    estimate_migration_months,
    site_multiplier,
)
from quantumsafe.recommender import NO_ACTION_FAMILIES, RECOMMENDATIONS
from quantumsafe.scanner import RISK_HIGH, RISK_LOW, Finding

TODAY = datetime.date(2026, 10, 21)


def F(family, risk=RISK_HIGH, line=1):
    return Finding(file_path="a.py", line_number=line, algorithm=family.upper(),
                   risk_level=risk, why="x", family=family)


# --------------------------------------------------------------------------- #
# The inequality
# --------------------------------------------------------------------------- #
def test_long_secrecy_is_late_however_fast_the_migration():
    """The case the model exists to surface.

    Health-record-grade confidentiality (50 years) cannot be rescued by
    migrating quickly: data sent today is still sensitive long after any
    plausible CRQC. Severity scoring cannot express this at all.
    """
    a = assess([F("rsa")], secrecy_years=50, crqc_years=15, today=TODAY)
    assert a.verdict == VERDICT_LATE


def test_short_secrecy_with_distant_crqc_is_on_track():
    a = assess([F("rsa")], secrecy_years=1, crqc_years=30, today=TODAY)
    assert a.verdict == VERDICT_ON_TRACK


def test_at_risk_is_the_band_between_the_two_estimates():
    """Z between the optimistic and pessimistic break-even is 'at risk'."""
    a = assess([F("rsa")], secrecy_years=10, crqc_years=15, today=TODAY)
    # Place Z inside the band this finding produces.
    z = (a.breakeven_years_low + a.breakeven_years_high) / 2
    mid = assess([F("rsa")], secrecy_years=10, crqc_years=z, today=TODAY)
    assert mid.verdict == VERDICT_AT_RISK


def test_verdict_boundaries_are_strict_inequalities():
    """X + Y > Z is late; X + Y == Z exactly is not."""
    a = assess([F("rsa")], secrecy_years=10, crqc_years=99, today=TODAY)
    exact_low = a.breakeven_years_low
    exact_high = a.breakeven_years_high

    # Z exactly equal to the pessimistic break-even: not late, not at risk.
    on_edge = assess([F("rsa")], secrecy_years=10, crqc_years=exact_high, today=TODAY)
    assert on_edge.verdict == VERDICT_ON_TRACK

    # A hair below the optimistic break-even: late.
    late = assess([F("rsa")], secrecy_years=10,
                  crqc_years=exact_low - 0.001, today=TODAY)
    assert late.verdict == VERDICT_LATE


def test_breakeven_is_secrecy_plus_migration():
    a = assess([F("rsa")], secrecy_years=7, crqc_years=20, today=TODAY)
    assert a.breakeven_years_low == pytest.approx(7 + a.migration_years_low)
    assert a.breakeven_years_high == pytest.approx(7 + a.migration_years_high)
    assert a.breakeven_year_low == TODAY.year + int(a.breakeven_years_low)


# --------------------------------------------------------------------------- #
# Honesty properties
# --------------------------------------------------------------------------- #
def test_no_crqc_means_no_verdict_not_a_guess():
    """Z is unknowable, so omitting it must not produce a verdict."""
    a = assess([F("rsa")], secrecy_years=10, today=TODAY)
    assert a.verdict == VERDICT_UNKNOWN
    assert a.crqc_years is None
    # The break-even is still computable -- it needs no Z.
    assert a.breakeven_years_low > 10


def test_there_is_no_default_crqc_year():
    """A default Z would be a prediction the tool has no basis for."""
    import inspect
    sig = inspect.signature(assess)
    assert sig.parameters["crqc_years"].default is None


def test_migration_time_is_a_range_not_a_point():
    a = assess([F("rsa")], secrecy_years=1, crqc_years=10, today=TODAY)
    assert a.migration_years_low < a.migration_years_high


def test_assumptions_are_reported_with_the_numbers():
    """A reader must be able to disagree with the model specifically."""
    d = assess([F("rsa")], secrecy_years=1, crqc_years=10, today=TODAY).to_dict()
    assert len(d["assumptions"]) >= 5
    blob = " ".join(d["assumptions"])
    for token in (str(ASYMMETRIC_WORKSTREAM_MONTHS[1]),
                  str(DROP_IN_FAMILY_MONTHS[0]),
                  str(MAX_SITE_MULTIPLIER)):
        assert token in blob, f"{token} missing from stated assumptions"
    assert "assumptions, not measurements" in blob


def test_to_dict_shape():
    d = assess([F("rsa")], secrecy_years=5, crqc_years=12, today=TODAY).to_dict()
    assert set(d) == {
        "secrecy_years", "migration_years", "crqc_years", "verdict", "message",
        "breakeven_years", "breakeven_year", "asymmetric_families",
        "drop_in_families", "assumptions",
    }
    assert set(d["migration_years"]) == {"low", "high"}


# --------------------------------------------------------------------------- #
# Effort model
# --------------------------------------------------------------------------- #
def test_effort_is_counted_per_family_not_per_finding():
    """A hundred RSA call sites are not a hundred migrations."""
    one = estimate_migration_months([F("rsa")])[1]
    hundred = estimate_migration_months([F("rsa", line=i) for i in range(100)])[1]
    assert hundred > one, "more call sites should cost something"
    assert hundred < one * 5, "but nowhere near linearly more"


def test_site_multiplier_is_sublinear_and_capped():
    assert site_multiplier(0) == 1.0
    assert site_multiplier(1) == 1.0
    assert site_multiplier(4) == pytest.approx(2.0)
    assert site_multiplier(16) == pytest.approx(3.0)
    assert site_multiplier(10_000) == MAX_SITE_MULTIPLIER
    # Monotone non-decreasing.
    vals = [site_multiplier(n) for n in (1, 2, 8, 64, 512, 100_000)]
    assert vals == sorted(vals)


def test_asymmetric_families_cost_more_than_drop_ins():
    rsa = estimate_migration_months([F("rsa")])[1]
    md5 = estimate_migration_months([F("md5", RISK_LOW)])[1]
    assert rsa > md5


@pytest.mark.parametrize("family", sorted(set(RECOMMENDATIONS) - NO_ACTION_FAMILIES))
def test_family_classification_follows_the_recommender(family):
    """The split must not drift from recommender.RECOMMENDATIONS."""
    _, _, asym, drop_in = estimate_migration_months([F(family)])
    expected_asym = RECOMMENDATIONS[family].complexity == "High"
    assert (family in asym) is expected_asym
    assert (family in drop_in) is (not expected_asym)
    assert not (asym and drop_in), "a family cannot be in both lists"


@pytest.mark.parametrize("family", sorted(NO_ACTION_FAMILIES))
def test_no_action_families_cost_nothing(family):
    """Reported-but-fine findings must not be charged as migration work.

    "SHA-256 is acceptable" and "already using a post-quantum hybrid" are
    findings so a scan can show what is already right. Counting them as
    effort would bill months of work for nothing, and would make a
    fully-migrated endpoint look like it still had a migration pending.
    """
    low, high, asym, drop_in = estimate_migration_months([F(family)])
    assert (low, high) == (0.0, 0.0)
    assert asym == [] and drop_in == []


def test_no_action_findings_do_not_mask_real_ones():
    """Mixing them in must not change the estimate for the real work."""
    real = estimate_migration_months([F("rsa")])
    mixed = estimate_migration_months(
        [F("rsa")] + [F(f, RISK_LOW) for f in sorted(NO_ACTION_FAMILIES)])
    assert mixed[:2] == real[:2]
    assert mixed[2] == ["rsa"]


def test_unknown_family_is_costed_as_a_design_change():
    """Being wrong in the expensive direction is the safe default."""
    _, _, asym, drop_in = estimate_migration_months([F("some-new-family")])
    assert asym == ["some-new-family"]
    assert drop_in == []


def test_empty_findings_cost_nothing_at_all():
    """No findings means no migration -- not even discovery."""
    low, high, asym, drop_in = estimate_migration_months([])
    assert (low, high) == (0.0, 0.0)
    assert asym == [] and drop_in == []


def test_nothing_to_migrate_is_not_reported_as_late():
    """The inequality presumes vulnerable crypto exists.

    With no findings Y is 0, so a naive X > Z comparison would report
    "already late" for a codebase containing no vulnerable cryptography at
    all. That would be a false alarm, and the kind a security tool loses
    trust over.
    """
    a = assess([], secrecy_years=50, crqc_years=1, today=TODAY)
    assert a.migration_years_high == 0.0
    assert a.verdict == VERDICT_ON_TRACK
    assert "Nothing to migrate" in a.message
    # And it does not overclaim: the scanner's blind spots are acknowledged.
    assert "cannot see" in a.message


def test_discovery_is_charged_once_not_per_family():
    one = estimate_migration_months([F("rsa")])[0]
    two = estimate_migration_months([F("rsa"), F("ecc")])[0]
    added = two - one
    assert added == pytest.approx(ASYMMETRIC_WORKSTREAM_MONTHS[0]), (
        "adding a family must add exactly one workstream, not another "
        "discovery phase"
    )
    assert one >= DISCOVERY_MONTHS[0]


def test_findings_with_no_family_are_ignored():
    f = F("rsa")
    f.family = ""
    assert estimate_migration_months([f])[0] == 0.0


# --------------------------------------------------------------------------- #
# Input validation
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("kwargs", [
    {"secrecy_years": -1, "crqc_years": 10},
    {"secrecy_years": 10, "crqc_years": -5},
])
def test_negative_horizons_are_rejected(kwargs):
    with pytest.raises(ValueError):
        assess([F("rsa")], today=TODAY, **kwargs)


def test_zero_secrecy_is_allowed():
    """Data that needs no confidentiality is a legitimate answer."""
    a = assess([F("rsa")], secrecy_years=0, crqc_years=50, today=TODAY)
    assert a.verdict == VERDICT_ON_TRACK


# --------------------------------------------------------------------------- #
# The HTTP endpoint
#
# The dashboard fetches Y once and then recomputes the verdict locally as the
# sliders move, so this endpoint's job is to produce the migration estimate and
# the assumptions behind it -- and to refuse nonsense input without a 500.
# --------------------------------------------------------------------------- #
def _post(client, **body):
    return client.post("/api/v1/horizon", json=body)


def test_endpoint_returns_a_migration_estimate(client):
    res = _post(client, findings=[{"family": "rsa"}, {"family": "md5"}],
                secrecy_years=10, crqc_years=12)
    assert res.status_code == 200
    h = res.get_json()["horizon"]
    assert h["migration_years"]["low"] > 0
    assert h["migration_years"]["high"] > h["migration_years"]["low"]
    assert h["verdict"] in ("already_late", "at_risk", "on_track")
    assert len(h["assumptions"]) >= 5


def test_endpoint_only_needs_the_family(client):
    """The dashboard sends nothing but the family, by design."""
    res = _post(client, findings=[{"family": "rsa"}], secrecy_years=0)
    assert res.status_code == 200
    assert res.get_json()["horizon"]["migration_years"]["high"] > 0


def test_endpoint_ignores_extra_finding_fields(client):
    """File paths and snippets are irrelevant to the estimate and unneeded."""
    plain = _post(client, findings=[{"family": "rsa"}], secrecy_years=0)
    noisy = _post(client, findings=[{"family": "rsa", "file_path": "/etc/passwd",
                                     "snippet": "x" * 500, "line_number": 9}],
                  secrecy_years=0)
    assert (plain.get_json()["horizon"]["migration_years"]
            == noisy.get_json()["horizon"]["migration_years"])


def test_endpoint_gives_no_verdict_without_a_quantum_year(client):
    res = _post(client, findings=[{"family": "rsa"}], secrecy_years=10)
    h = res.get_json()["horizon"]
    assert h["verdict"] == "no_verdict"
    assert h["crqc_years"] is None
    # The break-even is still returned: it needs no guess about Z.
    assert h["breakeven_year"]["low"] >= 2026


def test_endpoint_requires_a_findings_list(client):
    for body in ({}, {"findings": "rsa"}, {"findings": 5}):
        res = client.post("/api/v1/horizon", json=body)
        assert res.status_code == 400
        assert "findings" in res.get_json()["error"].lower()


def test_endpoint_caps_the_findings_count(client):
    res = _post(client, findings=[{"family": "rsa"}] * 5001, secrecy_years=0)
    assert res.status_code == 413


def test_empty_findings_list_is_accepted(client):
    """A clean scan is a legitimate thing to ask about."""
    res = _post(client, findings=[], secrecy_years=50, crqc_years=1)
    assert res.status_code == 200
    h = res.get_json()["horizon"]
    assert h["migration_years"] == {"low": 0.0, "high": 0.0}
    assert h["verdict"] == "on_track"


@pytest.mark.parametrize("bad", ["abc", -1, 10_000, [1], {"a": 1}])
def test_endpoint_rejects_nonsense_years(client, bad):
    res = _post(client, findings=[{"family": "rsa"}], secrecy_years=bad)
    assert res.status_code == 400, f"{bad!r} should be refused"


def test_endpoint_tolerates_malformed_finding_entries(client):
    """A non-dict in the list must not 500."""
    res = _post(client, findings=[{"family": "rsa"}, "garbage", None, 7],
                secrecy_years=0)
    assert res.status_code == 200
    assert res.get_json()["horizon"]["asymmetric_families"] == ["rsa"]


def test_endpoint_stores_nothing_and_needs_no_auth(client):
    """No token is sent; the call must still work and persist nothing."""
    res = _post(client, findings=[{"family": "ecc"}], secrecy_years=5)
    assert res.status_code == 200
    assert "scan_id" not in res.get_json()
