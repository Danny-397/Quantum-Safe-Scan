"""Mosca's inequality: is this migration already too late?

The Quantum Risk Score in :mod:`scorer` answers "how much vulnerable
cryptography is there". It cannot answer the question the threat model actually
poses, which is "will we finish in time". Those are different: a codebase with
one RSA key exchange protecting data that must stay secret for fifty years is
in more trouble than one with forty MD5 checksums.

Michele Mosca's formulation:

    X  how long the data must remain confidential  (secrecy shelf life)
    Y  how long the migration takes
    Z  how long until a cryptographically relevant quantum computer exists

    If  X + Y > Z  then data being transmitted today is already exposed.

The reason is harvest-now-decrypt-later: an adversary records ciphertext today
and decrypts it once Z arrives. Anything still needing confidentiality at that
point was compromised the moment it was sent, and no amount of later migration
can undo it. Migration has to *finish* Z - X from now, not at Z.

WHAT THIS MODULE WILL AND WILL NOT CLAIM
Z is unknowable. This module therefore does not predict it, and no default is
supplied: the caller passes the Z it wants to reason about. What is computed is
the **break-even year** -- the latest a quantum computer could arrive while
still leaving time to migrate. That is a property of the codebase and the data,
not a forecast, so it is honest to state.

Y is an estimate, and estimates of engineering effort are weak. It is therefore
reported as a range rather than a point, every coefficient below is named and
justified, and :meth:`MoscaAssessment.to_dict` emits the assumptions alongside
the numbers so a reader can disagree with them specifically.
"""

from __future__ import annotations

import datetime as _dt
import math
from dataclasses import dataclass, field

from .recommender import NO_ACTION_FAMILIES, RECOMMENDATIONS
from .scanner import Finding

# --------------------------------------------------------------------------- #
# Effort coefficients, in MONTHS, as (optimistic, pessimistic) pairs.
#
# These are the model's assumptions, not measurements, which is why they are
# named constants rather than inline numbers and why every one of them is
# surfaced in the output. Replace them with figures from your own migration if
# you have them -- that is strictly better than these.
# --------------------------------------------------------------------------- #

#: Inventory and planning before any code changes: finding every usage,
#: deciding target algorithms, agreeing a rollout. Paid once.
DISCOVERY_MONTHS = (1.0, 3.0)

#: One asymmetric family (RSA, ECC, DH, DSA) replaced by a PQC scheme. These
#: are the families `recommender` marks complexity="High" because there is no
#: like-for-like swap: key sizes change, handshakes change, and both ends of
#: every protocol must be migrated together, usually via a hybrid period.
ASYMMETRIC_WORKSTREAM_MONTHS = (6.0, 18.0)

#: One drop-in family (MD5 -> SHA-256, 3DES -> AES, TLS 1.2 -> 1.3). A real
#: change with real testing, but local and mechanical.
DROP_IN_FAMILY_MONTHS = (0.5, 2.0)

#: Ceiling on the call-site multiplier. Beyond a few hundred sites the work is
#: dominated by process rather than edits, so the curve is flattened rather
#: than allowed to grow without bound.
MAX_SITE_MULTIPLIER = 4.0

VERDICT_LATE = "already_late"
VERDICT_AT_RISK = "at_risk"
VERDICT_ON_TRACK = "on_track"
#: No Z was supplied, so the inequality cannot be evaluated. A distinct state
#: rather than a pessimistic guess: reporting "at risk" when nothing was
#: assessed would be a claim the model has not earned.
VERDICT_UNKNOWN = "no_verdict"

_VERDICT_MESSAGE = {
    VERDICT_LATE: (
        "Already too late: even on the optimistic estimate, data sent today "
        "that must stay confidential for this long will still be sensitive "
        "when the migration finishes."
    ),
    VERDICT_AT_RISK: (
        "At risk: the optimistic estimate finishes in time but the "
        "pessimistic one does not. The margin depends on assumptions you "
        "should replace with your own."
    ),
    VERDICT_ON_TRACK: (
        "On track: the migration finishes with time to spare even on the "
        "pessimistic estimate, for this choice of Z."
    ),
}


def site_multiplier(sites: int) -> float:
    """Sub-linear growth in the number of call sites for one family.

    Five hundred RSA call sites are not five hundred times the work of one.
    The expensive part -- choosing a replacement, changing a protocol, running
    a hybrid period -- is paid once per family. Additional sites add mechanical
    edits and test surface, which grows far slower than linearly, so the term
    is logarithmic and capped by MAX_SITE_MULTIPLIER.
    """
    if sites <= 1:
        return 1.0
    return min(1.0 + math.log2(sites) / 2.0, MAX_SITE_MULTIPLIER)


@dataclass
class MoscaAssessment:
    """The result of applying Mosca's inequality to a set of findings."""

    secrecy_years: float                 # X
    migration_years_low: float           # Y, optimistic
    migration_years_high: float          # Y, pessimistic
    crqc_years: float | None             # Z, as supplied by the caller
    verdict: str
    message: str
    #: Latest a CRQC could arrive while still leaving time to migrate.
    breakeven_years_low: float
    breakeven_years_high: float
    breakeven_year_low: int
    breakeven_year_high: int
    asymmetric_families: list[str] = field(default_factory=list)
    drop_in_families: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "secrecy_years": self.secrecy_years,
            "migration_years": {
                "low": round(self.migration_years_low, 2),
                "high": round(self.migration_years_high, 2),
            },
            "crqc_years": self.crqc_years,
            "verdict": self.verdict,
            "message": self.message,
            # X + Y: migration must be complete this many years from now.
            "breakeven_years": {
                "low": round(self.breakeven_years_low, 2),
                "high": round(self.breakeven_years_high, 2),
            },
            "breakeven_year": {
                "low": self.breakeven_year_low,
                "high": self.breakeven_year_high,
            },
            "asymmetric_families": self.asymmetric_families,
            "drop_in_families": self.drop_in_families,
            "assumptions": self.assumptions,
        }


def estimate_migration_months(findings: list[Finding]) -> tuple[float, float, list[str], list[str]]:
    """Estimate (optimistic, pessimistic) migration months from findings.

    Work is counted per *family*, not per finding, because the cost is driven
    by the number of distinct cryptographic decisions to be made rather than
    the number of lines to edit. Call-site counts then scale each family
    sub-linearly (see :func:`site_multiplier`).
    """
    sites: dict[str, int] = {}
    for f in findings:
        # Families that need no migration contribute no migration time. Without
        # this, a scan whose only findings are "SHA-256 is fine" or "already
        # using a PQC hybrid" would be charged months of work for nothing.
        if f.family and f.family not in NO_ACTION_FAMILIES:
            sites[f.family] = sites.get(f.family, 0) + 1

    asymmetric: list[str] = []
    drop_in: list[str] = []
    low = high = 0.0

    for family, count in sorted(sites.items()):
        scale = site_multiplier(count)
        # An unknown family is treated as a design change: that is the
        # expensive assumption, which is the safe direction to be wrong in.
        known = RECOMMENDATIONS.get(family)
        # An unrecognised family is costed as a design change. That is the
        # expensive assumption, and the safe direction to be wrong in.
        is_asymmetric = known.complexity == "High" if known else True
        if is_asymmetric:
            asymmetric.append(family)
            base_low, base_high = ASYMMETRIC_WORKSTREAM_MONTHS
        else:
            drop_in.append(family)
            base_low, base_high = DROP_IN_FAMILY_MONTHS
        low += base_low * scale
        high += base_high * scale

    if sites:
        low += DISCOVERY_MONTHS[0]
        high += DISCOVERY_MONTHS[1]

    return low, high, asymmetric, drop_in


def assess(
    findings: list[Finding],
    secrecy_years: float,
    crqc_years: float | None = None,
    today: _dt.date | None = None,
) -> MoscaAssessment:
    """Apply Mosca's inequality.

    ``secrecy_years`` (X) is how long the data this code protects must stay
    confidential -- minutes for a session cookie, decades for health records.
    ``crqc_years`` (Z) is how long until a quantum computer could break the
    cryptography. It has no default on purpose: nobody knows it, so the caller
    states the scenario they want to reason about. Omit it to get the
    break-even year without a verdict.
    """
    if secrecy_years < 0:
        raise ValueError("secrecy_years cannot be negative")
    if crqc_years is not None and crqc_years < 0:
        raise ValueError("crqc_years cannot be negative")

    today = today or _dt.date.today()
    months_low, months_high, asymmetric, drop_in = estimate_migration_months(findings)
    y_low, y_high = months_low / 12.0, months_high / 12.0

    # X + Y. Migration must be finished by this point for data sent today to
    # still be confidential when a CRQC arrives.
    be_low = secrecy_years + y_low
    be_high = secrecy_years + y_high

    if not asymmetric and not drop_in:
        # Mosca's inequality presumes there is something to migrate. With no
        # findings the comparison is vacuous: X > Z would otherwise report
        # "already late" for a codebase that has no vulnerable cryptography
        # in it at all.
        verdict = VERDICT_ON_TRACK
        message = (
            "Nothing to migrate: no quantum-vulnerable cryptography was "
            "detected, so the inequality does not apply. This says nothing "
            "about cryptography the scanner cannot see."
        )
    elif crqc_years is None:
        verdict = VERDICT_UNKNOWN
        message = (
            "No Z supplied, so the inequality was not evaluated. The break-even "
            "year is the latest a quantum computer could arrive while still "
            "leaving time to migrate."
        )
    elif be_low > crqc_years:
        verdict, message = VERDICT_LATE, _VERDICT_MESSAGE[VERDICT_LATE]
    elif be_high > crqc_years:
        verdict, message = VERDICT_AT_RISK, _VERDICT_MESSAGE[VERDICT_AT_RISK]
    else:
        verdict, message = VERDICT_ON_TRACK, _VERDICT_MESSAGE[VERDICT_ON_TRACK]

    assumptions = [
        f"Discovery and planning: {DISCOVERY_MONTHS[0]}-{DISCOVERY_MONTHS[1]} months, once.",
        f"Each asymmetric family (no drop-in replacement): "
        f"{ASYMMETRIC_WORKSTREAM_MONTHS[0]}-{ASYMMETRIC_WORKSTREAM_MONTHS[1]} months.",
        f"Each drop-in family: {DROP_IN_FAMILY_MONTHS[0]}-{DROP_IN_FAMILY_MONTHS[1]} months.",
        f"Call sites scale a family sub-linearly (1 + log2(n)/2, capped at "
        f"{MAX_SITE_MULTIPLIER}x): the design change is paid once per family.",
        "Workstreams are assumed sequential; a team running them in parallel "
        "finishes sooner than the optimistic estimate.",
        "These coefficients are assumptions, not measurements. Replace them "
        "with figures from your own migration.",
    ]

    return MoscaAssessment(
        secrecy_years=secrecy_years,
        migration_years_low=y_low,
        migration_years_high=y_high,
        crqc_years=crqc_years,
        verdict=verdict,
        message=message,
        breakeven_years_low=be_low,
        breakeven_years_high=be_high,
        breakeven_year_low=today.year + math.floor(be_low),
        breakeven_year_high=today.year + math.floor(be_high),
        asymmetric_families=asymmetric,
        drop_in_families=drop_in,
        assumptions=assumptions,
    )
