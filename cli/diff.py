"""Compare two scan reports: what was fixed, what is new, what stayed.

A single scan is a snapshot, and a snapshot is a bad gate for CI. A repository
with forty known findings cannot adopt ``--fail-on-high`` without failing every
build from day one, so in practice the check gets dropped and nothing is
enforced at all. What a team can adopt is a ratchet: the existing backlog is
tolerated, and the build fails only when the situation gets *worse*.

HOW A FINDING IS IDENTIFIED
Not by line number. Line numbers move when an import is added or a file is
reformatted, and keying on them reports a no-op diff as one fix plus one
regression -- noise that trains people to ignore the output. Identity is
``(file_path, family, algorithm)`` instead, which is stable under edits that
do not change the cryptography.

The cost is that several findings of the same kind in the same file collapse to
one key, so the diff tracks a *count* per key and reports growth and shrinkage
within a key. Three RSA call sites in one file becoming five is two new
findings, not "unchanged".

WHAT A DIFF CANNOT TELL YOU
That a finding is gone does not prove it was fixed: the file may have been
deleted, excluded, or renamed, and a rename shows up as one fixed and one new.
:meth:`Diff.to_dict` reports counts and locations, not conclusions, and the
caller is told when the two reports describe different targets rather than
silently comparing unrelated scans.
"""

from __future__ import annotations

from dataclasses import dataclass, field

#: Fields that identify "the same finding" across two scans.
IDENTITY_FIELDS = ("file_path", "family", "algorithm")

_SEVERITIES = ("high", "medium", "low")


def finding_key(finding: dict) -> tuple:
    """A line-number-independent identity for one finding."""
    return tuple(finding.get(f) or "" for f in IDENTITY_FIELDS)


def _tally(findings: list[dict]) -> dict[tuple, list[dict]]:
    out: dict[tuple, list[dict]] = {}
    for f in findings:
        out.setdefault(finding_key(f), []).append(f)
    return out


@dataclass
class Diff:
    """The difference between two scan reports."""

    new: list[dict] = field(default_factory=list)
    fixed: list[dict] = field(default_factory=list)
    unchanged: int = 0
    score_before: int = 0
    score_after: int = 0
    severity_delta: dict[str, int] = field(default_factory=dict)
    target_before: str = ""
    target_after: str = ""
    #: Set when the two reports describe different targets, which usually means
    #: the comparison is not meaningful.
    target_mismatch: bool = False

    @property
    def score_delta(self) -> int:
        return self.score_after - self.score_before

    @property
    def regressed(self) -> bool:
        """True when the situation got worse.

        Driven by new findings rather than by the score: the score is capped at
        100, so a codebase already at the cap can acquire new HIGH findings
        without the number moving at all.
        """
        return bool(self.new)

    @property
    def improved(self) -> bool:
        return bool(self.fixed) and not self.new

    def summary_line(self) -> str:
        bits = [f"{len(self.fixed)} fixed", f"{len(self.new)} new",
                f"{self.unchanged} unchanged"]
        if self.score_delta:
            bits.append(f"score {self.score_before} -> {self.score_after} "
                        f"({self.score_delta:+d})")
        return ", ".join(bits)

    def to_dict(self) -> dict:
        return {
            "new": self.new,
            "fixed": self.fixed,
            "counts": {
                "new": len(self.new),
                "fixed": len(self.fixed),
                "unchanged": self.unchanged,
            },
            "risk_score": {
                "before": self.score_before,
                "after": self.score_after,
                "delta": self.score_delta,
            },
            "severity_delta": self.severity_delta,
            "regressed": self.regressed,
            "improved": self.improved,
            "target": {
                "before": self.target_before,
                "after": self.target_after,
                "mismatch": self.target_mismatch,
            },
            "summary": self.summary_line(),
            "caveat": (
                "A finding that is gone was not necessarily fixed: the file may "
                "have been deleted, excluded or renamed, and a rename appears "
                "as one fixed and one new."
            ),
        }


def diff_reports(before: dict, after: dict) -> Diff:
    """Compare two reports produced by :func:`reporter.build_report`."""
    before_findings = before.get("findings") or []
    after_findings = after.get("findings") or []

    old, new_ = _tally(before_findings), _tally(after_findings)

    added: list[dict] = []
    removed: list[dict] = []
    unchanged = 0

    for key, items in new_.items():
        previous = len(old.get(key, ()))
        if previous == 0:
            added.extend(items)
        elif len(items) > previous:
            # The same kind of finding, but more of it than before.
            added.extend(items[previous:])
            unchanged += previous
        else:
            unchanged += len(items)

    for key, items in old.items():
        current = len(new_.get(key, ()))
        if current < len(items):
            removed.extend(items[current:])

    before_sum = before.get("summary") or {}
    after_sum = after.get("summary") or {}
    severity_delta = {
        s: int(after_sum.get(s, 0)) - int(before_sum.get(s, 0))
        for s in _SEVERITIES
    }

    t_before = before.get("target", "") or ""
    t_after = after.get("target", "") or ""

    return Diff(
        new=added,
        fixed=removed,
        unchanged=unchanged,
        score_before=int(before.get("risk_score", 0) or 0),
        score_after=int(after.get("risk_score", 0) or 0),
        severity_delta=severity_delta,
        target_before=t_before,
        target_after=t_after,
        target_mismatch=bool(t_before and t_after and t_before != t_after),
    )
