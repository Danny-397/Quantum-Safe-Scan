"""Tests for scan diffing.

The feature exists so CI can ratchet: tolerate an existing backlog and fail
only when it grows. Two properties carry the weight.

IDENTITY MUST SURVIVE LINE MOVEMENT. Keying a finding on its line number turns
adding an import into one "fixed" plus one "new", and a diff that cries wolf
gets ignored, which is worse than having no diff at all.

REGRESSION MUST NOT BE SCORE-DRIVEN. The risk score caps at 100, so a codebase
already at the cap can acquire new HIGH findings with the score unchanged.
Verified against the real examples/ directory, which scores 100 before and
after a new DSA file is added.
"""


from quantumsafe.diff import IDENTITY_FIELDS, Diff, diff_reports, finding_key


def F(file_path="a.py", line=1, algorithm="RSA", family="rsa", risk="HIGH"):
    return {"file_path": file_path, "line_number": line, "algorithm": algorithm,
            "family": family, "risk_level": risk}


def R(findings, score=50, target="repo", high=None, medium=0, low=0):
    if high is None:
        high = sum(1 for f in findings if f.get("risk_level") == "HIGH")
    return {"target": target, "risk_score": score, "findings": findings,
            "summary": {"high": high, "medium": medium, "low": low,
                        "total_findings": len(findings)}}


# --------------------------------------------------------------------------- #
# Identity
# --------------------------------------------------------------------------- #
def test_identity_ignores_the_line_number():
    """The property the whole diff rests on."""
    assert "line_number" not in IDENTITY_FIELDS
    assert finding_key(F(line=10)) == finding_key(F(line=400))


def test_a_moved_finding_is_unchanged_not_fixed_and_new():
    before = R([F(line=10)])
    after = R([F(line=512)])
    d = diff_reports(before, after)
    assert (d.new, d.fixed) == ([], [])
    assert d.unchanged == 1
    assert not d.regressed


def test_identity_distinguishes_file_family_and_algorithm():
    base = finding_key(F())
    assert finding_key(F(file_path="b.py")) != base
    assert finding_key(F(family="ecc")) != base
    assert finding_key(F(algorithm="DSA")) != base


def test_missing_fields_do_not_raise():
    assert finding_key({}) == ("", "", "")


# --------------------------------------------------------------------------- #
# New / fixed / unchanged
# --------------------------------------------------------------------------- #
def test_a_new_finding_is_reported():
    d = diff_reports(R([F()]), R([F(), F(file_path="new.py")]))
    assert len(d.new) == 1
    assert d.new[0]["file_path"] == "new.py"
    assert d.unchanged == 1
    assert d.regressed


def test_a_removed_finding_is_reported_as_fixed():
    d = diff_reports(R([F(), F(file_path="gone.py")]), R([F()]))
    assert len(d.fixed) == 1
    assert d.fixed[0]["file_path"] == "gone.py"
    assert not d.regressed
    assert d.improved


def test_identical_reports_show_no_change():
    findings = [F(), F(file_path="b.py", family="ecc", algorithm="ECDSA")]
    d = diff_reports(R(findings), R(list(findings)))
    assert (d.new, d.fixed) == ([], [])
    assert d.unchanged == 2
    assert not d.regressed and not d.improved


def test_growth_within_one_key_counts_as_new():
    """Three RSA sites in a file becoming five is two new findings."""
    before = R([F(line=i) for i in (1, 2, 3)])
    after = R([F(line=i) for i in (1, 2, 3, 4, 5)])
    d = diff_reports(before, after)
    assert len(d.new) == 2
    assert d.unchanged == 3
    assert d.regressed


def test_shrinkage_within_one_key_counts_as_fixed():
    before = R([F(line=i) for i in (1, 2, 3, 4, 5)])
    after = R([F(line=i) for i in (1, 2)])
    d = diff_reports(before, after)
    assert len(d.fixed) == 3
    assert d.unchanged == 2
    assert not d.regressed


def test_simultaneous_fix_and_regression_reports_both():
    before = R([F(file_path="old.py")])
    after = R([F(file_path="new.py")])
    d = diff_reports(before, after)
    assert len(d.new) == 1 and len(d.fixed) == 1
    assert d.regressed, "a regression is a regression even alongside a fix"
    assert not d.improved


def test_empty_before_means_everything_is_new():
    d = diff_reports(R([]), R([F(), F(file_path="b.py")]))
    assert len(d.new) == 2 and d.fixed == []


def test_empty_after_means_everything_is_fixed():
    d = diff_reports(R([F(), F(file_path="b.py")]), R([]))
    assert len(d.fixed) == 2 and d.new == []
    assert d.improved


def test_two_empty_reports_are_unchanged():
    d = diff_reports(R([]), R([]))
    assert not d.regressed and not d.improved
    assert d.unchanged == 0


def test_reports_missing_findings_key_are_tolerated():
    d = diff_reports({}, {})
    assert d.unchanged == 0 and d.new == [] and d.fixed == []


# --------------------------------------------------------------------------- #
# Regression is not score-driven
# --------------------------------------------------------------------------- #
def test_new_findings_at_a_capped_score_still_regress():
    """The reason `regressed` ignores the score.

    examples/ already scores 100, so adding a DSA file moves the score not at
    all. A score-driven gate would wave that through.
    """
    before = R([F(line=i) for i in range(10)], score=100)
    after = R([F(line=i) for i in range(10)] + [F(file_path="new.py",
                                                  family="dsa",
                                                  algorithm="DSA")], score=100)
    d = diff_reports(before, after)
    assert d.score_delta == 0
    assert d.regressed, "a new HIGH finding must regress even at a capped score"


def test_score_delta_is_reported_even_when_it_does_not_drive_the_verdict():
    d = diff_reports(R([F()], score=40), R([F()], score=75))
    assert d.score_before == 40 and d.score_after == 75
    assert d.score_delta == 35
    assert not d.regressed, "no new findings, so no regression"


def test_a_falling_score_with_new_findings_still_regresses():
    before = R([F(line=i) for i in range(5)], score=90)
    after = R([F(file_path="x.py", family="md5", algorithm="MD5", risk="LOW")],
              score=5)
    d = diff_reports(before, after)
    assert d.score_delta < 0
    assert d.regressed


# --------------------------------------------------------------------------- #
# Severity deltas and targets
# --------------------------------------------------------------------------- #
def test_severity_delta_is_per_level():
    before = R([], score=0, high=1, medium=2, low=3)
    after = R([], score=0, high=4, medium=0, low=3)
    d = diff_reports(before, after)
    assert d.severity_delta == {"high": 3, "medium": -2, "low": 0}


def test_mismatched_targets_are_flagged():
    d = diff_reports(R([F()], target="repo-a"), R([F()], target="repo-b"))
    assert d.target_mismatch
    assert d.to_dict()["target"] == {"before": "repo-a", "after": "repo-b",
                                     "mismatch": True}


def test_matching_targets_are_not_flagged():
    assert not diff_reports(R([F()], target="x"), R([F()], target="x")).target_mismatch


def test_absent_target_is_not_a_mismatch():
    """A report without a target should not raise a false warning."""
    assert not diff_reports({"findings": []}, {"findings": []}).target_mismatch


# --------------------------------------------------------------------------- #
# Serialisation
# --------------------------------------------------------------------------- #
def test_to_dict_shape():
    d = diff_reports(R([F()]), R([F(), F(file_path="n.py")])).to_dict()
    assert set(d) == {"new", "fixed", "counts", "risk_score", "severity_delta",
                      "regressed", "improved", "target", "summary", "caveat"}
    assert d["counts"] == {"new": 1, "fixed": 0, "unchanged": 1}
    assert d["risk_score"]["delta"] == 0


def test_to_dict_states_what_a_diff_cannot_prove():
    """A disappeared finding is not evidence of a fix."""
    caveat = diff_reports(R([F()]), R([])).to_dict()["caveat"]
    assert "not necessarily fixed" in caveat
    assert "renamed" in caveat


def test_summary_line_is_human_readable():
    s = diff_reports(R([F()], score=40), R([F(file_path="n.py")], score=50)).summary_line()
    assert "1 fixed" in s and "1 new" in s and "40 -> 50" in s and "+10" in s


def test_empty_diff_is_falsy_in_both_directions():
    d = Diff()
    assert not d.regressed and not d.improved
    assert d.score_delta == 0


# --------------------------------------------------------------------------- #
# The HTTP endpoint
#
# The security property here is tenancy: one account must not be able to diff
# against another's scan history, and a scan it does not own must look absent
# rather than forbidden -- a 403 would confirm the id exists.
# --------------------------------------------------------------------------- #
def _persist(app, user_email_token, findings, score):
    """Insert a Scan with findings for the authenticated user."""
    from extensions import db
    from models import Finding as FindingRow, Scan, User
    with app.app_context():
        user = User.query.filter_by(email=user_email_token).first()
        scan = Scan(user_id=user.id, repo_url="repo", risk_score=score,
                    risk_band="Medium",
                    high_count=sum(1 for f in findings if f["risk_level"] == "HIGH"),
                    medium_count=0, low_count=0, findings_json="[]")
        db.session.add(scan)
        db.session.flush()
        for f in findings:
            db.session.add(FindingRow(
                scan_id=scan.id, file_path=f["file_path"],
                line_number=f["line_number"], algorithm=f["algorithm"],
                risk_level=f["risk_level"], recommendation="x",
                nist_reference="x", complexity="High", family=f["family"],
                why="x"))
        db.session.commit()
        return scan.id


def _register(client, email):
    r = client.post("/api/v1/auth/register",
                    json={"email": email, "password": "password123",
                          "accept_terms": True})
    return {"Authorization": f"Bearer {r.get_json()['token']}"}


def test_endpoint_diffs_two_of_my_scans(app, client):
    headers = _register(client, "diffuser@test.com")
    first = _persist(app, "diffuser@test.com", [F()], 40)
    second = _persist(app, "diffuser@test.com", [F(), F(file_path="new.py")], 55)

    res = client.get(f"/api/v1/scans/{second}/diff?against={first}", headers=headers)
    assert res.status_code == 200
    body = res.get_json()
    assert body["baseline_scan_id"] == first and body["scan_id"] == second
    assert body["diff"]["counts"]["new"] == 1
    assert body["diff"]["regressed"] is True


def test_endpoint_defaults_to_the_previous_scan(app, client):
    headers = _register(client, "defaultdiff@test.com")
    _persist(app, "defaultdiff@test.com", [F()], 40)
    second = _persist(app, "defaultdiff@test.com", [F(), F(file_path="n.py")], 55)

    res = client.get(f"/api/v1/scans/{second}/diff", headers=headers)
    assert res.status_code == 200
    assert res.get_json()["diff"]["counts"]["new"] == 1


def test_endpoint_refuses_to_diff_against_another_users_scan(app, client):
    """Tenancy: the baseline is looked up scoped to the caller."""
    mine_headers = _register(client, "owner@test.com")
    _register(client, "stranger@test.com")
    theirs = _persist(app, "stranger@test.com", [F()], 10)
    mine = _persist(app, "owner@test.com", [F(), F(file_path="x.py")], 60)

    res = client.get(f"/api/v1/scans/{mine}/diff?against={theirs}",
                     headers=mine_headers)
    assert res.status_code == 404, "another user's scan must look absent"
    assert "not found" in res.get_json()["error"].lower()


def test_endpoint_refuses_someone_elses_scan_as_the_subject(app, client):
    mine_headers = _register(client, "owner2@test.com")
    _register(client, "stranger2@test.com")
    theirs = _persist(app, "stranger2@test.com", [F()], 10)

    res = client.get(f"/api/v1/scans/{theirs}/diff", headers=mine_headers)
    assert res.status_code == 404


def test_endpoint_404s_when_there_is_nothing_earlier(app, client):
    headers = _register(client, "lonely@test.com")
    only = _persist(app, "lonely@test.com", [F()], 40)
    res = client.get(f"/api/v1/scans/{only}/diff", headers=headers)
    assert res.status_code == 404
    assert "earlier" in res.get_json()["error"].lower()


def test_endpoint_refuses_diffing_a_scan_against_itself(app, client):
    headers = _register(client, "selfdiff@test.com")
    _persist(app, "selfdiff@test.com", [F()], 40)
    second = _persist(app, "selfdiff@test.com", [F()], 40)
    res = client.get(f"/api/v1/scans/{second}/diff?against={second}", headers=headers)
    assert res.status_code == 400
    assert "itself" in res.get_json()["error"].lower()


def test_endpoint_requires_authentication(client):
    assert client.get("/api/v1/scans/1/diff").status_code in (401, 422)
