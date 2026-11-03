"""The cross-run harness (CROSSRUN.md): case file, fixtures, the reference run
and the result-file check."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import httpx
import pytest

from aae_a2a import crossrun
from aae_a2a.digest import request_digest

from .conftest import BASE_URL, run

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "vectors" / "crossrun"
SHA = "0" * 40


@pytest.fixture
def env(deferred_env):
    """The cross-run supplier declares deferred_decisions (CROSSRUN.md 1)."""
    return deferred_env


def _cases():
    return crossrun.load_cases()


def test_every_expected_digest_is_that_of_the_request_part():
    spec, _ = _cases()
    for case in spec["cases"]:
        if case["expect"]["kind"] == "task":
            assert case["expect"]["request_digest"] == request_digest(case["request_part"]), case["id"]


def test_case_digests_include_the_appendix_b_vectors():
    spec, _ = _cases()
    vectors = json.loads((ROOT / "tests" / "vectors" / "request-digest.json").read_text())
    used = {c["expect"].get("request_digest") for c in spec["cases"]}
    assert {v["request_digest"] for v in vectors["vectors"]} - used == {
        "sha256:fd2490962a20b0d8223d69248ffa5f073180e791864295247ed1eed8661f48f9"}


def test_case_ids_unique_and_paired_case_present():
    spec, _ = _cases()
    ids = [c["id"] for c in spec["cases"]]
    assert len(ids) == len(set(ids))
    states = {c["expect"].get("task_state") for c in spec["cases"]}
    assert {"TASK_STATE_COMPLETED", "TASK_STATE_FAILED", "TASK_STATE_REJECTED"} <= states


def test_published_fixtures_match_the_test_keys():
    for name, doc in crossrun.fixture_documents().items():
        assert json.loads((FIXTURES / "did" / f"{name}.json").read_text()) == doc
    assert json.loads((FIXTURES / "test-keys.json").read_text()) == crossrun.fixture_keys()


def _reference_results(env):
    spec, _ = _cases()
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=env.app), base_url=BASE_URL)
    return run(crossrun.run_cases(BASE_URL, spec["cases"], httpx_client=client))


def _doc(results):
    _, digest = _cases()
    return {"format": crossrun.RESULT_FORMAT, "profile": crossrun.EXTENSION_URI,
            "draft": crossrun.AAE_DRAFT, "cases_commit": SHA, "cases_sha256": digest,
            "run_at": "2026-10-28T00:00:00Z",
            "participant": {"name": "test", "url": None},
            "client": {"implementation": "ref", "repository": crossrun.REFERENCE_REPO, "commit": SHA},
            "server": {"implementation": "ref", "repository": crossrun.REFERENCE_REPO, "commit": SHA},
            "cases": results, "summary": crossrun.summarize(results)}


def test_reference_supplier_passes_every_case(env):
    results = _reference_results(env)
    assert [r["result"] for r in results] == ["pass"] * len(results)
    spec, digest = _cases()
    assert crossrun.check_result(_doc(results), spec, digest) == []


def test_reference_supplier_records_each_decision(env):
    rows = []
    env.executor.observer = lambda task_id, result, state: rows.append((task_id, state, result))
    results = _reference_results(env)
    flat = [o for r in results for o in (r["attempts"] if "attempts" in r else [r])]
    tasks = [r for r in flat if r.get("task_id")]
    # A held task is decided twice, held and then closed (spec 7.6); the last
    # decision per task is the one its result reports.
    last = {}
    for t, s, res in rows:
        last[t] = (s, res)
    assert [r["task_id"] for r in tasks] == list(last)
    assert [(r["task_state"], r["request_digest"]) for r in tasks] == \
        [(s, res["request_digest"]) for s, res in last.values()]


def test_check_rejects_a_claim_its_observation_does_not_support(env):
    spec, digest = _cases()
    doc = _doc(_reference_results(env))
    bad = copy.deepcopy(doc)
    bad["cases"][2]["step"] = 6
    assert any("XR-03 claims pass" in e for e in crossrun.check_result(bad, spec, digest))
    bad = copy.deepcopy(doc)
    bad["cases"][5]["task_id"] = bad["cases"][0]["task_id"]
    assert any("XR-06 claims pass" in e for e in crossrun.check_result(bad, spec, digest))


def test_check_requires_commits_required_cases_and_the_case_file():
    spec, digest = _cases()
    skipped = [{"id": c["id"], "result": "skipped"} for c in spec["cases"]]
    doc = _doc(skipped)
    doc["server"]["commit"] = "main"
    errs = crossrun.check_result(doc, spec, digest)
    assert "server.commit is not a 40-character commit SHA" in errs
    assert "XR-01 is required and was skipped" in errs
    assert "XR-07 is required and was skipped" not in errs
    assert crossrun.check_result(doc, spec, "sha256:" + "1" * 64)[0].startswith("cases_sha256")


def test_reason_code_difference_is_a_note_not_a_failure():
    spec, _ = _cases()
    case = next(c for c in spec["cases"] if c["id"] == "XR-03")
    obs = {"task_state": "TASK_STATE_REJECTED", "verdict": "REJECT", "step": 7,
           "reason_code": "over_limit", "request_digest": case["expect"]["request_digest"]}
    result, notes = crossrun.evaluate(case, obs, {})
    assert result == "pass" and notes == ["reason_code over_limit != max_transaction_value_exceeded"]


def test_reported_runs_validate():
    files = sorted(p for p in (ROOT / "crossruns").glob("*.json") if not p.name.startswith("TEMPLATE"))
    for p in files:
        assert crossrun.check_reported(json.loads(p.read_text())) == [], p.name


def test_template_has_the_members_of_a_result_file(env):
    template = json.loads((ROOT / "crossruns" / "TEMPLATE.json").read_text())
    doc = _doc(_reference_results(env))
    assert set(template) == set(doc)
    for side in ("participant", "client", "server"):
        assert set(doc[side]) <= set(template[side])


def test_crossrun_md_lists_every_case_with_its_expected_result():
    spec, _ = _cases()
    rows = {line.split("|")[1].strip(): line for line in (ROOT / "CROSSRUN.md").read_text().splitlines()
            if line.startswith("| XR-")}
    assert list(rows) == [c["id"] for c in spec["cases"]]
    for c in spec["cases"]:
        e, row = c["expect"], rows[c["id"]]
        assert f"| {c['client_side']} |" in row
        for value in (e.get("task_state"), e.get("request_digest"), e.get("reason_code")):
            if value is not None:
                assert value in row, (c["id"], value)


# --- offline receiver runs (CROSSRUN.md 6.1) ----------------------------------------

def _offline(results):
    doc = _doc(results)
    del doc["client"], doc["server"]
    doc.update({"form": "offline",
                "receiver": {"implementation": "receiver", "version": "1.0",
                             "content_sha256": "sha256:" + "a" * 64},
                "audience": crossrun.OFFLINE_AUDIENCE,
                "evaluation_instant": "2026-10-30T20:15:00Z",
                "inventions": [{"what": "task ids", "choice": "uuid5 of the case id"}]})
    return doc


def test_offline_run_validates(env):
    spec, digest = _cases()
    assert crossrun.check_result(_offline(_reference_results(env)), spec, digest) == []


def test_offline_run_needs_its_members_and_every_case(env):
    spec, digest = _cases()
    doc = _offline(_reference_results(env))
    doc["cases"][6] = {"id": doc["cases"][6]["id"], "result": "skipped"}
    doc["summary"] = crossrun.summarize(doc["cases"])
    doc["receiver"] = {"implementation": "receiver", "version": "1.0"}
    doc["audience"] = "https://elsewhere.example/a2a"
    doc["inventions"] = None
    errs = crossrun.check_result(doc, spec, digest)
    assert "XR-07 is required and was skipped" in errs
    assert "receiver needs a commit or a content_sha256" in errs
    assert f"audience is not {crossrun.OFFLINE_AUDIENCE}" in errs
    assert any(e.startswith("inventions") for e in errs)


def test_offline_template_has_the_members_of_an_offline_file(env):
    template = json.loads((ROOT / "crossruns" / "TEMPLATE-offline.json").read_text())
    doc = _offline(_reference_results(env))
    assert set(template) == set(doc)
    assert set(doc["receiver"]) <= set(template["receiver"])


# --- pinned bundle, the retry pair and the reuse pair (CROSSRUN.md 4, 5) -----------

PINNED = FIXTURES / "pinned"


def test_pinned_bundle_rebuilds_byte_for_byte(tmp_path):
    from aae_a2a import pinned
    pinned.build(tmp_path)
    for p in sorted(PINNED.rglob("*")):
        if p.is_file():
            assert (tmp_path / p.relative_to(PINNED)).read_bytes() == p.read_bytes(), p.name
    assert sorted(q.relative_to(tmp_path) for q in tmp_path.rglob("*") if q.is_file()) == \
        sorted(q.relative_to(PINNED) for q in PINNED.rglob("*") if q.is_file())


def test_pinned_manifest_covers_every_file():
    from aae_a2a import pinned
    assert pinned.verify_manifest(PINNED) == []


def test_pinned_nonces_follow_from_bundle_json_alone():
    """A third party recomputes every pinned nonce from bundle.json, with no
    aae_a2a code: hashlib, hmac and base64 only."""
    import base64
    import hashlib
    import hmac
    from datetime import datetime
    b = json.loads((PINNED / "bundle.json").read_text(encoding="utf-8"))
    d = b["nonce"]
    master = hashlib.sha256(d["master_key_input"].encode("ascii")).digest()
    key = hmac.new(master, d["key_label"].encode("ascii"), hashlib.sha256).digest()
    verify_at = datetime.fromisoformat(b["verify_at"].replace("Z", "+00:00"))
    expiry = str(int(verify_at.timestamp()) + d["lifetime_s"])
    count: dict[str, int] = {}
    for case in b["cases"]:
        for att in case["attempts"]:
            ch = att["challenge"]
            count[ch["aae_id"]] = count.get(ch["aae_id"], 0) + 1
            rnd = hashlib.sha256(f"{d['random_prefix']}{ch['aae_id']}/{count[ch['aae_id']]}"
                                 .encode("utf-8")).hexdigest()[:32]
            mac = hmac.new(key, f"{rnd}.{expiry}.{ch['aud']}.{ch['aae_id']}".encode("utf-8"),
                           hashlib.sha256).digest()
            tag = base64.urlsafe_b64encode(mac).rstrip(b"=").decode("ascii")
            assert ch["nonce"] == f"{rnd}.{expiry}.{tag}", (case["id"], att["attempt"])


def test_pinned_key_label_is_the_one_challenge_uses():
    from aae_a2a import challenge, pinned
    assert pinned.load(PINNED)["nonce"]["key_label"].encode("ascii") == challenge._KEY_LABEL


def test_pinned_authorization_is_separate_from_admission():
    """Every attempt is a valid authorization, the second of XR-20 included."""
    from aae_a2a import pinned
    bundle = pinned.load(PINNED)
    for case in bundle["cases"]:
        for att in case["attempts"]:
            if "authorization" in att["expect"]:
                assert pinned.authorization(PINNED, case, att) == att["expect"]["authorization"], \
                    (case["id"], att["attempt"])
    xr20 = next(c for c in bundle["cases"] if c["id"] == "XR-20")
    assert [a["expect"]["admission"]["admitted"] for a in xr20["attempts"]] == [True, False]
    xr24 = next(c for c in bundle["cases"] if c["id"] == "XR-24")
    assert [a["expect"]["admission"]["admitted"] for a in xr24["attempts"]] == [True, True]


def test_pinned_reuse_presents_the_same_reusable_aae_with_a_new_nonce():
    """XR-24: one AAE, single_use false, two attempts with distinct nonces.
    XR-06 is a new request with its own AAE."""
    from aae_a2a import pinned
    from aae_a2a.jose import b64url_decode
    bundle = pinned.load(PINNED)
    by_id = {c["id"]: c for c in bundle["cases"]}
    xr24 = by_id["XR-24"]
    vc = json.loads(b64url_decode(pinned.read_jws(PINNED, xr24["aae"]).split(".")[1]))
    assert vc["credentialSubject"]["aae"]["validity"]["single_use"] is False
    nonces = [a["challenge"]["nonce"] for a in xr24["attempts"]]
    assert len(nonces) == 2 and len(set(nonces)) == 2
    assert {a["challenge"]["aae_id"] for a in xr24["attempts"]} == {vc["id"]}
    assert by_id["XR-06"]["aae"] != by_id["XR-01"]["aae"]
    assert (pinned.read_jws(PINNED, by_id["XR-06"]["aae"])
            != pinned.read_jws(PINNED, by_id["XR-01"]["aae"]))


def test_pinned_bytes_give_the_expected_results_with_a_fixed_clock():
    from aae_a2a import pinned
    from aae_a2a.server import create_supplier_app
    bundle = pinned.load(PINNED)
    res = pinned.resolver(PINNED)
    at = pinned.VERIFY_AT
    app, _card, _ex = create_supplier_app(BASE_URL, resolver=res,
                                          accepted_issuers=bundle["params"]["accepted_issuers"],
                                          clock=lambda: at, binding=pinned.pinned_binding(res),
                                          audience=bundle["params"]["audience"])
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE_URL)
    results = run(crossrun.run_pinned(BASE_URL, PINNED, httpx_client=client))
    assert [(r["id"], r["result"]) for r in results] == [("XR-01", "pass"), ("XR-06", "pass"),
                                                         ("XR-20", "pass"), ("XR-24", "pass")], \
        results


def test_pinned_cases_agree_with_cases_json():
    from aae_a2a import pinned
    spec, _ = _cases()
    by_id = {c["id"]: c for c in spec["cases"]}
    for case in pinned.load(PINNED)["cases"]:
        live = by_id[case["id"]]
        assert case["request_part"] == live["request_part"]
        exp = live["expect"]["attempts"] if live["expect"]["kind"] == "retry" else [live["expect"]]
        assert [a["expect"] for a in case["attempts"]] == exp, case["id"]


def test_crossrun_md_links_resolve_in_this_commit():
    import re
    text = (ROOT / "CROSSRUN.md").read_text()
    for target in re.findall(r"\]\(([^)#]+)(?:#[^)]*)?\)", text):
        if not target.startswith("http"):
            assert (ROOT / target).exists(), target


# --- a reported run is checked against the cases it ran (CROSSRUN.md 6) -------------

BASE_6C857EE = "6c857eeb60a9dac379954f5be5900a10616dfc7b"


def _run_from_expectations(spec):
    """A result file whose observations are the expectations of `spec`."""
    out = []
    for n, c in enumerate(spec["cases"]):
        e = c["expect"]
        if e["kind"] == "error":
            obs = {"jsonrpc_code": e["jsonrpc_code"], **({"reason_code": e["reason_code"]}
                                                         if "reason_code" in e else {})}
        else:
            obs = {"task_id": f"t-{n}", "task_state": e["task_state"], "verdict": e["verdict"],
                   "request_digest": e["request_digest"]}
            if e["verdict"] == "REJECT":
                obs.update(step=e["step"], reason_code=e["reason_code"])
            else:
                obs["steps_passed"] = [1, 2, 3, 4, 5, 6, 7]
        out.append({"id": c["id"], "result": "pass", **obs})
    return out


def test_a_run_against_6c857ee_is_checked_with_the_cases_of_that_commit():
    old, digest = crossrun.load_cases_at(BASE_6C857EE)
    assert digest == "sha256:9c25d66899fa2b790e3fc51ac83cb9f2fa06f07f896f08b0a2d77c462e4eb99b"
    assert len(old["cases"]) == 13
    doc = {**_doc(_run_from_expectations(old)), "cases_commit": BASE_6C857EE,
           "cases_sha256": digest}
    assert crossrun.check_reported(doc) == []
    # The same file is not valid against today's cases, which is why it is
    # checked against its own.
    spec, today = _cases()
    assert crossrun.check_result(doc, spec, today) != []


def test_a_run_with_a_wrong_cases_hash_is_rejected():
    old, _ = crossrun.load_cases_at(BASE_6C857EE)
    doc = {**_doc(_run_from_expectations(old)), "cases_commit": BASE_6C857EE,
           "cases_sha256": "sha256:" + "1" * 64}
    errs = crossrun.check_reported(doc)
    assert any(e.startswith("cases_sha256 is not that of") for e in errs)


def test_a_run_naming_no_readable_commit_is_rejected():
    doc = {**_doc([]), "cases_commit": "f" * 40}
    assert crossrun.check_reported(doc)[0].startswith("cases_commit:")
    doc["cases_commit"] = "main"
    assert crossrun.check_reported(doc)[0].startswith("cases_commit:")


def test_credit_table_names_the_state_of_the_cases():
    header = next(line for line in (ROOT / "crossruns" / "README.md").read_text().splitlines()
                  if line.startswith("| Date |"))
    assert "| Cases (commit) |" in header


# --- XR-04 is an exception to the client rule of spec 6.4 (CROSSRUN.md 4) -----------

BASE_08F41146 = "08f41146ac0d24d0d3e6212256fd9f3f58079adb"


def test_xr04_is_marked_as_the_exception_to_the_client_rule():
    spec, _ = _cases()
    case = next(c for c in spec["cases"] if c["id"] == "XR-04")
    amount = case["request_part"]["transaction"]["amount"]
    assert isinstance(amount, float) and amount == 120
    assert case["client_side"] == "optional"
    assert "spec 6.4" in case["client_rule_exception"]
    assert "XR-04 is an exception to the client rule of spec Section 6.4" in \
        (ROOT / "CROSSRUN.md").read_text()


def _without_xr04(results):
    return [{"id": r["id"], "result": "skipped"} if r["id"] == "XR-04" else r for r in results]


def test_a_client_run_may_skip_xr04(env):
    spec, digest = _cases()
    doc = _doc(_without_xr04(_reference_results(env)))
    assert crossrun.check_result(doc, spec, digest) == []


def test_xr04_stays_required_for_a_run_against_08f41146(env):
    old, digest = crossrun.load_cases_at(BASE_08F41146)
    full = {**_doc(_reference_results(env)), "cases_commit": BASE_08F41146, "cases_sha256": digest}
    assert crossrun.check_reported(full) == []
    skipped = _without_xr04(full["cases"])
    doc = {**full, "cases": skipped, "summary": crossrun.summarize(skipped)}
    assert "XR-04 is required and was skipped" in crossrun.check_reported(doc)
