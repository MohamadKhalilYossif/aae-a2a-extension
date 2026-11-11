"""Cross-run harness: the reference supplier and buyer as separate processes,
the cases of tests/vectors/crossrun/cases.json, and the result file format of
CROSSRUN.md.

  python -m aae_a2a.crossrun serve  [--port N] [--public-url URL] [--did-dir DIR]
                                    [--accept-issuer DID ...] [--record FILE]
  python -m aae_a2a.crossrun client --url URL --out FILE [--server-* ...] [--participant ...]
  python -m aae_a2a.crossrun check  FILE ...
  python -m aae_a2a.crossrun fixtures [--out DIR]

`client` runs every case against the supplier at URL with the reference buyer
and writes a result file. `check` recomputes pass or fail of every case in a
result file from what it records, so a submitted file cannot claim more than it
shows.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlsplit

from a2a.types import TaskState
from a2a.utils.errors import A2AError, JSON_RPC_ERROR_CODE_MAP

from .buyer import BuyerAgent, task_result
from .challenge import utc_now
from .constants import AAE_DRAFT, EXTENSION_URI
from .digest import request_digest
from .jose import b64url_decode, b64url_encode, sign_compact
from .psea import PseaHashError, covers_same_request
from .testkeys import (PARTIES, buyer_constraints, buyer_mandate, demo_key, did_document,
                       did_of, held_mandate, issue_buyer_aae, issue_supplier_aae, kid_of,
                       make_vc, ratification_proof, PRINCIPAL_DID)

ROOT = Path(__file__).resolve().parent.parent
CASES_FILE = ROOT / "tests" / "vectors" / "crossrun" / "cases.json"
RESULT_FORMAT = "aae-a2a-crossrun/1"
REFERENCE_REPO = "https://github.com/MoltyCel/aae-a2a-extension"
_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
# The audience of an offline receiver run, which has no endpoint to name: the
# value of the spec's Section 4 example (CROSSRUN.md, "Audience").
OFFLINE_AUDIENCE = "https://supplier.example/a2a/jsonrpc"
# How the implementation the participant built was written, as the participant
# states it (CROSSRUN.md Section 6). Absent or unstated is "unknown"; the case
# counts never stand in for it.
RECEIVER_PROVENANCE = ("clean_room", "reference_informed", "unknown")
# XR-25 and XR-26 carry a PSEA proof (draft-yossif-psea-03) over a request part;
# its file is named relative to the directory of cases.json.
PSEA_BINDINGS = ("ACCEPT", "REFUSE")


def load_cases(path: Path = CASES_FILE) -> tuple[dict, str]:
    raw = path.read_bytes()
    return json.loads(raw), "sha256:" + hashlib.sha256(raw).hexdigest()


class CasesUnavailable(Exception):
    """The cases a reported run names cannot be read from this repository."""


def load_cases_at(commit: str) -> tuple[dict, str]:
    """cases.json as it stood at `commit` of this repository, and its hash. A
    reported run is checked against the cases it ran (CROSSRUN.md 6), not the
    current ones. A shallow checkout fetches the commit first."""
    if not _SHA1.match(str(commit)):
        raise CasesUnavailable(f"{commit!r} is not a 40-character commit SHA")
    rel = CASES_FILE.relative_to(ROOT).as_posix()

    def show():
        return subprocess.run(["git", "-C", str(ROOT), "show", f"{commit}:{rel}"],
                              capture_output=True)
    got = show()
    if got.returncode != 0:
        subprocess.run(["git", "-C", str(ROOT), "fetch", "-q", "--depth", "1", "origin", commit],
                       capture_output=True)
        got = show()
    if got.returncode != 0:
        raise CasesUnavailable(f"cases.json is not readable at {commit}")
    return json.loads(got.stdout), "sha256:" + hashlib.sha256(got.stdout).hexdigest()


def repo_commit() -> tuple[str | None, bool]:
    """HEAD of this checkout and whether the working tree differs from it."""
    try:
        sha = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], check=True,
                             capture_output=True, text=True).stdout.strip()
        dirty = bool(subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain",
                                     "--untracked-files=no"], check=True,
                                    capture_output=True, text=True).stdout.strip())
        return sha, dirty
    except (OSError, subprocess.CalledProcessError):
        return os.environ.get("AAE_A2A_COMMIT"), False


# --- AAE and challenge-response variants (CROSSRUN.md, "Variants") ---------------------

def build_aae(variant: str, audience: str) -> str | None:
    now = utc_now()
    domains = [urlsplit(audience).hostname or ""]
    if variant == "none":
        return None
    if variant == "valid":
        return issue_buyer_aae(now, domains)
    if variant == "single_use":
        return issue_buyer_aae(now, domains, single_use=True)
    if variant == "hold":
        return issue_buyer_aae(now, domains, mandate=held_mandate(HOLD_ACTION))
    if variant == "expired":
        return issue_buyer_aae(now, domains, not_before=now - timedelta(hours=2),
                               not_after=now - timedelta(hours=1))
    if variant == "read_only":
        return issue_buyer_aae(now, domains, mandate={**buyer_mandate(), "actions": ["read"]})
    if variant == "other_domain":
        return issue_buyer_aae(now, ["other-supplier.example"])
    header = {"alg": "EdDSA", "cty": "aae+json", "kid": kid_of("issuer")}
    vc = make_vc(subject=did_of("buyer"), issuer=did_of("issuer"), mandate=buyer_mandate(),
                 constraints=buyer_constraints(domains), not_before=now - timedelta(minutes=5),
                 not_after=now + timedelta(hours=1))
    if variant == "forged":
        return sign_compact(header, vc, demo_key("mallory"))
    if variant == "payload_not_json":
        # A correct signature over bytes that are not JSON: the signature passes
        # step 1 (a)-(d), the payload fails at step 2 (spec 7.2, reading order).
        return sign_raw(header, b'{"issuer": "did:example:issuer", ', demo_key("issuer"))
    if variant == "duplicate_issuer":
        # issuer twice, a foreign DID first. A first-wins parser run for step 1
        # would fail signing authority there; the profile parses once, strictly,
        # and fails at step 2.
        body = json.dumps(vc, separators=(",", ":"), ensure_ascii=False)
        body = '{"issuer":"' + did_of("other-agent") + '",' + body[1:]
        return sign_raw(header, body.encode("utf-8"), demo_key("issuer"))
    raise ValueError(f"unknown AAE variant {variant!r}")


# The action of the hold cases XR-21 to XR-23 (CROSSRUN.md, "Variants").
HOLD_ACTION = {"verb": "pay", "category": "office-supplies"}


def ratification_for(variant: str, prior_core_digest: str):
    """(decision, authority proof) of a ratification variant, or None."""
    from .enforce import APPROVED
    mandate = held_mandate(HOLD_ACTION)
    if variant == "principal":
        return APPROVED, ratification_proof(prior_core_digest, APPROVED, mandate)
    if variant == "stranger":
        return APPROVED, ratification_proof(prior_core_digest, APPROVED, mandate,
                                            signer="mallory", authority="did:example:mallory")
    if variant == "none":
        return None
    raise ValueError(f"unknown ratification variant {variant!r}")


def sign_raw(header: dict, payload: bytes, key) -> str:
    """An EdDSA compact JWS over payload bytes as given, for payloads sign_compact
    cannot produce (not JSON, duplicate member names)."""
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p = b64url_encode(payload)
    return f"{h}.{p}.{b64url_encode(key.sign(f'{h}.{p}'.encode('ascii')))}"


def wrong_key_response(challenge: dict, _aae_id: str) -> str:
    payload = {**challenge, "iat": utc_now().strftime("%Y-%m-%dT%H:%M:%SZ")}
    return sign_compact({"alg": "EdDSA", "kid": kid_of("buyer")}, payload, demo_key("mallory"))


def iat_response(offset_s: int):
    """A correct challenge response whose iat is offset_s seconds from now: the
    iat window of spec 7.4 step 4 is now - 360 s to now + 60 s. The cases sit
    30 seconds inside or outside a bound, so a clock difference between the two
    sides below 30 seconds does not change the outcome."""
    def respond(challenge: dict, _aae_id: str) -> str:
        iat = (utc_now() + timedelta(seconds=offset_s)).strftime("%Y-%m-%dT%H:%M:%SZ")
        return sign_compact({"alg": "EdDSA", "kid": kid_of("buyer")},
                            {**challenge, "iat": iat}, demo_key("buyer"))
    return respond


RESPONSES = {
    "valid": None,
    "wrong_key": wrong_key_response,
    "iat_past_inside": iat_response(-330),
    "iat_past_outside": iat_response(-390),
    "iat_future_inside": iat_response(30),
    "iat_future_outside": iat_response(90),
}


# --- evaluation: shared by `client` and `check` ----------------------------------------

def evaluate(case: dict, obs: dict, task_ids: dict[str, str]) -> tuple[str, list[str]]:
    """pass or fail for one observation, with the reasons. reason_code is
    compared too, but a different code is a note, not a failure: a server MAY
    use codes not listed in spec 8.4, and a client treats them as a rejection
    at the stated step."""
    exp, fails, notes = case["expect"], [], []
    if exp["kind"] == "retry":
        # One envelope, several presentations, each a task of its own.
        got = obs.get("attempts") or []
        if len(got) != len(exp["attempts"]):
            return "fail", [f"{len(got)} attempts reported, {len(exp['attempts'])} expected"]
        ids = [o.get("task_id") for o in got]
        if len(set(ids)) != len(ids) or None in ids:
            fails.append("the attempts are not distinct tasks")
        for n, (e, o) in enumerate(zip(exp["attempts"], got), start=1):
            _, msgs = evaluate({**case, "expect": e}, o, task_ids)
            sub_fails = [m for m in msgs if not m.startswith("reason_code")]
            fails += [f"attempt {n}: {m}" for m in sub_fails]
            notes += [f"attempt {n}: {m}" for m in msgs if m.startswith("reason_code")]
        return ("fail" if fails else "pass"), fails + notes
    if exp["kind"] == "error":
        if obs.get("jsonrpc_code") != exp["jsonrpc_code"]:
            fails.append(f"jsonrpc_code {obs.get('jsonrpc_code')} != {exp['jsonrpc_code']}")
        if "reason_code" in exp and obs.get("reason_code") != exp["reason_code"]:
            notes.append(f"reason_code {obs.get('reason_code')} != {exp['reason_code']}")
        return ("fail" if fails else "pass"), fails + notes
    for key in ("task_state", "verdict", "request_digest"):
        if obs.get(key) != exp[key]:
            fails.append(f"{key} {obs.get(key)} != {exp[key]}")
    if "step" in exp and obs.get("step") != exp["step"]:
        fails.append(f"step {obs.get('step')} != {exp['step']}")
    if exp["verdict"] == "ACCEPT":
        steps = obs.get("steps_passed") or []
        if not set(range(1, 8)) <= set(steps):
            fails.append(f"steps_passed {steps} lacks one of 1-7")
    if "reason_code" in exp and obs.get("reason_code") != exp["reason_code"]:
        notes.append(f"reason_code {obs.get('reason_code')} != {exp['reason_code']}")
    if "ratification_status" in exp and obs.get("ratification_status") != exp["ratification_status"]:
        fails.append(f"ratification_status {obs.get('ratification_status')} != "
                     f"{exp['ratification_status']}")
    psea = exp.get("psea")
    if psea is not None:
        # Recomputed from what the entry records, so a file cannot claim a
        # binding its own request_digest does not give.
        if obs.get("psea_payload_hash") != psea["psea_payload_hash"]:
            fails.append(f"psea_payload_hash {obs.get('psea_payload_hash')} != "
                         f"{psea['psea_payload_hash']}")
        try:
            same = covers_same_request(str(obs.get("psea_payload_hash")),
                                       str(obs.get("request_digest")))
        except PseaHashError:
            same = False
        if same != psea["same_octets"]:
            fails.append(f"same_octets {same} != {psea['same_octets']}")
        if obs.get("psea_binding") != psea["binding"]:
            fails.append(f"psea_binding {obs.get('psea_binding')} != {psea['binding']}")
        elif obs.get("psea_binding") != ("ACCEPT" if same else "REFUSE"):
            fails.append(f"psea_binding {obs.get('psea_binding')} does not follow from "
                         f"psea_payload_hash and request_digest")
    # Admission is step 5 against what the server has already accepted. A server
    # reports it through the verdict; authorization (every step but 5) is not
    # observable from a rejection at step 5 and is checked on the pinned bundle.
    adm = exp.get("admission")
    if adm is not None and (obs.get("verdict") == "ACCEPT") != adm["admitted"]:
        fails.append(f"admitted {obs.get('verdict') == 'ACCEPT'} != {adm['admitted']}")
    other = exp.get("task_id_differs_from")
    if other is not None:
        if not obs.get("task_id") or obs.get("task_id") == task_ids.get(other):
            fails.append(f"task_id equals that of {other}")
    return ("fail" if fails else "pass"), fails + notes


def psea_binding(proof: str, digest: str | None) -> tuple[str | None, str]:
    """The client side of XR-25 and XR-26 (CROSSRUN.md 4): psea_payload_hash of
    the PSEA proof against the request_digest the server returned, compared as
    decoded octets (aae_a2a/psea.py). ACCEPT when they are the same 32 octets,
    REFUSE otherwise, including a value in the wrong encoding. The signature of
    the proof is not checked here; that is a PSEA Verifier's job."""
    try:
        claims = json.loads(b64url_decode(proof.split(".")[1]))
        value = claims["psea_payload_hash"]
    except (IndexError, KeyError, TypeError, ValueError):
        return None, "REFUSE"
    try:
        same = covers_same_request(value, digest)
    except PseaHashError:
        same = False
    return value, "ACCEPT" if same else "REFUSE"


def observe_task(task) -> dict:
    res = task_result(task) or {}
    obs = {"task_id": task.id, "task_state": TaskState.Name(task.status.state),
           "verdict": res.get("verdict"), "request_digest": res.get("request_digest")}
    if res.get("verdict") == "REJECT":
        obs["step"] = int(res["step"])
        obs["reason_code"] = res.get("reason_code")
    elif res.get("verdict") in ("ACCEPT", "PENDING"):
        obs["steps_passed"] = [int(s) for s in res.get("steps_passed", [])]
    if isinstance(res.get("ratification"), dict):
        obs["ratification_status"] = res["ratification"].get("status")
    return obs


def observe_error(exc: A2AError) -> dict:
    obs = {"jsonrpc_code": JSON_RPC_ERROR_CODE_MAP.get(type(exc))}
    if exc.data and "reason_code" in exc.data:
        obs["reason_code"] = exc.data["reason_code"]
    return obs


# --- client: run the cases against a supplier ------------------------------------------

async def run_cases(base_url: str, cases: list[dict], only: set[str] | None = None,
                    httpx_client=None) -> list[dict]:
    buyer = BuyerAgent(base_url, httpx_client=httpx_client)
    await buyer.discover()
    audience = buyer.params["audience"]
    out, task_ids = [], {}
    try:
        for case in cases:
            if only and case["id"] not in only:
                out.append({"id": case["id"], "result": "skipped"})
                continue
            rp = case["request_part"]
            respond = RESPONSES[case["challenge_response"]]
            aae = build_aae(case["aae"], audience)
            attempts = []
            for _ in range(case.get("attempts", 1)):
                try:
                    task = await buyer.request(rp["skill"], rp["transaction"], aae=aae,
                                               activate=case["activate"], respond=respond)
                    held = task_result(task) or {}
                    if case.get("ratification") and held.get("verdict") == "PENDING":
                        closing = ratification_for(case["ratification"],
                                                   held["enforce"]["core_digest"])
                        if closing is not None:
                            task = await buyer.send_ratification(task, *closing)
                    attempts.append(observe_task(task))
                except A2AError as exc:
                    attempts.append(observe_error(exc))
            if "attempts" in case:
                obs = {"attempts": attempts}
            else:
                obs = attempts[0]
                if obs.get("task_id"):
                    task_ids[case["id"]] = obs["task_id"]
                if "psea_proof" in case:
                    proof = (CASES_FILE.parent / case["psea_proof"]).read_text(
                        encoding="ascii").strip()
                    value, binding = psea_binding(proof, obs.get("request_digest"))
                    obs.update(psea_payload_hash=value, psea_binding=binding)
            result, notes = evaluate(case, obs, task_ids)
            out.append({"id": case["id"], "result": result, **obs,
                        **({"notes": notes} if notes else {})})
    finally:
        await buyer.aclose()
    return out


def summarize(results: list[dict]) -> dict:
    return {k: sum(1 for r in results if r["result"] == k) for k in ("pass", "fail", "skipped")}


async def run_pinned(base_url: str, bundle_dir: Path, httpx_client=None) -> list[dict]:
    """Present the pinned bytes to a supplier started with --pinned and compare
    each attempt with what the bundle expects (CROSSRUN.md, "Pinned bundle")."""
    from . import pinned
    bundle = pinned.load(bundle_dir)
    buyer = BuyerAgent(base_url, httpx_client=httpx_client)
    await buyer.discover()
    out, task_ids = [], {}
    try:
        for case in bundle["cases"]:
            rp, aae = case["request_part"], pinned.read_jws(bundle_dir, case["aae"])
            got = []
            for att in case["attempts"]:
                def respond(challenge, _aae_id, att=att):
                    if challenge != att["challenge"]:
                        raise RuntimeError(f"{case['id']} attempt {att['attempt']}: the supplier "
                                           f"minted another challenge; start it with --pinned")
                    return pinned.read_jws(bundle_dir, att["challenge_response"])
                try:
                    got.append(observe_task(await buyer.request(
                        rp["skill"], rp["transaction"], aae=aae, respond=respond)))
                except A2AError as exc:
                    got.append(observe_error(exc))
            exp = [att["expect"] for att in case["attempts"]]
            if "psea_proof" in case:
                value, binding = psea_binding(pinned.read_jws(bundle_dir, case["psea_proof"]),
                                              got[0].get("request_digest"))
                got[0].update(psea_payload_hash=value, psea_binding=binding)
            if len(exp) == 1:
                result, notes = evaluate({"id": case["id"], "expect": exp[0]}, got[0], task_ids)
                entry = {"id": case["id"], "result": result, **got[0]}
                task_ids[case["id"]] = got[0].get("task_id")
            else:
                result, notes = evaluate({"id": case["id"],
                                          "expect": {"kind": "retry", "attempts": exp}},
                                         {"attempts": got}, task_ids)
                entry = {"id": case["id"], "result": result, "attempts": got}
            out.append({**entry, **({"notes": notes} if notes else {})})
    finally:
        await buyer.aclose()
    return out


def _print_results(results: list[dict]) -> None:
    for r in results:
        line = f"{r['id']}  {r['result']:<7}"
        for o in (r["attempts"] if "attempts" in r else [r]) if r["result"] != "skipped" else []:
            line += f" {o.get('task_state') or 'error ' + str(o.get('jsonrpc_code'))}"
            if o.get("step") is not None:
                line += f" step {o['step']} {o.get('reason_code')}"
            if o.get("request_digest"):
                line += f" {o['request_digest'][:19]}..."
            if o.get("psea_binding"):
                line += f" psea {o['psea_binding']}"
        for n in r.get("notes", []):
            line += f"\n        {n}"
        print(line)


def cmd_client(a) -> int:
    if a.pinned:
        results = asyncio.run(run_pinned(a.url, Path(a.pinned)))
        _print_results(results)
        s = summarize(results)
        print(f"\npinned bundle: {s['pass']} pass, {s['fail']} fail")
        return 1 if s["fail"] else 0
    if not a.out:
        raise SystemExit("--out is required unless --pinned is given")
    spec, cases_digest = load_cases()
    only = set(a.cases.split(",")) if a.cases else None
    results = asyncio.run(run_cases(a.url, spec["cases"], only))
    commit, dirty = repo_commit()
    reference_server = a.server_commit is None and a.server_repo == REFERENCE_REPO
    doc = {
        "format": RESULT_FORMAT,
        "profile": EXTENSION_URI,
        "draft": AAE_DRAFT,
        "cases_commit": commit,
        "cases_sha256": cases_digest,
        "run_at": utc_now().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "participant": {"name": a.participant, "url": a.participant_url},
        "receiver_provenance": a.receiver_provenance,
        "client": {"implementation": "aae-a2a-extension reference buyer",
                   "repository": REFERENCE_REPO, "commit": commit,
                   **({"dirty": True} if dirty else {})},
        "server": {"implementation": a.server_impl, "repository": a.server_repo,
                   "commit": a.server_commit or (commit if reference_server else None),
                   **({"dirty": True} if dirty and reference_server else {}),
                   "agent_card": a.url.rstrip("/") + "/.well-known/agent-card.json"},
        "cases": results,
        "summary": summarize(results),
    }
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    _print_results(results)
    s = doc["summary"]
    print(f"\n{s['pass']} pass, {s['fail']} fail, {s['skipped']} skipped -> {a.out}")
    return 1 if s["fail"] else 0


# --- check: validate a result file ------------------------------------------------------

def check_result(doc: dict, spec: dict, cases_digest: str) -> list[str]:
    errs = []
    if doc.get("format") != RESULT_FORMAT:
        errs.append(f"format is not {RESULT_FORMAT}")
    if doc.get("profile") != EXTENSION_URI or doc.get("draft") != AAE_DRAFT:
        errs.append("profile or draft differs")
    if not _SHA1.match(str(doc.get("cases_commit"))):
        errs.append("cases_commit is not a 40-character commit SHA")
    if doc.get("cases_sha256") != cases_digest:
        errs.append("cases_sha256 is not that of tests/vectors/crossrun/cases.json at "
                    "cases_commit")
    if not (doc.get("participant") or {}).get("name"):
        errs.append("participant.name missing")
    if "receiver_provenance" not in doc:
        errs.append("receiver_provenance missing (clean_room, reference_informed or unknown; "
                    "unknown if the participant has not stated it)")
    elif doc["receiver_provenance"] not in RECEIVER_PROVENANCE:
        errs.append(f"receiver_provenance {doc['receiver_provenance']!r} is not one of "
                    + ", ".join(RECEIVER_PROVENANCE))
    form = doc.get("form", "interactive")
    if form == "interactive":
        for side in ("client", "server"):
            part = doc.get(side) or {}
            if not part.get("implementation"):
                errs.append(f"{side}.implementation missing")
            if not _SHA1.match(str(part.get("commit"))):
                errs.append(f"{side}.commit is not a 40-character commit SHA")
    elif form == "offline":
        errs += _check_offline(doc)
    else:
        errs.append(f"form {form!r} is neither interactive nor offline")
    # An offline receiver decides every case itself, as a server does, so none
    # may be skipped; an interactive client run may skip the optional ones.
    required = (lambda c: True) if form == "offline" else (lambda c: c["client_side"] == "required")
    by_id = {c["id"]: c for c in spec["cases"]}
    seen, task_ids = [], {}
    for r in doc.get("cases", []):
        case = by_id.get(r.get("id"))
        if case is None:
            errs.append(f"unknown case {r.get('id')}")
            continue
        seen.append(r["id"])
        if r.get("result") == "skipped":
            if required(case):
                errs.append(f"{r['id']} is required and was skipped")
            continue
        if r.get("request_digest") is not None and not _DIGEST.match(r["request_digest"]):
            errs.append(f"{r['id']} request_digest malformed")
        result, _ = evaluate(case, r, task_ids)
        if r.get("task_id"):
            task_ids[r["id"]] = r["task_id"]
        if r.get("result") != result:
            errs.append(f"{r['id']} claims {r.get('result')}, its observation gives {result}")
    missing = [i for i in by_id if i not in seen]
    if missing:
        errs.append(f"cases missing: {', '.join(missing)}")
    if doc.get("summary") != summarize(doc.get("cases", [])):
        errs.append("summary does not match the cases")
    return errs


_RFC3339_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$")


def _check_offline(doc: dict) -> list[str]:
    """The members an offline receiver run carries instead of client and server
    (CROSSRUN.md, "Offline receiver runs")."""
    errs = []
    if "client" in doc or "server" in doc:
        errs.append("an offline run names a receiver, not a client or server")
    rec = doc.get("receiver") or {}
    if not rec.get("implementation") or not rec.get("version"):
        errs.append("receiver.implementation and receiver.version are required")
    commit, content = rec.get("commit"), rec.get("content_sha256")
    if commit is not None and not _SHA1.match(str(commit)):
        errs.append("receiver.commit is not a 40-character commit SHA")
    if content is not None and not _DIGEST.match(str(content)):
        errs.append("receiver.content_sha256 is not sha256:<64 hex>")
    if commit is None and content is None:
        errs.append("receiver needs a commit or a content_sha256")
    if doc.get("audience") != OFFLINE_AUDIENCE:
        errs.append(f"audience is not {OFFLINE_AUDIENCE}")
    if not _RFC3339_UTC.match(str(doc.get("evaluation_instant"))):
        errs.append("evaluation_instant is not an RFC 3339 UTC time")
    inv = doc.get("inventions")
    if not isinstance(inv, list) or not all(isinstance(i, dict) and i.get("what") and i.get("choice")
                                            for i in inv):
        errs.append("inventions must be a list of {what, choice} (empty if there were none)")
    return errs


def check_reported(doc: dict) -> list[str]:
    """Check a reported run against the cases of the commit it names."""
    try:
        spec, cases_digest = load_cases_at(doc.get("cases_commit"))
    except CasesUnavailable as exc:
        return [f"cases_commit: {exc}"]
    return check_result(doc, spec, cases_digest)


def cmd_check(a) -> int:
    bad = 0
    for path in a.files:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
        errs = check_reported(doc)
        s = doc.get("summary", {})
        status = "invalid" if errs else f"valid ({s.get('pass')} pass, {s.get('fail')} fail, " \
                                        f"{s.get('skipped')} skipped)"
        print(f"{path}: {status}")
        for e in errs:
            print(f"  - {e}")
        bad += bool(errs)
    return 1 if bad else 0


# --- serve: the reference supplier as its own process ----------------------------------

def cmd_serve(a) -> int:
    import uvicorn

    from .didres import LocalDidResolver
    from .server import create_supplier_app

    from datetime import datetime
    docs = list(fixture_documents().values())
    clock, binding, audience = utc_now, None, None
    if a.pinned:
        from . import pinned
        bundle = pinned.load(Path(a.pinned))
        at = a.at or bundle["verify_at"]
        audience = bundle["params"]["audience"]
    else:
        at = a.at
    if at:
        frozen = datetime.fromisoformat(at.replace("Z", "+00:00"))
        clock = lambda: frozen  # noqa: E731
    if a.did_dir:
        docs += [json.loads(p.read_text(encoding="utf-8"))
                 for p in sorted(Path(a.did_dir).glob("*.json"))]
    resolver = LocalDidResolver(docs)
    issuers = [did_of("issuer")] + list(a.accept_issuer or [])
    base_url = a.public_url or f"http://{a.host}:{a.port}"
    if a.pinned:
        binding = pinned.pinned_binding(resolver)
    app, _card, executor = create_supplier_app(base_url, resolver=resolver,
                                               accepted_issuers=issuers,
                                               own_aae=issue_supplier_aae(clock()),
                                               clock=clock, binding=binding,
                                               audience=audience, deferred_decisions=True)
    if a.record:
        record = open(a.record, "a", encoding="utf-8")

        def observer(task_id, result, state):
            row = {"task_id": task_id, "task_state": state,
                   **{k: result.get(k) for k in ("verdict", "step", "reason_code",
                                                 "request_digest") if k in result}}
            record.write(json.dumps(row, sort_keys=True) + "\n")
            record.flush()

        executor.observer = observer
    print(f"Reference supplier on {base_url} (card at /.well-known/agent-card.json), "
          f"accepted issuers {issuers}" + (f", clock fixed at {at}" if at else "")
          + (", pinned nonces" if a.pinned else ""), flush=True)
    uvicorn.run(app, host=a.host, port=a.port, log_level="warning")
    return 0


# --- fixtures: DID documents and public test keys --------------------------------------

def fixture_documents() -> dict[str, dict]:
    return {name: did_document(name, rels) for name, rels in PARTIES.items()}


def fixture_keys() -> dict:
    """The test keys a cross-run needs, with their derivation. They are derived
    from public labels and are not secrets (README, "Keys")."""
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
    keys = {}
    for name in ("issuer", "buyer", "mallory", "principal"):
        seed = demo_key(name).private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        did = PRINCIPAL_DID if name == "principal" else did_of(name)
        keys[name] = {"did": did, "kid": kid_of(name) if name not in ("mallory", "principal") else None,
                      "ed25519_seed_hex": seed.hex()}
    return {"description": "TEST-ONLY Ed25519 keys. seed = SHA-256(UTF-8('aae-a2a-extension/"
                           "testkey/v1/' + name)). Public by construction; never use them "
                           "for anything but tests. mallory has no DID document; principal "
                           "has none either, its key is carried in the mandate (-02 6.4).",
            "keys": keys}


def cmd_fixtures(a) -> int:
    out = Path(a.out)
    (out / "did").mkdir(parents=True, exist_ok=True)
    for name, doc in fixture_documents().items():
        (out / "did" / f"{name}.json").write_text(json.dumps(doc, indent=2) + "\n")
    (out / "test-keys.json").write_text(json.dumps(fixture_keys(), indent=2) + "\n")
    print(f"wrote {out}/did/*.json and {out}/test-keys.json")
    return 0


def cmd_pin(a) -> int:
    from . import pinned
    out = Path(a.out) if a.out else pinned.PINNED_DIR
    files = pinned.build(out)
    print(f"wrote {len(files)} files to {out}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m aae_a2a.crossrun")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="run the reference supplier")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8790)
    s.add_argument("--public-url", help="base URL clients use, if not http://host:port")
    s.add_argument("--did-dir", help="directory of further DID documents (*.json) to resolve")
    s.add_argument("--accept-issuer", action="append", help="further accepted root issuer DID")
    s.add_argument("--record", help="append one JSON line per decision to this file")
    s.add_argument("--at", help="fix the supplier's clock at this RFC 3339 UTC instant")
    s.add_argument("--pinned", help="pinned bundle directory: fixed clock (its verify_at "
                                     "unless --at), its audience and its nonce derivation")
    s.set_defaults(fn=cmd_serve)

    c = sub.add_parser("client", help="run the cases with the reference buyer")
    c.add_argument("--url", required=True, help="supplier base URL (the Agent Card host)")
    c.add_argument("--out", help="result file to write (not with --pinned)")
    c.add_argument("--pinned", help="present the bytes of this pinned bundle instead of the cases")
    c.add_argument("--cases", help="comma-separated case ids; the others are skipped")
    c.add_argument("--participant", default="anonymous")
    c.add_argument("--participant-url")
    c.add_argument("--receiver-provenance", choices=RECEIVER_PROVENANCE, default="unknown",
                   help="how the side the participant built was written, as the participant "
                        "states it (CROSSRUN.md Section 6); unknown unless stated")
    c.add_argument("--server-impl", default="aae-a2a-extension reference supplier")
    c.add_argument("--server-repo", default=REFERENCE_REPO)
    c.add_argument("--server-commit", help="commit SHA of the server under test")
    c.set_defaults(fn=cmd_client)

    k = sub.add_parser("check", help="validate result files")
    k.add_argument("files", nargs="+")
    k.set_defaults(fn=cmd_check)

    q = sub.add_parser("pin", help="rebuild the pinned bundle")
    q.add_argument("--out", help="directory (default tests/vectors/crossrun/pinned)")
    q.set_defaults(fn=cmd_pin)

    f = sub.add_parser("fixtures", help="write the DID documents and test keys")
    f.add_argument("--out", default=str(CASES_FILE.parent))
    f.set_defaults(fn=cmd_fixtures)

    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
