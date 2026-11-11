"""The pinned bundle (CROSSRUN.md, "Pinned bundle"): fixed AAE and
challenge-response bytes for XR-01, XR-06, XR-20, XR-24, XR-25 and XR-26 at one
fixed verification time, the PSEA proofs of XR-25 and XR-26, with the profile parameters, DID documents and accepted issuers they were
made for, and a manifest of hashes.

A verifier can check the bytes without running a client, and the reference
supplier started with `--pinned` decides them the way the bundle expects. Every
input is derived from public labels, and Ed25519 signatures are deterministic,
so `python -m aae_a2a.crossrun pin` rebuilds the bundle byte for byte. The PSEA
proofs are ES256, which is randomized; they are copied from
tests/vectors/crossrun/psea/, where scripts/make-psea-proofs.py wrote them once.

Two things are fixed here that a deployment never fixes: the nonce key and the
random part of the nonce. Both are derived from public labels so that the
challenge the supplier mints equals the one the pinned response answers. They
exist for this bundle only.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .challenge import _KEY_LABEL, SubjectBinding
from .constants import AAE_DRAFT, EXTENSION_URI
from .didres import LocalDidResolver
from .jose import sign_compact
from .testkeys import (buyer_constraints, buyer_mandate, demo_key, did_of, kid_of, make_vc,
                       sign_aae)
from .verifier import AaeVerifier, Reject

ROOT = Path(__file__).resolve().parent.parent
PINNED_DIR = ROOT / "tests" / "vectors" / "crossrun" / "pinned"
DID_DIR = ROOT / "tests" / "vectors" / "crossrun" / "did"
PSEA_DIR = ROOT / "tests" / "vectors" / "crossrun" / "psea"
BUNDLE_FORMAT = "aae-a2a-crossrun-pinned/1"

VERIFY_AT = datetime(2026, 11, 2, 9, 0, 0, tzinfo=timezone.utc)
BASE_URL = "https://supplier.example"
AUDIENCE = BASE_URL + "/a2a/jsonrpc"
ACCEPTED_ISSUERS = ["did:example:issuer"]
SKILLS = {"get-quote": {"action": "read"}, "place-order": {"action": "pay"}}
_LABEL = "aae-a2a-extension/pinned/v1/"
NONCE_MASTER_KEY = hashlib.sha256((_LABEL + "nonce-master").encode("ascii")).digest()

ORDER = {"amount": 120, "currency": "EUR", "items": [{"sku": "PAPER-A4", "qty": 20}]}
SMALL = {"amount": 120, "currency": "EUR"}
# Authorization is the outcome of every step but step 5 for this presentation;
# admission is step 5 against what the server has already accepted. The second
# attempt of XR-20 is a valid authorization that is not admitted again; XR-24
# presents a reusable AAE twice, and both attempts are admitted.
AUTHORIZED = {"verdict": "ACCEPT", "steps_passed": [1, 2, 3, 4, 6, 7]}
DIGEST_ORDER = "sha256:84559612f1f46ec0a03f8c448905af075ba4edf66e529b15b50f69c85a68b59a"
DIGEST_SMALL = "sha256:7081684b67799fdd4045a25d028f770a8254746ff279dbabb0486bdb7eeb4176"


def _accepted(digest: str, **extra) -> dict:
    return {"kind": "task", "task_state": "TASK_STATE_COMPLETED", "verdict": "ACCEPT",
            "request_digest": digest, **extra,
            "authorization": AUTHORIZED, "admission": {"admitted": True}}


CASES = [
    # XR-01 is here as the task XR-06 is compared with; its expectation is that
    # of cases.json, which states no authorization or admission for it.
    {"id": "XR-01", "transaction": ORDER, "single_use": False,
     "expect": [{"kind": "task", "task_state": "TASK_STATE_COMPLETED", "verdict": "ACCEPT",
                 "request_digest": DIGEST_ORDER}]},
    {"id": "XR-06", "transaction": ORDER, "single_use": False,
     "expect": [_accepted(DIGEST_ORDER, task_id_differs_from="XR-01")]},
    {"id": "XR-20", "transaction": SMALL, "single_use": True,
     "expect": [_accepted(DIGEST_SMALL),
                {"kind": "task", "task_state": "TASK_STATE_REJECTED", "verdict": "REJECT",
                 "step": 5, "reason_code": "single_use_already_consumed",
                 "request_digest": DIGEST_SMALL, "authorization": AUTHORIZED,
                 "admission": {"admitted": False, "step": 5,
                               "reason_code": "single_use_already_consumed"}}]},
    # XR-24 is the reuse case: one AAE file, so both attempts present the same
    # bytes, each as a new task with a new nonce.
    {"id": "XR-24", "transaction": SMALL, "single_use": False,
     "expect": [_accepted(DIGEST_SMALL), _accepted(DIGEST_SMALL)]},
    # XR-25 and XR-26 send the request part of XR-01 and carry a PSEA proof; the
    # expectation is that of cases.json. XR-26's proof is over amount 121.
    {"id": "XR-25", "transaction": ORDER, "single_use": False, "psea": True,
     "expect": [{"kind": "task", "task_state": "TASK_STATE_COMPLETED", "verdict": "ACCEPT",
                 "request_digest": DIGEST_ORDER,
                 "psea": {"psea_payload_hash": "hFWWEvH0bsCgP4xEiQWvB1uk7fZuUpsVtQ9pyFpotZo=",
                          "same_octets": True, "binding": "ACCEPT"}}]},
    {"id": "XR-26", "transaction": ORDER, "single_use": False, "psea": True,
     "expect": [{"kind": "task", "task_state": "TASK_STATE_COMPLETED", "verdict": "ACCEPT",
                 "request_digest": DIGEST_ORDER,
                 "psea": {"psea_payload_hash": "/SSQliogsNgiPWkkj/pfBzGA55GGQpUkftHu2GYfSPk=",
                          "same_octets": False, "binding": "REFUSE"}}]},
]


def pinned_random():
    """random_source for SubjectBinding: the n-th nonce minted for an aae_id has
    the random part SHA-256(label + aae_id + "/" + n), first 32 hex digits."""
    count: dict[str, int] = {}

    def source(aae_id: str) -> str:
        count[aae_id] = count.get(aae_id, 0) + 1
        msg = f"{_LABEL}nonce/{aae_id}/{count[aae_id]}".encode("utf-8")
        return hashlib.sha256(msg).hexdigest()[:32]
    return source


def pinned_binding(resolver: LocalDidResolver) -> SubjectBinding:
    return SubjectBinding(resolver, master_key=NONCE_MASTER_KEY, random_source=pinned_random())


def vc_id(case_id: str) -> str:
    return f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, _LABEL + case_id)}"


def _iat() -> str:
    return VERIFY_AT.strftime("%Y-%m-%dT%H:%M:%SZ")


def _dump(obj) -> bytes:
    return (json.dumps(obj, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def build(out: Path = PINNED_DIR) -> list[Path]:
    """Write the bundle to `out` and return the files written."""
    out.mkdir(parents=True, exist_ok=True)
    (out / "did").mkdir(exist_ok=True)
    written: list[Path] = []

    def put(name: str, data: bytes):
        p = out / name
        p.write_bytes(data)
        written.append(p)

    for src in sorted(DID_DIR.glob("*.json")):
        put(f"did/{src.name}", src.read_bytes())
    minter = pinned_binding(LocalDidResolver([]))
    cases = []
    for c in CASES:
        vid = vc_id(c["id"])
        vc = make_vc(subject=did_of("buyer"), issuer=did_of("issuer"), mandate=buyer_mandate(),
                     constraints=buyer_constraints(["supplier.example"]),
                     not_before=VERIFY_AT - timedelta(minutes=5),
                     not_after=VERIFY_AT + timedelta(hours=1), single_use=c["single_use"],
                     vc_id=vid)
        aae_file = f"{c['id']}.aae.jws"
        put(aae_file, (sign_aae(vc, "issuer") + "\n").encode("ascii"))
        attempts = []
        for n, expect in enumerate(c["expect"], start=1):
            nonce = minter.mint(AUDIENCE, vid, VERIFY_AT)
            challenge = {"nonce": nonce, "aud": AUDIENCE, "aae_id": vid}
            payload = {"nonce": nonce, "aud": AUDIENCE, "iat": _iat(), "aae_id": vid}
            resp_file = f"{c['id']}.{n}.response.jws"
            put(resp_file, (sign_compact({"alg": "EdDSA", "kid": kid_of("buyer")}, payload,
                                         demo_key("buyer")) + "\n").encode("ascii"))
            attempts.append({"attempt": n, "challenge": challenge,
                             "challenge_response": resp_file, "expect": expect})
        entry = {"id": c["id"], "aae": aae_file,
                 "request_part": {"skill": "place-order", "transaction": c["transaction"]},
                 "attempts": attempts}
        if c.get("psea"):
            psea_file = f"{c['id']}.psea.jws"
            put(psea_file, (PSEA_DIR / psea_file).read_bytes())
            entry["psea_proof"] = psea_file
        cases.append(entry)
    bundle = {
        "format": BUNDLE_FORMAT,
        "profile": EXTENSION_URI,
        "verify_at": _iat(),
        "params": {"draft": AAE_DRAFT, "audience": AUDIENCE, "skills": SKILLS,
                   "did_methods": ["example"], "accepted_issuers": ACCEPTED_ISSUERS},
        "did_documents": sorted(f"did/{p.name}" for p in DID_DIR.glob("*.json")),
        # Everything a third party needs to recompute each challenge nonce
        # without this code: SubjectBinding.mint() in aae_a2a/challenge.py.
        "nonce": {"master_key_input": _LABEL + "nonce-master",
                  "master_key": "SHA-256(ASCII(master_key_input))",
                  "key_label": _KEY_LABEL.decode("ascii"),
                  "key": "HMAC-SHA256(key = master_key, message = ASCII(key_label))",
                  "random_prefix": _LABEL + "nonce/",
                  "random": "first 32 hex digits of SHA-256(UTF-8(random_prefix + aae_id + "
                            "'/' + n)), n counting the nonces minted for that aae_id from 1",
                  "lifetime_s": 300,
                  "expiry": "decimal seconds since the Unix epoch of verify_at, plus lifetime_s",
                  "authenticator": "base64url without padding of HMAC-SHA256(key = key, "
                                   "message = UTF-8(random + '.' + expiry + '.' + aud + '.' + "
                                   "aae_id)), aud and aae_id as in the challenge",
                  "nonce": "random + '.' + expiry + '.' + authenticator"},
        "description": "Fixed bytes for XR-01, XR-06, XR-20, XR-24, XR-25 and XR-26 at "
                       "verify_at. Present the cases in order, each attempt as a new task. "
                       "authorization is the outcome of every step but step 5; admission "
                       "is step 5 against what the server has already accepted. For XR-25 "
                       "and XR-26, psea_payload_hash of psea_proof is compared with the "
                       "returned request_digest as decoded octets. TEST-ONLY keys.",
        "cases": cases,
    }
    put("bundle.json", _dump(bundle))
    lines = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(out).as_posix()}"
             for p in sorted(written, key=lambda p: p.relative_to(out).as_posix())]
    (out / "MANIFEST.sha256").write_text("\n".join(lines) + "\n", encoding="ascii")
    return written + [out / "MANIFEST.sha256"]


def load(bundle_dir: Path = PINNED_DIR) -> dict:
    return json.loads((bundle_dir / "bundle.json").read_text(encoding="utf-8"))


def read_jws(bundle_dir: Path, name: str) -> str:
    return (bundle_dir / name).read_text(encoding="ascii").strip()


def resolver(bundle_dir: Path = PINNED_DIR) -> LocalDidResolver:
    b = load(bundle_dir)
    return LocalDidResolver([json.loads((bundle_dir / p).read_text(encoding="utf-8"))
                             for p in b["did_documents"]])


def authorization(bundle_dir: Path, case: dict, attempt: dict) -> dict:
    """Every step but step 5, for one attempt, with no earlier use counted."""
    res = resolver(bundle_dir)
    b = load(bundle_dir)
    verifier = AaeVerifier(res, accepted_issuers=b["params"]["accepted_issuers"])
    binding = SubjectBinding(res, master_key=NONCE_MASTER_KEY)
    response = read_jws(bundle_dir, attempt["challenge_response"])
    tx = case["request_part"]["transaction"]
    action = b["params"]["skills"][case["request_part"]["skill"]]["action"]

    def subject_binding(vc):
        from .challenge import ChallengeError
        try:
            binding.verify_response(response, subject_did=vc["credentialSubject"]["id"],
                                    aae_id=vc["id"], aud=b["params"]["audience"],
                                    expected_nonce=attempt["challenge"]["nonce"], now=VERIFY_AT)
        except ChallengeError as exc:
            raise Reject(4, exc.reason) from exc
    try:
        acc = verifier.verify(read_jws(bundle_dir, case["aae"]), now=VERIFY_AT, action=action,
                              subject_binding=subject_binding, transaction=tx,
                              action_ctx={"amount": tx.get("amount"),
                                          "currency": tx.get("currency"),
                                          "domain": "supplier.example"})
    except Reject as r:
        return {"verdict": "REJECT", "step": r.step, "reason_code": r.reason}
    return {"verdict": "ACCEPT", "steps_passed": [s for s in acc.steps if s != 5]}


def verify_manifest(bundle_dir: Path = PINNED_DIR) -> list[str]:
    """Files whose hash differs from MANIFEST.sha256, or that are missing from it."""
    errs, listed = [], set()
    for line in (bundle_dir / "MANIFEST.sha256").read_text(encoding="ascii").splitlines():
        digest, name = line.split("  ", 1)
        listed.add(name)
        p = bundle_dir / name
        if not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest() != digest:
            errs.append(name)
    present = {p.relative_to(bundle_dir).as_posix() for p in bundle_dir.rglob("*")
               if p.is_file() and p.name != "MANIFEST.sha256"}
    errs += sorted(present - listed)
    return errs
