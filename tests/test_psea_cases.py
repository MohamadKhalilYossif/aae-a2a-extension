"""XR-25 and XR-26 (CROSSRUN.md 4): a PSEA proof (draft-yossif-psea-03) over a
request part, compared with request_digest (spec 8.5) as decoded octets.

The proofs in tests/vectors/crossrun/psea/ were made by the psea-spec reference
Attester (scripts/make-psea-proofs.py). These tests check them without that
code: the ES256 signature under the published test key, the key's derivation
from its label, and psea_payload_hash against the JCS SHA-256 of the request
part each proof is over.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from aae_a2a import crossrun
from aae_a2a.digest import request_digest
from aae_a2a.jose import b64url_decode
from aae_a2a.psea import covers_same_request, decode_payload_hash

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "vectors" / "crossrun"
PSEA = FIXTURES / "psea"
PINNED = FIXTURES / "pinned"
KEY = json.loads((PSEA / "approver-key.json").read_text())


def _cases():
    spec, _ = crossrun.load_cases()
    return {c["id"]: c for c in spec["cases"]}


def _proof(case_id: str) -> str:
    return (PSEA / f"{case_id}.psea.jws").read_text(encoding="ascii").strip()


def _claims(token: str) -> dict:
    return json.loads(b64url_decode(token.split(".")[1]))


def test_test_key_follows_from_its_label():
    d = int.from_bytes(hashlib.sha256(
        b"aae-a2a-extension/testkey/v1/psea-approver").digest(), "big")
    nums = ec.derive_private_key(d, ec.SECP256R1()).public_key().public_numbers()
    jwk = KEY["jwk"]
    assert int.from_bytes(b64url_decode(jwk["d"]), "big") == d
    assert int.from_bytes(b64url_decode(jwk["x"]), "big") == nums.x
    assert int.from_bytes(b64url_decode(jwk["y"]), "big") == nums.y


@pytest.mark.parametrize("case_id", ["XR-25", "XR-26"])
def test_proof_signature_verifies_under_the_test_key(case_id):
    header_b64, payload_b64, sig_b64 = _proof(case_id).split(".")
    header = json.loads(b64url_decode(header_b64))
    assert header == {"alg": "ES256", "typ": "psea-proof+jwt", "kid": KEY["kid"]}
    jwk = KEY["jwk"]
    key = ec.EllipticCurvePublicNumbers(int.from_bytes(b64url_decode(jwk["x"]), "big"),
                                        int.from_bytes(b64url_decode(jwk["y"]), "big"),
                                        ec.SECP256R1()).public_key()
    raw = b64url_decode(sig_b64)
    der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    key.verify(der, f"{header_b64}.{payload_b64}".encode("ascii"), ec.ECDSA(hashes.SHA256()))


def test_xr25_proof_is_over_the_request_part_it_is_sent_with():
    case = _cases()["XR-25"]
    value = _claims(_proof("XR-25"))["psea_payload_hash"]
    assert value == case["expect"]["psea"]["psea_payload_hash"]
    digest = case["expect"]["request_digest"]
    assert digest == request_digest(case["request_part"])
    assert decode_payload_hash(value) == bytes.fromhex(digest[len("sha256:"):])
    assert covers_same_request(value, digest) is True
    # The encodings never agree as strings; only the octets do.
    assert value != digest


def test_xr26_proof_is_over_a_request_part_differing_in_one_value():
    case = _cases()["XR-26"]
    value = _claims(_proof("XR-26"))["psea_payload_hash"]
    assert value == case["expect"]["psea"]["psea_payload_hash"]
    signed = copy.deepcopy(case["request_part"])
    signed["transaction"]["amount"] = 121
    assert decode_payload_hash(value) == bytes.fromhex(request_digest(signed)[len("sha256:"):])
    assert covers_same_request(value, case["expect"]["request_digest"]) is False
    assert crossrun.psea_binding(_proof("XR-26"), case["expect"]["request_digest"]) == \
        (value, "REFUSE")


def test_the_two_cases_send_the_same_request_part():
    by_id = _cases()
    assert by_id["XR-25"]["request_part"] == by_id["XR-26"]["request_part"] == \
        by_id["XR-01"]["request_part"]


def test_pinned_proofs_are_the_published_ones():
    bundle = json.loads((PINNED / "bundle.json").read_text(encoding="utf-8"))
    pinned_cases = {c["id"]: c for c in bundle["cases"]}
    for case_id in ("XR-25", "XR-26"):
        name = pinned_cases[case_id]["psea_proof"]
        assert (PINNED / name).read_bytes() == (PSEA / f"{case_id}.psea.jws").read_bytes()


def _entry(case_id: str, binding: str, value: str | None = None) -> dict:
    case = _cases()[case_id]
    return {"id": case_id, "result": "pass", "task_id": "t", "task_state": "TASK_STATE_COMPLETED",
            "verdict": "ACCEPT", "request_digest": case["expect"]["request_digest"],
            "steps_passed": [1, 2, 3, 4, 5, 6, 7],
            "psea_payload_hash": value or case["expect"]["psea"]["psea_payload_hash"],
            "psea_binding": binding}


def test_evaluate_passes_the_expected_bindings():
    by_id = _cases()
    assert crossrun.evaluate(by_id["XR-25"], _entry("XR-25", "ACCEPT"), {})[0] == "pass"
    assert crossrun.evaluate(by_id["XR-26"], _entry("XR-26", "REFUSE"), {})[0] == "pass"


def test_evaluate_fails_a_binding_the_octets_do_not_give():
    by_id = _cases()
    result, msgs = crossrun.evaluate(by_id["XR-26"], _entry("XR-26", "ACCEPT"), {})
    assert result == "fail" and any(m.startswith("psea_binding") for m in msgs)
    # The XR-25 hash recorded under XR-26 is not the case's proof.
    result, msgs = crossrun.evaluate(by_id["XR-26"], _entry(
        "XR-26", "ACCEPT", by_id["XR-25"]["expect"]["psea"]["psea_payload_hash"]), {})
    assert result == "fail" and any(m.startswith("psea_payload_hash") for m in msgs)


def test_a_base64url_payload_hash_is_refused_not_matched():
    case = _cases()["XR-25"]
    raw = decode_payload_hash(case["expect"]["psea"]["psea_payload_hash"])
    b64url = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps({"psea_payload_hash": b64url}).encode()) \
        .decode().rstrip("=")
    assert crossrun.psea_binding(f"{header}.{payload}.", case["expect"]["request_digest"]) == \
        (b64url, "REFUSE")
