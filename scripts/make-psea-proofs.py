"""Write the PSEA proofs of XR-25 and XR-26 (CROSSRUN.md 4) and their test key.

  python scripts/make-psea-proofs.py --psea-src <psea-spec>/conformance/src

The proofs are made by the Attester of the draft-yossif-psea-03 reference
implementation (github.com/yuthent/psea-spec, conformance/src/psea.py), not
by this repository. ES256 signatures are randomized, so a second run writes
different tokens: the committed files are the vectors. The script refuses to
overwrite them.

The P-256 test key is derived from a public label, as the Ed25519 test keys
are (test-keys.json): d = SHA-256(UTF-8("aae-a2a-extension/testkey/v1/" +
"psea-approver")) read as a big-endian integer. It is public by construction
and exists only for tests.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "tests" / "vectors" / "crossrun" / "psea"
LABEL = "aae-a2a-extension/testkey/v1/psea-approver"
KID = "psea-approver"
# P-256 group order.
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

ISS = "approver.example"
AUD = "https://supplier.example/a2a/jsonrpc"  # the audience of the pinned bundle
OP, TIER = "place-order", "high"
IAT = 1793610000  # 2026-11-02T09:00:00Z, verify_at of the pinned bundle
EXP = IAT + 300

ORDER = {"skill": "place-order",
         "transaction": {"amount": 120, "currency": "EUR",
                         "items": [{"sku": "PAPER-A4", "qty": 20}]}}
# XR-26: the same request part with one value changed, amount 121.
CHANGED = {"skill": "place-order",
           "transaction": {"amount": 121, "currency": "EUR",
                           "items": [{"sku": "PAPER-A4", "qty": 20}]}}


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--psea-src", required=True,
                   help="conformance/src of a psea-spec checkout")
    a = p.parse_args()
    sys.path.insert(0, a.psea_src)
    from cryptography.hazmat.primitives.asymmetric import ec
    from psea import Attester, b64u

    targets = [OUT / "approver-key.json", OUT / "XR-25.psea.jws", OUT / "XR-26.psea.jws"]
    if any(t.exists() for t in targets):
        raise SystemExit("the PSEA vectors exist; refusing to replace them")

    d = int.from_bytes(hashlib.sha256(LABEL.encode("utf-8")).digest(), "big")
    if not 1 <= d < N:
        raise SystemExit("label does not give a P-256 scalar")
    priv = ec.derive_private_key(d, ec.SECP256R1())
    nums = priv.public_key().public_numbers()

    def coord(n: int) -> str:
        return b64u(n.to_bytes(32, "big"))

    OUT.mkdir(parents=True, exist_ok=True)
    key = {
        "description": "TEST-ONLY P-256 key of the PSEA approver of XR-25 and XR-26. "
                       "d = SHA-256(UTF-8('" + LABEL + "')) as a big-endian integer. "
                       "Public by construction; never use it for anything but tests.",
        "kid": KID,
        "jwk": {"kty": "EC", "crv": "P-256", "x": coord(nums.x), "y": coord(nums.y),
                "d": coord(d)},
    }
    (OUT / "approver-key.json").write_text(json.dumps(key, indent=2) + "\n", encoding="utf-8")
    att = Attester(KID, priv)
    for name, action in (("XR-25", ORDER), ("XR-26", CHANGED)):
        token = att.sign(action=action, op=OP, tier=TIER, aud=AUD, iss=ISS,
                         jti=name, iat=IAT, exp=EXP)
        (OUT / f"{name}.psea.jws").write_text(token + "\n", encoding="ascii")
    print(f"wrote {', '.join(t.name for t in targets)} to {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
