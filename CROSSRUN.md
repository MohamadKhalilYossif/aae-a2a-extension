# Cross-Run Guide

A cross-run checks one implementation of the
[AAE extension for A2A](spec/aae-a2a-extension-v1.md) against another: your
client against the reference supplier, the reference buyer against your
server, or both. This guide lists what to build, the cases, the expected
result of each case, and the form in which to report a run. It is written so
that you can do all of it without asking us anything.

The reference side of every run is this repository at a commit you name.

## 1. Roles

| Role | You build | Runs against | Who writes the result file |
| :-- | :-- | :-- | :-- |
| `server` | A supplier agent (A2A server) that implements spec Sections 4-8 | the reference buyer, `python -m aae_a2a.crossrun client` | the reference buyer |
| `client` | A buyer agent (A2A client) that implements spec Sections 5, 6 and the checks of 6.3 | the reference supplier, `python -m aae_a2a.crossrun serve` | your client |
| `both` | Both of the above | each other, with no reference code in the loop | your client |

A `server` run is the cheaper one to report, because the reference buyer runs
every case and writes the file for you. A `client` run needs your client to
produce the result file itself (Section 6).

### What a server must offer

- An Agent Card at `/.well-known/agent-card.json` declaring the extension URI
  `https://moltrust.ch/extensions/aae/v1` with `required: true` and the
  `params` of spec Section 4: `draft` `draft-kroehl-agentic-trust-aae-02`,
  `audience` (the URL of your JSON-RPC endpoint), `skills`
  `{"get-quote": {"action": "read"}, "place-order": {"action": "pay"}}`,
  `did_methods` `["example"]`, `accepted_issuers` `["did:example:issuer"]`,
  `deferred_decisions` `true`.
- The JSON-RPC binding of A2A v1.0 (`SendMessage`). The reference buyer uses
  `a2a-sdk` 1.2.2.
- DID resolution for the documents in
  [`tests/vectors/crossrun/did/`](tests/vectors/crossrun/did/), loaded
  locally. `did:example` is never resolved over the network (spec Section 7.4,
  -02 Section 5.2).
- A `place-order` skill that succeeds unless `transaction.items` names a `sku`
  outside `["PAPER-A4", "TONER-K1"]`, and then fails after the AAE was
  accepted. This is what produces the paired case (XR-02 against XR-03).
- A clock within a few minutes of UTC. The reference buyer issues AAEs valid
  from five minutes ago to one hour ahead. Cases XR-14 to XR-17 place `iat`
  30 seconds inside or outside the window of spec Section 7.4 step 4, so client
  and server clocks must agree to within 30 seconds for those four.

### What a client must do

- Discover the card, check `draft`, and present an AAE in
  `metadata[URI].aae` with exactly one data part `{"skill", "transaction"}`
  (spec 6.1), sending `A2A-Extensions: https://moltrust.ch/extensions/aae/v1`.
- Answer the challenge of `TASK_STATE_AUTH_REQUIRED` with a JWS over
  `{nonce, aud, iat, aae_id}` after checking `aud` and `aae_id` (spec 6.3).
- Read the result from `Task.metadata[URI].result` and recompute
  `request_digest` from the request part it sent (spec 8.5).
- Build the AAE variants of Section 3 for the cases it runs.

## 2. Inputs

| Input | Path |
| :-- | :-- |
| Profile | [`spec/aae-a2a-extension-v1.md`](spec/aae-a2a-extension-v1.md) |
| Cases, machine-readable | [`tests/vectors/crossrun/cases.json`](tests/vectors/crossrun/cases.json) |
| DID documents | [`tests/vectors/crossrun/did/`](tests/vectors/crossrun/did/) |
| Test keys | [`tests/vectors/crossrun/test-keys.json`](tests/vectors/crossrun/test-keys.json) |
| `request_digest` vectors | [`tests/vectors/request-digest.json`](tests/vectors/request-digest.json), spec Appendix B |
| -02 Section 5 vectors | [MoltyCel/aae-conformance-vectors](https://github.com/MoltyCel/aae-conformance-vectors) at `2f117799c604f258e67d5c13d69fea63881bdae0` (spec Section 13) |

The test keys are Ed25519 seeds derived as
`SHA-256(UTF-8("aae-a2a-extension/testkey/v1/" + name))`. They are public by
construction and exist only for tests. `issuer` signs AAEs (`assertionMethod`),
`buyer` is the subject and signs challenge responses (`authentication`),
`mallory` has a key and no DID document.

A client may use its own DIDs and keys instead. Start the reference supplier
with `--did-dir <directory of your DID documents>` and
`--accept-issuer <your issuer DID>`; the expected results stay the same.

## 3. Variants

### Audience

Every case depends on one audience value: the challenge carries it as `aud`,
and `allowed_domains` is built from its host.

- In an interactive run the audience is `params.audience` of the Agent Card
  the client discovered, the URL of the server's JSON-RPC endpoint (Section 1).
  The reference supplier sets it from `--public-url`, or from
  `http://<host>:<port>`.
- In an offline run (Section 6.1) there is no endpoint to name. The audience is
  `https://supplier.example/a2a/jsonrpc`, the value of the spec's Section 4
  example, and the host in `allowed_domains` is `supplier.example`.

### AAE and challenge-response variants

"Now" is the server's clock in an interactive run and the evaluation instant
in an offline run. Each case names an AAE variant and a challenge-response
variant. Unless a variant says otherwise, the AAE is a VC secured as an EdDSA compact JWS with
`cty` `aae+json` and `kid` `did:example:issuer#key-1`, issuer
`did:example:issuer`, subject `did:example:buyer`, and:

- `mandate`: `actions` `["read", "pay"]`, `purpose`, `scope`, `principal_did`
  as in `aae_a2a/testkeys.py` `buyer_mandate()`;
- `constraints`: `max_transaction_value` `{"value": 500, "currency": "EUR",
  "required": true}` and `allowed_domains` `{"value": [<host of
  params.audience>], "required": true}`;
- `validity`: `not_before` five minutes ago, `not_after` in one hour,
  `single_use` `false`; `validFrom` equal to `not_before`.

| AAE variant | Difference from the above |
| :-- | :-- |
| `valid` | none |
| `forged` | the same header, signed with `mallory`'s key |
| `expired` | `not_before` two hours ago, `not_after` one hour ago |
| `read_only` | `mandate.actions` `["read"]` |
| `other_domain` | `allowed_domains` `["other-supplier.example"]` |
| `none` | no `aae` member; `metadata[URI]` and the message `extensions` are left out |
| `single_use` | `validity.single_use` `true` |
| `hold` | `mandate` is `aae_a2a/testkeys.py` `held_mandate()` of the action `{"verb": "pay", "category": "office-supplies"}`: `buyer_mandate()` plus `principal` `{"did": "did:example:principal-acme", "public_key": <principal's key>}` and one grant with disposition `hold` for that action, `amount` 0 to 300 and `currency` `EUR` |
| `payload_not_json` | the same header, signed with `issuer`'s key over the payload bytes `{"issuer": "did:example:issuer", ` (not JSON) |
| `duplicate_issuer` | the `valid` payload with a first member `"issuer": "did:example:other-agent"` added in front of it, so `issuer` appears twice; signed with `issuer`'s key |

| Response variant | Meaning |
| :-- | :-- |
| `valid` | JWS over the challenge plus `iat` (now), `kid` `did:example:buyer#key-1`, signed with `buyer`'s key |
| `wrong_key` | the same, signed with `mallory`'s key |
| `iat_past_inside` | `valid` with `iat` 330 seconds before now |
| `iat_past_outside` | `valid` with `iat` 390 seconds before now |
| `iat_future_inside` | `valid` with `iat` 30 seconds after now |
| `iat_future_outside` | `valid` with `iat` 90 seconds after now |

| Ratification variant | Message on the held task (spec 7.6) |
| :-- | :-- |
| `none` | none; the case ends with the task held |
| `principal` | `decision` `APPROVED`, the statement over `enforce.core_digest` signed with `principal`'s key, `authority` `did:example:principal-acme`, `mandate` the full mandate of the AAE |
| `stranger` | the same, signed with `mallory`'s key, `authority` `did:example:mallory`, a DID the mandate does not name |

The spec fixes the `iat` window at now minus 360 seconds to now plus 60
seconds (Section 7.4 step 4). XR-14 to XR-17 sit 30 seconds on either side of
each bound. XR-18 and XR-19 test the reading order of Section 7.2: the
signature is valid in both, the payload is parsed once and strictly, and both
fail at step 2. A receiver that reads `issuer` for step 1 with a first-wins
parser would reject XR-19 at step 1 instead.

`activate: false` means the presentation is sent without the
`A2A-Extensions` header.

## 4. Cases and expected results

Every case is one new task (XR-20 and XR-24: two, one per presentation) with the request part `{"skill": "place-order",
"transaction": <below>}`, run in the order listed. A `server` run covers all
cases. A `client` run must cover the `required` ones and may skip the
`optional` ones.

| Case | Client-side run | AAE / response | `transaction` (skill `place-order`) | Expected | `request_digest` |
| :-- | :-- | :-- | :-- | :-- | :-- |
| XR-01 | required | `valid` / `valid` | `{"amount": 120, "currency": "EUR", "items": [{"sku": "PAPER-A4", "qty": 20}]}` | `TASK_STATE_COMPLETED`, `ACCEPT` | `sha256:84559612f1f46ec0a03f8c448905af075ba4edf66e529b15b50f69c85a68b59a` |
| XR-02 | required | `valid` / `valid` | `{"amount": 80, "currency": "EUR", "items": [{"sku": "DESK-02", "qty": 1}]}` | `TASK_STATE_FAILED`, `ACCEPT` | `sha256:97ff82c176abd81ff1260c0885e3e25c2e651f153c6f4bcb8c6263e77d55198b` |
| XR-03 | required | `valid` / `valid` | `{"amount": 900, "currency": "EUR"}` | `TASK_STATE_REJECTED`, `REJECT`, step 7, `max_transaction_value_exceeded` | `sha256:edf9dc35873b6b0f0c46f8aeead5193a7dc97bcdecc6116ae68899b75e0e86d6` |
| XR-04 | optional | `valid` / `valid` | `{"note": "Bürobedarf", "unit_price": 6.25, "amount": 120.0, "currency": "EUR"}` | `TASK_STATE_COMPLETED`, `ACCEPT` | `sha256:20673ecb3bc45abe8dd1aa5455aa90397eb769e42f9af1cff56680f4204eb0c1` |
| XR-05 | required | `valid` / `valid` | `{"amount": 120, "currency": "EUR"}` | `TASK_STATE_COMPLETED`, `ACCEPT` | `sha256:7081684b67799fdd4045a25d028f770a8254746ff279dbabb0486bdb7eeb4176` |
| XR-06 | required | `valid` / `valid` | `{"amount": 120, "currency": "EUR", "items": [{"sku": "PAPER-A4", "qty": 20}]}` | `TASK_STATE_COMPLETED`, `ACCEPT`, task id differs from XR-01's | `sha256:84559612f1f46ec0a03f8c448905af075ba4edf66e529b15b50f69c85a68b59a` |
| XR-07 | optional | `forged` / `valid` | `{"amount": 120, "currency": "EUR"}` | `TASK_STATE_REJECTED`, `REJECT`, step 1, `invalid_signature` | `sha256:7081684b67799fdd4045a25d028f770a8254746ff279dbabb0486bdb7eeb4176` |
| XR-08 | optional | `expired` / `valid` | `{"amount": 120, "currency": "EUR"}` | `TASK_STATE_REJECTED`, `REJECT`, step 3, `expired_not_after` | `sha256:7081684b67799fdd4045a25d028f770a8254746ff279dbabb0486bdb7eeb4176` |
| XR-09 | optional | `valid` / `wrong_key` | `{"amount": 120, "currency": "EUR"}` | `TASK_STATE_REJECTED`, `REJECT`, step 4, `challenge_signature_invalid` | `sha256:7081684b67799fdd4045a25d028f770a8254746ff279dbabb0486bdb7eeb4176` |
| XR-10 | optional | `read_only` / `valid` | `{"amount": 120, "currency": "EUR"}` | `TASK_STATE_REJECTED`, `REJECT`, step 6, `action_not_in_mandate` | `sha256:7081684b67799fdd4045a25d028f770a8254746ff279dbabb0486bdb7eeb4176` |
| XR-11 | optional | `other_domain` / `valid` | `{"amount": 120, "currency": "EUR"}` | `TASK_STATE_REJECTED`, `REJECT`, step 7, `domain_not_in_allowlist` | `sha256:7081684b67799fdd4045a25d028f770a8254746ff279dbabb0486bdb7eeb4176` |
| XR-12 | optional | `valid` / `valid`, not activated | `{"amount": 120, "currency": "EUR"}` | JSON-RPC error `-32008`, no task | none |
| XR-13 | optional | `none` / `valid` | `{"amount": 120, "currency": "EUR"}` | JSON-RPC error `-32602`, `reason_code` `aae_missing`, no task | none |
| XR-14 | optional | `valid` / `iat_past_inside` | `{"amount": 120, "currency": "EUR"}` | `TASK_STATE_COMPLETED`, `ACCEPT` | `sha256:7081684b67799fdd4045a25d028f770a8254746ff279dbabb0486bdb7eeb4176` |
| XR-15 | optional | `valid` / `iat_past_outside` | `{"amount": 120, "currency": "EUR"}` | `TASK_STATE_REJECTED`, `REJECT`, step 4, `iat_too_old` | `sha256:7081684b67799fdd4045a25d028f770a8254746ff279dbabb0486bdb7eeb4176` |
| XR-16 | optional | `valid` / `iat_future_inside` | `{"amount": 120, "currency": "EUR"}` | `TASK_STATE_COMPLETED`, `ACCEPT` | `sha256:7081684b67799fdd4045a25d028f770a8254746ff279dbabb0486bdb7eeb4176` |
| XR-17 | optional | `valid` / `iat_future_outside` | `{"amount": 120, "currency": "EUR"}` | `TASK_STATE_REJECTED`, `REJECT`, step 4, `iat_in_future` | `sha256:7081684b67799fdd4045a25d028f770a8254746ff279dbabb0486bdb7eeb4176` |
| XR-18 | optional | `payload_not_json` / `valid` | `{"amount": 120, "currency": "EUR"}` | `TASK_STATE_REJECTED`, `REJECT`, step 2, `payload_not_json` | `sha256:7081684b67799fdd4045a25d028f770a8254746ff279dbabb0486bdb7eeb4176` |
| XR-19 | optional | `duplicate_issuer` / `valid` | `{"amount": 120, "currency": "EUR"}` | `TASK_STATE_REJECTED`, `REJECT`, step 2, `payload_not_json` | `sha256:7081684b67799fdd4045a25d028f770a8254746ff279dbabb0486bdb7eeb4176` |
| XR-20 | optional | `single_use` / `valid`, presented twice | `{"amount": 120, "currency": "EUR"}` | first `TASK_STATE_COMPLETED`, `ACCEPT`; second `TASK_STATE_REJECTED`, `REJECT`, step 5, `single_use_already_consumed` | `sha256:7081684b67799fdd4045a25d028f770a8254746ff279dbabb0486bdb7eeb4176` |
| XR-21 | optional | `hold` / `valid`, ratification `none` | `{"action": {"verb": "pay", "category": "office-supplies"}, "amount": 120, "currency": "EUR"}` | `TASK_STATE_INPUT_REQUIRED`, `PENDING` | `sha256:91d816ca447777616f133386a3be2d0129be4e7a5edd29b5f7aabd6b2aa26c70` |
| XR-22 | optional | `hold` / `valid`, ratification `principal` | `{"action": {"verb": "pay", "category": "office-supplies"}, "amount": 120, "currency": "EUR"}` | `TASK_STATE_COMPLETED`, `ACCEPT`, ratification `RATIFIED` | `sha256:91d816ca447777616f133386a3be2d0129be4e7a5edd29b5f7aabd6b2aa26c70` |
| XR-23 | optional | `hold` / `valid`, ratification `stranger` | `{"action": {"verb": "pay", "category": "office-supplies"}, "amount": 120, "currency": "EUR"}` | `TASK_STATE_INPUT_REQUIRED`, `PENDING`, ratification `REJECTED` | `sha256:91d816ca447777616f133386a3be2d0129be4e7a5edd29b5f7aabd6b2aa26c70` |
| XR-24 | optional | `valid` / `valid`, the same AAE presented twice | `{"amount": 120, "currency": "EUR"}` | both `TASK_STATE_COMPLETED`, `ACCEPT` | `sha256:7081684b67799fdd4045a25d028f770a8254746ff279dbabb0486bdb7eeb4176` |

XR-21 to XR-23 cover a deferred decision (spec Section 7.6). The grant's
verdict is PENDING, so the supplier holds the task in
`TASK_STATE_INPUT_REQUIRED` with the verdict record and the authorities the
mandate names. The client then sends the ratification of the case's variant
on the held task, signing the statement of -02 §6.3 over
`result.enforce.core_digest`. A ratification from the principal closes the
hold and the skill runs. One from a DID the mandate does not name produces a
REJECTED record and leaves the task held (-02 §6.4).

XR-06, XR-20 and XR-24 belong together. XR-06 is a new request with a new
AAE: the request part of XR-01 again, under an AAE of its own with its own VC
id, so only `request_digest` is shared with XR-01. XR-20 and XR-24 each present
one AAE twice, the same bytes both times, each time as a new task with a new
challenge nonce. XR-20's AAE is single-use; XR-24's has `single_use` `false`
and is reused. For all three, `cases.json` states two expectations apart:

- *authorization*: the outcome of every step except step 5 for that
  presentation, as if no earlier use were counted. It is `ACCEPT` with steps 1,
  2, 3, 4, 6 and 7 in all five presentations.
- *admission*: step 5 against what the server has already accepted. XR-06 is
  admitted. XR-20 is admitted the first time; the second time the same valid
  authorization is not admitted, at step 5 with `single_use_already_consumed`.
  XR-24 is admitted both times, since a reusable AAE carries no use to consume.

A live run observes admission through the verdict. Authorization cannot be
observed from a rejection at step 5, since the server stops there; it is
checked on the pinned bundle (Section 5). For XR-20 and XR-24 the result entry carries an
`attempts` list with one entry per presentation, each with the members of a
task entry (Section 6).

The `request_digest` column is the value of spec Section 8.5 for that request
part; the result of a rejection carries it as well (spec 8.2). XR-04 uses the
member order, `120.0` and non-ASCII string of vector B.2, so it fails if
either side hashes something other than the JCS form of the request part.

XR-04 is an exception to the client rule of spec Section 6.4 and tests the
server's side of it. A conforming client encodes integer-valued fields as JSON
integers, so it sends `120`, not `120.0`. XR-04 sends `120.0` on purpose: the
server must treat a number with an integral value as an integer, and since JCS
serializes `120.0` and `120` alike, `request_digest` is the same for both. A
client-side run may therefore skip XR-04. A client that runs it sends `120.0`
as written in `cases.json`, outside its own rule, only for this case. In the
cases of commit `08f41146` XR-04 is still required for a client-side run; a
run against those cases is checked with them (Section 7.1) and stays valid.

## 5. Running

Install once (Python 3.12): `make install`, or
`python -m pip install --require-hashes --no-deps -r requirements.txt`.

**Reference against reference** (what CI does, and the baseline for your
run):

```
scripts/crossrun-local.sh            # or: make crossrun
```

This starts the reference supplier and the reference buyer as two processes on
`127.0.0.1`, runs all cases, writes `.crossrun/local.json`, validates it, and
logs every decision the supplier made to `.crossrun/supplier-decisions.jsonl`.

**Pinned bundle** — fixed bytes for XR-01, XR-06, XR-20 and XR-24, for a verifier
that checks bytes rather than running a client, and for comparing two runs
byte for byte. [`tests/vectors/crossrun/pinned/`](tests/vectors/crossrun/pinned/)
holds:

| File | Content |
| :-- | :-- |
| [`bundle.json`](tests/vectors/crossrun/pinned/bundle.json) | `verify_at`, the card `params` (audience `https://supplier.example/a2a/jsonrpc`, skills, DID methods, accepted issuers), the nonce derivation, and per case the request part, the AAE file and per attempt the challenge, the response file and the expected result with `authorization` and `admission` |
| `XR-01.aae.jws`, `XR-06.aae.jws`, `XR-20.aae.jws`, `XR-24.aae.jws` | the AAEs, one per case and presented in every attempt of that case; XR-20's is single-use |
| `XR-01.1.response.jws`, `XR-06.1.response.jws`, `XR-20.1.response.jws`, `XR-20.2.response.jws`, `XR-24.1.response.jws`, `XR-24.2.response.jws` | the challenge responses, one per attempt, `iat` equal to `verify_at` |
| `did/` | the DID documents of [`tests/vectors/crossrun/did/`](tests/vectors/crossrun/did/), copied |
| [`MANIFEST.sha256`](tests/vectors/crossrun/pinned/MANIFEST.sha256) | the SHA-256 of every other file in the bundle; `shasum -a 256 -c MANIFEST.sha256` in the directory checks them |

A challenge response answers one nonce, and a server mints the nonce. For the
pinned responses to verify, the supplier has to mint exactly the pinned nonces,
so the bundle fixes what a deployment never fixes: the nonce key and the random
part, both derived from public labels. `bundle.json` `nonce` states the whole
derivation, the same as `SubjectBinding.mint()` in
[`aae_a2a/challenge.py`](aae_a2a/challenge.py):

1. master key = SHA-256 over the ASCII bytes of `master_key_input`
   (`aae-a2a-extension/pinned/v1/nonce-master`);
2. nonce key = HMAC-SHA256 with the master key as key over the ASCII bytes of
   `key_label` (`aae-a2a-extension/v1/subject-binding-nonce`);
3. random part = the first 32 hex digits of SHA-256 over the UTF-8 bytes of
   `random_prefix` + `aae_id` + `/` + n, where n counts the nonces minted for
   that `aae_id` from 1 in bundle order;
4. expiry = `verify_at` in seconds since the Unix epoch plus `lifetime_s`
   (300), as a decimal string;
5. authenticator = base64url without padding of HMAC-SHA256 with the nonce key
   over the UTF-8 bytes of random `.` expiry `.` `aud` `.` `aae_id`;
6. nonce = random `.` expiry `.` authenticator.

`tests/test_crossrun.py` recomputes every pinned nonce this way with `hashlib`,
`hmac` and `base64` alone. Run the bundle with the supplier's clock fixed at
`verify_at`:

```
.venv/bin/python -m aae_a2a.crossrun serve --port 8790 --pinned tests/vectors/crossrun/pinned
.venv/bin/python -m aae_a2a.crossrun client --url http://127.0.0.1:8790 --pinned tests/vectors/crossrun/pinned
```

`--pinned` fixes the clock at `verify_at`, the audience and the nonce
derivation; `--at <RFC 3339 UTC>` alone fixes only the clock and can be used
with any run. Present the cases in order and each attempt as a new task. The
client checks that every challenge equals the pinned one before it answers, and
compares each attempt with its expected result. `python -m aae_a2a.crossrun pin`
rebuilds the bundle; the result is byte-identical, since every input is fixed
and Ed25519 signatures are deterministic.

**Role `server`** — the reference buyer against your supplier:

```
.venv/bin/python -m aae_a2a.crossrun client \
  --url https://your-supplier.example \
  --out crossruns/2026-11-02-yourname-server.json \
  --participant "Your Name" --participant-url https://github.com/you \
  --server-impl "your-supplier" --server-repo https://github.com/you/your-supplier \
  --server-commit <40-character SHA of your server>
```

`--url` is the base URL under which your Agent Card is served. The exit status
is non-zero if any case fails.

**Role `client`** — your buyer against the reference supplier:

```
.venv/bin/python -m aae_a2a.crossrun serve --port 8790 \
  --record crossruns/2026-11-02-yourname-client.decisions.jsonl
```

Point your client at `http://127.0.0.1:8790`. `--public-url` sets the
audience if the supplier is reached under another URL. The decision log has
one line per task with `task_id`, `task_state`, `verdict`, `step`,
`reason_code` and `request_digest`, so both sides of the run can be compared
line by line.

**Role `both`**: run your client against your server and write the result file
as in Section 6. Name the commits of both sides.

## 6. Result file

One JSON file per run, format `aae-a2a-crossrun/1`. See
[`crossruns/TEMPLATE.json`](crossruns/TEMPLATE.json).

| Member | Content |
| :-- | :-- |
| `format` | `"aae-a2a-crossrun/1"` |
| `profile`, `draft` | the extension URI and `draft-kroehl-agentic-trust-aae-02` |
| `cases_commit` | the 40-character commit SHA of this repository whose `cases.json` the run used |
| `cases_sha256` | `sha256:` and the SHA-256 of `cases.json` as run; it must equal the hash of `cases.json` at `cases_commit` |
| `run_at` | RFC 3339 UTC |
| `participant` | `name` to credit, optional `url` |
| `receiver_provenance` | how the implementation the participant built was written: `clean_room`, `reference_informed` or `unknown` (below); required |
| `client`, `server` | `implementation`, `repository`, `commit` (40-character SHA), `dirty: true` if the working tree differed from that commit; `server.agent_card` |
| `cases` | one entry per case, in order (below) |
| `summary` | `{"pass", "fail", "skipped"}` counts |

Each entry in `cases`:

| Member | When | Content |
| :-- | :-- | :-- |
| `id` | always | case id |
| `result` | always | `pass`, `fail` or `skipped` |
| `task_id`, `task_state` | a task was returned | as returned |
| `verdict` | a task was returned | `result.verdict`, `ACCEPT` or `REJECT` |
| `request_digest` | a task was returned | `result.request_digest`, as returned (not recomputed) |
| `steps_passed` | `ACCEPT` | integers |
| `step`, `reason_code` | `REJECT` | as returned |
| `jsonrpc_code`, `reason_code` | JSON-RPC error | the error code and `ErrorInfo.metadata.reason_code` if present |
| `attempts` | a case with several presentations (XR-20, XR-24) | one entry per presentation, in order, each with the members above that apply |
| `ratification_status` | a ratification was sent | `result.ratification.status`, `RATIFIED` or `REJECTED` |
| `notes` | optional | free text, for example a differing `reason_code` |

A case passes when `task_state`, `verdict`, `request_digest` and, for a
rejection, `step` equal the expected values, an accepted case has
`steps_passed` containing 1 to 7, XR-06's task id differs from XR-01's, and
where a case states `admission`, the verdict is `ACCEPT` exactly when the
presentation is to be admitted. For XR-20 and XR-24 each attempt passes on its
own and the attempts are distinct tasks.
For an error case, `jsonrpc_code` decides. A different `reason_code` is a note,
not a failure: spec 8.4 lets a server use codes it does not list.

`receiver_provenance` names how the side the participant built was written:
the receiver in an offline run or a server run, the client in a client run.

| Value | Meaning |
| :-- | :-- |
| `clean_room` | written from the profile text and this guide alone, without the source code of this repository |
| `reference_informed` | the source code of this repository was read or used while writing it |
| `unknown` | the participant has not stated either |

The value is the participant's own statement. Where the participant has not
made one, or a statement is not theirs, the value is `unknown`; a file without
the member does not validate. Independence is never inferred from the number of cases that pass:
a run that passes every case says nothing about how its receiver was written.

### 6.1 Offline receiver runs

In an offline run a receiver you built decides each case from artefacts a
client wrote, with no live counterpart: no Agent Card, no HTTP and no commits
on the other side to name. The receiver plays the server role, so it decides
every case and none may be skipped. Report it in the same format with
`"form": "offline"` and these members in place of `client` and `server`. See
[`crossruns/TEMPLATE-offline.json`](crossruns/TEMPLATE-offline.json).

| Member | Content |
| :-- | :-- |
| `form` | `"offline"`; absent or `"interactive"` means the form above |
| `receiver` | `implementation` and `version`; `commit` (40-character SHA) if the receiver is in a repository, otherwise `content_sha256` (`sha256:` and the SHA-256 of an archive of its code); optional `repository` |
| `audience` | `https://supplier.example/a2a/jsonrpc` (Section 3, "Audience") |
| `evaluation_instant` | the RFC 3339 UTC instant every temporal check used and every issued validity window was computed from |
| `inventions` | one `{"what", "choice"}` per point where the profile or this guide is silent and the run had to choose, under the participant's name; an empty list if there were none |

The case entries and the pass rule are those of the interactive form. A run
that derives task ids deterministically so that it reproduces records that as
an invention; the profile leaves the form of task ids open (spec Section 8.3).

Validate before reporting:

```
.venv/bin/python -m aae_a2a.crossrun check crossruns/2026-11-02-yourname-server.json
```

`check` reads `cases.json` at `cases_commit` from this repository, compares its
hash with `cases_sha256`, and checks the run against those cases, not the
current ones. It recomputes `pass` or `fail` from what each entry records, so a
file cannot claim a pass its own observations do not support. Every run needs
`receiver_provenance` with one of its three values. For an interactive
run it also requires commit SHAs for both sides and every `required` case; for
an offline run it requires the members of Section 6.1 and every case.

## 7. Reporting a run

1. Publish the result file in your own repository if you can; that is your
   record of the run.
2. Open a pull request against this repository that adds the file under
   [`crossruns/`](crossruns/) as `<YYYY-MM-DD>-<participant>-<role>.json` and
   one row in the credit table of [`crossruns/README.md`](crossruns/README.md).
   CI runs `check` on every file there. If you would rather not open a pull
   request, open an issue with the file attached or linked.
3. A failing case is worth reporting. Say in the pull request which side you
   think is wrong; if it is the reference, that is a bug here.

Runs are credited with the participant's name, the commits of both sides, the
state of the cases they ran and the receiver provenance the participant states.

### 7.1 A run holds for the cases it ran

A run is a result about the cases at its `cases_commit` and stays valid for
them when the case set changes later: cases are added, and expectations follow
the profile. CI checks every reported file against its own `cases_commit`. A
re-run against newer cases is voluntary. It is a new file with its own date and
`cases_commit` and its own row in the credit table, and the earlier file
stays. The reference buyer writes `cases_commit` as the commit of the checkout
it runs from; if `cases.json` differs from that commit in the working tree, the
run does not validate, because the cases it ran were never published.

## 8. Not covered by this case set

Delegation chains (step 9) are in the reference tests (`tests/test_flow.py`)
and the conformance vectors, not in this case set. Grant evaluation is in the
set only as the hold of XR-21 to XR-23; PERMIT and DENY under grants, a
DISAPPROVED decision and the other REJECTED causes of -02 §6.4 are in
`tests/test_flow.py` and `tests/test_deferred.py`. There is no hosted reference endpoint; every run is local or
against an endpoint the participant operates.
