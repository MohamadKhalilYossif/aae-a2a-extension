# Reported cross-runs

One JSON file per run, in the format of [TEMPLATE.json](TEMPLATE.json) and
[CROSSRUN.md](../CROSSRUN.md#result-file). CI validates every file here with
`python -m aae_a2a.crossrun check`.

File name: `<YYYY-MM-DD>-<participant>-<role>.json`, where role is `client`
(your client against the reference supplier), `server` (the reference buyer
against your server), `both` or `offline` (an offline receiver run,
[CROSSRUN.md](../CROSSRUN.md) Section 6.1).

## Credit

Each run is credited to the participant who ran it, with the commits of both
sides as recorded in the result file. A run with failures is listed as well;
the failure is a finding about one of the two sides, not about the participant.

A run holds for the cases it ran ([CROSSRUN.md](../CROSSRUN.md), Section 7.1).
The column *Cases* names the commit of this repository whose `cases.json` the
run used, its `cases_commit`; a later re-run against newer cases gets a row of
its own.

| Date | Participant | Role | Cases (commit) | Client (commit) | Server (commit) | Result | File |
| :-- | :-- | :-- | :-- | :-- | :-- | :-- | :-- |
| 2026-10-30 | [Prasanna Bableshwar](https://github.com/bprasana/aae-a2a-crossrun) | offline | [`6c857ee`](https://github.com/MoltyCel/aae-a2a-extension/commit/6c857eeb60a9dac379954f5be5900a10616dfc7b) | receiver [`04cc8c5`](https://github.com/bprasana/aae-a2a-crossrun/commit/04cc8c5966b8a1a4f63495a4e4ce6d71f8f3cdc7) | none (offline) | 13 pass, 0 fail | [2026-10-30-prasanna-bableshwar-offline.json](2026-10-30-prasanna-bableshwar-offline.json) |
| — | Songbo Bu | client | [`08f4114`](https://github.com/MoltyCel/aae-a2a-extension/commit/08f41146ac0d24d0d3e6212256fd9f3f58079adb) | — | — | "Songbo Bu: separately written raw JSON-RPC client against the reference supplier at 08f41146, XR-01 to XR-06, XR-20 and XR-24 as expected" | — |
| — | Iman Schrock | offline | [`08f4114`](https://github.com/MoltyCel/aae-a2a-extension/commit/08f41146ac0d24d0d3e6212256fd9f3f58079adb) | — | — | "Iman Schrock (EMILIA Protocol): independent offline receiver check at 08f41146 using synthetic trust and clock inputs; XR-01, XR-06, XR-20 and XR-24 matched the tested expectations." | — |
| 2026-11-02 | [Tymofii Pidlisnyi (Agent Passport System)](https://github.com/aeoess) | client | [`08f4114`](https://github.com/MoltyCel/aae-a2a-extension/commit/08f41146ac0d24d0d3e6212256fd9f3f58079adb) | [`58639f6`](https://github.com/Agent-Authority-Conformance/aps-conformance-suite/tree/58639f603686c5aea9ed529e7080dfc7a4539435/interop/aae-a2a-client-08f41146/client) | reference supplier [`08f4114`](https://github.com/MoltyCel/aae-a2a-extension/commit/08f41146ac0d24d0d3e6212256fd9f3f58079adb) | 24 pass, 0 fail | [2026-11-02-tymofii-pidlisnyi-client.json](2026-11-02-tymofii-pidlisnyi-client.json) |

The limits of that run, in the participant's own words
([findings.md](https://github.com/bprasana/aae-a2a-crossrun/blob/04cc8c5966b8a1a4f63495a4e4ce6d71f8f3cdc7/findings.md)):
"The run was not blind. The expected results are published in the cases file
and in the guide, and the implementer had read them." And: "It does not
establish conformance of this receiver to the profile, because the interactive
run the guide defines was not performed. It does not establish that a second
implementation would agree on inputs neither has seen, in particular on the
nonce format and the iat window, where the text is silent." His
[run-report.md](https://github.com/bprasana/aae-a2a-crossrun/blob/04cc8c5966b8a1a4f63495a4e4ce6d71f8f3cdc7/run-report.md)
states the offline form and the artefacts it builds instead of the transport;
his six named inventions are carried in the result file.

The file above restates his run in the format of this repository. His own
result file is kept unchanged at
[sources/2026-10-30-prasanna-bableshwar-offline.source.json](sources/2026-10-30-prasanna-bableshwar-offline.source.json)
(from `bprasana/aae-a2a-crossrun` at `04cc8c5`, records in `a68bb04`,
sha256 `45474183ddc0080592f11ffa0e1a534f239e9ee253289d713a5f4a464435acf3`).
