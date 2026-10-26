# Guarded native validation, 2026-10-26

Two fresh native builds passed with the repaired OS network-deny recipe. Both
complete executables and unstripped outputs were also compared literally with the
tracked tested collector files: `fdfdb5f2…` (1,590,856 bytes) and `1e088e9a…`
(2,174,728 bytes). This closes the repaired recipe's previously unperformed native
build gate on the recorded host. It does not establish original deployment identity.

The landed guard pin rejected this host before preparation. The successor adds
one exact `sandbox-exec` pin for macOS 27.2 build 26B5101f and preserves the earlier
pin. Apple signature verification passed. Four ordinary loopback controls sent
successfully; four guarded TCP/UDP attempts, directly and through descendants,
failed with permission errors and delivered nothing. The profile is unchanged:
`(version 1)(allow default)(deny network*)`. These observations cover the recorded
loopback controls; they are not a measured library-load inventory.

Fresh preparation authenticated the release downloads, compiler inventory, SDK53,
252 locked crates and the existing observed v1.52/Criterion cache inventories.
Both builds preserved the authenticated inputs and compiled source37. The OS
launcher aggregate and recorded build-sbf exits are zero. Separate helper,
compiler and stripper child exits remain unknown. All 50 synthetic regression
tests pass. The earlier SHA rejection is retained alongside the successful runs.

The old `validation.json` and `receipts/` are unchanged historical evidence. A
local cleanup accidentally deleted their unexported qualification payloads on
2026-10-26. Their old index does not recover those bytes. New qualification reruns
are separate evidence; raw rerun payloads remain local and are not exported here.
The new runs passed 9,269 differential comparisons and 1,024 Surfpool comparisons
(2,048 signed submissions), with zero target failures or mismatches. The existing
fixtures and normalization are unchanged. Crypto checks covered 17,966 retained
transaction fields and 27,332 signature fields, including repeated payloads;
3,003 payloads were distinct. One orchestration-only port precheck failure is
retained; only previously unexecuted families resumed. The compressed rerun index
and raw-file inventory bind these new local results without exporting the payloads.
The differential total is 9,217 base comparisons plus 20 two-curve, 16 nested and
16 route comparisons. Another 32 original-only nested/route controls are retained
separately and excluded from that total.

Run `python3.12 repro/pump/collector-v2-reproduction/native-validation-20261026/verify.py`
to check publication integrity and receipt bindings without executing native
tools or target programs. This checks retained observations, not a new build,
signature verification, network test or replay of unexported transaction data.
