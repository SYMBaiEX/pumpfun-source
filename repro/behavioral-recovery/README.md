# Behavioral recovery overlay

Recovered Pump and Mayhem handlers that are validated against the captured
originals but are **not** in active `programs/` source. Use this overlay when you
need a dispatch-complete build for local SDK testing.

## What it adds

| Handler | Program | Differential result vs. captured original (re-run 2026-10-26) |
| --- | --- | --- |
| `admin_update_token_incentives` | pump | 299 cases, 0 mismatches |
| `claim_token_incentives` | pump | recovered; its differential is bound to an older build record and was not re-run |
| `create_v2` Mayhem mode + `initialize_mayhem_state` (pump→Mayhem CPI) | pump, mayhem | 17 cases, 0 mismatches |
| v3 Token-2022 transfer-fee quotes (`buy_v3`, `sell_v3`, `buy_exact_quote_in_v3`) | pump | 126 cases, 0 mismatches |
| `set_mayhem_virtual_params` (dormant, CPI-only) | pump | 84 cases, 0 mismatches (signer-stub driver) |

The initializer's account-validation mismatch is corrected: `mint_authority` uses
an unchecked account with an explicit signer constraint, and the associated vault
uses `init_if_needed`. Both constraints follow original disassembly and runtime
traces. The five previously differing standalone cases and seven vault-data
variants now match; all 17 genuine Pump-to-Mayhem CPI cases still match. See
[the source-recovery evidence](../mayhem/initializer-account-constraints/README.md).
Whole-program and complete-parser byte identity remain unresolved.

With the overlay applied, pump dispatches 56/56 IDL instructions and Mayhem 25/25.
Builds of this overlay on 2026-10-26 (`scripts/build_partial_candidate.py`):

- Corrected Mayhem (v1.52):
  `repro/mayhem/initializer-account-constraints/candidate.so`
  (sha256 `b088163ae28a3e03649f2da8de03ca7b053a1397275b0fa61716a9f720180d76`).
  The earlier `cbe8c8e7…` candidate remains an unchanged pre-correction baseline in
  `repro/mayhem/recovered-dispatch-25-from-main-v152/main/`.
- Pump (v1.44) builds to sha256
  `df61557a0bed2450d32b277df56a68d3e58ecd87e41486b9ea4c2071e9a67155`. It differs
  from the older committed candidate
  `repro/pump/recovered-dispatch-56-from-main-v144/main/candidate.so`
  (`5392c9a9…`) because the overlay now sits on main's newer `admin_cto.rs`. The
  differentials below were re-run against both builds with identical results.

The `@pump-fun/pump-sdk` harness in
`repro/parallel-work/2026-10-25/independent-reconstruction-review/sdk-integration-test/`
runs create/buy/sell, v3, incentives, Mayhem create and AMM flows against them.

## Why it is not active source

CI hash-binds `programs/pump/src/{lib,trade,create_v2,admin_cto,volume_sync}.rs`
to the selected checkpoint (`scripts/verify_recovered_builds.py`), and the
reconciliation policy only admits source with matching byte-level evidence. None
of these builds is byte-identical to the deployed original, so promoting them
means selecting a new checkpoint and re-running the bound differential suites.
Main's checkpoint notes also flag an AccountInfo ownership question on the
virtual-params proposal that review has not closed.

## Files

`programs/` mirrors the repository layout. Each file replaces its counterpart in
active source; `lib.rs`, `create_v2.rs`, `trade.rs` and `volume_sync.rs` are full
replacements, the rest are new modules. `admin_cto.rs` and the Fees sources are
intentionally absent: main's versions are newer and already include the typed
CTO errors.

`scripts/` holds the recovery differentials and `fixtures/signer_stub` their
signer-forwarder program. They live here rather than in the top-level `scripts/`
and `programs/` because the pass-27 CI guard pins the top-level script set and
lists these exact active paths as must-not-exist.

## Use

```sh
python3 repro/behavioral-recovery/apply.py --target work/behavioral-recovery
cd work/behavioral-recovery
cargo build-sbf --manifest-path programs/pump/Cargo.toml --tools-version v1.44 -- --locked
cargo build-sbf --manifest-path programs/mayhem/Cargo.toml --tools-version v1.52 -- --locked
```

Validate a build against the captured originals (from the repository root):

```sh
python3 repro/behavioral-recovery/scripts/pump_incentives_admin_differential.py --candidate <pump.so> --output work/incentives.json
python3 repro/behavioral-recovery/scripts/pump_set_mayhem_virtual_params_differential.py --candidate <pump.so> --output work/virtual-params.json
python3 repro/behavioral-recovery/scripts/pump_v3_token_extensions_differential.py --candidate <pump.so> --output work/v3.json
python3 repro/behavioral-recovery/scripts/pump_create_mayhem_differential.py --candidate-pump <pump.so> --candidate-mayhem <mayhem.so> --output work/create-mayhem.json
python3 repro/behavioral-recovery/scripts/mayhem_initialize_state_differential.py --candidate <mayhem.so> --output work/mayhem-init.json
```

`fixtures/signer_stub` is the forwarder used to invoke the CPI-only
virtual-params handler with a genuine `invoke_signed` PDA signature.

## Provenance

Recovered in commits `294c9186` (incentives), `14ec9b5c` (validated 56/56 +
25/25 state) and `5f38701c` (virtual-params wiring); the primary checkout's
uncommitted deltas were snapshotted in `1bec3365` and rebased onto main here.
