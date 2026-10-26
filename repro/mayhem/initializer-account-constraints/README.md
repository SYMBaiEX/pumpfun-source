# Mayhem initializer account constraints

Recover two clauses in the behavioral overlay's `InitializeMayhemState` context:
`mint_authority` is an `UncheckedAccount` with an explicit signer constraint, and
the associated vault uses `init_if_needed`. Pump PDA seeds, token-account checks
and the Mayhem state's unconditional `init` remain enforced.

The original parser checks the signer flag late (`0x6ae58`, error 2002 at
`0x6b3c0`). The old reconstruction instead deserialized a second `Signer` early,
returning 3010 before mint deserialization. The original vault-initialization
closure (`0x6b548`) tests all four owner limbs and skips creation for an existing
account. Runtime traces independently confirm ATA creation only for an absent
vault. Compressed disassemblies and the partial signer-only attempt are retained.

Two fresh v1.52 builds produce `candidate.so`, SHA-256
`b088163ae28a3e03649f2da8de03ca7b053a1397275b0fa61716a9f720180d76`
(695,456 bytes), from the published overlay. The unchanged pre-correction baseline
was independently rebuilt as `cbe8c8e7…` before testing the source changes.

Validation against the captured original:

- Five standalone cases: mismatches fall from five to zero. The driver now exits
  nonzero on a candidate mismatch instead of merely confirming the original gate.
- Seven existing-vault data variants match, including wrong mint/authority and
  malformed/uninitialized data. Rejection comparisons cover error, AnchorError and
  `state_created`, without requiring raw log or compute equality.
- All 17 genuine Pump-to-Mayhem CPI cases match, including 11 successes. The caller
  is the unmodified captured Pump, so this isolates the Mayhem reconstruction.
- 9,589 existing comparisons have zero mismatches. Three captured two-step burn
  sequences pass their existing verifier with the known second-error-log differences.
  Full regression payloads remain local; their compact inventory is not a portable replay.

Complete parser and ELF byte identity remain false. The original parser is 8,784
bytes, baseline 9,960 and corrected 10,576. Ordered exact-instruction alignment
increases from 135 to 204; this is a diagnostic, not a recovery percentage or body
match. Error-constructor calling conventions still differ. No selected checkpoint
or active `programs/` source is changed.

Apply/build the overlay using its existing README, then run its initializer driver
and `check_vaults.py --repo <repo> --candidate <build.so> --output <fresh.json>`.
For CPI checks, pass both `--candidate-pump evidence/original/pump/deployed.so` and
`--candidate-mayhem <build.so>` to the overlay's `pump_create_mayhem_differential.py`.
`manifest.sha256` seals the retained files; raw observations keep their coverage limits.
