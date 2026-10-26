# Fees terminal comparison helper: bounded CFG certificate

The selected Fees binary's 272-byte `__gedf2` symbol is raw-identical to the
captured original's terminal text interval. This packet adds a complete local
control-flow certificate and rechecks both complete current Rent caller windows
and every one of their signed direct-call operands. It supports the terminal
immediate-target comparison without changing the generic inventory's conservative
classifications, source, selected binary, status or handler counts.

| Input | SHA-256 |
| --- | --- |
| Captured Fees payload | `4f2955d0f6b40cc9ff7daa18ccad7d19119ba1249759f4e7e3bb691beee6b35e` |
| Selected Fees executable | `2387f8139a13918a5c9c523f140ecdd72db7243c8e2ed9cd7e1ff9d42ad6c8af` |
| Selected symbol ELF | `4a8084f8a1056e3d0b2df5b0a272c1a3f0a56d3e96532e1b8a2ba7eb21d6ac4c` |
| Both terminal-helper slices | `5064629c0b173ec75a08a105975751990109ead5c78610174e373612d9c53026` |

The candidate symbol's actual ELF `STT_FUNC` extent is [787152,787424).
The original interval is [799664,799936): its start is an observed direct-call
target and its end is the allocated `.text` boundary. The original has no
recovered historical function symbol for this interval. A self-contained leaf
does not prove historical source/function ownership or uniqueness.

The existing [pass-23 inventory](../../layered-passes/pass-23/fees-current-evidence/analysis/full-function-inventory.json)
already retained this complete raw match as a supplemental terminal match. The
earlier [8f89 report](../function-inventory-8f89/REPORT.md) explicitly identified
the two Rent conflicts as a boundary artifact. Raw equality and that explanation
are prior results, not discoveries of this packet. The added evidence is the
current-input-bound CFG certificate and a small, independently replayable verifier.

## Complete local control flow

The 34 eight-byte slots decode to 29 instructions, including five two-slot LDDW
instructions. All 29 instruction starts are reachable from the admitted entry.
Eight conditional and two unconditional branches target instruction starts
strictly inside the 272 bytes. The complete graph is acyclic and every local path
reaches the sole EXIT at byte offset 264. No call, syscall, indirect branch,
memory access or relocation occurs in the interval. No branch targets an LDDW
continuation slot. The verifier rejects unsupported opcodes instead of assigning
them default flow behavior.

This is a finite static control-flow result. It neither executes the helper nor
proves its floating-point specification, calling convention at every possible
caller, or original compiler provenance.

## Both complete Rent callers

| Candidate symbol | Original interval | Candidate interval | Direct calls |
| --- | --- | --- | ---: |
| `Rent::minimum_balance` | [725664,726064) | [710688,711088) | 8 |
| `Rent::is_exempt` | [726064,726488) | [711088,711512) | 8 |

Both caller pairs agree over every byte after masking only relative-call
immediates and recorded LDDW relocation fields. Their relocation offset/type
patterns agree. All 16 signed call displacements are decoded from the saved raw
instructions and recomputed as `pc + 8 + immediate * 8`; no candidate target is
assigned by a symbol name alone. In both callers, the call at body offset 232
targets original 799664 and candidate 787152.

The eight corresponding immediate-target windows also agree under the same
documented normalization. These targets comprise `__multi3`, `__floatundidf`,
`__muldf3`, the terminal comparison helper, `__fixunsdfdi`, `__gtdf2`, and two
overflow panic wrappers, with names taken only from the candidate symbols.
`__muldf3` and the panic wrappers have further calls; their recursive call/data
closure and the caller's relocated diagnostic contents remain unproved. Thus
the certificate supports the bounded terminal edge and complete immediate-body
comparisons, not unrestricted equivalence of Rent or the whole executable.

## Reproduce

The packet retains 20 exact slices totaling 5,216 bytes, original ELF section
mappings and relocation records, signed calls, the candidate symbol record, full
input hashes, the prior inventory hash and deterministic measurements. A stdlib
ELF reader calculates each slice's file offset from its section virtual address;
equal file/virtual offsets are not assumed.

From the repository root, verify the live selected images and saved evidence:

```sh
python3 -B repro/pump_fees/rent-terminal-helper-proof/verify.py --repository . --self-test
```

From any directory, including a relocated copy, replay saved evidence only:

```sh
python3 -B /path/to/rent-terminal-helper-proof/verify.py --self-test
```

Saved-only mode verifies the packet seals, exact raw bytes, complete CFG and
signed edges. Only `--repository` independently rechecks the full original,
candidate and symbol ELF hashes, actual section mappings/relocations, candidate
symbol extent, original `.text` end and selected status hash. The saved metadata
alone is not independent evidence of absent full ELF contents.

Eight negative CFG mutations must fail: a call, memory load, outward branch,
branch into an LDDW continuation, cycle, terminal fallthrough, invalid register
and injected relocation. All mutations are in memory. No compiler, contract VM,
network call, program-source change or executable edit is performed.
