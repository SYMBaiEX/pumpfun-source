# AMM formatter: complete direct-call group

This check binds three complete code windows to the currently selected AMM
executable and its symbol ELF. It verifies the two child bodies raw-exact and
resolves every direct call from the parent to the corresponding child.
The parent has one differing instruction record, at body offset 432: its signed
relative call reaches the same raw-identical character-count helper in each
image. Neither child contains another direct call.

This adds a small, executable whole-group check to the prior
[pass-33 parent analysis](../../layered-passes/pass-33/README.md). The prefix's
separate return-routing study is also being published in
[PR #22](https://github.com/lalalune/pumpfun-source/pull/22).
Prior raw/pattern matches are not claimed as new discoveries. This packet adds
the complete 1,472-byte leaf and its six LDDW records to this check's explicit
raw-body/direct-edge closure; it does not reinterpret indirect callbacks.

| Candidate symbol role | Original window | Candidate symbol extent | Bytes | Raw body equal |
| --- | --- | --- | ---: | --- |
| `Formatter::pad_integral` | [1132800,1134344) | [1074592,1076136) | 1,544 | No; only call record +432 differs |
| `pad_integral::write_prefix` | [1134344,1134528) | [1076136,1076320) | 184 | Yes |
| `str::count::do_count_chars` | [1142448,1143920) | [1083480,1084952) | 1,472 | Yes |

Names and exact function sizes come from the candidate's actual `STT_FUNC`
records. Original windows remain inferred extents, even when a direct call
observes their entry. The ELF section reader maps virtual addresses to file
offsets; it does not assume those numbers are equal. Whole-image SHA-256 values,
candidate symbols, slice hashes and measurements are in
[measurements.json](measurements.json). The selected status pointer and original
capture hash are checked on every invocation. The symbol ELF must contain
exactly the same code bytes as the selected stripped executable in all three
windows. No code-window relocation is present in either executable.

The five direct call sites in the parent are:

| Body offset | Original target | Candidate target | Corresponding child |
| ---: | ---: | ---: | --- |
| 224 | 1134344 | 1076136 | `write_prefix` |
| 432 | 1142448 | 1083480 | `do_count_chars` |
| 496 | 1134344 | 1076136 | `write_prefix` |
| 912 | 1134344 | 1076136 | `write_prefix` |
| 1336 | 1134344 | 1076136 | `write_prefix` |

Targets are calculated from actual source-register-1 CALL instructions as
`pc + 8 + signed_immediate * 8`. Source-register-0 calls are rejected instead of
being interpreted as relative calls. Branches may target only decoded instruction
starts inside the same window; no branch may enter an LDDW continuation.
All 193 parent, 23 prefix and 178 leaf instruction starts are syntactically
reachable when both conditional arms and call-return continuations are retained.
The leaf contains six complete two-slot LDDW instructions and no calls.
All instruction operands, LDDW payloads, local edges and memory-operation records
can be emitted with `--full`; no address, stack or data operand is masked.

The parent local graph has **218 edges** under this packet's explicit model:
193 instructions minus one EXIT, plus 26 additional conditional-branch edges.
Sixteen unconditional jumps replace fallthrough edges. Calls have a conditional
return-continuation edge; interprocedural targets and EXIT-to-caller edges are
not local edges. This recomputation corrects the 219 count stated in pass 33
under this model. The prefix and leaf have 25 and 197 local edges respectively.

Eight indirect call sites remain unresolved: six in the parent and two in the
prefix. The leaf's 14 memory operations, incoming pointers, stack initialization,
aliases, feasible loop paths and output semantics are not proved by raw equality.
Syntactic reachability assumes an opaque call can return; it does not prove
that a concrete execution reaches a branch or terminates. See the upstream
[sBPF bytecode description](https://github.com/anza-xyz/sbpf/blob/main/doc/bytecode.md)
for instruction/ABI background; the frozen bytes and explicit checks above are
the authority for this packet's measurements.

## Reproduce

From this checkout:

```sh
python3 -B repro/pump_amm/formatter-direct-closure/verify.py --repo .
python3 -B repro/pump_amm/formatter-direct-closure/test_verify.py
```

Ten tests check live image/symbol/capture/status bindings, exact published
measurements, the complete direct-call group, and rejection of a changed child,
wrong corresponding target, source-0 CALL, outward branch, branch into an LDDW
continuation, unsupported opcode and terminal fallthrough. Mutation checks run
below the whole-file hash gate to exercise the structural reasoning itself.
The checker needs only the Python standard library and the already committed
ELF inputs. `--repo` supports a relocated checkout; it creates no file or process.

No source, selected binary, generic inventory classification, status or identity
count changes. No compiler or target VM ran. Complete AMM source/build provenance,
indirect-call/data/ownership closure and whole-file identity remain open.
