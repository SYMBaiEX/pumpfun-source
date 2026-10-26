# Collector v2 reproducible build

Rebuilds the existing **unselected** collector candidate from its exact 37-source
snapshot. The preserved pre-repair build receipts report both complete tested outputs:

| Output | Bytes | SHA-256 |
| --- | ---: | --- |
| Executable | 1,590,856 | `fdfdb5f27af9b8c22effd48ea523c06bd037ceedf49df0da8178cad19eed38f5` |
| Unstripped symbols | 2,174,728 | `1e088e9add0218ebf6745a7f7557a4dc55dc68e86ec97790584db7f169c14bc3` |

## Run

Requires Darwin ARM64, Python 3.12+, `/usr/bin/sandbox-exec` with a supported pinned
executable hash, and complete existing v1.52 platform-tools and Darwin Criterion
v2.3.2 caches matching [install-cache-identity](install-cache-identity/REPORT.md).
Those inventories are newly observed local input identities, not official release
asset authentication, historical provenance or a measured loaded-library set. Preparation
downloads authenticated v1.44 compiler tools, Agave 2.1.21 and Rustup 1.29.0,
installs host Cargo 1.94.0 privately, and fetches the unchanged locked dependency
graph. Existing global toolchain aliases are preserved. The SDK-required v1.44
cache link is created only when absent; an existing tree must match completely.

```sh
python3.12 repro/pump/collector-v2-reproduction/prepare.py --output work/collector-tools
python3.12 repro/pump/collector-v2-reproduction/reproduce.py \
  --prepared work/collector-tools --output work/collector-build
python3.12 -m unittest discover -s repro/pump/collector-v2-reproduction -p 'test_*.py'
```

`prepare.py --download-cache PATH --registry-cache PATH` can reuse authenticated
downloads and crate archives. Build output must be fresh and outside the prepared
tools. The repaired reproduction wraps the helper and all descendants in the OS
profile `(version 1)(allow default)(deny network*)`; it fails closed if the pinned
sandbox executable is missing or altered. Cargo offline remains enabled. The
network guard is used for reproduction; preparation remains an online phase.
Reproduction uses a fresh source copy, target and private
Rustup aliases. The recorded SDK's content is retained; executable modes come
from the matching official release. Captured original bytes are staged outside
the Rust inputs solely for the frozen helper's postcompile comparison. Tested
candidate bytes are never copied into the build workspace.

`reproduction.json` records the wrapped and helper commands, OS guard/profile,
new cache pins, guarded-command aggregate exit, authenticated inputs and
whole-file equality. Failed attempts retain their logs and cannot become a pass.
Both output hashes, all source inputs, compiler files and links, SDK files and
locked crate sources are checked before acceptance. The complete v1.52 tree
(including installer-invoked `rustc`, driver library and stripper) and Criterion
cache are checked before and after preparation and reproduction: exact membership,
file hashes/sizes/modes, directory modes, symlink spellings/modes/containment and
dangling state. The helper, compiler and strip exits remain unknown unless
separately captured; the OS launcher exit is explicitly named.

## Validation and scope

[validation.json](validation.json) and all existing receipts are frozen evidence
for the earlier recipe, which did not enforce OS network denial or authenticate
the complete installer inputs. Their successful output comparisons remain evidence;
they do not establish those stronger offline/tool-closure properties.
[OFFLINE_REPAIR.md](OFFLINE_REPAIR.md) records the repair and its unexecuted native
validation boundary at that time. [Native validation](native-validation-20261026/README.md)
now records two fresh guarded builds, both matching the tested executable and
symbols, and an additional exact Apple-signed guard pin for the recorded host.

The earlier local validation reported 9,269 existing differential comparisons and
1,024 offline Surfpool comparisons. A local cleanup deleted those unexported raw
payloads; their frozen index cannot recover them. The native validation package
records separate new reruns with the same comparison counts and zero mismatches.
Counts include repeated inputs and retain the harnesses' existing normalization
and coverage limits. New raw qualification receipts remain local; the published
inventory does not provide portable re-verification of unexported data. Build logs
and compact reproduction receipts are published here. Standard repository CI checks
the unchanged selected state; the commands above exercise this recipe.

Active source, selected artifacts and status remain unchanged. The preserved receipts support reproduction of the tested collector candidate; original deployment byte identity
and historical build provenance remain unresolved. The original controller's
exit-2/cache review and the local preparation/permission failures remain preserved.
