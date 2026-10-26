# Offline installer-input repair

The status below records the repair's boundary when it landed. The subsequent
[native validation](native-validation-20261026/README.md) records two actual
guarded executions; the earlier receipts have not been reclassified.

The repaired recipe has not been run with native SDK/compiler tools. Its tests
use synthetic trees, inert data fixtures and mocked subprocess launches. No new
build output or target-runtime qualification is claimed.

The old `validation.json` and every file under `receipts/` retain their original
bytes. They describe the preceding recipe. That recipe enabled Cargo offline but
left the SDK installer's curl/wget fallback possible. It also pinned v1.52
llvm-objcopy without pinning installer-invoked v1.52 rustc and its driver or the
Criterion cache. The supplied old log actually records rustc --version and
--print sysroot commands; this repair does not invent their output or a measured
loaded-library set.

The new `offline_inputs.py` checks the entire current observed v1.52 and Darwin
Criterion v2.3.2 inventories, including files, directories and symlinks. Copies in
`install-cache-identity/` are exact manifested members of root's current local
collection, manifest SHA256
`704222a8ab95bb0f09ddba93b9d6c9411c2553d0a378b92ccb6354342f8254a0`.
These pins do not authenticate an official release archive or establish that an
earlier build used these bytes. Original collection paths are provenance labels;
verification uses the running user's conventional SDK cache locations.

Preparation checks the cache/guard controls before downloads or native commands
and after preparation. Reproduction checks them before launch and after return
alongside the other inputs. Cache traversal never follows member symlinks;
symlink mode, exact target, inside-tree resolution and existence state are pinned.
The intentionally dangling inside-tree LLDB utility link remains permitted only
as inventoried. File/link membership and metadata are checked again after hashing.

Reproduction wraps the unchanged helper in absolute `/usr/bin/sandbox-exec`,
SHA256 `fd89e1f6e6d822fcc0f3844bd11fecdc9b68f705f80c32f4334bc23913d5451b`,
with exact profile `(version 1)(allow default)(deny network*)`. The OS guard covers
its descendants. No shell downloader replacement or mocked compiler is used in
the production path. Preparation remains explicitly online. The new receipt names
the guarded command's aggregate exit; a separate helper/compiler/strip exit is
not inferred. The frozen helper and SDK have not changed.

Unit tests reject missing/unreadable/deleted Criterion, rustc/driver/stripper
mutations, size/mode/membership changes, redirected/escaping links, altered dangling
state and mutation during hashing. Tests also cover control export tampering,
required driver omission, missing/modified/nonexecutable OS guard, exact wrapped
command and receipt, postcheck failure, and rejection before any preparation
launch. Raw test streams are preserved externally for root review. A real guarded
build remains a separate unperformed gate; the old receipts cannot satisfy it.
