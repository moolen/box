# box Orphan Runtime Cleanup Design

## Summary

`box` already records enough teardown information to clean up runtime-owned host resources:
network namespace names, veth names, nft table names, fwmark route tables, and the exact
teardown commands that were applied during startup. The current problem is not missing ownership
data; it is that startup treats any leftover host resource as a hard conflict, even when that
resource clearly belongs to a dead `box` runtime whose state directory was left behind by an
aborted run.

This design adds a narrow startup auto-heal pass. Before the existing monitor/enforce ownership
checks run, `box` should scan its runtime state root for orphaned runtime directories, load their
recorded manifests, and replay the normal runtime cleanup using only the manifest-recorded
teardown commands plus validated managed-path removal. After that pass, the existing preflight
checks stay strict. Unknown or ambiguous conflicts remain hard failures.

## Goals

- Auto-heal stale host resources left behind by aborted `box` runs.
- Reuse the existing runtime ownership and cleanup model instead of inventing a second deletion
  path.
- Limit cleanup strictly to resources backed by a trusted runtime manifest inside the configured
  state root.
- Preserve strict conflict behavior for anything not clearly proven to belong to an orphaned
  `box` runtime.

## Non-Goals

- No broad garbage collection of every `box_*` host resource by name pattern alone.
- No deletion of resources that lack a readable, self-consistent runtime manifest.
- No attempt to reconstruct teardown commands from live host state.
- No recovery of orphaned state directories whose manifest still points outside the current state
  root or otherwise fails validation.

## Ownership Model

Each runtime already persists:

- `state_root`
- `state_dir`
- `manifest_path`
- `runtime_id`
- `net.table_name`
- `net.fwmark`
- `net.route_table`
- `net.netns`
- `net.host_veth`
- `teardown_cmds`
- `managed_paths`

That is enough to safely prove ownership for cleanup, as long as the manifest is trusted. The key
principle is that startup should only delete resources if they can be traced back to a manifest in
the runtime state root and that manifest validates against the directory being scanned.

## Orphan Definition

For the initial pass, a runtime directory is considered eligible for orphan cleanup only when all
of the following are true:

1. The entry is a directory directly under the runtime state root.
2. The directory contains a readable manifest file.
3. The manifest decodes successfully.
4. The manifest is self-consistent:
   - `runtime_id` matches the directory name.
   - `state_dir` resolves to that directory.
   - `manifest_path` resolves to that manifest file.
   - all managed paths remain inside the runtime state root under the existing cleanup validation.
5. Cleanup can be performed using only the recorded manifest data.

Anything that fails those checks is ignored by the orphan-cleanup pass and left to the existing
strict conflict path.

This first version intentionally does not try to decide whether a directory with a valid manifest
represents a still-running runtime. The practical goal is to clean up state left by aborted test
runs where the directory remains but no runtime successfully removed it. Because the deletion path
is limited to recorded teardown commands and validated state-root paths, the cleanup remains
scoped to artifacts that `box` already declared as its own.

## Startup Flow

Runtime startup should change as follows:

1. Resolve `state_root`.
2. Run orphan cleanup over that state root.
3. Continue with the existing monitor/enforce preflight ownership checks.
4. If preflight still sees a conflicting nft table, fwmark rule, route table entry, netns, or
   host veth, return `ErrResourceConflict` exactly as today.

This keeps conflict handling conservative while removing the most common stale-resource footgun.

## Cleanup Strategy

The orphan pass should reuse `runtime.Cleanup(...)` rather than implementing bespoke deletion
logic. For each trusted orphan manifest:

- call `Cleanup(...)`
- provide `CommandExec`
- provide no `StopRunner` callback
- allow cleanup to execute the manifest’s recorded `TeardownCmds`
- allow cleanup to remove the manifest’s recorded `ManagedPaths`

This preserves the current cleanup ordering and validation:

- runner shutdown first when present
- teardown commands next
- managed path removal last

Because orphan cleanup does not have live runner handles, `StopRunner` remains nil and cleanup is
effectively “network teardown plus state-root removal.”

## Safety Rules

The orphan pass must not:

- derive deletion commands from `net` fields when `teardown_cmds` are missing
- delete nft tables or policy rules based only on `box_*` naming
- remove any path outside the runtime state root
- treat a malformed manifest as permission to delete anything

If a manifest is unreadable, malformed, or inconsistent, startup should leave it alone. If its
resources still cause conflicts later, preflight should fail loudly. That is preferable to
guessing ownership.

## Error Handling

- If scanning the state root itself fails, startup should return an error. That is a local
  environment problem, not an ownership conflict.
- If cleanup of one orphan manifest fails, startup should return that error instead of continuing
  silently, because partial teardown can leave the host in a mixed state.
- Missing resources during orphan cleanup should be treated the same way current cleanup treats
  them: best-effort teardown, aggregate hard failures only.

## Testing Strategy

Unit coverage should prove:

- orphan cleanup loads a valid manifest from the state root and runs its recorded teardown
  commands
- orphan cleanup removes managed paths for a valid orphan runtime directory
- orphan cleanup ignores directories with no manifest
- orphan cleanup ignores malformed manifests
- orphan cleanup ignores manifests whose recorded paths do not match the scanned directory
- startup still returns `ErrResourceConflict` when a conflict remains after orphan cleanup

The most important regression test is:

- create an orphan runtime directory with a valid manifest whose teardown commands would remove a
  stale nft table / fwmark rule / route-table usage
- run startup preflight
- verify orphan cleanup runs before conflict detection
- verify startup then succeeds

## Verification

The change is complete when all of these succeed:

- targeted runtime and preflight unit tests for orphan cleanup
- `go test ./cmd/box ./internal/runtime -count=1`
- `go test ./... -count=1`

