# box Cobra CLI and Release Automation Design

## Summary

`box` already depends on `spf13/cobra`, but the current CLI is still effectively a single-file
entrypoint with runtime orchestration and command wiring mixed together. That makes help output,
flag growth, and future subcommands harder to evolve than they need to be. Separately, the repo
has no GitHub Actions yet, so build, test, and release behavior depends entirely on local manual
steps.

This design refactors the CLI onto a clear Cobra command tree and adds GitHub Actions for both CI
and automatic releases. The CLI refactor keeps the current user-facing behavior intact, including
support for `box -- <command...>` and `box run -- <command...>`. The automation side adds one
workflow for normal validation and one workflow that creates a tag and GitHub Release for every
merge commit pushed to `main`.

## Goals

- Move `cmd/box` to an explicit Cobra command structure.
- Keep existing execution behavior stable for both `box -- ...` and `box run -- ...`.
- Separate CLI parsing concerns from sandbox runtime execution concerns.
- Add a GitHub Actions workflow that runs build and test checks in CI.
- Add a GitHub Actions workflow that creates a tag and GitHub Release on every push to `main`.
- Publish built `box` and `box-initshim` binaries as release assets.

## Non-Goals

- No change to sandbox runtime semantics, networking, DNS, or Docker behavior.
- No packaging beyond uploaded release binaries.
- No manual version-bump workflow.
- No expansion of the CLI surface beyond what is needed for the existing root command and `run`
  subcommand.

## CLI Architecture

### Command Layout

The CLI should be decomposed into a small set of focused files under `cmd/box`:

- a thin `main.go` that constructs and executes the root command
- a root-command file that owns persistent flags and top-level help text
- a run-command file that owns the `run` subcommand
- shared request-building helpers that translate parsed Cobra input into the existing runtime
  request shape
- the runtime executor and orchestration helpers that remain responsible for config loading,
  rootfs staging, OCI spec generation, and `runsc` execution

This preserves the existing executor seam while making Cobra responsible for argument parsing and
command dispatch rather than mixing those concerns in one file.

### Compatibility Behavior

Current users can invoke:

- `box -- <command...>`
- `box run -- <command...>`

That compatibility should remain. The root command should continue to accept arbitrary trailing
args and route them through the same payload path used by `run`. The `run` subcommand should stay
as the explicit form, and tests should pin that both forms build the same runtime request.

### Error Handling and Help

Cobra should own usage rendering and help output. The implementation should preserve the current
non-zero exit behavior on execution failures, while making CLI-level errors clearer:

- missing payload after `--` should return a deterministic command error
- `--config` remains a persistent flag available to both `box` and `box run`
- `box --help` and `box run --help` should produce Cobra-generated help instead of implicit parser
  behavior

## Internal Boundaries

The refactor should not push sandbox logic into the Cobra layer. The command tree should stop at a
small request assembly boundary:

1. Cobra parses args and flags.
2. Shared command helpers build `runRequest`.
3. `runtimeExecutor` performs the existing runtime, rootfs, spec, and `runsc` work.

That keeps CLI tests lightweight and lets the current runtime-focused tests continue to assert the
behavior that matters for sandbox execution.

## CI Workflow

Add a CI workflow under `.github/workflows/ci.yml` with these triggers:

- pull requests targeting `main`
- pushes to `main`

The workflow should:

1. check out the repo
2. install the configured Go toolchain
3. restore module/build caches
4. run `go test ./... -count=1`
5. run `make build`

This gives normal validation for both pull requests and post-merge pushes without entangling test
execution with release publication logic.

## Release Workflow

Add a separate workflow under `.github/workflows/release.yml` triggered on pushes to `main`.

The release workflow should:

1. check out the repo with sufficient history to tag
2. install Go
3. build release artifacts for the supported target set
4. derive a unique tag for the pushed commit
5. create and push that tag
6. create a GitHub Release for the tag
7. upload built binaries as release assets

Because the requirement is to release on every merge to `main`, the tag must be generated
automatically rather than sourced from manual version edits. A practical format is:

- `v0.0.0-<utc-timestamp>-<short-sha>`

That guarantees one unique tag per merged commit and avoids blocking normal merges on manual
version bookkeeping.

## Release Assets

The workflow should publish at least:

- `box_<os>_<arch>.tar.gz`
- `box-initshim_<os>_<arch>.tar.gz`

If both binaries are always consumed together, an acceptable alternative is a single archive per
target containing both executables plus a short checksum file. The release workflow should choose
one shape and keep it stable so later installation automation has a predictable asset contract.

## Testing Strategy

CLI tests should cover:

- root command executes payload args directly
- `run` subcommand executes payload args through the same path
- persistent `--config` reaches both command forms
- missing payload returns the expected command error
- help rendering works for root and `run`

Workflow changes should be validated by:

- keeping local verification commands explicit in the YAML
- checking the built artifact names and paths in the workflow
- ensuring the release workflow does not depend on unpublished repository state or manual secrets
  beyond the default GitHub token

## Verification

Before implementation is considered complete, all of the following should succeed:

- `go test ./... -count=1`
- `make build`

After the workflows are merged to `main`, GitHub should show:

- CI runs on pull requests and pushes to `main`
- one release run per merge commit pushed to `main`
- one created tag and GitHub Release per successful post-merge release run
