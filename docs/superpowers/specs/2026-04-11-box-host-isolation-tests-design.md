# box Host Isolation Test Expansion Design

## Summary

The current integration surface proves that `box` launches a payload in a separate network view,
can resolve and fetch basic traffic, and supports a narrow enforce-mode story. It does not yet
prove the more security-relevant isolation claims around filesystem mutability, writable sandbox
areas, mount behavior, and visible privilege surface.

This design expands the integration suite with a focused first pass for host isolation. The goal
is to add a small number of root-required black-box tests that exercise the live sandbox instead of
only pinning generated plans and OCI specs in unit tests.

## Goals

- Add live integration coverage for filesystem isolation in the default non-Docker sandbox path.
- Prove that expected read-only host-overlay paths remain read-only inside the sandbox.
- Prove that expected writable sandbox paths remain writable inside the sandbox.
- Add one bounded privilege-surface assertion for the default non-Docker case.
- Keep the new tests narrow, stable, and aligned with the existing harness.

## Non-Goals

- No expansion of enforce-mode or monitor-mode network-policy coverage in this first pass.
- No new runtime isolation features beyond what the code already intends to provide.
- No attempt to define a seccomp contract, because the current code does not expose one.
- No broad mount-table snapshot testing that would be brittle across hosts or `runsc` revisions.

## Current Gaps

Today the integration suite in `integration/box_smoke_test.go` covers:

- basic command execution
- env injection
- DNS and HTTP reachability
- sandbox network address visibility
- Docker-enabled startup and one enforce-mode Docker build
- one blocked DNS case in enforce mode

That is useful smoke coverage, but several important isolation properties are only unit-tested:

- host-overlay read-only bind intent
- writable directory planning
- OCI namespace selection
- Docker-only capability injection

Those seams are worth keeping, but they do not prove the live sandbox actually behaves that way at
runtime.

## Proposed Test Surface

The first pass should add a dedicated integration file, `integration/box_isolation_test.go`, and
cover four black-box checks.

### 1. Read-Only Host Overlay Paths

Run a command inside `box` that attempts to create or overwrite a file under `/usr`, such as
`/usr/.box-write-test`, and require the command to fail.

This is the strongest single filesystem isolation assertion because `/usr` comes from the
host-overlay read-only bind set and is expected to be immutable from inside the sandbox.

The test should avoid modifying an existing host file and should only target a synthetic path.

### 2. Writable Sandbox Paths

Run a command that writes to:

- `/tmp`
- the configured sandbox workdir, which maps to the repo path for `host-overlay`

Require both writes to succeed and verify the resulting content.

This distinguishes the intended writable surfaces from the protected overlay paths and guards
against regressions where tmpfs mounts or the repo bind stop behaving as expected.

The workdir assertion should use a temporary file under the repo root and clean it up with
`t.Cleanup`.

### 3. Targeted Mount Behavior

Probe mount behavior in a narrow way instead of snapshotting the full mount table.

The test should inspect `/proc/self/mountinfo` or an equivalent command only for targeted facts:

- `/usr` is mounted read-only
- `/tmp` is present as a writable sandbox mount

This keeps the assertion resilient while still proving that the live sandbox mount layout matches
the intent already encoded in the rootfs and gVisor layers.

### 4. Default Privilege Surface

Run a non-Docker sandbox command that reads `/proc/self/status` and inspect the capability fields,
starting with `CapEff`.

The first-pass assertion should be conservative:

- the capability field must be present
- it must not match the Docker-enabled elevated capability set path by default

This does not fully define the non-Docker capability contract, but it does guard against an
obvious regression where the default sandbox accidentally inherits the Docker-elevated privilege
surface.

If the repo wants a stronger contract later, that should be a follow-up with an explicit runtime
decision about the intended default capability set.

## Harness Changes

The existing helpers in `integration/testenv/testenv.go` are close to sufficient. The first pass
should add only minimal support:

- a helper to write a temporary default config with targeted overrides when the test needs a custom
  workdir or Docker setting
- a helper that runs `box` and returns stdout, stderr, and error without forcing the success path,
  so negative assertions stay easy to express

The current `runBoxSmoke` helper in `integration/box_smoke_test.go` is optimized for success-only
smoke tests and should stay that way. Isolation tests should use a separate helper with clearer
failure handling.

## File Layout

- Create: `integration/box_isolation_test.go`
- Modify: `integration/testenv/testenv.go`
- Modify: `integration/testenv/testenv_test.go` only if new helper logic needs direct unit coverage
- Keep existing smoke tests in `integration/box_smoke_test.go` unchanged unless a shared helper
  extraction materially reduces duplication

This keeps the isolation expansion separate from the current network and Docker smoke coverage.

## Failure Model

The new tests should fail only on meaningful isolation regressions, not on incidental output
formatting differences.

That means:

- prefer shell exit status and small output fragments over exact full-output snapshots
- avoid depending on host-specific mount ordering
- skip when root access or required Linux-only tools are unavailable, following the current suite
- clean up any repo workdir sentinel files even on failure

## Verification

The work is complete when all of the following succeed on a Linux host with the existing
prerequisites:

- `go test ./integration/testenv -count=1`
- `sudo -E go test ./integration -run 'TestBox.*Isolation|TestBox.*Writable|TestBox.*ReadOnly|TestBox.*Privilege' -v -count=1`
- `go test ./... -count=1`

## Follow-Up Work

Once this host-isolation slice is in place, the next logical expansion should be network-policy
integration coverage for:

- deny-over-allow domain policy behavior
- direct-IP bypass attempts
- `extra_allowed_cidrs`
- monitor summary assertions for DNS, HTTP, and TLS observations
