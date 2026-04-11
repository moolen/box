# OpenCode CI Smoke Test Design

## Context

The current CI workflow installs Linux host tooling, runs `go test ./...`, and builds the
project. The integration suite already exercises `box` end to end with root-required smoke
tests and uses generated config files plus the existing `integration/testenv` harness to keep
those tests reproducible.

This design adds one more end-to-end smoke test for an external CLI binary that is not part of
the default host rootfs bind set. The test must prove three things together:

1. CI can install `opencode` into a non-standard host bin directory.
2. That bin directory can be made visible inside `box`.
3. Running `opencode run 'hi'` inside the sandbox emits observable traffic to `models.dev`.

The command is expected to fail because no credentials or interactive session setup will be
provided. Success is not the target. The target is executable reachability plus observed
network activity to the expected host.

## Goals

- Extend CI so `opencode` is installed into a custom bin prefix instead of a default system path.
- Preserve that custom bin path across later GitHub Actions steps through the workflow PATH.
- Add a smoke test that mounts the custom bin directory into the sandbox and invokes
  `opencode run 'hi'`.
- Assert that the command fails after launch but still produces monitor-mode traffic mentioning
  `models.dev`.
- Keep local development sane by skipping the new test when `opencode` is not available on the
  host `PATH`.

## Non-Goals

- Verifying that `opencode` authentication succeeds.
- Validating the semantic correctness of `opencode` output.
- Adding a dedicated `opencode` installer abstraction to the Go test harness.
- Making `opencode` part of the default `box.yaml` host overlay bind set.

## Existing Constraints

The host-overlay rootfs plan currently bind-mounts a fixed read-only host tool set:

- `/bin`
- `/sbin`
- `/usr`
- `/lib`
- `/lib64`

Additional host paths can already be injected through config-driven mounts:

- `mounts.extra_ro`
- `mounts.extra_rw`

The sandbox process environment is config-driven. With `sandbox.inherit_env: true`, the runtime
starts from the host process environment, then applies `sandbox.env`, then applies forced box
runtime variables such as proxy and Docker wiring. That means the new smoke test can rely on the
current PATH seen by the host test process, as long as CI exports the custom prefix into PATH
before `go test` runs.

## Proposed Approach

### CI Workflow

Add a Node setup and install sequence to `.github/workflows/ci.yml` before the `Test` step:

1. Use `actions/setup-node` with a current LTS release.
2. Install `opencode-ai` with npm using a custom prefix under `$RUNNER_TEMP`, for example
   `$RUNNER_TEMP/opencode-prefix`.
3. Append that prefix’s `bin` directory to `$GITHUB_PATH`.

Using `$GITHUB_PATH` makes the non-standard bin directory persist across later workflow steps,
including the `go test ./...` step that launches the integration suite.

No CI-only environment variable is required for the test. The integration test can detect
availability through `exec.LookPath("opencode")` and skip when it is absent.

### Integration Smoke Test

Add a new root-required integration test in `integration/box_smoke_test.go`.

The test should:

1. Skip on non-Linux platforms.
2. Require root or passwordless `sudo`, following the existing smoke-test pattern.
3. Skip if `opencode` is not available on the current host `PATH`.
4. Resolve the absolute `opencode` binary path with `exec.LookPath("opencode")`.
5. Derive the containing host bin directory from that path.
6. Generate a dedicated monitor-mode config file that:
   - uses `rootfs: host-overlay`
   - sets `sandbox.inherit_env: true`
   - injects `PATH=<current host PATH>` in `sandbox.env`
   - mounts the custom host bin directory through `mounts.extra_ro`
7. Run:

   `box --config <generated-config> -- opencode run 'hi'`

8. Expect the command to fail.
9. Assert from `stderr` that the monitor summary is present and includes `models.dev`.

### Monitor Assertions

The most stable assertions are:

- `stderr` contains `Monitor summary`
- `stderr` contains `models.dev`
- `stderr` contains `DNS:`
- `stderr` contains either `TLS:` or `HTTP:`

This keeps the test aligned with current monitor-mode semantics:

- DNS queries are recorded in the DNS section.
- HTTPS traffic is likely surfaced as TLS SNI in peek mode.
- Some future `opencode` behavior may also emit HTTP metadata, so the test should allow either
  transport section as long as `models.dev` appears in the summary.

The test should also make sure failure happened after launch rather than because the binary was
missing. A practical negative assertion is to reject stderr/stdout that indicates shell-level
`command not found`.

## Required Helper Changes

Add one focused config helper to `integration/testenv/testenv.go` for this smoke test so the
test file stays concise.

Recommended helper responsibility:

- write a temporary monitor-mode config file for OpenCode execution
- accept:
  - host bin directory to bind read-only
  - PATH value to inject

The helper should keep the config minimal and match existing defaults where possible.

Example config shape:

```yaml
sandbox:
  rootfs: host-overlay
  rootfs_source: ""
  hostname: box
  workdir: .
  inherit_env: true
  env:
    - TERM=xterm
    - PATH=<host path>
  command_shell: /bin/bash -lc
network:
  mode: monitor
  subnet: 100.96.0.0/30
  dns:
    bind_addr: auto
    upstream:
      - 1.1.1.1:53
      - 8.8.8.8:53
  transparent_proxy:
    enabled: true
    mode: peek
    http_port: 18080
    tls_port: 18443
policy:
  allow_domains: []
  deny_domains: []
  allow_cidrs: []
  deny_cidrs: []
  extra_allowed_cidrs: []
  log_all_connects: true
mounts:
  extra_ro:
    - <host bin dir>
  extra_rw: []
docker:
  enabled: false
  data_root: /var/lib/docker
  socket_path: /var/run/docker.sock
  wait_for_socket: true
  ready_timeout: 10s
  host_network_nested_containers: true
gvisor:
  platform: systrap
  network: sandbox
  debug: false
```

## File Changes

- Modify `.github/workflows/ci.yml`
  Add Node setup and custom-prefix `opencode` installation before the test step.
- Modify `integration/box_smoke_test.go`
  Add the OpenCode smoke test and any file-local assertion helpers that are only useful there.
- Modify `integration/testenv/testenv.go`
  Add a helper that writes the dedicated config used by the OpenCode smoke test.
- Modify `integration/testenv/testenv_test.go` only if the new helper contains logic worth direct
  unit coverage.

## Risks and Mitigations

### PATH Differences Under sudo

Risk:
`sudo -E` may preserve most environment variables but still apply a constrained secure path on
some hosts.

Mitigation:
The test config should explicitly inject `PATH=<host path>` through `sandbox.env`, which already
has higher precedence than inherited host values inside the sandbox.

### Host-Overlay Does Not See Non-Standard Prefix

Risk:
The custom bin prefix is outside the default host-overlay bind set, so the sandbox would fail to
resolve the binary even if PATH points at it.

Mitigation:
Bind the containing host bin directory through `mounts.extra_ro`.

### Network Signature Changes

Risk:
Future `opencode` versions may change whether the observable traffic shows up as HTTP or TLS in
the summary.

Mitigation:
Assert on `models.dev` plus DNS and allow either TLS or HTTP transport sections.

### Local Developer Friction

Risk:
A mandatory `opencode` dependency would make local integration runs noisy or brittle.

Mitigation:
Skip unless `opencode` is already available on the host `PATH`.

## Validation Plan

Minimum verification:

- `go test ./integration/testenv -count=1`
- `sudo -E go test ./integration -run TestBoxRunsOpenCodeFromMountedCustomBinDir -v -count=1`

Repository verification after the change:

- `go test ./... -count=1`

## Success Criteria

The design is complete when:

- CI installs `opencode` into a non-standard bin directory and exports that path for later steps.
- The new smoke test runs `opencode` from inside `box` via a mounted custom host bin directory.
- The command fails as expected, but not because the executable is missing.
- The box monitor summary shows traffic mentioning `models.dev`.
