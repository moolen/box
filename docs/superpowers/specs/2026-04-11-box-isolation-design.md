# box Isolation Wiring Design

## Summary

`box` currently prepares some runtime state and then executes the payload directly on the host.
That means the payload inherits the host network namespace, host filesystem view, host Docker
socket, and the preserved environment from `sudo -E`. The missing work is not a policy tweak; it
is the absent handoff from CLI/runtime orchestration to the existing rootfs and gVisor helpers.

This design wires the existing pieces together so `box` stages a bundle, launches the payload
through `runsc`, and tears down all host-side resources after the sandbox exits. The first
integration proof should be a real root-required test that runs `ip` inside the sandbox and
verifies the observed interface address matches the configured sandbox subnet rather than the host
network view.

## Goals

- Replace direct host execution with sandboxed execution through `runsc`.
- Materialize the planned rootfs and OCI bundle for each `box` run.
- Preserve the current config shape and the existing monitor-mode resource setup.
- Record sandbox-owned state in the runtime manifest so teardown remains scoped and safe.
- Add a real integration test that proves network isolation by observing the sandbox interface
  address from inside the sandbox.

## Non-Goals

- No new policy-engine behavior.
- No new network modes beyond the current config/runtime contract.
- No TLS MITM support.
- No attempt to expose host resources less broadly than the existing `host-overlay` plan unless
  required to make the sandbox actually run.

## Root Cause

The active execution path ends in a direct `exec.CommandContext` call for the payload. The repo
already contains:

- rootfs planning and bundle staging helpers
- OCI spec generation for `runsc`
- a `runsc` launcher wrapper

Those helpers are unused, so the sandbox never starts. The current runtime also computes network
resource names but does not yet create or join a sandbox network namespace, so the first wiring
step must include actual netns setup alongside the gVisor launch path.

## Architecture

### CLI and Execution Boundary

`cmd/box` remains the top-level orchestrator, but its executor should no longer call the payload
directly. Instead it should:

1. load config
2. start the runtime
3. build and stage the rootfs bundle
4. create the OCI spec
5. launch `runsc`
6. wait for the sandbox process
7. clean up in reverse order

The CLI should keep the current init-shim resolution behavior and pass the chosen shim path into
bundle staging.

### Runtime Responsibilities

`internal/runtime` should continue to own manifest creation and cleanup ordering, but it now needs
to own enough run metadata to support a real sandbox launch:

- bundle directory path
- staged rootfs path
- sandbox-side IP address
- host/sandbox netns resources actually created
- started runner names including the `runsc` process

The runtime should create the host-managed network namespace and veth pair derived from the
runtime ID, assign the subnet addresses, and leave the sandbox-side namespace ready for gVisor to
use. Cleanup remains manifest-driven and reverse-ordered.

### gVisor Launch Path

The existing `internal/gvisor` package already knows how to build a spec and invoke `runsc`. The
missing piece is a richer launch request that can include the bundle path, container ID, and the
network namespace to join. The implementation should prefer a narrow seam:

- spec generation remains pure
- runsc invocation stays in `internal/gvisor`
- the CLI/runtime integration decides which paths and IDs to pass

If the current `runsc` invocation needs extra flags to join the prepared network namespace, those
flags belong in the gVisor runner wrapper so tests can pin them directly.

### Rootfs and Environment

The rootfs plan should be applied for every sandboxed run. For `host-overlay`, this means the
bundle rootfs contains the generated `/etc/*` files plus the copied `box-initshim`, and the spec
must include the bind-mounts already described by the plan. The sandbox process environment should
come from the config-driven OCI spec rather than inheriting the host environment implicitly.

### Testing Strategy

The change needs both seam-level tests and one real integration proof.

Unit and orchestration tests should cover:

- `runtimeExecutor` no longer calling the payload directly
- rootfs apply and OCI spec generation being invoked with the expected paths
- `runsc` being launched with the expected bundle/container/netns inputs
- runtime manifest ownership for bundle paths and started runners

Integration should add a real root-required test:

- invoke `box -- ip -4 -o addr show`
- assert the output includes the sandbox-side subnet address derived from `box.yaml`
- assert the host primary interface address is not being reported as the sandbox address

That test proves the payload is no longer executing directly in the host network namespace.

## Verification

Before the change is considered complete, all of the following should succeed on a Linux host with
the required tooling:

- `go test ./... -count=1`
- `sudo -E go test ./integration -run TestBoxShowsSandboxInterfaceAddress -v -count=1`
- `make build`
