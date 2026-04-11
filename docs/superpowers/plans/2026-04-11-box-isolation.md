# box Isolation Wiring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `box`'s direct host payload execution with a real sandbox launch through rootfs staging and `runsc`, then prove network isolation with a real integration test.

**Architecture:** Keep the current package boundaries and wire the missing execution path through them. `cmd/box` remains the orchestrator, `internal/runtime` owns manifest-scoped resources and cleanup, `internal/rootfs` stages the bundle, `internal/gvisor` builds and launches the OCI bundle, and `integration` proves the payload sees the sandbox network rather than the host.

**Tech Stack:** Go, Cobra, `runsc`, Linux namespaces, `ip`, Go testing

---

## File Structure

- `cmd/box/root.go`: replace direct host payload execution with sandbox launch orchestration.
- `cmd/box/run_test.go`: pin executor behavior around runtime/rootfs/gVisor wiring.
- `internal/runtime/runtime.go`: extend runtime state with bundle/network resource ownership.
- `internal/runtime/cleanup.go`: tear down additional runtime-owned paths and the sandbox runner.
- `internal/runtime/runtime_test.go`: pin manifest content and cleanup ordering for sandbox runs.
- `internal/rootfs/plan.go`: ensure the rootfs plan exposes the mounts needed by the OCI spec.
- `internal/rootfs/apply.go`: stage the bundle rootfs and return concrete bundle paths.
- `internal/rootfs/rootfs_test.go`: pin bundle staging behavior if the request shape changes.
- `internal/netns/netns.go`: add creation/application helpers for the planned namespace resources.
- `internal/netns/netns_test.go`: keep deterministic naming tests and add render-only plan tests.
- `internal/gvisor/spec.go`: emit the OCI spec needed for a real sandboxed payload launch.
- `internal/gvisor/run.go`: accept the full launch request and translate it into `runsc` args.
- `internal/gvisor/gvisor_test.go`: pin the exact `runsc` invocation shape.
- `integration/box_smoke_test.go`: add the real isolation test using `ip`.

### Task 1: Pin The Missing Sandbox Handoff In Tests

**Files:**
- Modify: `cmd/box/run_test.go`
- Modify: `internal/gvisor/gvisor_test.go`
- Modify: `internal/runtime/runtime_test.go`

- [ ] **Step 1: Write failing executor tests**

Add tests showing that the executor uses a sandbox launch seam instead of direct host execution.
Pin expected calls for:

```go
func TestRuntimeExecutorStagesBundleAndLaunchesSandbox(t *testing.T) {}
func TestRuntimeExecutorCleansUpAfterSandboxExit(t *testing.T) {}
```

- [ ] **Step 2: Write failing gVisor runner tests**

Add a failing test that requires the `runsc` wrapper to include the new launch inputs, such as the
bundle path and any netns-related flags needed for the prepared sandbox namespace.

- [ ] **Step 3: Write failing runtime manifest tests**

Add runtime tests that require the manifest to record the bundle directory and any additional
managed paths created for the sandbox launch.

- [ ] **Step 4: Run the targeted tests to verify they fail**

Run: `go test ./cmd/box ./internal/gvisor ./internal/runtime -run 'TestRuntimeExecutorStagesBundleAndLaunchesSandbox|TestRuntimeExecutorCleansUpAfterSandboxExit|TestRunnerRun|TestRunRecordsBundle' -count=1`

Expected: FAIL because the active code still executes the payload directly on the host and does
not record bundle launch state.

### Task 2: Implement Bundle Staging And Sandbox Launch

**Files:**
- Modify: `cmd/box/root.go`
- Modify: `internal/runtime/runtime.go`
- Modify: `internal/runtime/cleanup.go`
- Modify: `internal/rootfs/apply.go`
- Modify: `internal/gvisor/spec.go`
- Modify: `internal/gvisor/run.go`
- Modify: `internal/netns/netns.go`

- [ ] **Step 1: Implement the runtime-owned bundle and network state**

Extend runtime startup to create and record the bundle directory, rootfs staging paths, and the
actual sandbox network resources needed for launch.

- [ ] **Step 2: Implement the CLI launch path**

Replace direct payload execution with:

```go
rt, err := boxruntime.Run(...)
applyResult, err := rootfs.Apply(...)
spec, err := gvisor.BuildSpec(...)
err = gvisor.Runner{...}.Run(...)
```

Thread the staged paths and container ID through the executor so cleanup can stop the sandbox
runner and remove only runtime-owned paths.

- [ ] **Step 3: Implement the network namespace setup**

Create the host-managed namespace and veth pair derived from the runtime ID, assign the sandbox
address from the configured subnet, and make the namespace available to the gVisor launch path.

- [ ] **Step 4: Run targeted tests to verify they pass**

Run: `go test ./cmd/box ./internal/gvisor ./internal/runtime -count=1`

Expected: PASS

### Task 3: Add The Real Isolation Test

**Files:**
- Modify: `integration/box_smoke_test.go`

- [ ] **Step 1: Write the failing integration test**

Add:

```go
func TestBoxShowsSandboxInterfaceAddress(t *testing.T) {}
```

The test should run `box -- ip -4 -o addr show`, parse the output, and require the sandbox-side
address from the configured subnet rather than the host interface address.

- [ ] **Step 2: Run the integration test to verify it fails**

Run: `sudo -E go test ./integration -run TestBoxShowsSandboxInterfaceAddress -v -count=1`

Expected: FAIL because the payload still sees the host network namespace before the implementation
is complete.

- [ ] **Step 3: Implement the minimal code to make the integration test pass**

Adjust the runtime/gVisor wiring only as needed to satisfy the failing isolation assertion.

- [ ] **Step 4: Re-run the integration test**

Run: `sudo -E go test ./integration -run TestBoxShowsSandboxInterfaceAddress -v -count=1`

Expected: PASS

### Task 4: Run Full Verification

**Files:**
- Modify: `README.md` if the user-facing runtime requirements changed materially

- [ ] **Step 1: Run the full Go test suite**

Run: `go test ./... -count=1`

Expected: PASS

- [ ] **Step 2: Run the focused root-required integration proof**

Run: `sudo -E go test ./integration -run TestBoxShowsSandboxInterfaceAddress -v -count=1`

Expected: PASS

- [ ] **Step 3: Build the binaries**

Run: `make build`

Expected: PASS and produce `./bin/box` plus `./bin/box-initshim`
