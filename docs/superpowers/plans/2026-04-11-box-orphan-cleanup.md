# box Orphan Runtime Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Automatically clean up orphaned `box` runtime state directories and their manifest-recorded host resources before monitor/enforce preflight checks run, while leaving unknown conflicts strict.

**Architecture:** Add a runtime-owned orphan cleanup helper that scans the runtime state root for trusted manifest-backed orphan directories, reuses `Cleanup(...)` with recorded teardown commands plus managed-path removal, and runs before `monitorPreflightCheck`. Keep the existing conflict probes unchanged so any resource not proven to belong to a trusted orphan still fails closed with `ErrResourceConflict`.

**Tech Stack:** Go, existing `internal/runtime` manifest/cleanup logic, standard library filesystem and JSON handling, existing Go test suite.

---

## File Structure

- Modify: `internal/runtime/runtime.go`
  Responsibility: invoke orphan cleanup after resolving `state_root` and before preflight.
- Create: `internal/runtime/orphan_cleanup.go`
  Responsibility: scan state-root directories, load and validate orphan manifests, and replay manifest-backed cleanup.
- Modify: `internal/runtime/cleanup.go`
  Responsibility: reuse existing cleanup validation helpers from orphan cleanup without widening cleanup scope.
- Modify: `internal/runtime/runtime_test.go`
  Responsibility: integration-style runtime tests proving startup order and conflict behavior.
- Create: `internal/runtime/orphan_cleanup_test.go`
  Responsibility: focused unit tests for orphan discovery, trust checks, and manifest-backed cleanup.

### Task 1: Add Manifest-Backed Orphan Cleanup Unit Coverage

**Files:**
- Create: `internal/runtime/orphan_cleanup_test.go`
- Reference: `internal/runtime/runtime.go`
- Reference: `internal/runtime/cleanup.go`

- [ ] **Step 1: Write the failing tests for trusted orphan discovery and cleanup**

```go
func TestCleanupOrphanedRuntimesRunsRecordedTeardownAndRemovesStateDir(t *testing.T) {
	stateRoot := t.TempDir()
	stateDir := filepath.Join(stateRoot, "runtime-orphan-a")
	manifest := Manifest{
		RuntimeID:    "runtime-orphan-a",
		StateRoot:    stateRoot,
		StateDir:     stateDir,
		ManifestPath: filepath.Join(stateDir, manifestFileName),
		TeardownCmds: []string{
			"nft delete table inet box_deadbeef",
			"ip rule del fwmark 257 lookup 10001",
		},
		ManagedPaths: []ManagedPath{
			{Path: filepath.Join(stateDir, manifestFileName), Kind: PathKindFile},
			{Path: stateDir, Kind: PathKindDir},
		},
	}

	exec := &recordingCommandExec{}
	err := cleanupOrphanedRuntimes(context.Background(), stateRoot, exec)

	if err != nil {
		t.Fatalf("cleanupOrphanedRuntimes() error = %v", err)
	}
	if _, err := os.Stat(stateDir); !os.IsNotExist(err) {
		t.Fatalf("state dir still exists after orphan cleanup: %v", err)
	}
	if len(exec.calls) != 2 {
		t.Fatalf("teardown commands = %#v, want recorded teardown only", exec.calls)
	}
}

func TestCleanupOrphanedRuntimesSkipsManifestWithMismatchedStateDir(t *testing.T) {
	// Manifest.StateDir points elsewhere, so cleanup must ignore it.
}
```

- [ ] **Step 2: Run the orphan cleanup test file to verify the new tests fail for the expected missing-symbol reason**

Run: `go test ./internal/runtime -run 'TestCleanupOrphanedRuntimes' -count=1`

Expected: FAIL with undefined `cleanupOrphanedRuntimes` and missing helper/validation behavior.

- [ ] **Step 3: Add any extra failing tests needed to pin malformed-manifest handling**

```go
func TestCleanupOrphanedRuntimesSkipsUnreadableOrMalformedManifest(t *testing.T) {
	// Write bad JSON to manifest.json and assert no teardown commands run.
}
```

- [ ] **Step 4: Re-run the focused orphan cleanup tests and confirm they still fail for missing implementation, not test setup mistakes**

Run: `go test ./internal/runtime -run 'TestCleanupOrphanedRuntimes' -count=1`

Expected: FAIL with the implementation still absent.

- [ ] **Step 5: Commit the red tests**

```bash
git add internal/runtime/orphan_cleanup_test.go
git commit -m "test: add orphan runtime cleanup coverage"
```

### Task 2: Implement Trusted Orphan Discovery and Manifest-Backed Cleanup

**Files:**
- Create: `internal/runtime/orphan_cleanup.go`
- Modify: `internal/runtime/cleanup.go`
- Test: `internal/runtime/orphan_cleanup_test.go`

- [ ] **Step 1: Implement minimal orphan cleanup helpers to satisfy the focused tests**

```go
func cleanupOrphanedRuntimes(ctx context.Context, stateRoot string, execer CommandExec) error {
	entries, err := os.ReadDir(stateRoot)
	if err != nil {
		return fmt.Errorf("scan runtime state root %q: %w", stateRoot, err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		manifest, ok, err := loadTrustedOrphanManifest(stateRoot, entry.Name())
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		if err := Cleanup(ctx, manifest, CleanupDeps{CommandExec: execer}); err != nil {
			return fmt.Errorf("cleanup orphan runtime %q: %w", manifest.RuntimeID, err)
		}
	}
	return nil
}

func loadTrustedOrphanManifest(stateRoot, runtimeID string) (Manifest, bool, error) {
	// Join stateRoot/runtimeID/manifest.json, decode JSON, and require:
	// - manifest.RuntimeID == runtimeID
	// - cleaned Manifest.StateDir == scanned directory
	// - cleaned Manifest.ManifestPath == scanned manifest path
	// - managed paths validate under the existing cleanup rules
}
```

- [ ] **Step 2: Run the focused orphan cleanup tests and verify they pass**

Run: `go test ./internal/runtime -run 'TestCleanupOrphanedRuntimes' -count=1`

Expected: PASS

- [ ] **Step 3: Refactor shared validation only if needed to keep orphan cleanup small and avoid duplicating path-safety logic**

```go
// If helper extraction is needed, keep it internal/runtime-local and reuse
// validateManagedPath/pathInsideOrEqual rather than widening cleanup scope.
```

- [ ] **Step 4: Re-run the focused orphan cleanup tests after the refactor**

Run: `go test ./internal/runtime -run 'TestCleanupOrphanedRuntimes' -count=1`

Expected: PASS

- [ ] **Step 5: Commit the orphan cleanup implementation**

```bash
git add internal/runtime/orphan_cleanup.go internal/runtime/cleanup.go internal/runtime/orphan_cleanup_test.go
git commit -m "feat: clean orphaned runtime state"
```

### Task 3: Integrate Orphan Cleanup Into Runtime Startup

**Files:**
- Modify: `internal/runtime/runtime.go`
- Modify: `internal/runtime/runtime_test.go`
- Test: `internal/runtime/orphan_cleanup_test.go`

- [ ] **Step 1: Write the failing startup-order test**

```go
func TestRunCleansTrustedOrphansBeforeMonitorPreflight(t *testing.T) {
	stateRoot := t.TempDir()
	writeTrustedOrphanManifest(t, stateRoot, Manifest{
		RuntimeID:    "runtime-orphan-b",
		StateRoot:    stateRoot,
		StateDir:     filepath.Join(stateRoot, "runtime-orphan-b"),
		ManifestPath: filepath.Join(stateRoot, "runtime-orphan-b", manifestFileName),
		TeardownCmds: []string{"nft delete table inet box_orphaned"},
		ManagedPaths: []ManagedPath{
			{Path: filepath.Join(stateRoot, "runtime-orphan-b", manifestFileName), Kind: PathKindFile},
			{Path: filepath.Join(stateRoot, "runtime-orphan-b"), Kind: PathKindDir},
		},
	})

	exec := &recordingCommandExec{}
	preflightSawCleanHost := false
	_, err := Run(context.Background(), Request{
		Config:    testConfig("monitor"),
		StateRoot: stateRoot,
	}, Deps{
		Clock:       fixedClock,
		RandomID:    func() string { return "runtime-live-a" },
		CommandExec: exec,
		MonitorPreflight: func(context.Context, MonitorPreflightRequest) error {
			preflightSawCleanHost = !slices.Contains(exec.calls, "nft delete table inet box_orphaned")
			return nil
		},
		DNS: func(context.Context, DNSStartRequest) (Runner, error) { return noopRunner{}, nil },
	})

	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !preflightSawCleanHost {
		t.Fatalf("preflight ran before orphan cleanup")
	}
}
```

- [ ] **Step 2: Run the startup-order test to verify it fails before integration**

Run: `go test ./internal/runtime -run 'TestRunCleansTrustedOrphansBeforeMonitorPreflight' -count=1`

Expected: FAIL because `Run(...)` does not call orphan cleanup before preflight yet.

- [ ] **Step 3: Add the minimal runtime startup call**

```go
stateRoot, err := filepath.Abs(resolvedRoot)
if err != nil {
	return nil, fmt.Errorf("resolve runtime state root %q: %w", req.StateRoot, err)
}
if err := cleanupOrphanedRuntimes(ctx, stateRoot, deps.CommandExec); err != nil {
	return nil, err
}
```

- [ ] **Step 4: Run the startup-order test and the focused orphan cleanup tests**

Run: `go test ./internal/runtime -run 'TestRunCleansTrustedOrphansBeforeMonitorPreflight|TestCleanupOrphanedRuntimes' -count=1`

Expected: PASS

- [ ] **Step 5: Add or update a strict-conflict test proving startup still fails closed when cleanup cannot prove ownership**

```go
func TestRunLeavesUntrustedOrphanStateForConflictHandling(t *testing.T) {
	// Write a malformed or mismatched manifest and assert the existing
	// MonitorPreflight conflict path still returns ErrResourceConflict.
}
```

- [ ] **Step 6: Run the targeted runtime package suite**

Run: `go test ./internal/runtime -count=1`

Expected: PASS

- [ ] **Step 7: Commit the runtime integration**

```bash
git add internal/runtime/runtime.go internal/runtime/runtime_test.go internal/runtime/orphan_cleanup_test.go
git commit -m "feat: clean orphans before runtime preflight"
```

### Task 4: Full Verification and Documentation Sweep

**Files:**
- Verify: `internal/runtime/orphan_cleanup.go`
- Verify: `internal/runtime/runtime.go`
- Verify: `internal/runtime/orphan_cleanup_test.go`
- Verify: `internal/runtime/runtime_test.go`

- [ ] **Step 1: Run the package-level verification called for by the spec**

Run: `go test ./cmd/box ./internal/runtime -count=1`

Expected: PASS

- [ ] **Step 2: Run the full repository suite**

Run: `go test ./... -count=1`

Expected: PASS

- [ ] **Step 3: Check the diff for accidental scope creep**

Run: `git diff --stat HEAD~3..HEAD`

Expected: only runtime orphan-cleanup implementation, tests, and any tiny helper extraction required to support them.

- [ ] **Step 4: Commit any final cleanup if verification required minor polish**

```bash
git add internal/runtime/orphan_cleanup.go internal/runtime/runtime.go internal/runtime/orphan_cleanup_test.go internal/runtime/runtime_test.go
git commit -m "test: finalize orphan cleanup verification"
```

