package runtime

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCleanupOrphanedRuntimesRunsRecordedTeardownAndRemovesStateDir(t *testing.T) {
	t.Parallel()

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
	writeOrphanManifestForTest(t, manifest)

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
	t.Parallel()

	stateRoot := t.TempDir()
	stateDir := filepath.Join(stateRoot, "runtime-orphan-b")
	mismatchedStateDir := filepath.Join(stateRoot, "runtime-other")
	manifest := Manifest{
		RuntimeID:    "runtime-orphan-b",
		StateRoot:    stateRoot,
		StateDir:     mismatchedStateDir,
		ManifestPath: filepath.Join(stateDir, manifestFileName),
		TeardownCmds: []string{"nft delete table inet box_orphan_b"},
		ManagedPaths: []ManagedPath{
			{Path: filepath.Join(stateDir, manifestFileName), Kind: PathKindFile},
			{Path: stateDir, Kind: PathKindDir},
		},
	}
	writeOrphanManifestForTest(t, manifest)

	exec := &recordingCommandExec{}
	err := cleanupOrphanedRuntimes(context.Background(), stateRoot, exec)
	if err != nil {
		t.Fatalf("cleanupOrphanedRuntimes() error = %v", err)
	}
	if len(exec.calls) != 0 {
		t.Fatalf("teardown commands = %#v, want none for mismatched manifest", exec.calls)
	}
	if _, err := os.Stat(stateDir); err != nil {
		t.Fatalf("state dir should be kept for untrusted manifest: %v", err)
	}
}

func TestCleanupOrphanedRuntimesSkipsUnreadableOrMalformedManifest(t *testing.T) {
	t.Parallel()

	stateRoot := t.TempDir()

	unreadableDir := filepath.Join(stateRoot, "runtime-unreadable")
	unreadableManifestPath := filepath.Join(unreadableDir, manifestFileName)
	if err := os.MkdirAll(unreadableManifestPath, 0o755); err != nil {
		t.Fatalf("MkdirAll(unreadable manifest dir) error = %v", err)
	}

	malformedDir := filepath.Join(stateRoot, "runtime-malformed")
	if err := os.MkdirAll(malformedDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(malformed dir) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(malformedDir, manifestFileName), []byte("{bad json"), 0o644); err != nil {
		t.Fatalf("WriteFile(malformed manifest) error = %v", err)
	}

	exec := &recordingCommandExec{}
	err := cleanupOrphanedRuntimes(context.Background(), stateRoot, exec)
	if err != nil {
		t.Fatalf("cleanupOrphanedRuntimes() error = %v", err)
	}
	if len(exec.calls) != 0 {
		t.Fatalf("teardown commands = %#v, want none for unreadable/malformed manifests", exec.calls)
	}
}

func TestCleanupOrphanedRuntimesReturnsErrorWhenStateRootScanFails(t *testing.T) {
	t.Parallel()

	stateRoot := filepath.Join(t.TempDir(), "does-not-exist")
	err := cleanupOrphanedRuntimes(context.Background(), stateRoot, &recordingCommandExec{})
	if err == nil {
		t.Fatalf("cleanupOrphanedRuntimes() error = nil, want non-nil when state root scan fails")
	}
}

func TestCleanupOrphanedRuntimesReturnsErrorWhenTrustedCleanupFails(t *testing.T) {
	t.Parallel()

	stateRoot := t.TempDir()
	stateDir := filepath.Join(stateRoot, "runtime-orphan-c")
	manifest := Manifest{
		RuntimeID:    "runtime-orphan-c",
		StateRoot:    stateRoot,
		StateDir:     stateDir,
		ManifestPath: filepath.Join(stateDir, manifestFileName),
		TeardownCmds: []string{
			"nft delete table inet box_orphan_c",
		},
		ManagedPaths: []ManagedPath{
			{Path: filepath.Join(stateDir, manifestFileName), Kind: PathKindFile},
			{Path: stateDir, Kind: PathKindDir},
		},
	}
	writeOrphanManifestForTest(t, manifest)

	exec := &failingCommandExec{
		failures: map[string]error{
			"nft delete table inet box_orphan_c": os.ErrPermission,
		},
	}
	err := cleanupOrphanedRuntimes(context.Background(), stateRoot, exec)
	if err == nil {
		t.Fatalf("cleanupOrphanedRuntimes() error = nil, want cleanup failure")
	}
}

func TestCleanupOrphanedRuntimesSkipsCleanupWhenCommandExecMissing(t *testing.T) {
	t.Parallel()

	stateRoot := t.TempDir()
	stateDir := filepath.Join(stateRoot, "runtime-orphan-no-exec")
	manifest := Manifest{
		RuntimeID:    "runtime-orphan-no-exec",
		StateRoot:    stateRoot,
		StateDir:     stateDir,
		ManifestPath: filepath.Join(stateDir, manifestFileName),
		TeardownCmds: []string{
			"nft delete table inet box_orphan_no_exec",
		},
		ManagedPaths: []ManagedPath{
			{Path: filepath.Join(stateDir, manifestFileName), Kind: PathKindFile},
			{Path: stateDir, Kind: PathKindDir},
		},
	}
	writeOrphanManifestForTest(t, manifest)

	err := cleanupOrphanedRuntimes(context.Background(), stateRoot, nil)
	if err != nil {
		t.Fatalf("cleanupOrphanedRuntimes() error = %v", err)
	}

	if _, err := os.Stat(stateDir); err != nil {
		t.Fatalf("state dir should remain when command exec is unavailable: %v", err)
	}
	if _, err := os.Stat(manifest.ManifestPath); err != nil {
		t.Fatalf("manifest should remain when command exec is unavailable: %v", err)
	}
}

func writeOrphanManifestForTest(t *testing.T, manifest Manifest) {
	t.Helper()

	if err := os.MkdirAll(manifest.StateDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(state dir) error = %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(manifest.ManifestPath), 0o755); err != nil {
		t.Fatalf("MkdirAll(manifest dir) error = %v", err)
	}
	if err := writeManifest(manifest.ManifestPath, manifest); err != nil {
		t.Fatalf("writeManifest() error = %v", err)
	}
}
