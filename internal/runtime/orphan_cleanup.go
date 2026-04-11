package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func cleanupOrphanedRuntimes(ctx context.Context, stateRoot string, execer CommandExec) error {
	entries, err := os.ReadDir(stateRoot)
	if err != nil {
		return fmt.Errorf("scan runtime state root %q: %w", stateRoot, err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		manifest, ok := loadTrustedOrphanManifest(stateRoot, entry.Name())
		if !ok {
			continue
		}

		if err := Cleanup(ctx, manifest, CleanupDeps{CommandExec: execer}); err != nil {
			return fmt.Errorf("cleanup orphan runtime %q: %w", manifest.RuntimeID, err)
		}
	}

	return nil
}

func loadTrustedOrphanManifest(stateRoot, runtimeID string) (Manifest, bool) {
	stateDir := filepath.Join(stateRoot, runtimeID)
	manifestPath := filepath.Join(stateDir, manifestFileName)

	content, err := os.ReadFile(manifestPath)
	if err != nil {
		return Manifest{}, false
	}

	var manifest Manifest
	if err := json.Unmarshal(content, &manifest); err != nil {
		return Manifest{}, false
	}

	if !trustedOrphanManifest(manifest, runtimeID, stateDir, manifestPath) {
		return Manifest{}, false
	}

	return manifest, true
}

func trustedOrphanManifest(manifest Manifest, runtimeID, stateDir, manifestPath string) bool {
	if manifest.RuntimeID != runtimeID {
		return false
	}

	wantStateDir, ok := cleanAbsPath(stateDir)
	if !ok {
		return false
	}
	wantManifestPath, ok := cleanAbsPath(manifestPath)
	if !ok {
		return false
	}

	gotStateDir, ok := cleanAbsPath(manifest.StateDir)
	if !ok {
		return false
	}
	gotManifestPath, ok := cleanAbsPath(manifest.ManifestPath)
	if !ok {
		return false
	}

	return gotStateDir == wantStateDir &&
		gotManifestPath == wantManifestPath
}

func cleanAbsPath(path string) (string, bool) {
	if path == "" {
		return "", false
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", false
	}
	return filepath.Clean(abs), true
}
