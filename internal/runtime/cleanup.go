package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type CleanupDeps struct {
	CommandExec CommandExec
	StopRunner  func(name string) error
	RemovePath  func(path string, kind PathKind) error
}

func Cleanup(ctx context.Context, manifest Manifest, deps CleanupDeps) error {
	var errs []error

	for i := len(manifest.StartedRunners) - 1; i >= 0; i-- {
		runnerName := manifest.StartedRunners[i]
		if deps.StopRunner == nil {
			continue
		}
		if err := deps.StopRunner(runnerName); err != nil {
			errs = append(errs, fmt.Errorf("stop runner %q: %w", runnerName, err))
		}
	}

	errs = append(errs, runTeardownCommandsBestEffort(ctx, deps.CommandExec, manifest.TeardownCmds)...)

	removePath := deps.RemovePath
	if removePath == nil {
		removePath = defaultRemovePath
	}

	retryDirs := make([]ManagedPath, 0, len(manifest.ManagedPaths))
	for i := len(manifest.ManagedPaths) - 1; i >= 0; i-- {
		path := manifest.ManagedPaths[i]
		if err := validateManagedPath(manifest, path); err != nil {
			errs = append(errs, err)
			continue
		}
		if err := removePath(path.Path, path.Kind); err != nil {
			if path.Kind == PathKindDir {
				retryDirs = append(retryDirs, path)
				continue
			}
			if !os.IsNotExist(err) {
				errs = append(errs, fmt.Errorf("remove %s %q: %w", path.Kind, path.Path, err))
			}
		}
	}

	for _, path := range retryDirs {
		if err := removePath(path.Path, path.Kind); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("remove %s %q: %w", path.Kind, path.Path, err))
		}
	}

	return errors.Join(errs...)
}

func runTeardownCommandsBestEffort(ctx context.Context, execer CommandExec, commands []string) []error {
	if execer == nil {
		return nil
	}

	var errs []error
	for _, command := range commands {
		fields := strings.Fields(command)
		if len(fields) == 0 {
			continue
		}
		if err := execer.Run(ctx, fields[0], fields[1:]...); err != nil {
			errs = append(errs, fmt.Errorf("run %q: %w", command, err))
		}
	}
	return errs
}

func validateManagedPath(manifest Manifest, path ManagedPath) error {
	if path.Path == "" {
		return errors.New("managed path is empty")
	}
	if path.Kind != PathKindFile && path.Kind != PathKindDir {
		return fmt.Errorf("managed path %q has unsupported kind %q", path.Path, path.Kind)
	}

	stateDir := filepath.Clean(manifest.StateDir)
	stateRoot := filepath.Clean(manifest.StateRoot)
	target := filepath.Clean(path.Path)

	if stateDir == "." || stateDir == string(filepath.Separator) {
		return fmt.Errorf("unsafe runtime state dir %q", manifest.StateDir)
	}
	if stateRoot == "." || stateRoot == string(filepath.Separator) {
		return fmt.Errorf("unsafe runtime state root %q", manifest.StateRoot)
	}
	if !pathInsideOrEqual(stateDir, target) {
		return fmt.Errorf("managed path %q is outside runtime state dir %q", path.Path, manifest.StateDir)
	}
	if !pathInsideOrEqual(stateRoot, stateDir) {
		return fmt.Errorf("runtime state dir %q is outside runtime root %q", manifest.StateDir, manifest.StateRoot)
	}
	return nil
}

func pathInsideOrEqual(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func defaultRemovePath(path string, kind PathKind) error {
	switch kind {
	case PathKindFile, PathKindDir:
		if kind == PathKindDir {
			return os.RemoveAll(path)
		}
		return os.Remove(path)
	default:
		return fmt.Errorf("unsupported path kind %q", kind)
	}
}
