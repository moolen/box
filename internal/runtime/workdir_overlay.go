package runtime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gvisor-net/internal/config"
)

func prepareWorkdirOverlay(ctx context.Context, cfg config.Config, manifest *Manifest, execer CommandExec) error {
	if manifest == nil {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(cfg.Sandbox.Rootfs), "host-overlay") {
		return nil
	}
	if !cfg.Sandbox.WorkdirOverlay {
		return nil
	}
	if execer == nil {
		return nil
	}

	lowerdir := strings.TrimSpace(cfg.Sandbox.Workdir)
	if lowerdir == "" {
		return nil
	}

	baseDir := filepath.Join(manifest.StateDir, "workdir")
	upperdir := filepath.Join(baseDir, "upper")
	workdir := filepath.Join(baseDir, "work")
	mergeddir := filepath.Join(baseDir, "merged")
	for _, dir := range []string{upperdir, workdir, mergeddir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create workdir overlay path %q: %w", dir, err)
		}
	}

	options := fmt.Sprintf(
		"lowerdir=%s,upperdir=%s,workdir=%s",
		escapeOverlayPath(lowerdir),
		escapeOverlayPath(upperdir),
		escapeOverlayPath(workdir),
	)
	if err := execer.Run(ctx, "mount", "-t", "overlay", "overlay", "-o", options, mergeddir); err != nil {
		return fmt.Errorf("mount workdir overlay: %w", err)
	}

	manifest.WorkdirMountSource = mergeddir
	manifest.TeardownCmds = append(manifest.TeardownCmds, "umount "+mergeddir)
	return nil
}

func escapeOverlayPath(path string) string {
	replacer := strings.NewReplacer(
		`\`, `\\`,
		`,`, `\,`,
		`:`, `\:`,
	)
	return replacer.Replace(path)
}
