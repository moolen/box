package rootfs

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	envInitShimPath        = "BOX_INIT_SHIM_PATH"
	defaultInitShimAbsPath = "/usr/local/libexec/box-initshim"
)

type ApplyRequest struct {
	Plan           Plan
	BundleDir      string
	InitShimPath   string
	ExecutablePath string
}

type ApplyResult struct {
	InitShimSourcePath string
	InitShimBundlePath string
}

func Apply(req ApplyRequest) (ApplyResult, error) {
	if strings.TrimSpace(req.BundleDir) == "" {
		return ApplyResult{}, errors.New("bundle dir is required")
	}
	if err := os.MkdirAll(req.BundleDir, 0o755); err != nil {
		return ApplyResult{}, err
	}

	rootfsDir := filepath.Join(req.BundleDir, "rootfs")
	if err := os.MkdirAll(rootfsDir, 0o755); err != nil {
		return ApplyResult{}, err
	}

	for _, file := range req.Plan.GeneratedFiles {
		if err := writeGeneratedFile(rootfsDir, file); err != nil {
			return ApplyResult{}, err
		}
	}

	shimSource := resolveInitShimPath(req.InitShimPath, req.ExecutablePath)
	bundleShimPath := filepath.Join(rootfsDir, "box-initshim")
	if err := copyFile(shimSource, bundleShimPath, 0o755); err != nil {
		return ApplyResult{}, err
	}

	return ApplyResult{
		InitShimSourcePath: shimSource,
		InitShimBundlePath: bundleShimPath,
	}, nil
}

func resolveInitShimPath(explicit, executablePath string) string {
	if value := strings.TrimSpace(explicit); value != "" {
		return value
	}
	if fromEnv := strings.TrimSpace(os.Getenv(envInitShimPath)); fromEnv != "" {
		return fromEnv
	}
	if value := strings.TrimSpace(executablePath); value != "" {
		sibling := filepath.Join(filepath.Dir(value), "box-initshim")
		if _, err := os.Stat(sibling); err == nil {
			return sibling
		}
	}
	return defaultInitShimAbsPath
}

func writeGeneratedFile(rootfsDir string, file GeneratedFile) error {
	clean := filepath.Clean(file.Path)
	rel := strings.TrimPrefix(clean, "/")
	if rel == "." || rel == "" {
		return fmt.Errorf("invalid generated file path %q", file.Path)
	}
	path := filepath.Join(rootfsDir, rel)
	if !pathWithinRootfs(rootfsDir, path) {
		return fmt.Errorf("generated file path %q escapes rootfs", file.Path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	mode := file.Mode
	if mode == 0 {
		mode = 0o644
	}
	return os.WriteFile(path, []byte(file.Content), mode)
}

func copyFile(src, dst string, fallbackMode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	info, err := in.Stat()
	if err != nil {
		return err
	}
	mode := info.Mode().Perm()
	if mode == 0 {
		mode = fallbackMode
	}

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return nil
}

func pathWithinRootfs(rootfsDir, path string) bool {
	rel, err := filepath.Rel(rootfsDir, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}
