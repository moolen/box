package testenv

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestFindModuleRoot(t *testing.T) {
	t.Parallel()

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd() error = %v", err)
	}

	root, err := findModuleRoot(cwd)
	if err != nil {
		t.Fatalf("findModuleRoot() error = %v", err)
	}

	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("module root %q missing go.mod: %v", root, err)
	}
}

func TestInvalidPackageReturnsBuildError(t *testing.T) {
	t.Parallel()

	output := filepath.Join(t.TempDir(), "box-test-bin")
	err := buildPackage("./cmd/definitely-not-a-package", output)
	if err == nil {
		t.Fatal("buildPackage() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "go build") {
		t.Fatalf("buildPackage() error = %q, want mention of go build", err)
	}
}

func TestGoBuildArgsDisableVCSStamping(t *testing.T) {
	t.Parallel()

	got := goBuildArgs("./cmd/box", "/tmp/box")
	want := []string{"build", "-buildvcs=false", "-o", "/tmp/box", "./cmd/box"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("goBuildArgs() = %#v, want %#v", got, want)
	}
}
