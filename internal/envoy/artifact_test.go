package envoy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestResolveContainerRuntimePrefersDockerThenPodman(t *testing.T) {
	t.Parallel()

	got, err := ResolveContainerRuntime(RuntimeLocator{
		LookPath: func(name string) (string, error) {
			switch name {
			case "docker":
				return "/usr/bin/docker", nil
			case "podman":
				return "/usr/bin/podman", nil
			default:
				return "", errors.New("unexpected binary")
			}
		},
	})
	if err != nil {
		t.Fatalf("ResolveContainerRuntime() error = %v", err)
	}
	if got != "docker" {
		t.Fatalf("ResolveContainerRuntime() = %q, want docker", got)
	}
}

func TestBundledImageRefUsesDigestOnlyReference(t *testing.T) {
	t.Parallel()

	if !strings.Contains(BundledImageRef, "@sha256:") {
		t.Fatalf("BundledImageRef = %q, want digest-pinned reference", BundledImageRef)
	}

	repo, _, ok := strings.Cut(BundledImageRef, "@")
	if !ok {
		t.Fatalf("BundledImageRef = %q, want @sha256 separator", BundledImageRef)
	}
	nameOnly := repo[strings.LastIndex(repo, "/")+1:]
	if strings.Contains(nameOnly, ":") {
		t.Fatalf("BundledImageRef = %q, want digest-only reference without tag suffix", BundledImageRef)
	}
}

func TestStageBundledBinaryUsesPinnedImageAndCopiesBinary(t *testing.T) {
	t.Parallel()

	outputPath := filepath.Join(t.TempDir(), "envoy")
	var calls []string

	err := StageBundledBinary(context.Background(), StageRequest{
		OutputPath: outputPath,
		Runtime:    "docker",
		Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			calls = append(calls, strings.TrimSpace(name+" "+strings.Join(args, " ")))
			switch {
			case name == "docker" && len(args) >= 2 && args[0] == "create":
				return []byte("container-123\n"), nil
			case name == "docker" && len(args) >= 2 && args[0] == "cp":
				if err := os.WriteFile(outputPath+".tmp", []byte("envoy-binary"), 0o755); err != nil {
					return nil, err
				}
				return nil, nil
			case name == outputPath+".tmp" && reflect.DeepEqual(args, []string{"--version"}):
				return []byte("envoy  version: " + BundledVersion + "\n"), nil
			case name == "docker" && len(args) >= 2 && args[0] == "rm":
				return nil, nil
			default:
				return nil, errors.New("unexpected command")
			}
		},
	})
	if err != nil {
		t.Fatalf("StageBundledBinary() error = %v", err)
	}

	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("ReadFile(outputPath) error = %v", err)
	}
	if string(content) != "envoy-binary" {
		t.Fatalf("staged content = %q, want copied envoy binary", string(content))
	}

	wantCreate := "docker create " + BundledImageRef
	wantCP := "docker cp container-123:/usr/local/bin/envoy " + outputPath + ".tmp"
	wantVersion := outputPath + ".tmp --version"
	wantRemove := "docker rm -f container-123"
	for _, want := range []string{wantCreate, wantCP, wantVersion, wantRemove} {
		if !containsCall(calls, want) {
			t.Fatalf("command calls = %#v, want %q", calls, want)
		}
	}
}

func TestStageBundledBinaryPassesPlatformToContainerRuntime(t *testing.T) {
	t.Parallel()

	outputPath := filepath.Join(t.TempDir(), "envoy")
	var calls []string

	err := StageBundledBinary(context.Background(), StageRequest{
		OutputPath: outputPath,
		Runtime:    "docker",
		Platform:   "linux/arm64",
		Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			calls = append(calls, strings.TrimSpace(name+" "+strings.Join(args, " ")))
			switch {
			case name == "docker" && len(args) >= 4 && args[0] == "create":
				return []byte("container-123\n"), nil
			case name == "docker" && len(args) >= 2 && args[0] == "cp":
				if err := os.WriteFile(outputPath+".tmp", []byte("envoy-binary"), 0o755); err != nil {
					return nil, err
				}
				return nil, nil
			case name == outputPath+".tmp":
				return []byte("envoy  version: " + BundledVersion + "\n"), nil
			case name == "docker" && len(args) >= 2 && args[0] == "rm":
				return nil, nil
			default:
				return nil, errors.New("unexpected command")
			}
		},
	})
	if err != nil {
		t.Fatalf("StageBundledBinary() error = %v", err)
	}
	if !containsCall(calls, "docker create --platform linux/arm64 "+BundledPlatformImageRef) {
		t.Fatalf("command calls = %#v, want docker create with explicit platform tag reference", calls)
	}
}

func TestStageBundledBinaryParsesContainerIDFromCreateOutputWithPullProgress(t *testing.T) {
	t.Parallel()

	outputPath := filepath.Join(t.TempDir(), "envoy")
	var copyArg string

	err := StageBundledBinary(context.Background(), StageRequest{
		OutputPath: outputPath,
		Runtime:    "docker",
		Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			switch {
			case name == "docker" && len(args) >= 2 && args[0] == "create":
				return []byte("Unable to find image 'envoyproxy/envoy:distroless-v1.37.1' locally\nsha256:container-123\n"), nil
			case name == "docker" && len(args) >= 2 && args[0] == "cp":
				copyArg = args[1]
				if err := os.WriteFile(outputPath+".tmp", []byte("envoy-binary"), 0o755); err != nil {
					return nil, err
				}
				return nil, nil
			case name == outputPath+".tmp":
				return []byte("envoy  version: " + BundledVersion + "\n"), nil
			case name == "docker" && len(args) >= 2 && args[0] == "rm":
				return nil, nil
			default:
				return nil, errors.New("unexpected command")
			}
		},
	})
	if err != nil {
		t.Fatalf("StageBundledBinary() error = %v", err)
	}
	if got, want := copyArg, "sha256:container-123:"+bundledBinaryInImage; got != want {
		t.Fatalf("docker cp source = %q, want %q", got, want)
	}
}

func TestStageBundledBinaryRejectsVersionMismatch(t *testing.T) {
	t.Parallel()

	outputPath := filepath.Join(t.TempDir(), "envoy")

	err := StageBundledBinary(context.Background(), StageRequest{
		OutputPath: outputPath,
		Runtime:    "docker",
		Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			switch {
			case name == "docker" && len(args) >= 2 && args[0] == "create":
				return []byte("container-123\n"), nil
			case name == "docker" && len(args) >= 2 && args[0] == "cp":
				if err := os.WriteFile(outputPath+".tmp", []byte("envoy-binary"), 0o755); err != nil {
					return nil, err
				}
				return nil, nil
			case name == outputPath+".tmp":
				return []byte("envoy  version: old-build\n"), nil
			case name == "docker" && len(args) >= 2 && args[0] == "rm":
				return nil, nil
			default:
				return nil, errors.New("unexpected command")
			}
		},
	})
	if err == nil {
		t.Fatal("StageBundledBinary() error = nil, want version mismatch")
	}
	if !strings.Contains(err.Error(), BundledVersion) {
		t.Fatalf("StageBundledBinary() error = %q, want pinned version context", err.Error())
	}
}

func TestStageBundledBinaryIncludesContainerRuntimeOutputOnCopyFailure(t *testing.T) {
	t.Parallel()

	outputPath := filepath.Join(t.TempDir(), "envoy")

	err := StageBundledBinary(context.Background(), StageRequest{
		OutputPath: outputPath,
		Runtime:    "docker",
		Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			switch {
			case name == "docker" && len(args) >= 2 && args[0] == "create":
				return []byte("container-123\n"), nil
			case name == "docker" && len(args) >= 2 && args[0] == "cp":
				return []byte("permission denied"), errors.New("exit status 1")
			case name == "docker" && len(args) >= 2 && args[0] == "rm":
				return nil, nil
			default:
				return nil, errors.New("unexpected command")
			}
		},
	})
	if err == nil {
		t.Fatal("StageBundledBinary() error = nil, want copy failure")
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("StageBundledBinary() error = %q, want container runtime output", err.Error())
	}
}

func containsCall(calls []string, want string) bool {
	for _, call := range calls {
		if call == want {
			return true
		}
	}
	return false
}
