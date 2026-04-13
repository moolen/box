package envoy

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestResolveBundledEnvoyPrefersSiblingBinary(t *testing.T) {
	got, err := ResolveBinary(BinaryLocator{
		ExecutablePath: "/tmp/bin/box",
		FileExists: func(path string) bool {
			return path == "/tmp/bin/envoy"
		},
	})
	if err != nil {
		t.Fatalf("ResolveBinary() error = %v", err)
	}
	if got != "/tmp/bin/envoy" {
		t.Fatalf("ResolveBinary() = %q, want /tmp/bin/envoy", got)
	}
}

func TestArgsIncludesBootstrapAndLogPath(t *testing.T) {
	args, err := Args(StartRequest{
		BinaryPath:    "/tmp/bin/envoy",
		BootstrapPath: "/tmp/runtime/bootstrap.yaml",
		LogPath:       "/tmp/runtime/envoy.log",
	})
	if err != nil {
		t.Fatalf("Args() error = %v", err)
	}

	joined := strings.Join(args, " ")
	for _, want := range []string{
		"-c /tmp/runtime/bootstrap.yaml",
		"--disable-hot-restart",
		"--log-path /tmp/runtime/envoy.log",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("Args() = %#v, want %q", args, want)
		}
	}
}

func TestStartFailsForMissingBinary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err := Start(ctx, StartRequest{
		BinaryPath:    "/definitely/missing/envoy",
		BootstrapPath: "/tmp/bootstrap.yaml",
	})
	if err == nil {
		t.Fatal("Start() error = nil, want missing binary failure")
	}
}
