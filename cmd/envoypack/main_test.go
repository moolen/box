package main

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestRunParsesOutputFlagAndStagesBinary(t *testing.T) {
	t.Parallel()

	var gotOutput string
	err := run(context.Background(), []string{"--output", "/tmp/bin/envoy"}, func(_ context.Context, outputPath string, platform string) error {
		gotOutput = outputPath
		return nil
	})
	if err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if gotOutput != "/tmp/bin/envoy" {
		t.Fatalf("staged output = %q, want /tmp/bin/envoy", gotOutput)
	}
}

func TestRunRejectsMissingOutputFlag(t *testing.T) {
	t.Parallel()

	err := run(context.Background(), nil, func(context.Context, string, string) error { return nil })
	if err == nil {
		t.Fatal("run() error = nil, want missing output flag")
	}
}

func TestRunReturnsStageError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("boom")
	err := run(context.Background(), []string{"--output", "/tmp/bin/envoy"}, func(context.Context, string, string) error {
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("run() error = %v, want %v", err, wantErr)
	}
}

func TestRunParsesPlatformFlag(t *testing.T) {
	t.Parallel()

	var gotPlatform string
	err := run(context.Background(), []string{"--output", "/tmp/bin/envoy", "--platform", "linux/arm64"}, func(_ context.Context, _ string, platform string) error {
		gotPlatform = platform
		return nil
	})
	if err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if gotPlatform != "linux/arm64" {
		t.Fatalf("platform = %q, want linux/arm64", gotPlatform)
	}
}

func TestFilterArgsDropsGoRunSeparator(t *testing.T) {
	t.Parallel()

	got := filterArgs([]string{"--", "--output", "/tmp/bin/envoy"})
	want := []string{"--output", "/tmp/bin/envoy"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("filterArgs() = %#v, want %#v", got, want)
	}
}
