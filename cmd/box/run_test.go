package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gvisor-net/internal/config"
	boxruntime "gvisor-net/internal/runtime"
)

type stubExecutor struct {
	called bool
	req    runRequest
}

func (s *stubExecutor) Run(req runRequest) error {
	s.called = true
	s.req = req
	return nil
}

func TestRootCommandAcceptsConfigFlag(t *testing.T) {
	exec := &stubExecutor{}
	cmd := newRootCommand(deps{
		executor:        exec,
		resolveInitShim: func() string { return "/shim" },
		detectTTY: func() ttyState {
			return ttyState{}
		},
	})

	cmd.SetArgs([]string{"--config", "custom.yaml", "--", "/bin/pwd"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if !exec.called {
		t.Fatalf("executor was not called")
	}
	if exec.req.ConfigPath != "custom.yaml" {
		t.Fatalf("ConfigPath = %q, want %q", exec.req.ConfigPath, "custom.yaml")
	}
	if got, want := exec.req.Payload, []string{"/bin/pwd"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Payload = %#v, want %#v", got, want)
	}
}

func TestRootCommandRequiresPayloadAfterDoubleDash(t *testing.T) {
	exec := &stubExecutor{}
	cmd := newRootCommand(deps{
		executor:        exec,
		resolveInitShim: func() string { return "/shim" },
		detectTTY: func() ttyState {
			return ttyState{}
		},
	})

	cmd.SetArgs([]string{"--"})
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("Execute() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "payload") {
		t.Fatalf("error = %q, want contains %q", err.Error(), "payload")
	}
	if exec.called {
		t.Fatalf("executor should not be called on argument error")
	}
}

func TestRunSubcommandAcceptsPayloadAfterDoubleDash(t *testing.T) {
	exec := &stubExecutor{}
	cmd := newRootCommand(deps{
		executor:        exec,
		resolveInitShim: func() string { return "/shim" },
		detectTTY: func() ttyState {
			return ttyState{}
		},
	})

	cmd.SetArgs([]string{"run", "--", "bash", "-lc", "getent hosts example.com"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if !exec.called {
		t.Fatalf("executor was not called")
	}
	if got, want := exec.req.Payload, []string{"bash", "-lc", "getent hosts example.com"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Payload = %#v, want %#v", got, want)
	}
	got := shellCommand([]string{"bash", "-lc", "getent hosts example.com"})
	want := "bash -lc 'getent hosts example.com'"
	if got != want {
		t.Fatalf("shellCommand() = %q, want %q", got, want)
	}
}

func TestResolveInitShimPrefersEnvThenSiblingThenFallback(t *testing.T) {
	temp := t.TempDir()
	exePath := filepath.Join(temp, "box")
	sibling := filepath.Join(temp, "box-initshim")

	cases := []struct {
		name       string
		envValue   string
		fileExists func(path string) bool
		want       string
	}{
		{
			name:     "prefers env",
			envValue: "/env/initshim",
			fileExists: func(path string) bool {
				return true
			},
			want: "/env/initshim",
		},
		{
			name:     "uses sibling when present",
			envValue: "",
			fileExists: func(path string) bool {
				return path == sibling
			},
			want: sibling,
		},
		{
			name:     "falls back when sibling missing",
			envValue: "",
			fileExists: func(path string) bool {
				return false
			},
			want: defaultInitShimPath,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveInitShimPath(
				func(string) string { return tc.envValue },
				func() (string, error) { return exePath, nil },
				tc.fileExists,
			)
			if got != tc.want {
				t.Fatalf("resolveInitShimPath() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestTTYDetectionReportsInteractiveStdStreams(t *testing.T) {
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() stdin: %v", err)
	}
	defer stdinR.Close()
	defer stdinW.Close()

	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() stdout: %v", err)
	}
	defer stdoutR.Close()
	defer stdoutW.Close()

	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() stderr: %v", err)
	}
	defer stderrR.Close()
	defer stderrW.Close()

	state := detectTTY(stdinR, stdoutW, stderrW, func(fd uintptr) bool {
		return fd == stdinR.Fd() || fd == stderrW.Fd()
	})

	if !state.Stdin {
		t.Fatalf("Stdin = false, want true")
	}
	if state.Stdout {
		t.Fatalf("Stdout = true, want false")
	}
	if !state.Stderr {
		t.Fatalf("Stderr = false, want true")
	}
}

func TestCheckMonitorOwnershipDetectsNftTableConflict(t *testing.T) {
	t.Parallel()

	req := boxruntime.MonitorPreflightRequest{
		Net: boxruntime.NetResources{
			TableName: "box_deadbeef",
		},
	}

	err := checkMonitorOwnership(context.Background(), req, fakePreflightRunner(map[string]preflightCommandResult{
		"nft list table inet box_deadbeef": {output: "table inet box_deadbeef", err: nil},
	}))
	if err == nil {
		t.Fatal("checkMonitorOwnership() error = nil, want conflict")
	}
	if !errors.Is(err, boxruntime.ErrResourceConflict) {
		t.Fatalf("checkMonitorOwnership() error = %v, want ErrResourceConflict", err)
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("checkMonitorOwnership() error = %q, want already exists message", err.Error())
	}
}

func TestCheckMonitorOwnershipAllowsMissingResources(t *testing.T) {
	t.Parallel()

	req := boxruntime.MonitorPreflightRequest{
		Net: boxruntime.NetResources{
			TableName:  "box_deadbeef",
			FWMark:     0x1234,
			RouteTable: 12345,
			NetNS:      "box-deadbeef",
			HostVeth:   "vethhdeadbeef",
		},
	}

	err := checkMonitorOwnership(context.Background(), req, fakePreflightRunner(map[string]preflightCommandResult{
		"nft list table inet box_deadbeef": {output: "No such file or directory", err: errors.New("exit status 1")},
		"ip -o route show table 12345":     {output: "", err: nil},
		"ip -o rule show":                  {output: "0: from all lookup local\n", err: nil},
		"ip netns list":                    {output: "", err: nil},
		"ip link show vethhdeadbeef":       {output: "Device \"vethhdeadbeef\" does not exist.", err: errors.New("exit status 1")},
	}))
	if err != nil {
		t.Fatalf("checkMonitorOwnership() error = %v, want nil", err)
	}
}

func TestCheckMonitorOwnershipFailsClosedWhenProbeErrors(t *testing.T) {
	t.Parallel()

	req := boxruntime.MonitorPreflightRequest{
		Net: boxruntime.NetResources{
			TableName: "box_deadbeef",
		},
	}

	err := checkMonitorOwnership(context.Background(), req, fakePreflightRunner(map[string]preflightCommandResult{
		"nft list table inet box_deadbeef": {output: "", err: errors.New("permission denied")},
	}))
	if err == nil {
		t.Fatal("checkMonitorOwnership() error = nil, want non-nil")
	}
	if !errors.Is(err, boxruntime.ErrResourceConflict) {
		t.Fatalf("checkMonitorOwnership() error = %v, want ErrResourceConflict", err)
	}
	if !strings.Contains(err.Error(), "query nft table") {
		t.Fatalf("checkMonitorOwnership() error = %q, want nft probe context", err.Error())
	}
}

func TestRuntimeExecutorPrintsMonitorSummaryToStderr(t *testing.T) {
	t.Parallel()

	var stderr bytes.Buffer
	rt := &fakeRuntimeHandle{
		summary: "Monitor summary\nDNS:\n  example.com [ALLOW]: 1\nTotal events: 1\n",
	}

	exec := runtimeExecutor{
		stderr: &stderr,
		getwd: func() (string, error) {
			return "/workspace", nil
		},
		loadConfig: func(path, cwd string) (config.Config, error) {
			if path != "box.yaml" {
				t.Fatalf("loadConfig path = %q, want %q", path, "box.yaml")
			}
			if cwd != "/workspace" {
				t.Fatalf("loadConfig cwd = %q, want %q", cwd, "/workspace")
			}
			return config.Config{}, nil
		},
		startRuntime: func(context.Context, config.Config, boxruntime.Deps) (runtimeHandle, error) {
			return rt, nil
		},
		runPayload: func(_ context.Context, payload []string) error {
			if got, want := payload, []string{"/bin/true"}; !reflect.DeepEqual(got, want) {
				t.Fatalf("payload = %#v, want %#v", got, want)
			}
			return nil
		},
	}

	err := exec.Run(runRequest{
		ConfigPath: "box.yaml",
		Payload:    []string{"/bin/true"},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !rt.cleaned {
		t.Fatalf("runtime cleanup was not called")
	}
	if got := stderr.String(); got != rt.summary {
		t.Fatalf("stderr = %q, want %q", got, rt.summary)
	}
}

func TestRuntimeExecutorPrintsMonitorSummaryWhenPayloadFails(t *testing.T) {
	t.Parallel()

	var stderr bytes.Buffer
	payloadErr := errors.New("payload failed")
	rt := &fakeRuntimeHandle{
		summary: "Monitor summary\nHTTP:\n  GET example.com [ALLOW]: 1\nTotal events: 1\n",
	}

	exec := runtimeExecutor{
		stderr: &stderr,
		getwd: func() (string, error) {
			return "/workspace", nil
		},
		loadConfig: func(string, string) (config.Config, error) {
			return config.Config{}, nil
		},
		startRuntime: func(context.Context, config.Config, boxruntime.Deps) (runtimeHandle, error) {
			return rt, nil
		},
		runPayload: func(context.Context, []string) error {
			return payloadErr
		},
	}

	err := exec.Run(runRequest{
		ConfigPath: "box.yaml",
		Payload:    []string{"/bin/false"},
	})
	if !errors.Is(err, payloadErr) {
		t.Fatalf("Run() error = %v, want payload error", err)
	}
	if !rt.cleaned {
		t.Fatalf("runtime cleanup was not called")
	}
	if got := stderr.String(); got != rt.summary {
		t.Fatalf("stderr = %q, want %q", got, rt.summary)
	}
}

type preflightCommandResult struct {
	output string
	err    error
}

func fakePreflightRunner(results map[string]preflightCommandResult) preflightCommandRunner {
	return func(_ context.Context, name string, args ...string) (string, error) {
		key := strings.TrimSpace(name + " " + strings.Join(args, " "))
		result, ok := results[key]
		if !ok {
			return "", fmt.Errorf("unexpected command %q", key)
		}
		return result.output, result.err
	}
}

type fakeRuntimeHandle struct {
	summary string
	cleaned bool
}

func (f *fakeRuntimeHandle) Cleanup(context.Context, boxruntime.Deps) error {
	f.cleaned = true
	return nil
}

func (f *fakeRuntimeHandle) MonitorSummary() string {
	return f.summary
}
