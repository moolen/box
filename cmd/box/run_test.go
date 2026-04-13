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
	"gvisor-net/internal/gvisor"
	"gvisor-net/internal/rootfs"
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

func TestCommandShellForTTYDropsInteractiveFlagWithoutTTY(t *testing.T) {
	got := commandShellForTTY("/bin/bash -ilc", ttyState{})
	want := "/bin/bash -lc"
	if got != want {
		t.Fatalf("commandShellForTTY() = %q, want %q", got, want)
	}
}

func TestSandboxProxyEnvIncludesProxyVariablesInMonitorMode(t *testing.T) {
	env := sandboxProxyEnv(boxruntime.Manifest{
		GatewayIP: "100.96.0.1",
		Envoy: boxruntime.EnvoyRuntime{
			ExplicitPort: 19001,
		},
		CA: boxruntime.CARuntime{
			SandboxCertPath: "/etc/ssl/certs/box-runtime-ca.pem",
		},
	})
	for _, want := range []string{
		"HTTP_PROXY=http://100.96.0.1:19001",
		"HTTPS_PROXY=http://100.96.0.1:19001",
		"http_proxy=http://100.96.0.1:19001",
		"https_proxy=http://100.96.0.1:19001",
		"NO_PROXY=127.0.0.1,localhost",
		"no_proxy=127.0.0.1,localhost",
		"SSL_CERT_FILE=/etc/ssl/certs/box-runtime-ca.pem",
		"CURL_CA_BUNDLE=/etc/ssl/certs/box-runtime-ca.pem",
		"REQUESTS_CA_BUNDLE=/etc/ssl/certs/box-runtime-ca.pem",
		"NODE_EXTRA_CA_CERTS=/etc/ssl/certs/box-runtime-ca.pem",
	} {
		if !containsString(env, want) {
			t.Fatalf("sandboxProxyEnv() = %#v, want %q", env, want)
		}
	}
}

func TestRuntimeExecutorPassesRuntimeCAAndManifestToSandboxBuilders(t *testing.T) {
	t.Parallel()

	stateDir := t.TempDir()
	caCertPath := filepath.Join(stateDir, "runtime-ca.pem")
	caCertPEM := "-----BEGIN CERTIFICATE-----\nruntime\n-----END CERTIFICATE-----\n"
	if err := os.WriteFile(caCertPath, []byte(caCertPEM), 0o644); err != nil {
		t.Fatalf("WriteFile(ca cert) error = %v", err)
	}

	rt := &fakeRuntimeHandle{
		manifest: boxruntime.Manifest{
			RuntimeID: "runtime-env",
			StateDir:  stateDir,
			GatewayIP: "100.96.0.1",
			Net: boxruntime.NetResources{
				NetNS: "box-runtime-env",
			},
			Envoy: boxruntime.EnvoyRuntime{
				ExplicitPort: 19001,
			},
			CA: boxruntime.CARuntime{
				CertPath:        caCertPath,
				SandboxCertPath: "/etc/ssl/certs/box-runtime-ca.pem",
			},
		},
	}

	exec := runtimeExecutor{
		getwd: func() (string, error) {
			return "/workspace", nil
		},
		loadConfig: func(string, string) (config.Config, error) {
			return config.Config{
				Sandbox: config.SandboxConfig{
					Rootfs:       "host-overlay",
					Workdir:      "/workspace",
					CommandShell: "/bin/bash -lc",
				},
			}, nil
		},
		startRuntime: func(context.Context, config.Config, boxruntime.Deps) (runtimeHandle, error) {
			return rt, nil
		},
		buildRootfsPlan: func(req rootfs.PlanRequest) (rootfs.Plan, error) {
			if req.TrustedCACertPEM != caCertPEM {
				t.Fatalf("TrustedCACertPEM = %q, want runtime CA contents", req.TrustedCACertPEM)
			}
			if req.TrustedCACertPath != "/etc/ssl/certs/box-runtime-ca.pem" {
				t.Fatalf("TrustedCACertPath = %q, want runtime CA target", req.TrustedCACertPath)
			}
			return rootfs.Plan{}, nil
		},
		applyRootfs: func(rootfs.ApplyRequest) (rootfs.ApplyResult, error) {
			return rootfs.ApplyResult{}, nil
		},
		buildSandboxSpec: func(req gvisor.BuildSpecRequest) (gvisor.Spec, error) {
			if req.RuntimeManifest.Envoy.ExplicitPort != 19001 {
				t.Fatalf("RuntimeManifest.Envoy.ExplicitPort = %d, want 19001", req.RuntimeManifest.Envoy.ExplicitPort)
			}
			if req.RuntimeManifest.CA.SandboxCertPath != "/etc/ssl/certs/box-runtime-ca.pem" {
				t.Fatalf("RuntimeManifest.CA.SandboxCertPath = %q, want runtime CA path", req.RuntimeManifest.CA.SandboxCertPath)
			}

			spec, err := gvisor.BuildSandboxSpec(req)
			if err != nil {
				return gvisor.Spec{}, err
			}
			for _, want := range []string{
				"HTTP_PROXY=http://100.96.0.1:19001",
				"HTTPS_PROXY=http://100.96.0.1:19001",
				"http_proxy=http://100.96.0.1:19001",
				"https_proxy=http://100.96.0.1:19001",
				"NO_PROXY=127.0.0.1,localhost",
				"no_proxy=127.0.0.1,localhost",
				"SSL_CERT_FILE=/etc/ssl/certs/box-runtime-ca.pem",
			} {
				if !containsString(spec.Process.Env, want) {
					t.Fatalf("Process.Env = %#v, want %q", spec.Process.Env, want)
				}
			}
			return spec, nil
		},
		writeBundleSpec: func(string, gvisor.Spec) error {
			return nil
		},
		runSandbox: func(gvisor.RunRequest) error {
			return nil
		},
	}

	if err := exec.Run(runRequest{
		ConfigPath: "box.yaml",
		Payload:    []string{"/bin/true"},
	}); err != nil {
		t.Fatalf("Run() error = %v", err)
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

func TestCheckMonitorOwnershipDetectsRouteTableReferencedByExistingPolicyRule(t *testing.T) {
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
		"ip -o rule show":                  {output: "1000: from all lookup 12345\n", err: nil},
		"ip netns list":                    {output: "", err: nil},
		"ip link show vethhdeadbeef":       {output: "Device \"vethhdeadbeef\" does not exist.", err: errors.New("exit status 1")},
	}))
	if err == nil {
		t.Fatal("checkMonitorOwnership() error = nil, want route table conflict")
	}
	if !errors.Is(err, boxruntime.ErrResourceConflict) {
		t.Fatalf("checkMonitorOwnership() error = %v, want ErrResourceConflict", err)
	}
	if !strings.Contains(err.Error(), "route table") {
		t.Fatalf("checkMonitorOwnership() error = %q, want route table conflict message", err.Error())
	}
}

func TestCheckMonitorOwnershipDetectsFWMarkReferencedByExistingPolicyRule(t *testing.T) {
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
		"ip -o rule show":                  {output: "1000: from all fwmark 0x1234 lookup 9999\n", err: nil},
		"ip netns list":                    {output: "", err: nil},
		"ip link show vethhdeadbeef":       {output: "Device \"vethhdeadbeef\" does not exist.", err: errors.New("exit status 1")},
	}))
	if err == nil {
		t.Fatal("checkMonitorOwnership() error = nil, want fwmark conflict")
	}
	if !errors.Is(err, boxruntime.ErrResourceConflict) {
		t.Fatalf("checkMonitorOwnership() error = %v, want ErrResourceConflict", err)
	}
	if !strings.Contains(err.Error(), "fwmark") {
		t.Fatalf("checkMonitorOwnership() error = %q, want fwmark conflict message", err.Error())
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
		manifest: boxruntime.Manifest{
			RuntimeID: "runtime-a",
			StateDir:  "/tmp/runtime-a",
			Net: boxruntime.NetResources{
				NetNS: "box-runtime-a",
			},
		},
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
		buildRootfsPlan: func(rootfs.PlanRequest) (rootfs.Plan, error) {
			return rootfs.Plan{}, nil
		},
		applyRootfs: func(req rootfs.ApplyRequest) (rootfs.ApplyResult, error) {
			if req.BundleDir != "/tmp/runtime-a/bundle" {
				t.Fatalf("BundleDir = %q, want %q", req.BundleDir, "/tmp/runtime-a/bundle")
			}
			return rootfs.ApplyResult{}, nil
		},
		buildSandboxSpec: func(req gvisor.BuildSpecRequest) (gvisor.Spec, error) {
			if req.NetworkNamespacePath != "/run/netns/box-runtime-a" {
				t.Fatalf("NetworkNamespacePath = %q, want %q", req.NetworkNamespacePath, "/run/netns/box-runtime-a")
			}
			if req.Payload != "" {
				t.Fatalf("Payload = %q, want empty shell command for this test", req.Payload)
			}
			return gvisor.Spec{}, nil
		},
		writeBundleSpec: func(bundleDir string, _ gvisor.Spec) error {
			if bundleDir != "/tmp/runtime-a/bundle" {
				t.Fatalf("bundleDir = %q, want %q", bundleDir, "/tmp/runtime-a/bundle")
			}
			return nil
		},
		runSandbox: func(req gvisor.RunRequest) error {
			if req.BundleDir != "/tmp/runtime-a/bundle" {
				t.Fatalf("BundleDir = %q, want %q", req.BundleDir, "/tmp/runtime-a/bundle")
			}
			if req.ContainerID != "runtime-a" {
				t.Fatalf("ContainerID = %q, want %q", req.ContainerID, "runtime-a")
			}
			if req.NetNS != "box-runtime-a" {
				t.Fatalf("NetNS = %q, want %q", req.NetNS, "box-runtime-a")
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
		manifest: boxruntime.Manifest{
			RuntimeID: "runtime-b",
			StateDir:  "/tmp/runtime-b",
			Net: boxruntime.NetResources{
				NetNS: "box-runtime-b",
			},
		},
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
		buildRootfsPlan: func(rootfs.PlanRequest) (rootfs.Plan, error) {
			return rootfs.Plan{}, nil
		},
		applyRootfs: func(rootfs.ApplyRequest) (rootfs.ApplyResult, error) {
			return rootfs.ApplyResult{}, nil
		},
		buildSandboxSpec: func(gvisor.BuildSpecRequest) (gvisor.Spec, error) {
			return gvisor.Spec{}, nil
		},
		writeBundleSpec: func(string, gvisor.Spec) error {
			return nil
		},
		runSandbox: func(gvisor.RunRequest) error {
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

func TestRuntimeExecutorPassesRuntimeNetNSToSandboxRunner(t *testing.T) {
	t.Parallel()

	rt := &fakeRuntimeHandle{
		manifest: boxruntime.Manifest{
			RuntimeID: "runtime-c",
			StateDir:  "/tmp/runtime-c",
			Net: boxruntime.NetResources{
				NetNS: "box-deadbeef",
			},
		},
	}
	exec := runtimeExecutor{
		getwd: func() (string, error) {
			return "/workspace", nil
		},
		loadConfig: func(string, string) (config.Config, error) {
			return config.Config{}, nil
		},
		startRuntime: func(context.Context, config.Config, boxruntime.Deps) (runtimeHandle, error) {
			return rt, nil
		},
		buildRootfsPlan: func(rootfs.PlanRequest) (rootfs.Plan, error) {
			return rootfs.Plan{}, nil
		},
		applyRootfs: func(rootfs.ApplyRequest) (rootfs.ApplyResult, error) {
			return rootfs.ApplyResult{}, nil
		},
		buildSandboxSpec: func(gvisor.BuildSpecRequest) (gvisor.Spec, error) {
			return gvisor.Spec{}, nil
		},
		writeBundleSpec: func(string, gvisor.Spec) error {
			return nil
		},
		runSandbox: func(req gvisor.RunRequest) error {
			if req.NetNS != "box-deadbeef" {
				t.Fatalf("NetNS = %q, want %q", req.NetNS, "box-deadbeef")
			}
			return nil
		},
	}

	if err := exec.Run(runRequest{
		ConfigPath: "box.yaml",
		Payload:    []string{"/bin/true"},
	}); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestRuntimeExecutorUsesRuntimePreparedWorkdirMountSource(t *testing.T) {
	t.Parallel()

	rt := &fakeRuntimeHandle{
		manifest: boxruntime.Manifest{
			RuntimeID:          "runtime-workdir-overlay",
			StateDir:           "/tmp/runtime-workdir-overlay",
			WorkdirMountSource: "/tmp/runtime-workdir-overlay/workdir/merged",
			Net: boxruntime.NetResources{
				NetNS: "box-runtime-workdir-overlay",
			},
		},
	}
	exec := runtimeExecutor{
		getwd: func() (string, error) {
			return "/workspace-src", nil
		},
		loadConfig: func(string, string) (config.Config, error) {
			return config.Config{
				Sandbox: config.SandboxConfig{
					Rootfs:  "host-overlay",
					Workdir: "/workspace-src",
				},
			}, nil
		},
		startRuntime: func(context.Context, config.Config, boxruntime.Deps) (runtimeHandle, error) {
			return rt, nil
		},
		buildRootfsPlan: func(req rootfs.PlanRequest) (rootfs.Plan, error) {
			if req.RepoPath != "/tmp/runtime-workdir-overlay/workdir/merged" {
				t.Fatalf("RepoPath = %q, want runtime prepared merged mount", req.RepoPath)
			}
			if req.Workdir != "/workspace-src" {
				t.Fatalf("Workdir = %q, want %q", req.Workdir, "/workspace-src")
			}
			return rootfs.Plan{}, nil
		},
		applyRootfs: func(rootfs.ApplyRequest) (rootfs.ApplyResult, error) {
			return rootfs.ApplyResult{}, nil
		},
		buildSandboxSpec: func(gvisor.BuildSpecRequest) (gvisor.Spec, error) {
			return gvisor.Spec{}, nil
		},
		writeBundleSpec: func(string, gvisor.Spec) error {
			return nil
		},
		runSandbox: func(gvisor.RunRequest) error {
			return nil
		},
	}

	if err := exec.Run(runRequest{
		ConfigPath: "box.yaml",
		Payload:    []string{"/bin/true"},
	}); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestRuntimeExecutorFallsBackToHostWorkdirWhenOverlayDisabled(t *testing.T) {
	t.Parallel()

	overlayDisabled := false
	rt := &fakeRuntimeHandle{
		manifest: boxruntime.Manifest{
			RuntimeID: "runtime-workdir-bind",
			StateDir:  "/tmp/runtime-workdir-bind",
			Net: boxruntime.NetResources{
				NetNS: "box-runtime-workdir-bind",
			},
		},
	}
	exec := runtimeExecutor{
		getwd: func() (string, error) {
			return "/workspace-src", nil
		},
		loadConfig: func(string, string) (config.Config, error) {
			return config.Config{
				Sandbox: config.SandboxConfig{
					Rootfs:         "host-overlay",
					Workdir:        "/workspace-src",
					WorkdirOverlay: &overlayDisabled,
				},
			}, nil
		},
		startRuntime: func(context.Context, config.Config, boxruntime.Deps) (runtimeHandle, error) {
			return rt, nil
		},
		buildRootfsPlan: func(req rootfs.PlanRequest) (rootfs.Plan, error) {
			if req.RepoPath != "/workspace-src" {
				t.Fatalf("RepoPath = %q, want host workdir when overlay disabled", req.RepoPath)
			}
			return rootfs.Plan{}, nil
		},
		applyRootfs: func(rootfs.ApplyRequest) (rootfs.ApplyResult, error) {
			return rootfs.ApplyResult{}, nil
		},
		buildSandboxSpec: func(gvisor.BuildSpecRequest) (gvisor.Spec, error) {
			return gvisor.Spec{}, nil
		},
		writeBundleSpec: func(string, gvisor.Spec) error {
			return nil
		},
		runSandbox: func(gvisor.RunRequest) error {
			return nil
		},
	}

	if err := exec.Run(runRequest{
		ConfigPath: "box.yaml",
		Payload:    []string{"/bin/true"},
	}); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestRuntimeExecutorPassesManagedNetNSToSandboxRunner(t *testing.T) {
	stateDir := t.TempDir()
	rt := &fakeRuntimeHandle{
		manifest: boxruntime.Manifest{
			RuntimeID: "runtime-d",
			StateDir:  stateDir,
			Net: boxruntime.NetResources{
				NetNS: "box-cafebabe",
			},
		},
	}
	exec := runtimeExecutor{
		getwd: func() (string, error) {
			return "/workspace", nil
		},
		loadConfig: func(string, string) (config.Config, error) {
			return config.Config{}, nil
		},
		startRuntime: func(context.Context, config.Config, boxruntime.Deps) (runtimeHandle, error) {
			return rt, nil
		},
		buildRootfsPlan: func(rootfs.PlanRequest) (rootfs.Plan, error) {
			return rootfs.Plan{}, nil
		},
		applyRootfs: func(req rootfs.ApplyRequest) (rootfs.ApplyResult, error) {
			if err := os.MkdirAll(req.BundleDir, 0o755); err != nil {
				t.Fatalf("MkdirAll(%q) error = %v", req.BundleDir, err)
			}
			return rootfs.ApplyResult{}, nil
		},
		buildSandboxSpec: func(gvisor.BuildSpecRequest) (gvisor.Spec, error) {
			return gvisor.Spec{}, nil
		},
		writeBundleSpec: func(string, gvisor.Spec) error {
			return nil
		},
		runSandbox: func(req gvisor.RunRequest) error {
			if req.NetNS != "box-cafebabe" {
				t.Fatalf("NetNS = %q, want %q", req.NetNS, "box-cafebabe")
			}
			return nil
		},
	}

	if err := exec.Run(runRequest{
		ConfigPath: "box.yaml",
		Payload:    []string{"/bin/true"},
	}); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestSandboxNetworkNamespacePathUsesManagedNetNS(t *testing.T) {
	if got := sandboxNetworkNamespacePath(config.Config{}, "box-runtime-a"); got != "/run/netns/box-runtime-a" {
		t.Fatalf("sandboxNetworkNamespacePath() = %q, want %q", got, "/run/netns/box-runtime-a")
	}
}

func TestRuntimeExecutorSuppliesPolicyServiceAndEnvoyFactories(t *testing.T) {
	t.Parallel()

	rt := &fakeRuntimeHandle{}
	exec := runtimeExecutor{
		getwd: func() (string, error) {
			return "/workspace", nil
		},
		loadConfig: func(string, string) (config.Config, error) {
			return config.Config{}, nil
		},
		startRuntime: func(_ context.Context, _ config.Config, deps boxruntime.Deps) (runtimeHandle, error) {
			if deps.StartPolicyService == nil {
				t.Fatalf("Deps.StartPolicyService = nil, want non-nil")
			}
			if deps.StartEnvoy == nil {
				t.Fatalf("Deps.StartEnvoy = nil, want non-nil")
			}
			return rt, nil
		},
		buildRootfsPlan: func(rootfs.PlanRequest) (rootfs.Plan, error) {
			return rootfs.Plan{}, nil
		},
		applyRootfs: func(rootfs.ApplyRequest) (rootfs.ApplyResult, error) {
			return rootfs.ApplyResult{}, nil
		},
		buildSandboxSpec: func(gvisor.BuildSpecRequest) (gvisor.Spec, error) {
			return gvisor.Spec{}, nil
		},
		writeBundleSpec: func(string, gvisor.Spec) error {
			return nil
		},
		runSandbox: func(gvisor.RunRequest) error {
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
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
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
	summary  string
	cleaned  bool
	manifest boxruntime.Manifest
	netns    string
}

func (f *fakeRuntimeHandle) Cleanup(context.Context, boxruntime.Deps) error {
	f.cleaned = true
	return nil
}

func (f *fakeRuntimeHandle) MonitorSummary() string {
	return f.summary
}

func (f *fakeRuntimeHandle) PayloadNetNS() string {
	return f.netns
}

func (f *fakeRuntimeHandle) RuntimeManifest() boxruntime.Manifest {
	if f.netns != "" && f.manifest.Net.NetNS == "" {
		f.manifest.Net.NetNS = f.netns
	}
	return f.manifest
}
