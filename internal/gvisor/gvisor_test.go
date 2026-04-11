package gvisor

import (
	"reflect"
	"strings"
	"testing"

	"gvisor-net/internal/config"
	"gvisor-net/internal/rootfs"
)

func TestSpecUsesInitShimAsEntrypoint(t *testing.T) {
	cfg := config.Config{
		Sandbox: config.SandboxConfig{
			CommandShell: "/bin/bash -ilc",
		},
	}

	spec, err := BuildSpec(cfg, "/workspace", "env")
	if err != nil {
		t.Fatalf("BuildSpec() error: %v", err)
	}

	wantArgs := []string{"/box-initshim", "/bin/bash", "-ilc", "env"}
	if !reflect.DeepEqual(spec.Process.Args, wantArgs) {
		t.Fatalf("Process.Args = %#v, want %#v", spec.Process.Args, wantArgs)
	}
}

func TestSpecIncludesConfiguredWorkdirEnvAndHostname(t *testing.T) {
	cfg := config.Config{
		Sandbox: config.SandboxConfig{
			Hostname:     "sandbox-host",
			Workdir:      "/repo",
			Env:          []string{"A=1", "B=two"},
			CommandShell: "/bin/bash -ilc",
		},
	}

	spec, err := BuildSpec(cfg, cfg.Sandbox.Workdir, "echo hi")
	if err != nil {
		t.Fatalf("BuildSpec() error: %v", err)
	}

	if spec.Process.Cwd != "/repo" {
		t.Fatalf("Process.Cwd = %q, want %q", spec.Process.Cwd, "/repo")
	}
	if !containsEnv(spec.Process.Env, "A=1") || !containsEnv(spec.Process.Env, "B=two") {
		t.Fatalf("Process.Env = %#v, want configured entries", spec.Process.Env)
	}
	if !containsEnv(spec.Process.Env, "PATH=") {
		t.Fatalf("Process.Env = %#v, want PATH entry", spec.Process.Env)
	}
	if spec.Hostname != "sandbox-host" {
		t.Fatalf("Hostname = %q, want %q", spec.Hostname, "sandbox-host")
	}
}

func TestSpecParsesQuotedCommandShellSegment(t *testing.T) {
	cfg := config.Config{
		Sandbox: config.SandboxConfig{
			CommandShell: `/bin/bash -lc 'echo quoted segment'`,
		},
	}

	spec, err := BuildSpec(cfg, "/workspace", "env")
	if err != nil {
		t.Fatalf("BuildSpec() error: %v", err)
	}

	wantArgs := []string{"/box-initshim", "/bin/bash", "-lc", "echo quoted segment", "env"}
	if !reflect.DeepEqual(spec.Process.Args, wantArgs) {
		t.Fatalf("Process.Args = %#v, want %#v", spec.Process.Args, wantArgs)
	}
}

func TestSpecDefaultsCwdToRootWhenUnset(t *testing.T) {
	cfg := config.Config{
		Sandbox: config.SandboxConfig{
			CommandShell: "/bin/bash -ilc",
		},
	}

	spec, err := BuildSpec(cfg, "", "env")
	if err != nil {
		t.Fatalf("BuildSpec() error: %v", err)
	}

	if spec.Process.Cwd != "/" {
		t.Fatalf("Process.Cwd = %q, want %q", spec.Process.Cwd, "/")
	}
}

func TestSpecAddsDefaultPATHWhenUnset(t *testing.T) {
	cfg := config.Config{
		Sandbox: config.SandboxConfig{
			Env:          []string{"TERM=xterm"},
			CommandShell: "/bin/bash -lc",
		},
	}

	spec, err := BuildSpec(cfg, "/workspace", "env")
	if err != nil {
		t.Fatalf("BuildSpec() error: %v", err)
	}

	if !containsEnv(spec.Process.Env, "PATH=") {
		t.Fatalf("Process.Env = %#v, want PATH entry", spec.Process.Env)
	}
}

func TestBuildSandboxSpecIncludesBindsAndNetworkNamespace(t *testing.T) {
	cfg := config.Config{
		Sandbox: config.SandboxConfig{
			Hostname:     "sandbox-host",
			Workdir:      "/workspace",
			Env:          []string{"A=1", "B=two"},
			CommandShell: "/bin/bash -ilc",
		},
	}

	spec, err := BuildSandboxSpec(BuildSpecRequest{
		Config:  cfg,
		Workdir: "/workspace",
		Payload: "ip -4 -o addr show",
		RootfsPlan: rootfs.Plan{
			Binds: []rootfs.Bind{
				{Source: "/usr", Target: "/usr", ReadOnly: true},
				{Source: "/workspace-src", Target: "/workspace", ReadOnly: false},
			},
		},
		NetworkNamespacePath: "/run/netns/box-deadbeef",
	})
	if err != nil {
		t.Fatalf("BuildSandboxSpec() error: %v", err)
	}

	if !containsMount(spec.Mounts, "/usr", "/usr", true) {
		t.Fatalf("Mounts = %#v, want readonly bind for /usr", spec.Mounts)
	}
	if !containsMount(spec.Mounts, "/workspace", "/workspace-src", false) {
		t.Fatalf("Mounts = %#v, want read-write bind for /workspace", spec.Mounts)
	}
	if !containsNetworkNamespace(spec.Linux.Namespaces, "/run/netns/box-deadbeef") {
		t.Fatalf("Namespaces = %#v, want network namespace path", spec.Linux.Namespaces)
	}
}

func TestBuildSandboxSpecInjectsForcedProxyAndInitEnv(t *testing.T) {
	cfg := config.Config{
		Sandbox: config.SandboxConfig{
			Env:          []string{"HTTP_PROXY=http://bypass.invalid:3128", "TERM=xterm"},
			CommandShell: "/bin/bash -lc",
		},
	}

	spec, err := BuildSandboxSpec(BuildSpecRequest{
		Config:  cfg,
		Workdir: "/workspace",
		Payload: "env",
		ExtraEnv: []string{
			"HTTP_PROXY=http://100.96.0.1:18080",
			"HTTPS_PROXY=http://100.96.0.1:18080",
			"NO_PROXY=127.0.0.1,localhost",
			"BOX_DOCKER_ENABLED=1",
			"BOX_DOCKER_SOCKET_PATH=/var/run/docker.sock",
			"BOX_DOCKER_WAIT_FOR_SOCKET=1",
			"BOX_DOCKER_READY_TIMEOUT=10s",
		},
	})
	if err != nil {
		t.Fatalf("BuildSandboxSpec() error: %v", err)
	}

	if value := envValue(spec.Process.Env, "HTTP_PROXY"); value != "http://100.96.0.1:18080" {
		t.Fatalf("HTTP_PROXY = %q, want host proxy URL", value)
	}
	if value := envValue(spec.Process.Env, "HTTPS_PROXY"); value != "http://100.96.0.1:18080" {
		t.Fatalf("HTTPS_PROXY = %q, want host proxy URL", value)
	}
	if value := envValue(spec.Process.Env, "NO_PROXY"); value != "127.0.0.1,localhost" {
		t.Fatalf("NO_PROXY = %q, want localhost bypass list", value)
	}
	if value := envValue(spec.Process.Env, "BOX_DOCKER_SOCKET_PATH"); value != "/var/run/docker.sock" {
		t.Fatalf("BOX_DOCKER_SOCKET_PATH = %q, want configured socket path", value)
	}
	if value := envValue(spec.Process.Env, "BOX_DOCKER_READY_TIMEOUT"); value != "10s" {
		t.Fatalf("BOX_DOCKER_READY_TIMEOUT = %q, want configured timeout", value)
	}
}

func TestRunnerInvokesRunscWithExpectedArgs(t *testing.T) {
	fake := &fakeCommandRunner{}
	runner := Runner{
		Command: fake,
	}

	err := runner.Run(RunRequest{
		BundleDir:   "/tmp/box-bundle",
		ContainerID: "box-123",
	})
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	if fake.name != "runsc" {
		t.Fatalf("command name = %q, want %q", fake.name, "runsc")
	}
	wantArgs := []string{"--ignore-cgroups", "run", "--bundle", "/tmp/box-bundle", "box-123"}
	if !reflect.DeepEqual(fake.args, wantArgs) {
		t.Fatalf("command args = %#v, want %#v", fake.args, wantArgs)
	}
}

func TestRunnerExecutesRunscInsideNamedNetworkNamespace(t *testing.T) {
	fake := &fakeCommandRunner{}
	runner := Runner{
		Command: fake,
	}

	err := runner.Run(RunRequest{
		BundleDir:   "/tmp/box-bundle",
		ContainerID: "box-123",
		NetNS:       "box-deadbeef",
	})
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	if fake.name != "ip" {
		t.Fatalf("command name = %q, want %q", fake.name, "ip")
	}
	wantArgs := []string{"netns", "exec", "box-deadbeef", "runsc", "--ignore-cgroups", "run", "--bundle", "/tmp/box-bundle", "box-123"}
	if !reflect.DeepEqual(fake.args, wantArgs) {
		t.Fatalf("command args = %#v, want %#v", fake.args, wantArgs)
	}
}

func TestRunnerAddsDockerNetworkingFlagsWhenDockerEnabled(t *testing.T) {
	fake := &fakeCommandRunner{}
	runner := Runner{
		Command: fake,
	}

	err := runner.Run(RunRequest{
		BundleDir:     "/tmp/box-bundle",
		ContainerID:   "box-123",
		DockerEnabled: true,
	})
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	wantArgs := []string{
		"--ignore-cgroups",
		"--net-raw",
		"--allow-packet-socket-write",
		"run",
		"--bundle",
		"/tmp/box-bundle",
		"box-123",
	}
	if !reflect.DeepEqual(fake.args, wantArgs) {
		t.Fatalf("command args = %#v, want %#v", fake.args, wantArgs)
	}
}

func TestBuildSandboxSpecAddsDockerCapabilities(t *testing.T) {
	cfg := config.Config{
		Sandbox: config.SandboxConfig{
			CommandShell: "/bin/bash -lc",
		},
		Docker: config.DockerConfig{
			Enabled: true,
		},
	}

	spec, err := BuildSandboxSpec(BuildSpecRequest{
		Config:  cfg,
		Workdir: "/workspace",
		Payload: "docker version",
	})
	if err != nil {
		t.Fatalf("BuildSandboxSpec() error: %v", err)
	}

	for _, capability := range []string{
		"CAP_NET_ADMIN",
		"CAP_NET_RAW",
		"CAP_SYS_ADMIN",
		"CAP_SYS_CHROOT",
	} {
		if !containsCapability(spec.Process.Capabilities.Bounding, capability) {
			t.Fatalf("Bounding capabilities = %#v, want %q", spec.Process.Capabilities.Bounding, capability)
		}
		if !containsCapability(spec.Process.Capabilities.Effective, capability) {
			t.Fatalf("Effective capabilities = %#v, want %q", spec.Process.Capabilities.Effective, capability)
		}
	}
}

type fakeCommandRunner struct {
	name string
	args []string
}

func (f *fakeCommandRunner) Run(name string, args ...string) error {
	f.name = name
	f.args = append([]string{}, args...)
	return nil
}

func containsMount(mounts []MountSpec, destination, source string, readOnly bool) bool {
	for _, mount := range mounts {
		if mount.Destination != destination || mount.Source != source {
			continue
		}
		hasBind := false
		hasReadOnly := false
		hasReadWrite := false
		for _, option := range mount.Options {
			switch option {
			case "bind", "rbind":
				hasBind = true
			case "ro":
				hasReadOnly = true
			case "rw":
				hasReadWrite = true
			}
		}
		if !hasBind {
			continue
		}
		if readOnly {
			return hasReadOnly
		}
		return hasReadWrite
	}
	return false
}

func containsNetworkNamespace(namespaces []LinuxNamespace, path string) bool {
	for _, namespace := range namespaces {
		if namespace.Type == "network" && namespace.Path == path {
			return true
		}
	}
	return false
}

func containsEnv(env []string, prefix string) bool {
	for _, entry := range env {
		if entry == prefix || strings.HasPrefix(entry, prefix) {
			return true
		}
	}
	return false
}

func envValue(env []string, key string) string {
	prefix := key + "="
	for _, entry := range env {
		if strings.HasPrefix(entry, prefix) {
			return strings.TrimPrefix(entry, prefix)
		}
	}
	return ""
}

func containsCapability(capabilities []string, capability string) bool {
	for _, value := range capabilities {
		if value == capability {
			return true
		}
	}
	return false
}
