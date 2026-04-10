package gvisor

import (
	"reflect"
	"testing"

	"gvisor-net/internal/config"
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
	if !reflect.DeepEqual(spec.Process.Env, []string{"A=1", "B=two"}) {
		t.Fatalf("Process.Env = %#v, want %#v", spec.Process.Env, []string{"A=1", "B=two"})
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
	wantArgs := []string{"run", "--bundle", "/tmp/box-bundle", "box-123"}
	if !reflect.DeepEqual(fake.args, wantArgs) {
		t.Fatalf("command args = %#v, want %#v", fake.args, wantArgs)
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
