package main

import (
	"reflect"
	"testing"
)

func TestRootAndRunCommandsBuildSameRunRequest(t *testing.T) {
	rootExec := &stubExecutor{}
	rootCmd := newRootCommand(deps{
		executor:        rootExec,
		resolveInitShim: func() string { return "/shim" },
		detectTTY: func() ttyState {
			return ttyState{Stdin: true, Stdout: true}
		},
	})

	rootCmd.SetArgs([]string{"--config", "custom.yaml", "--", "/bin/true"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("root Execute() returned error: %v", err)
	}
	if !rootExec.called {
		t.Fatalf("root executor was not called")
	}

	runExec := &stubExecutor{}
	configPath := "box.yaml"
	runCmd := newRunCommand(deps{
		executor:        runExec,
		resolveInitShim: func() string { return "/shim" },
		detectTTY: func() ttyState {
			return ttyState{Stdin: true, Stdout: true}
		},
	}, &configPath)

	configPath = "custom.yaml"
	runCmd.SetArgs([]string{"--", "/bin/true"})
	if err := runCmd.Execute(); err != nil {
		t.Fatalf("run Execute() returned error: %v", err)
	}
	if !runExec.called {
		t.Fatalf("run executor was not called")
	}

	if !reflect.DeepEqual(runExec.req, rootExec.req) {
		t.Fatalf("run request = %#v, want %#v", runExec.req, rootExec.req)
	}
}

func TestRunSubcommandAcceptsConfigFlag(t *testing.T) {
	exec := &stubExecutor{}
	cmd := newRootCommand(deps{
		executor:        exec,
		resolveInitShim: func() string { return "/shim" },
		detectTTY: func() ttyState {
			return ttyState{}
		},
	})

	cmd.SetArgs([]string{"run", "--config", "custom.yaml", "--", "/bin/pwd"})
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

func TestRootAndRunHelpRender(t *testing.T) {
	rootCmd := newRootCommand(deps{})
	rootCmd.SetArgs([]string{"--help"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("root help Execute() returned error: %v", err)
	}

	runCmd := newRootCommand(deps{})
	runCmd.SetArgs([]string{"run", "--help"})
	if err := runCmd.Execute(); err != nil {
		t.Fatalf("run help Execute() returned error: %v", err)
	}
}
