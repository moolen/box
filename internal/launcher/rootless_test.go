package launcher

import (
	"reflect"
	"strings"
	"testing"
)

func TestCommandBuildsNsenterSetprivRootlesskitInvocation(t *testing.T) {
	name, args, err := Command(Request{
		NetNSPath: "/run/netns/box-deadbeef",
		Binary:    "runsc",
		Args: []string{
			"--ignore-cgroups",
			"run",
			"--bundle",
			"/tmp/box-bundle",
			"box-123",
		},
		UID: 1000,
		GID: 1000,
	})
	if err != nil {
		t.Fatalf("Command() error = %v", err)
	}

	if name != "nsenter" {
		t.Fatalf("command name = %q, want %q", name, "nsenter")
	}
	wantArgs := []string{
		"--net=/run/netns/box-deadbeef",
		"--",
		"setpriv",
		"--reuid",
		"1000",
		"--regid",
		"1000",
		"--clear-groups",
		"rootlesskit",
		"--net=host",
		"--copy-up=/etc",
		"runsc",
		"--ignore-cgroups",
		"run",
		"--bundle",
		"/tmp/box-bundle",
		"box-123",
	}
	if !reflect.DeepEqual(args, wantArgs) {
		t.Fatalf("command args = %#v, want %#v", args, wantArgs)
	}
}

func TestCommandRejectsMissingCallerIDs(t *testing.T) {
	_, _, err := Command(Request{
		NetNSPath: "/run/netns/box-deadbeef",
		Binary:    "runsc",
		Args:      []string{"run", "--bundle", "/tmp/box-bundle", "box-123"},
	})
	if err == nil {
		t.Fatal("Command() error = nil, want rejection for missing caller ids")
	}
	if !strings.Contains(err.Error(), "caller") {
		t.Fatalf("Command() error = %q, want mention of caller identity", err)
	}
}

func TestHostCommandBuildsSetprivRootlesskitInvocationWithoutNetNS(t *testing.T) {
	name, args, err := HostCommand(Request{
		Binary: "buildkitd",
		Args: []string{
			"--addr", "unix:///tmp/buildkitd.sock",
			"--rootless",
		},
		UID: 1000,
		GID: 1000,
	})
	if err != nil {
		t.Fatalf("HostCommand() error = %v", err)
	}

	if name != "setpriv" {
		t.Fatalf("command name = %q, want %q", name, "setpriv")
	}
	wantArgs := []string{
		"--reuid", "1000",
		"--regid", "1000",
		"--clear-groups",
		"rootlesskit",
		"--net=host",
		"--copy-up=/etc",
		"buildkitd",
		"--addr", "unix:///tmp/buildkitd.sock",
		"--rootless",
	}
	if !reflect.DeepEqual(args, wantArgs) {
		t.Fatalf("command args = %#v, want %#v", args, wantArgs)
	}
}

func TestUserCommandBuildsSetprivInvocationWithoutNetNS(t *testing.T) {
	name, args, err := UserCommand(Request{
		Binary: "buildctl",
		Args: []string{
			"--addr=unix:///tmp/buildkitd.sock",
			"debug", "workers",
		},
		UID: 1000,
		GID: 1000,
	})
	if err != nil {
		t.Fatalf("UserCommand() error = %v", err)
	}

	if name != "setpriv" {
		t.Fatalf("command name = %q, want %q", name, "setpriv")
	}
	wantArgs := []string{
		"--reuid", "1000",
		"--regid", "1000",
		"--clear-groups",
		"buildctl",
		"--addr=unix:///tmp/buildkitd.sock",
		"debug", "workers",
	}
	if !reflect.DeepEqual(args, wantArgs) {
		t.Fatalf("command args = %#v, want %#v", args, wantArgs)
	}
}
