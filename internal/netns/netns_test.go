package netns

import (
	"strings"
	"testing"
)

func TestRuntimeIDProducesDeterministicResourceNames(t *testing.T) {
	first, err := ResourcesForRuntimeID("runtime-abc-123")
	if err != nil {
		t.Fatalf("ResourcesForRuntimeID() error: %v", err)
	}
	second, err := ResourcesForRuntimeID("runtime-abc-123")
	if err != nil {
		t.Fatalf("ResourcesForRuntimeID() error: %v", err)
	}
	other, err := ResourcesForRuntimeID("runtime-def-456")
	if err != nil {
		t.Fatalf("ResourcesForRuntimeID() error: %v", err)
	}

	if first != second {
		t.Fatalf("same runtime id must produce identical resources: first=%+v second=%+v", first, second)
	}
	if first == other {
		t.Fatalf("different runtime ids must not produce identical resources: first=%+v other=%+v", first, other)
	}
	if first.NetNS == "" || first.HostVeth == "" || first.GuestVeth == "" || first.TableName == "" {
		t.Fatalf("resource names must be populated: %+v", first)
	}
	if !strings.HasPrefix(first.NetNS, "box-") {
		t.Fatalf("NetNS = %q, want prefix %q", first.NetNS, "box-")
	}
	if !strings.HasPrefix(first.HostVeth, "vethh") {
		t.Fatalf("HostVeth = %q, want prefix %q", first.HostVeth, "vethh")
	}
	if !strings.HasPrefix(first.GuestVeth, "vethg") {
		t.Fatalf("GuestVeth = %q, want prefix %q", first.GuestVeth, "vethg")
	}
	if !strings.HasPrefix(first.TableName, "box_") {
		t.Fatalf("TableName = %q, want prefix %q", first.TableName, "box_")
	}
}
