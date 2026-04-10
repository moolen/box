package main

import (
	"errors"
	"syscall"
	"testing"
	"time"
)

func TestReapAllChildrenReturnsWhenWait4ReportsNoChildrenReady(t *testing.T) {
	origWait4 := wait4
	t.Cleanup(func() {
		wait4 = origWait4
	})

	calls := 0
	wait4 = func(pid int, wstatus *syscall.WaitStatus, options int, rusage *syscall.Rusage) (int, error) {
		calls++
		return 0, nil
	}

	done := make(chan struct{})
	go func() {
		reapAllChildren()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("reapChildren() did not return when wait4 returned pid=0, err=nil")
	}
	if calls != 1 {
		t.Fatalf("wait4 calls = %d, want 1", calls)
	}
}

func TestReapChildrenExceptDoesNotReapMainPayloadPID(t *testing.T) {
	origWait4 := wait4
	origList := listChildPIDs
	t.Cleanup(func() {
		wait4 = origWait4
		listChildPIDs = origList
	})

	const mainPID = 42
	const sidePID = 99
	listChildPIDs = func() ([]int, error) {
		return []int{mainPID, sidePID}, nil
	}

	wait4Calls := []int{}
	wait4 = func(pid int, wstatus *syscall.WaitStatus, options int, rusage *syscall.Rusage) (int, error) {
		wait4Calls = append(wait4Calls, pid)
		if pid == mainPID || pid == -1 {
			t.Fatalf("wait4 called with main payload pid selector %d", pid)
		}
		// First interruption, then child is reaped.
		if len(wait4Calls) == 1 {
			return 0, syscall.EINTR
		}
		if len(wait4Calls) == 2 {
			return sidePID, nil
		}
		return 0, errors.New("stop")
	}

	reapChildrenExcept(mainPID)
	if len(wait4Calls) < 2 {
		t.Fatalf("wait4 calls = %d, want at least 2", len(wait4Calls))
	}
	for _, pid := range wait4Calls {
		if pid != sidePID {
			t.Fatalf("wait4 called with pid %d, want only side pid %d", pid, sidePID)
		}
	}
}
