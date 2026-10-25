package rawfork

import (
	"errors"
	"fmt"
	"io"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func openNull(t *testing.T) int {
	t.Helper()
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return int(f.Fd())
}

func TestSetFds(t *testing.T) {
	rd, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	defer wr.Close()
	null := openNull(t)
	other := openNull(t) // Not passed to the child.

	var p Program
	if err := p.SetFds([]int{null, null, null, int(wr.Fd())}, 3); err != nil {
		t.Fatal(err)
	}
	buf := []byte("ok")
	p.Ops = append(p.Ops,
		Op{Name: "write", Trap: unix.SYS_WRITE, Args: [6]uintptr{3, p.Bytes(buf), uintptr(len(buf))}},
		Op{Name: "getfd other", Trap: unix.SYS_FCNTL, Args: [6]uintptr{uintptr(other), unix.F_GETFD}},
	)
	proc, err := p.Start()
	if err != nil {
		t.Fatal(err)
	}
	wr.Close()
	got, readErr := io.ReadAll(rd)
	err = proc.Wait()
	// The last op must fail as the descriptor is closed, and the
	// error must be reported via the moved error descriptor.
	var serr *os.SyscallError
	if !errors.As(err, &serr) || serr.Syscall != "getfd other" || !errors.Is(err, unix.EBADF) {
		t.Fatalf("want getfd other EBADF error, got %v", err)
	}
	if readErr != nil || string(got) != "ok" {
		t.Fatalf("want ok, got %q (err: %v)", got, readErr)
	}
}

func TestSetFdsCloexec(t *testing.T) {
	null := openNull(t)
	for fd, want := range []int{
		0: 0,
		1: 0,
		2: unix.FD_CLOEXEC,
		3: unix.FD_CLOEXEC, // Error reporting descriptor.
	} {
		var p Program
		if err := p.SetFds([]int{null, null, null}, 2); err != nil {
			t.Fatal(err)
		}
		// Use the descriptor flags as the exit status.
		p.Ops = append(p.Ops,
			Op{Name: "getfd", Trap: unix.SYS_FCNTL, Args: [6]uintptr{uintptr(fd), unix.F_GETFD}, Ret: R1},
			Op{Name: "exit", Trap: unix.SYS_EXIT_GROUP, ArgRegs: [6]Reg{R1}},
		)
		err := run(t, &p)
		got := 0
		if err != nil {
			if _, serr := fmt.Sscanf(err.Error(), "child exited with status %d", &got); serr != nil {
				t.Fatalf("fd %d: unexpected error: %v", fd, err)
			}
		}
		if got != want {
			t.Errorf("fd %d: want flags %d, got %d", fd, want, got)
		}
	}
}

// TestStartRetry checks that errors are reported after the program is
// started again (with descriptors opened in between).
func TestStartRetry(t *testing.T) {
	nfd := openNull(t)
	p := Program{UseCgroupFD: true, CgroupFD: -1}
	if err := p.SetFds([]int{nfd, nfd, nfd}, 3); err != nil {
		t.Fatal(err)
	}
	p.Ops = append(p.Ops, Op{Name: "close bad fd", Trap: unix.SYS_CLOSE, Args: [6]uintptr{^uintptr(0)}})
	if _, err := p.Start(); err == nil {
		t.Fatal("want error, got nil")
	}
	// Take the lowest descriptors.
	for range 3 {
		openNull(t)
	}
	p.UseCgroupFD = false
	err := run(t, &p)
	var serr *os.SyscallError
	if !errors.As(err, &serr) || serr.Syscall != "close bad fd" {
		t.Fatalf("want close bad fd error, got %v", err)
	}
}
