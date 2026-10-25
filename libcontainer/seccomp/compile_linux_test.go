//go:build cgo && seccomp

package seccomp

import (
	"errors"
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/internal/rawfork"
)

// TestCompile checks that a filter compiled by Compile can be loaded
// by a different (child) process.
func TestCompile(t *testing.T) {
	errnoRet := uint(unix.EXDEV)
	filter, err := Compile(&configs.Seccomp{
		DefaultAction: configs.Allow,
		Syscalls: []*configs.Syscall{
			{Name: "getcwd", Action: configs.Errno, ErrnoRet: &errnoRet},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(filter.Program) == 0 || filter.Listener {
		t.Fatalf("unexpected filter: %+v", filter)
	}

	var p rawfork.Program
	fprog := &unix.SockFprog{
		Len:    uint16(len(filter.Program)),
		Filter: &filter.Program[0],
	}
	buf := make([]byte, 256)
	p.Ops = []rawfork.Op{
		{Name: "getcwd before", Trap: unix.SYS_GETCWD, Args: [6]uintptr{p.Bytes(buf), uintptr(len(buf))}},
		{Name: "no_new_privs", Trap: unix.SYS_PRCTL, Args: [6]uintptr{unix.PR_SET_NO_NEW_PRIVS, 1}},
		{Name: "seccomp", Trap: unix.SYS_SECCOMP, Args: [6]uintptr{unix.SECCOMP_SET_MODE_FILTER, uintptr(filter.Flags), p.Pin(unsafe.Pointer(fprog))}},
		{Name: "getcwd after", Trap: unix.SYS_GETCWD, Args: [6]uintptr{p.Bytes(buf), uintptr(len(buf))}},
	}
	proc, err := p.Start()
	if err != nil {
		t.Fatal(err)
	}
	err = proc.Wait()
	var serr *os.SyscallError
	if !errors.As(err, &serr) || serr.Syscall != "getcwd after" || !errors.Is(err, unix.EXDEV) {
		t.Fatalf("want getcwd after EXDEV error, got %v", err)
	}
}
