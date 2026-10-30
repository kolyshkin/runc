package rawexec

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/libcontainer/capabilities"
	"github.com/opencontainers/runc/libcontainer/internal/rawfork"
)

// runChdir runs a program which uses chdir to change to cwd, with the
// before and middle functions (if not nil) appending ops performed before
// the first attempt and before the retry. It returns the resulting working
// directory, or the error from [rawfork.Process.Wait].
func runChdir(t *testing.T, cwd string, before, middle func(p *rawfork.Program)) (string, error) {
	t.Helper()
	rd, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	defer wr.Close()

	var p rawfork.Program
	if before != nil {
		before(&p)
	}
	retry, err := chdir(&p, cwd)
	if err != nil {
		t.Fatal(err)
	}
	if middle != nil {
		middle(&p)
	}
	retry()
	buf := make([]byte, unix.PathMax)
	p.Ops = append(p.Ops,
		rawfork.Op{Name: "getcwd", Trap: unix.SYS_GETCWD, Args: [6]uintptr{p.Bytes(buf), uintptr(len(buf))}, Ret: rawfork.R3},
		rawfork.Op{Name: "write", Trap: unix.SYS_WRITE, Args: [6]uintptr{wr.Fd(), p.Bytes(buf)}, ArgRegs: [6]rawfork.Reg{2: rawfork.R3}},
	)
	proc, err := p.Start()
	if err != nil {
		t.Fatal(err)
	}
	wr.Close()
	out, readErr := io.ReadAll(rd)
	if err := proc.Wait(); err != nil {
		return "", err
	}
	if readErr != nil {
		t.Fatal(readErr)
	}
	return string(bytes.TrimRight(out, "\x00")), nil
}

func TestChdir(t *testing.T) {
	dir := t.TempDir()
	got, err := runChdir(t, dir, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != dir {
		t.Fatalf("want cwd %q, got %q", dir, got)
	}
}

func TestChdirMagicLink(t *testing.T) {
	_, err := runChdir(t, "/proc/self/cwd", nil, nil)
	var serr *os.SyscallError
	if !errors.As(err, &serr) || serr.Syscall != `open cwd "/proc/self/cwd"` || !errors.Is(err, unix.ELOOP) {
		t.Fatalf("want open cwd ELOOP error, got %v", err)
	}
}

func TestChdirNoAccess(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires non-root")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	// Both the first attempt and the retry fail.
	_, err := runChdir(t, dir, nil, nil)
	var serr *os.SyscallError
	if !errors.As(err, &serr) || serr.Syscall != "chdir to cwd "+strconv.Quote(dir) || !errors.Is(err, unix.EACCES) {
		t.Fatalf("want chdir to cwd EACCES error, got %v", err)
	}
}

func TestChdirRetry(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	const id = 1000
	// A directory which is only accessible by the user.
	dir := t.TempDir()
	for _, d := range []string{filepath.Dir(dir), dir} {
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	user := filepath.Join(dir, "user")
	sub := filepath.Join(user, "sub")
	for _, d := range []string{user, sub} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(d, id, id); err != nil {
			t.Fatal(err)
		}
	}

	// Without CAP_DAC_OVERRIDE and CAP_DAC_READ_SEARCH, the first attempt
	// fails, and the retry (after changing the user) succeeds.
	last, err := capabilities.LastCap()
	if err != nil {
		t.Fatal(err)
	}
	all := uint64(1)<<(last+1) - 1
	caps := all &^ (1<<unix.CAP_DAC_OVERRIDE | 1<<unix.CAP_DAC_READ_SEARCH)
	hdr := &unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := &[2]unix.CapUserData{
		{Effective: uint32(caps), Permitted: uint32(all)},
		{Effective: uint32(caps >> 32), Permitted: uint32(all >> 32)},
	}
	// For user, the first attempt fails at fchdir, and for sub, at open.
	for _, cwd := range []string{user, sub} {
		got, err := runChdir(t, cwd, func(p *rawfork.Program) {
			p.Ops = append(p.Ops, rawfork.Op{
				Name: "capset", Trap: unix.SYS_CAPSET,
				Args: [6]uintptr{p.Pin(unsafe.Pointer(hdr)), p.Pin(unsafe.Pointer(data))},
			})
		}, func(p *rawfork.Program) {
			setUser(p, id, id, nil, true)
		})
		if err != nil {
			t.Fatal(err)
		}
		if got != cwd {
			t.Fatalf("want cwd %q, got %q", cwd, got)
		}
	}
}
