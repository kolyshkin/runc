package rawexec

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/opencontainers/selinux/go-selinux"
	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/libcontainer/apparmor"
	"github.com/opencontainers/runc/libcontainer/internal/rawfork"
)

// runProcAttr runs a program which uses fn to set a process attribute,
// and returns the value of /proc/thread-self/<attr> as read by the child.
func runProcAttr(t *testing.T, attr string, fn func(p *rawfork.Program, procFd int) error) string {
	t.Helper()
	proc, err := ProcRoot()
	if err != nil {
		t.Fatal(err)
	}
	defer proc.Close()
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	rd, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	defer wr.Close()

	// The child's descriptors are: stdio, the pipe (3), and procfs (4).
	nfd := int(null.Fd())
	p, err := newProgram([]int{nfd, nfd, nfd, int(wr.Fd()), int(proc.Fd())}, 3)
	if err != nil {
		t.Fatal(err)
	}
	if err := fn(p, 4); err != nil {
		t.Fatal(err)
	}
	path, err := p.String("thread-self/" + attr)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	p.Ops = append(p.Ops,
		rawfork.Op{Name: "open", Trap: unix.SYS_OPENAT, Args: [6]uintptr{4, path, unix.O_RDONLY | unix.O_CLOEXEC}, Ret: rawfork.R1},
		rawfork.Op{Name: "read", Trap: unix.SYS_READ, Args: [6]uintptr{0, p.Bytes(buf), uintptr(len(buf))}, ArgRegs: [6]rawfork.Reg{rawfork.R1}, Ret: rawfork.R2},
		rawfork.Op{Name: "write", Trap: unix.SYS_WRITE, Args: [6]uintptr{3, p.Bytes(buf)}, ArgRegs: [6]rawfork.Reg{2: rawfork.R2}},
	)
	child, err := p.Start()
	if err != nil {
		t.Fatal(err)
	}
	wr.Close()
	out, readErr := io.ReadAll(rd)
	if err := child.Wait(); err != nil {
		t.Fatal(err)
	}
	if readErr != nil {
		t.Fatal(readErr)
	}
	return string(bytes.TrimRight(out, "\x00\n"))
}

func TestProcRoot(t *testing.T) {
	f, err := ProcRoot()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := verifyProcRoot(f); err != nil {
		t.Fatal(err)
	}
	// As root, a private procfs instance with subset=pid (which has no
	// /proc/uptime) should be created.
	var st unix.Stat_t
	err = unix.Fstatat(int(f.Fd()), "uptime", &st, unix.AT_SYMLINK_NOFOLLOW)
	if os.Geteuid() == 0 && !errors.Is(err, unix.ENOENT) {
		t.Errorf("want private procfs with subset=pid, got uptime error %v", err)
	}
}

func TestSELinuxExecLabel(t *testing.T) {
	if !selinux.GetEnabled() {
		t.Skip("requires SELinux")
	}
	// Setting the exec label to the current one should be allowed.
	label, err := selinux.CurrentLabel()
	if err != nil {
		t.Fatal(err)
	}
	got := runProcAttr(t, "attr/exec", func(p *rawfork.Program, procFd int) error {
		return selinuxExecLabel(p, procFd, label)
	})
	if got != label {
		t.Fatalf("want exec label %q, got %q", label, got)
	}
}

func TestAppArmorProfile(t *testing.T) {
	if !apparmor.IsEnabled() {
		t.Skip("requires AppArmor")
	}
	// An unconfined process can change to unconfined on exec.
	got := runProcAttr(t, "attr/apparmor/exec", func(p *rawfork.Program, procFd int) error {
		return apparmorProfile(p, procFd, "unconfined")
	})
	if got != "unconfined" {
		t.Fatalf("want exec profile unconfined, got %q", got)
	}
}

func TestSELinuxKeyLabel(t *testing.T) {
	if !selinux.GetEnabled() {
		t.Skip("requires SELinux")
	}
	// Setting the key label to the current one should be allowed.
	label, err := selinux.CurrentLabel()
	if err != nil {
		t.Fatal(err)
	}
	got := runProcAttr(t, "attr/keycreate", func(p *rawfork.Program, procFd int) error {
		return selinuxKeyLabel(p, procFd, label)
	})
	if got != label {
		t.Fatalf("want key label %q, got %q", label, got)
	}
}
