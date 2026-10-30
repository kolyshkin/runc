package rawexec

import (
	"errors"
	"os"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/internal/rawfork"
	"github.com/opencontainers/runc/libcontainer/seccomp"
)

func compileSeccomp(t *testing.T, action configs.Action) *seccomp.Filter {
	t.Helper()
	if !seccomp.Enabled {
		t.Skip("requires seccomp support")
	}
	errnoRet := uint(unix.EXDEV)
	f, err := seccomp.Compile(&configs.Seccomp{
		DefaultAction: configs.Allow,
		Syscalls: []*configs.Syscall{
			{Name: "getcwd", Action: action, ErrnoRet: &errnoRet},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestLoadSeccomp(t *testing.T) {
	f := compileSeccomp(t, configs.Errno)
	var p rawfork.Program
	noNewPrivs(&p)
	loadSeccomp(&p, f, -1)
	buf := make([]byte, 256)
	p.Ops = append(p.Ops, rawfork.Op{Name: "getcwd", Trap: unix.SYS_GETCWD, Args: [6]uintptr{p.Bytes(buf), uintptr(len(buf))}})
	proc, err := p.Start()
	if err != nil {
		t.Fatal(err)
	}
	err = proc.Wait()
	var serr *os.SyscallError
	if !errors.As(err, &serr) || serr.Syscall != "getcwd" || !errors.Is(err, unix.EXDEV) {
		t.Fatalf("want getcwd EXDEV error, got %v", err)
	}
}

func TestSeccompListener(t *testing.T) {
	f := compileSeccomp(t, configs.Notify)
	if !f.Listener {
		t.Fatal("want filter with listener")
	}
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()

	for _, ack := range []bool{true, false} {
		t.Run("ack="+strconv.FormatBool(ack), func(t *testing.T) {
			fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			parent, child := os.NewFile(uintptr(fds[0]), "parent"), os.NewFile(uintptr(fds[1]), "child")
			defer parent.Close()
			defer child.Close()

			// Make sure the child does not have the parent's end.
			nfd := int(null.Fd())
			var p rawfork.Program
			if err := p.SetFds([]int{nfd, nfd, nfd, int(child.Fd())}, 3); err != nil {
				t.Fatal(err)
			}
			noNewPrivs(&p)
			loadSeccomp(&p, f, 3)
			proc, err := p.Start()
			if err != nil {
				t.Fatal(err)
			}
			child.Close()
			if !ack {
				// Read the fd number, but close the socket instead of
				// sending an ack.
				buf := make([]byte, 4)
				if _, err := parent.Read(buf); err != nil {
					t.Fatal(err)
				}
				parent.Close()
				err := proc.Wait()
				var serr *os.SyscallError
				if !errors.As(err, &serr) || serr.Syscall != "no seccomp listener ack from parent" {
					t.Fatalf("want no ack error, got %v", err)
				}
				return
			}
			listener, err := SeccompListener(proc.Pid, parent)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			if err := proc.Wait(); err != nil {
				t.Fatal(err)
			}
			link, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(listener.Fd())))
			if err != nil {
				t.Fatal(err)
			}
			if link != "anon_inode:seccomp notify" {
				t.Fatalf("want seccomp notify fd, got %q", link)
			}
		})
	}
}
