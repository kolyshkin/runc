package rawexec

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"unsafe"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/internal/linux"
	"github.com/opencontainers/runc/libcontainer/internal/rawfork"
	"github.com/opencontainers/runc/libcontainer/seccomp"
)

// loadSeccomp is like seccomp.InitSeccomp followed by [syncParentSeccomp],
// except the filter is compiled by the parent (see [seccomp.Compile]) and the
// child only loads it.
//
// If the filter has a listener, the child sends its descriptor number to
// syncFd (the child's end of a socket pair), and waits for the parent to get
// a copy of it (see [SeccompListener]). Note that all system calls made by
// the child after loading the filter (write, read, close, and execve in case
// of a listener) are subject to it.
func loadSeccomp(p *rawfork.Program, f *seccomp.Filter, syncFd int) {
	if f.NoNewPrivs {
		// Same as patchbpf.PatchAndLoad.
		logrus.Warnf("potentially misconfigured filter -- setting no_new_privs in seccomp path")
		noNewPrivs(p)
	}
	fprog := &unix.SockFprog{
		Len:    uint16(len(f.Program)),
		Filter: &f.Program[0],
	}
	// Same as patchbpf.PatchAndLoad, use prctl if there are no flags.
	op := rawfork.Op{Name: "load seccomp filter"}
	if f.Flags == 0 {
		op.Trap = unix.SYS_PRCTL
		op.Args = [6]uintptr{unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, p.Pin(unsafe.Pointer(fprog))}
	} else {
		op.Trap = unix.SYS_SECCOMP
		op.Args = [6]uintptr{unix.SECCOMP_SET_MODE_FILTER, uintptr(f.Flags), p.Pin(unsafe.Pointer(fprog))}
	}
	if !f.Listener {
		p.Ops = append(p.Ops, op)
		return
	}

	fd := new(uint32)
	ack := make([]byte, 1)
	op.Ret, op.Store = scratchReg, fd
	i := len(p.Ops)
	p.Ops = append(p.Ops, op,
		rawfork.Op{
			Name: "send seccomp listener fd",
			Trap: unix.SYS_WRITE,
			Args: [6]uintptr{uintptr(syncFd), p.Pin(unsafe.Pointer(fd)), 4},
		},
		rawfork.Op{
			Name: "wait for seccomp listener ack",
			Trap: unix.SYS_READ,
			Args: [6]uintptr{uintptr(syncFd), p.Bytes(ack), 1},
			// EOF means the parent has failed to get the listener.
			Cond: rawfork.IfZero,
			Goto: i + 4,
		},
		rawfork.Op{
			Name:    "close seccomp listener fd",
			Trap:    unix.SYS_CLOSE,
			ArgRegs: [6]rawfork.Reg{scratchReg},
			Cond:    rawfork.Always,
			Goto:    i + 5,
		},
		rawfork.Op{
			// This always fails with EBADF.
			Name: "no seccomp listener ack from parent",
			Trap: unix.SYS_CLOSE,
			Args: [6]uintptr{^uintptr(0)},
		},
	)
}

// SeccompListener gets a copy of the seccomp listener descriptor from the
// child with the given pid, which sends its number to sync (the parent's end
// of the socket pair passed to [loadSeccomp]), and lets the child continue.
// The caller must close its copy of the child's end after starting the child,
// so that an EOF is seen if the child exits.
func SeccompListener(pid int, sync *os.File) (*os.File, error) {
	var buf [4]byte
	if _, err := io.ReadFull(sync, buf[:]); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("child exited before sending seccomp listener fd")
		}
		return nil, fmt.Errorf("reading seccomp listener fd: %w", err)
	}
	f, err := linux.PidGetFd(pid, int(binary.NativeEndian.Uint32(buf[:])))
	if err != nil {
		return nil, fmt.Errorf("get seccomp listener fd from child: %w", err)
	}
	if _, err := sync.Write([]byte{0}); err != nil {
		f.Close()
		return nil, fmt.Errorf("sending seccomp listener ack: %w", err)
	}
	return f, nil
}
