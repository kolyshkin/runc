package rawexec

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/libcontainer/internal/rawfork"
)

// forkChild appends ops to fork the child, which is needed for the PID and time
// namespaces joined by the child to take effect. The child writes the grandchild's pid to
// the child's descriptor pipeFd and exits, while the grandchild closes pipeFd
// and performs the rest of the program. The grandchild is a child of the
// parent (as clone(2) is used with CLONE_PARENT), which should use
// [WaitFork] to get it.
func forkChild(p *rawfork.Program, pipeFd int) {
	pid := new(uint32)
	flags := uintptr(unix.CLONE_PARENT | unix.SIGCHLD)
	args := [6]uintptr{flags}
	if runtime.GOARCH == "s390x" {
		// On Linux/s390, the first two arguments of clone(2) are swapped.
		args = [6]uintptr{0, flags}
	}
	next := len(p.Ops) + 3
	p.Ops = append(p.Ops,
		rawfork.Op{Name: "fork", Trap: unix.SYS_CLONE, Args: args, Store: pid, Cond: rawfork.IfZero, Goto: next},
		rawfork.Op{Name: "write pid", Trap: unix.SYS_WRITE, Args: [6]uintptr{uintptr(pipeFd), p.Pin(unsafe.Pointer(pid)), 4}},
		rawfork.Op{Name: "exit", Trap: unix.SYS_EXIT_GROUP},
	)
	closeFd(p, pipeFd, "pid pipe")
}

// WaitFork reads the grandchild's pid from pipe (see [forkChild]), and makes
// proc refer to the grandchild (see [rawfork.Process.Reparent]). On error, the
// caller should reap proc.
func WaitFork(proc *rawfork.Process, pipe *os.File) error {
	var buf [4]byte
	if _, err := io.ReadFull(pipe, buf[:]); err != nil {
		// The child has failed before writing the pid.
		if err := proc.WaitExec(); err != nil {
			return err
		}
		return fmt.Errorf("reading grandchild pid: %w", err)
	}
	return proc.Reparent(int(binary.NativeEndian.Uint32(buf[:])))
}
