package rawexec

import (
	"errors"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/libcontainer/internal/rawfork"
)

// ErrUnsupported means the configuration is not supported by raw exec, and
// runc init should be used instead.
var ErrUnsupported = errors.New("not supported by raw exec")

// Registers used by the functions appending ops to a rawfork program.
const (
	// scratchReg is for temporary values. Its value is not preserved
	// across calls of such functions.
	scratchReg = rawfork.R1
	// cwdReg is used by chdir.
	cwdReg = rawfork.R2
)

// nsRegs are used by joinNamespaces.
var nsRegs = [...]rawfork.Reg{rawfork.R3, rawfork.R4, rawfork.R5, rawfork.R6, rawfork.R7, rawfork.R8, rawfork.R9}

// newProgram returns a new rawfork program to run a process in the
// container, with the initial ops which must be performed first:
//
//  1. Make the child non-dumpable. The child is started in the container's
//     PID namespace, and once it joins the container's user namespace (but
//     before it changes the user), the container's root is privileged over
//     it, and can ptrace it or access its /proc/<pid>/fd. This is the same
//     as what nsexec does (see CVE-2016-9962). Upon execve(2), the kernel
//     makes the process dumpable again (unless its credentials have changed).
//
//  2. Set the child's file descriptors (see [rawfork.Program.SetFds]), so
//     that the descriptors inherited from the parent are closed before the
//     child joins any namespaces. Descriptors needed by subsequent ops (for
//     example, namespace ones) should be passed in fds at positions starting
//     from cloexecFrom, and closed by those ops once no longer needed.
func newProgram(fds []int, cloexecFrom int) (*rawfork.Program, error) {
	p := &rawfork.Program{}
	p.Ops = append(p.Ops, rawfork.Op{
		Name: "set non-dumpable",
		Trap: unix.SYS_PRCTL,
		Args: [6]uintptr{unix.PR_SET_DUMPABLE, 0},
	})
	if err := p.SetFds(fds, cloexecFrom); err != nil {
		return nil, err
	}
	return p, nil
}

// closeFd appends an op to close the child's descriptor fd.
func closeFd(p *rawfork.Program, fd int, name string) {
	p.Ops = append(p.Ops, rawfork.Op{
		Name: "close " + name,
		Trap: unix.SYS_CLOSE,
		Args: [6]uintptr{uintptr(fd)},
	})
}

// KernelSupported tells whether the kernel supports all the features
// required for raw exec (close_range and openat2).
var KernelSupported = sync.OnceValue(func() bool {
	if err := unix.CloseRange(^uint(0), ^uint(0), 0); errors.Is(err, unix.ENOSYS) {
		return false
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, "/", &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC})
	if err != nil {
		return false
	}
	_ = unix.Close(fd)
	return true
})
