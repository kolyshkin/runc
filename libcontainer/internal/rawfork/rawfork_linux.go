package rawfork

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Reg is a child register, which can hold a system call result to be used as
// an argument of a subsequent system call.
type Reg uint8

const (
	NoReg Reg = iota
	R1
	R2
	R3
	R4
	R5
	R6
	R7
	R8
	R9
	R10
	R11
	R12
	R13
	R14
	R15
	R16

	// ErrReg holds the file descriptor the child reports errors to. It is
	// initially set to [Program.ErrFd], and can be changed by the program
	// (for example, if it needs to move the descriptor elsewhere).
	ErrReg = R16
)

// numRegs is the number of registers. Must be a power of 2.
const numRegs = 16

// NoSyscall is a special [Op.Trap] value meaning the op does not perform a
// system call, and its result is Args[0] (which can come from a register).
// This is useful for conditional jumps based on a register value.
const NoSyscall = ^uintptr(0)

// Cond is a condition for jumping to [Op.Goto].
type Cond uint8

const (
	Never  Cond = iota // Never jump, continue with the next op.
	Always             // Always jump.
	IfZero             // Jump if the result is 0.
)

// Op is a single operation (normally, a system call) performed by the child.
//
// If the system call fails (and the error is not ignored), the child exits,
// and [Process.Wait] returns an [os.SyscallError] with the Name of the failed
// op.
type Op struct {
	// Name describes the op in error messages.
	Name string
	// Trap is the system call number, or NoSyscall.
	Trap uintptr
	// Args are the system call arguments. Pointers must be obtained using
	// [Program.Pin] or one of its wrappers.
	Args [6]uintptr
	// ArgRegs, if ArgRegs[i] is not NoReg, makes the child use the value of
	// the specified register instead of Args[i].
	ArgRegs [6]Reg
	// Ignore is a list of system call errors which are not fatal. If the
	// system call fails with one of these, the program continues, and the
	// result is the (positive) error number.
	Ignore [4]syscall.Errno
	// Ret, if not NoReg, is the register to store the result in.
	Ret Reg
	// Store, if not nil, is where to store the (truncated) result.
	Store *uint32
	// Cond and Goto set the index of the op to perform next. Goto equal
	// to the number of ops ends the program.
	Cond Cond
	Goto int
}

// Program is a sequence of ops to be performed by the child.
//
// Once the last op is performed, the child exits with the status of 0.
type Program struct {
	Ops []Op
	// UseCgroupFD and CgroupFD make the child start in the specified cgroup
	// (using clone3 with CLONE_INTO_CGROUP).
	UseCgroupFD bool
	CgroupFD    int

	pins         []unsafe.Pointer
	errRd, errWr *os.File
}

// Pin returns the address of ptr suitable for use in [Op.Args], and keeps the
// memory it points to alive until the program is started.
func (p *Program) Pin(ptr unsafe.Pointer) uintptr {
	// Storing ptr in p also makes it escape to the heap,
	// so it won't be moved by stack growth.
	p.pins = append(p.pins, ptr)
	return uintptr(ptr)
}

// Bytes is like [Program.Pin] but for a byte slice.
func (p *Program) Bytes(b []byte) uintptr {
	return p.Pin(unsafe.Pointer(unsafe.SliceData(b)))
}

// String is like [Program.Pin] but for a NUL-terminated copy of s.
func (p *Program) String(s string) (uintptr, error) {
	b, err := unix.BytePtrFromString(s)
	if err != nil {
		return 0, err
	}
	return p.Pin(unsafe.Pointer(b)), nil
}

// ErrFd returns the file descriptor which the child uses to report errors
// (initial value of [ErrReg]). It is only needed for programs which rearrange
// file descriptors. The descriptor has O_CLOEXEC flag set, so that the parent
// can tell when the child successfully calls execve(2).
func (p *Program) ErrFd() (int, error) {
	if p.errWr == nil {
		var err error
		p.errRd, p.errWr, err = os.Pipe()
		if err != nil {
			return -1, err
		}
	}
	return int(p.errWr.Fd()), nil
}

func (p *Program) validate() error {
	for i, op := range p.Ops {
		for _, r := range op.ArgRegs {
			if r > numRegs {
				return fmt.Errorf("op %d (%s): invalid arg register %d", i, op.Name, r)
			}
		}
		if op.Ret > numRegs {
			return fmt.Errorf("op %d (%s): invalid ret register %d", i, op.Name, op.Ret)
		}
		switch op.Cond {
		case Never:
		case Always, IfZero:
			if op.Goto < 0 || op.Goto > len(p.Ops) {
				return fmt.Errorf("op %d (%s): invalid goto %d", i, op.Name, op.Goto)
			}
		default:
			return fmt.Errorf("op %d (%s): invalid cond %d", i, op.Name, op.Cond)
		}
	}
	return nil
}

// Process is a running child started by [Program.Start].
type Process struct {
	Pid int

	ops     []Op
	errPipe *os.File
	opErr   error
}

// cloneArgs is struct clone_args from linux/sched.h.
type cloneArgs struct {
	flags      uint64
	pidFD      uint64
	childTID   uint64
	parentTID  uint64
	exitSignal uint64
	stack      uint64
	stackSize  uint64
	tls        uint64
	setTID     uint64
	setTIDSize uint64
	cgroup     uint64
}

// Start forks a child process which runs p.
//
// The child inherits all file descriptors of the parent, including those
// with O_CLOEXEC flag set. Note that until the child exits, it may keep
// open the descriptors which are closed by the parent.
//
// The child also inherits the properties of the calling thread, such as
// CPU affinity, or PID namespace for children (see setns(2)). To use these,
// the caller should lock the goroutine to the OS thread.
//
// If Start fails, it can be called again (for example, with a different
// [Program.CgroupFD]).
func (p *Program) Start() (*Process, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	errFd, err := p.ErrFd()
	if err != nil {
		return nil, err
	}
	var args *cloneArgs
	if p.UseCgroupFD {
		args = &cloneArgs{
			flags:      unix.CLONE_INTO_CGROUP,
			exitSignal: uint64(unix.SIGCHLD),
			cgroup:     uint64(p.CgroupFD),
		}
	}
	pid, errno := forkAndRun(p.Ops, uintptr(errFd), args)
	runtime.KeepAlive(p)
	runtime.KeepAlive(args)
	if errno != 0 {
		// Keep the error pipe, so that p can be started again (for
		// example, with a different cgroup), with the same ErrFd
		// (which ops may depend upon, see SetFds).
		name := "clone"
		if args != nil {
			name = "clone3"
		}
		return nil, os.NewSyscallError(name, errno)
	}
	rd := p.errRd
	p.errWr.Close()
	p.errRd, p.errWr = nil, nil
	return &Process{Pid: pid, ops: p.Ops, errPipe: rd}, nil
}

// readErr reads the error report from the child, if any. It returns once the
// child has either reported an error, exited, or successfully called execve.
func (c *Process) readErr() error {
	if c.errPipe == nil {
		return c.opErr
	}
	var info [8]byte
	// EOF (no error info) is fine.
	n, _ := io.ReadFull(c.errPipe, info[:])
	c.errPipe.Close()
	c.errPipe = nil
	if n == len(info) {
		idx := int(binary.NativeEndian.Uint32(info[0:]))
		errno := syscall.Errno(binary.NativeEndian.Uint32(info[4:]))
		name := fmt.Sprintf("op %d", idx)
		if idx >= 0 && idx < len(c.ops) {
			name = c.ops[idx].Name
		}
		c.opErr = os.NewSyscallError(name, errno)
	}
	return c.opErr
}

// WaitExec waits for the child to either successfully call execve(2), or
// exit. It returns an [os.SyscallError] if an op has failed (in which case
// the child has exited, and the caller should use [Process.Wait] to reap it).
func (c *Process) WaitExec() error {
	return c.readErr()
}

// Wait waits for the child to exit. It returns an [os.SyscallError] if an op
// has failed, or a generic error if the child exited abnormally.
func (c *Process) Wait() error {
	opErr := c.readErr()

	var (
		ws  unix.WaitStatus
		err error
	)
	for {
		_, err = unix.Wait4(c.Pid, &ws, 0, nil)
		if err != unix.EINTR {
			break
		}
	}
	if err != nil {
		return os.NewSyscallError("wait4", err)
	}
	if opErr != nil {
		return opErr
	}
	switch {
	case ws.Exited() && ws.ExitStatus() == 0:
		return nil
	case ws.Exited():
		return fmt.Errorf("child exited with status %d", ws.ExitStatus())
	case ws.Signaled():
		return fmt.Errorf("child killed by signal %v", ws.Signal())
	}
	return errors.New("child exited abnormally")
}
