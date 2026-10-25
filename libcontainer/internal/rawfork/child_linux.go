package rawfork

import (
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// These are implemented in the runtime, and are guaranteed to be available
// via linkname (see go.dev/issue/67401).

//go:linkname runtime_BeforeFork syscall.runtime_BeforeFork
func runtime_BeforeFork() //nolint:revive

//go:linkname runtime_AfterFork syscall.runtime_AfterFork
func runtime_AfterFork() //nolint:revive

//go:linkname runtime_AfterForkInChild syscall.runtime_AfterForkInChild
func runtime_AfterForkInChild() //nolint:revive

// forkAndRun forks a child process which runs ops and exits. If args is not
// nil, clone3(2) is used with the specified args. In the parent, it returns
// the child's pid. In the child, it never returns.
//
// Unlike package syscall, this uses fork rather than vfork, so the child has
// its own copy of the parent's memory, and can't corrupt it.
//
// Everything in the child must be nosplit and must not allocate; see
// TestChildCalls.
//
//go:noinline
//go:norace
//go:nocheckptr
func forkAndRun(ops []Op, errFd uintptr, args *cloneArgs) (pid int, errno syscall.Errno) {
	// Make sure file descriptors created concurrently without O_CLOEXEC
	// are not leaked to the child, as it may call execve(2).
	syscall.ForkLock.Lock()
	// No allocation or calls of non-nosplit functions from here on.
	runtime_BeforeFork()
	var r1 uintptr
	if args != nil {
		r1, _, errno = syscall.RawSyscall6(unix.SYS_CLONE3, uintptr(unsafe.Pointer(args)), unsafe.Sizeof(*args), 0, 0, 0, 0)
	} else if runtime.GOARCH == "s390x" {
		// On Linux/s390, the first two arguments of clone(2) are swapped.
		r1, _, errno = syscall.RawSyscall6(unix.SYS_CLONE, 0, uintptr(unix.SIGCHLD), 0, 0, 0, 0)
	} else {
		r1, _, errno = syscall.RawSyscall6(unix.SYS_CLONE, uintptr(unix.SIGCHLD), 0, 0, 0, 0, 0)
	}
	if errno != 0 || r1 != 0 {
		// In the parent.
		runtime_AfterFork()
		syscall.ForkLock.Unlock()
		return int(r1), errno
	}

	// In the child.
	runtime_AfterForkInChild()
	runChild(ops, errFd)
	return 0, 0 // Not reached.
}

// runChild performs ops. If an op fails, its index and errno are written
// to the file descriptor in ErrReg (initially errFd), and the child exits
// with status of 1.
//
//go:nosplit
//go:norace
//go:nocheckptr
func runChild(ops []Op, errFd uintptr) {
	var (
		regs [numRegs]uintptr
		args [6]uintptr
	)
	regs[(ErrReg-1)&(numRegs-1)] = errFd
	i := 0
	for uint(i) < uint(len(ops)) {
		op := &ops[i]
		for j := range args {
			args[j] = op.Args[j]
			if r := op.ArgRegs[j]; r != NoReg {
				args[j] = regs[(r-1)&(numRegs-1)]
			}
		}
		var (
			r1    uintptr
			errno syscall.Errno
		)
		if op.Trap == NoSyscall {
			r1 = args[0]
		} else {
			r1, _, errno = syscall.RawSyscall6(op.Trap, args[0], args[1], args[2], args[3], args[4], args[5])
		}
		if errno != 0 {
			ignore := false
			for _, e := range op.Ignore {
				if e == errno {
					ignore = true
				}
			}
			if !ignore {
				info := [2]uint32{uint32(i), uint32(errno)}
				_, _, _ = syscall.RawSyscall(unix.SYS_WRITE, regs[(ErrReg-1)&(numRegs-1)], uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info))
				exit(1)
			}
			r1 = uintptr(errno)
		}
		if op.Ret != NoReg {
			regs[(op.Ret-1)&(numRegs-1)] = r1
		}
		if op.Store != nil {
			*op.Store = uint32(r1)
		}
		i++
		switch op.Cond {
		case Always:
			i = op.Goto
		case IfZero:
			if r1 == 0 {
				i = op.Goto
			}
		}
	}
	exit(0)
}

//go:nosplit
//go:norace
func exit(code uintptr) {
	for {
		_, _, _ = syscall.RawSyscall(unix.SYS_EXIT_GROUP, code, 0, 0)
	}
}
