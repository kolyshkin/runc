package rawexec

import (
	"strconv"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/libcontainer/internal/rawfork"
)

// chdir is like the part of finalizeNamespace in libcontainer which changes the working
// directory. It appends ops to change the working directory to cwd, to be
// performed before changing the user (see [setUser]). If this fails with a
// permission error, the ops appended by the returned function retry it; these
// are to be performed after changing the user.
//
// Unlike chdir(2), magic links (such as /proc/self/fd/*) are not followed, so
// the working directory can't be outside of the container's root (which is
// what verifyCwd checks for, see CVE-2024-21626).
func chdir(p *rawfork.Program, cwd string) (retry func(), _ error) {
	path, err := p.String(cwd)
	if err != nil {
		return nil, err
	}
	how := &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_MAGICLINKS,
	}
	dirFd := unix.AT_FDCWD
	open := rawfork.Op{
		Name: "open cwd " + strconv.Quote(cwd),
		Trap: unix.SYS_OPENAT2,
		Args: [6]uintptr{uintptr(dirFd), path, p.Pin(unsafe.Pointer(how)), unsafe.Sizeof(*how)},
		Ret:  cwdReg,
	}
	chdir := rawfork.Op{
		Name:    "chdir to cwd " + strconv.Quote(cwd),
		Trap:    unix.SYS_FCHDIR,
		ArgRegs: [6]rawfork.Reg{cwdReg},
	}
	closeFd := rawfork.Op{
		Name:    "close cwd",
		Trap:    unix.SYS_CLOSE,
		ArgRegs: [6]rawfork.Reg{cwdReg},
	}

	// The first attempt ignores permission errors, leaving the error
	// number in cwdReg (or 0 on success).
	perm := [4]unix.Errno{unix.EACCES, unix.EPERM}
	i := len(p.Ops)
	first := []rawfork.Op{open, chdir, closeFd, {
		Name:    "save chdir result",
		Trap:    rawfork.NoSyscall,
		ArgRegs: [6]rawfork.Reg{scratchReg},
		Ret:     cwdReg,
	}}
	first[0].Ignore, first[0].Cond, first[0].Goto = perm, rawfork.IfError, i+len(first)
	first[1].Ignore, first[1].Ret = perm, scratchReg
	p.Ops = append(p.Ops, first...)

	return func() {
		i := len(p.Ops)
		p.Ops = append(p.Ops, rawfork.Op{
			Name:    "check chdir result",
			Trap:    rawfork.NoSyscall,
			ArgRegs: [6]rawfork.Reg{cwdReg},
			Cond:    rawfork.IfZero,
			Goto:    i + 4,
		}, open, chdir, closeFd)
	}, nil
}
