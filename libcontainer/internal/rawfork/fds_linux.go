package rawfork

import (
	"errors"
	"slices"
	"strconv"

	"golang.org/x/sys/unix"
)

// SetFds appends ops which make the child's file descriptor table consist of
// fds[i] at position i (for all i), and the error reporting descriptor (see
// [ErrReg]) at position len(fds). All other descriptors are closed. The new
// descriptors at positions starting from cloexecFrom have O_CLOEXEC flag set.
//
// This requires close_range(2) (Linux 5.9+).
func (p *Program) SetFds(fds []int, cloexecFrom int) error {
	errFd, err := p.ErrFd()
	if err != nil {
		return err
	}
	if slices.Contains(fds, -1) {
		return errors.New("invalid fd -1")
	}
	n := len(fds)
	// Use temporary positions above any of the source and target ones,
	// so no source descriptor is overwritten while moving.
	base := slices.Max(append([]int{errFd, n}, fds...)) + 1
	for i, fd := range fds {
		p.Ops = append(p.Ops, Op{
			Name: "dup3 " + strconv.Itoa(fd),
			Trap: unix.SYS_DUP3,
			Args: [6]uintptr{uintptr(fd), uintptr(base + i), unix.O_CLOEXEC},
		})
	}
	p.Ops = append(p.Ops, Op{
		Name:    "dup3 error fd",
		Trap:    unix.SYS_DUP3,
		Args:    [6]uintptr{0, uintptr(base + n), unix.O_CLOEXEC},
		ArgRegs: [6]Reg{ErrReg},
		Ret:     ErrReg,
	})
	for i := range n + 1 {
		flags := 0
		if i >= cloexecFrom || i == n {
			flags = unix.O_CLOEXEC
		}
		p.Ops = append(p.Ops, Op{
			Name: "dup3 to " + strconv.Itoa(i),
			Trap: unix.SYS_DUP3,
			Args: [6]uintptr{uintptr(base + i), uintptr(i), uintptr(flags)},
			Ret:  retIf(i == n, ErrReg),
		})
	}
	p.Ops = append(p.Ops, Op{
		Name: "close_range",
		Trap: unix.SYS_CLOSE_RANGE,
		Args: [6]uintptr{uintptr(n + 1), uintptr(^uint32(0)), 0},
	})
	return nil
}

func retIf(cond bool, r Reg) Reg {
	if cond {
		return r
	}
	return NoReg
}
