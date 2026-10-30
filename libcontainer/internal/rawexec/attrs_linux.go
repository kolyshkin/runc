package rawexec

import (
	"strconv"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/internal/rawfork"
)

// The functions below append ops to set process attributes to a rawfork
// program, doing the same as linuxSetnsInit.Init or setnsProcess do.

// noNewPrivs sets the no_new_privs bit.
func noNewPrivs(p *rawfork.Program) {
	p.Ops = append(p.Ops, rawfork.Op{
		Name: "set no new privs",
		Trap: unix.SYS_PRCTL,
		Args: [6]uintptr{unix.PR_SET_NO_NEW_PRIVS, 1},
	})
}

// setUmask sets the umask.
func setUmask(p *rawfork.Program, mask uint32) {
	p.Ops = append(p.Ops, rawfork.Op{
		Name: "umask",
		Trap: unix.SYS_UMASK,
		Args: [6]uintptr{uintptr(mask)},
	})
}

// setPersonality is like setupPersonality.
func setPersonality(p *rawfork.Program, domain int) {
	p.Ops = append(p.Ops, rawfork.Op{
		Name: "set_personality",
		Trap: unix.SYS_PERSONALITY,
		Args: [6]uintptr{uintptr(domain)},
	})
}

// setCPUAffinity is like setnsProcess.setFinalCPUAffinity. Unlike other
// per-thread attributes (set by the parent, see schedSupported), the CPU affinity is set by
// the child, since it may be changed by the kernel when the child is moved
// to the container's cgroup (which happens upon clone).
//
// As there is no runc init, the initial affinity is only used if the final
// one is not set.
func setCPUAffinity(p *rawfork.Program, aff *configs.CPUAffinity) {
	op := rawfork.Op{Name: "sched_setaffinity", Trap: unix.SYS_SCHED_SETAFFINITY}
	var mask unix.CPUSetDynamic
	switch {
	case aff != nil && len(aff.Final) > 0:
		mask = aff.Final
	case aff != nil && len(aff.Initial) > 0:
		mask = aff.Initial
	default:
		// Same as tryResetCPUAffinity, which only warns about errors.
		mask = unix.NewCPUSet(configs.MaxCPU)
		mask.Fill()
		op.Name = "reset cpu affinity"
		op.Ignore = [4]unix.Errno{unix.EINVAL, unix.EPERM}
	}
	op.Args = [6]uintptr{0, uintptr(len(mask)) * unsafe.Sizeof(mask[0]), p.Pin(unsafe.Pointer(&mask[0]))}
	p.Ops = append(p.Ops, op)
}

// setMemoryPolicy is like setupMemoryPolicy.
func setMemoryPolicy(p *rawfork.Program, mpol *configs.LinuxMemoryPolicy) {
	if mpol == nil {
		return
	}
	var nodes, maxNode uintptr
	if n := mpol.Nodes; len(n) > 0 {
		nodes = p.Pin(unsafe.Pointer(&n[0]))
		// The kernel uses maxnode-1 bits (see get_nodes in mm/mempolicy.c).
		maxNode = uintptr(len(n))*unsafe.Sizeof(n[0])*8 + 1
	}
	p.Ops = append(p.Ops, rawfork.Op{
		Name: "set_mempolicy",
		Trap: unix.SYS_SET_MEMPOLICY,
		Args: [6]uintptr{uintptr(mpol.Mode | mpol.Flags), nodes, maxNode},
	})
}

// setRlimits is like setupRlimits, except the limits are set by the child
// itself (rlimits are per-process, so they can't be set on the thread the
// child is forked from, and setting them from the parent would require an
// extra synchronization with the child).
func setRlimits(p *rawfork.Program, limits []configs.Rlimit) {
	for _, l := range limits {
		// This is struct rlimit64 used by prlimit64(2).
		rlim := &[2]uint64{l.Soft, l.Hard}
		p.Ops = append(p.Ops, rawfork.Op{
			Name: "set rlimit type " + strconv.Itoa(l.Type),
			Trap: unix.SYS_PRLIMIT64,
			Args: [6]uintptr{0, uintptr(l.Type), p.Pin(unsafe.Pointer(rlim))},
		})
	}
}

// setOomScoreAdj is like update_oom_score_adj in nsexec.c. As lowering the
// value requires privileges, it has to be performed before joining the user
// namespace (and therefore the mount namespace, so the host's /proc is used).
// Note that a non-dumpable child can only do it if it is root.
func setOomScoreAdj(p *rawfork.Program, score int) error {
	path, err := p.String("/proc/self/oom_score_adj")
	if err != nil {
		return err
	}
	val := []byte(strconv.Itoa(score))
	dirFd := unix.AT_FDCWD
	p.Ops = append(p.Ops,
		rawfork.Op{
			Name: "open /proc/self/oom_score_adj",
			Trap: unix.SYS_OPENAT,
			Args: [6]uintptr{uintptr(dirFd), path, unix.O_WRONLY | unix.O_CLOEXEC},
			Ret:  scratchReg,
		},
		rawfork.Op{
			Name:    "update /proc/self/oom_score_adj",
			Trap:    unix.SYS_WRITE,
			Args:    [6]uintptr{0, p.Bytes(val), uintptr(len(val))},
			ArgRegs: [6]rawfork.Reg{scratchReg},
		},
		rawfork.Op{
			Name:    "close /proc/self/oom_score_adj",
			Trap:    unix.SYS_CLOSE,
			ArgRegs: [6]rawfork.Reg{scratchReg},
		},
	)
	return nil
}
