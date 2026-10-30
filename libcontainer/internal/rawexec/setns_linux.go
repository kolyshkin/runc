package rawexec

import (
	"fmt"

	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/internal/rawfork"
)

// Namespace is a namespace to be joined by the child (see joinNamespaces).
type Namespace struct {
	Type configs.NamespaceType
	// Fd is the child's descriptor of the namespace.
	Fd int
	// Path is the namespace path (used in error messages).
	Path string
}

// joinNamespaces is like join_namespaces in nsexec.c. It appends ops to join the
// namespaces nss, and close their descriptors.
//
// First, all non-user namespaces are joined, skipping those failed with
// EPERM. Then, the user namespace is joined (and the child becomes root in
// it). Finally, the namespaces skipped earlier are joined (this is needed for
// rootless containers, which don't have setns(2) permissions until they join
// the user namespace).
//
// The PID and time namespaces only apply to the children of the calling
// process, so the child has to fork after joining them (see forkChild).
func joinNamespaces(p *rawfork.Program, nss []Namespace) error {
	var user *Namespace
	var other []Namespace
	for i := range nss {
		switch nss[i].Type {
		case configs.NEWUSER:
			user = &nss[i]
		default:
			other = append(other, nss[i])
		}
	}
	if len(other) > len(nsRegs) {
		return fmt.Errorf("too many namespaces (%d)", len(other))
	}
	setns := func(ns *Namespace) rawfork.Op {
		t := configs.Namespaces{{Type: ns.Type}}
		return rawfork.Op{
			Name: fmt.Sprintf("setns into %s namespace (%s)", configs.NsName(ns.Type), ns.Path),
			Trap: unix.SYS_SETNS,
			Args: [6]uintptr{uintptr(ns.Fd), t.CloneFlags()},
		}
	}

	// The first attempt skips permission errors, leaving the result
	// (0 or EPERM) in a register.
	for i := range other {
		op := setns(&other[i])
		op.Ignore = [4]unix.Errno{unix.EPERM}
		op.Ret = nsRegs[i]
		p.Ops = append(p.Ops, op)
	}
	if user != nil {
		p.Ops = append(p.Ops, setns(user), rawfork.Op{
			// Same as unshare(CLONE_NEWUSER), see
			// https://github.com/opencontainers/runc/issues/4466.
			Name: "become root in user namespace",
			Trap: sysSetresuid,
		})
	}
	for i := range other {
		p.Ops = append(p.Ops, rawfork.Op{
			Name:    "check setns result",
			Trap:    rawfork.NoSyscall,
			ArgRegs: [6]rawfork.Reg{nsRegs[i]},
			Cond:    rawfork.IfZero,
			Goto:    len(p.Ops) + 2,
		}, setns(&other[i]))
	}
	for _, ns := range nss {
		p.Ops = append(p.Ops, rawfork.Op{
			Name: "close " + ns.Path,
			Trap: unix.SYS_CLOSE,
			Args: [6]uintptr{uintptr(ns.Fd)},
		})
	}
	return nil
}

// joinNamespacesPidfd is like [joinNamespaces], but it joins the namespaces of
// the given types of the process referred to by pidFd (the child's descriptor
// of a pidfd) using a single setns(2) call, and closes the pidfd.
//
// As the namespaces are joined atomically (with the privilege checks done
// against the new user namespace), this may fail if some of them are not
// owned by the user namespace being joined, so it should only be used if
// all the namespaces were created by the container.
func joinNamespacesPidfd(p *rawfork.Program, pidFd int, types []configs.NamespaceType) {
	var (
		ns   configs.Namespaces
		user bool
	)
	for _, typ := range types {
		if typ == configs.NEWUSER {
			user = true
		}
		ns = append(ns, configs.Namespace{Type: typ})
	}
	if len(ns) == 0 {
		closeFd(p, pidFd, "pidfd")
		return
	}
	p.Ops = append(p.Ops, rawfork.Op{
		Name: "setns into container namespaces",
		Trap: unix.SYS_SETNS,
		Args: [6]uintptr{uintptr(pidFd), ns.CloneFlags()},
	})
	if user {
		p.Ops = append(p.Ops, rawfork.Op{
			// Same as unshare(CLONE_NEWUSER), see
			// https://github.com/opencontainers/runc/issues/4466.
			Name: "become root in user namespace",
			Trap: sysSetresuid,
		})
	}
	closeFd(p, pidFd, "pidfd")
}
