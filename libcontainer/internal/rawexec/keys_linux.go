package rawexec

import (
	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/libcontainer/internal/rawfork"
)

// joinSessionKeyring is like keys.JoinSessionKeyring, except that ENOSYS
// is ignored (as linuxSetnsInit.Init does).
//
// This can't be done by the parent, as the keyring is to be created (or
// joined) with the credentials of the child in the container's user namespace.
func joinSessionKeyring(p *rawfork.Program, name string) error {
	ptr, err := p.String(name)
	if err != nil {
		return err
	}
	p.Ops = append(p.Ops, rawfork.Op{
		Name:   "join session keyring",
		Trap:   unix.SYS_KEYCTL,
		Args:   [6]uintptr{unix.KEYCTL_JOIN_SESSION_KEYRING, ptr},
		Ignore: [4]unix.Errno{unix.ENOSYS},
	})
	return nil
}
