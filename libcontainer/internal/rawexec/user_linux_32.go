//go:build linux && (386 || arm)

package rawexec

import "golang.org/x/sys/unix"

// On these architectures, the legacy system calls use 16-bit IDs,
// so the 32-bit variants must be used instead.
const (
	sysSetgroups = unix.SYS_SETGROUPS32
	sysSetgid    = unix.SYS_SETGID32
	sysSetuid    = unix.SYS_SETUID32
	sysFchown    = unix.SYS_FCHOWN32
	sysSetresuid = unix.SYS_SETRESUID32
)
