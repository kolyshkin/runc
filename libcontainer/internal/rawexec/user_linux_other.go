//go:build linux && !386 && !arm

package rawexec

import "golang.org/x/sys/unix"

const (
	sysSetgroups = unix.SYS_SETGROUPS
	sysSetgid    = unix.SYS_SETGID
	sysSetuid    = unix.SYS_SETUID
	sysFchown    = unix.SYS_FCHOWN
	sysSetresuid = unix.SYS_SETRESUID
)
