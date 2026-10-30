package rawexec

import (
	"strconv"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/libcontainer/capabilities"
	"github.com/opencontainers/runc/libcontainer/internal/rawfork"
)

// The functions below append ops to set capabilities to a rawfork program,
// doing the same as [capabilities.Caps] methods do (see finalizeNamespace).

// capsBoundingSet is like capabilities.Caps.ApplyBoundingSet.
func capsBoundingSet(p *rawfork.Program, m capabilities.Masks, last int) {
	for c := range last + 1 {
		if m.Bounding&(1<<c) != 0 {
			continue
		}
		p.Ops = append(p.Ops, rawfork.Op{
			Name: "drop bounding capability " + strconv.Itoa(c),
			Trap: unix.SYS_PRCTL,
			Args: [6]uintptr{unix.PR_CAPBSET_DROP, uintptr(c)},
			// EINVAL: the capability is not supported by the kernel.
			// EPERM: no CAP_SETPCAP (the capability package skips
			// dropping in this case).
			Ignore: [4]unix.Errno{unix.EINVAL, unix.EPERM},
		})
	}
}

// applyCaps is like capabilities.Caps.ApplyCaps.
func applyCaps(p *rawfork.Program, m capabilities.Masks, last int) {
	capsBoundingSet(p, m, last)

	hdr := &unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := &[2]unix.CapUserData{
		{Effective: uint32(m.Effective), Permitted: uint32(m.Permitted), Inheritable: uint32(m.Inheritable)},
		{Effective: uint32(m.Effective >> 32), Permitted: uint32(m.Permitted >> 32), Inheritable: uint32(m.Inheritable >> 32)},
	}
	p.Ops = append(p.Ops, rawfork.Op{
		Name: "capset",
		Trap: unix.SYS_CAPSET,
		Args: [6]uintptr{p.Pin(unsafe.Pointer(hdr)), p.Pin(unsafe.Pointer(data))},
	})

	// Errors from setting ambient capabilities are ignored (the
	// capability package only warns about those).
	p.Ops = append(p.Ops, rawfork.Op{
		Name:   "clear ambient capabilities",
		Trap:   unix.SYS_PRCTL,
		Args:   [6]uintptr{unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL},
		Ignore: [4]unix.Errno{unix.EINVAL}, // Not supported (Linux < 4.3).
	})
	for c := range last + 1 {
		if m.Ambient&(1<<c) == 0 {
			continue
		}
		p.Ops = append(p.Ops, rawfork.Op{
			Name:   "raise ambient capability " + strconv.Itoa(c),
			Trap:   unix.SYS_PRCTL,
			Args:   [6]uintptr{unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_RAISE, uintptr(c)},
			Ignore: [4]unix.Errno{unix.EINVAL, unix.EPERM},
		})
	}
}
