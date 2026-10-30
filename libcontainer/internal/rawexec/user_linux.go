package rawexec

import (
	"fmt"
	"strconv"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/internal/sys"
	"github.com/opencontainers/runc/libcontainer/internal/rawfork"
)

// The functions below append ops to change the user to a rawfork program,
// doing the same as finalizeNamespace does (see setupUser).

// setKeepCaps is like system.SetKeepCaps (if keep is true) or
// system.ClearKeepCaps (otherwise).
func setKeepCaps(p *rawfork.Program, keep bool) {
	name, val := "clear keep caps", 0
	if keep {
		name, val = "set keep caps", 1
	}
	p.Ops = append(p.Ops, rawfork.Op{
		Name: name,
		Trap: unix.SYS_PRCTL,
		Args: [6]uintptr{unix.PR_SET_KEEPCAPS, uintptr(val)},
	})
}

// fixStdio is like fixStdioPermissions. The fds are the parent's
// descriptors which become the child's stdio, and the ops it appends
// work on the child's descriptors 0, 1, and 2 (so they must be performed
// after [rawfork.Program.SetFds] or similar).
//
// Whether to change the owner is decided by the parent, so in addition to
// uid it needs hostUID, which is the same uid as seen in the parent's user
// namespace (see configs.Config.HostUID), or -1 if unknown.
func fixStdio(p *rawfork.Program, uid, hostUID int, fds [3]int) error {
	for i, fd := range fds {
		var s unix.Stat_t
		if err := unix.Fstat(fd, &s); err != nil {
			return fmt.Errorf("fstat stdio fd %d: %w", fd, err)
		}
		// Skip chown if uid is already the one we want,
		// or fd is opened to /dev/null.
		if int(s.Uid) == hostUID || sys.IsDevNull(&s) {
			continue
		}
		p.Ops = append(p.Ops, rawfork.Op{
			Name: "fchown stdio fd " + strconv.Itoa(i),
			Trap: sysFchown,
			// Only change the uid (gid of -1 means no change).
			Args: [6]uintptr{uintptr(i), uintptr(uid), ^uintptr(0)},
			// EPERM: the inode's current owner is not mapped in the
			// user namespace. EROFS: read-only /dev. In any case,
			// it's better to not touch the stdio than to fail.
			Ignore: [4]unix.Errno{unix.EPERM, unix.EROFS},
		})
	}
	return nil
}

// setUser is like setupUser (except it does not call
// fixStdioPermissions, see [fixStdio]). Whether to set supplementary
// groups is decided by the caller, as setupUser does (setgroups(2) is not
// allowed in a rootless container, or if /proc/<pid>/setgroups is "deny").
//
// The setgid and setuid op names include the ID, as an EINVAL error from
// these means the ID is not mapped in the user namespace.
func setUser(p *rawfork.Program, uid, gid int, groups []int, setGroups bool) {
	if setGroups {
		// Same as [unix.Setgroups], which calls setgroups(0, NULL)
		// for an empty list (to clear supplementary groups).
		var args [6]uintptr
		if len(groups) > 0 {
			gids := make([]uint32, len(groups)) // gid_t
			for i, g := range groups {
				gids[i] = uint32(g)
			}
			args = [6]uintptr{uintptr(len(gids)), p.Pin(unsafe.Pointer(&gids[0]))}
		}
		p.Ops = append(p.Ops, rawfork.Op{
			Name: "setgroups",
			Trap: sysSetgroups,
			Args: args,
		})
	}
	// Unlike [unix.Setgid] and [unix.Setuid], which have to change all
	// threads, a raw system call is enough as the child is single-threaded.
	p.Ops = append(p.Ops,
		rawfork.Op{
			Name: "setgid " + strconv.Itoa(gid),
			Trap: sysSetgid,
			Args: [6]uintptr{uintptr(gid)},
		},
		rawfork.Op{
			Name: "setuid " + strconv.Itoa(uid),
			Trap: sysSetuid,
			Args: [6]uintptr{uintptr(uid)},
		},
	)
}
