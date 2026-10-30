package rawexec

import (
	"errors"
	"os"

	"github.com/moby/sys/user"
	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/internal/pathrs"
)

// UserHome is like getUserHome, but it is used by the parent, reading
// /etc/passwd inside root (the container's root directory).
//
// This is cheaper than running anything in the container, and gives the
// same result, as getUserHome does not use NSS either.
func UserHome(root *os.File, uid int) (string, error) {
	const defaultHome = "/" // Default value, return this with any error.

	// Open with O_PATH first, as opening a FIFO for reading blocks.
	handle, err := pathrs.OpenInRoot(root, "/etc/passwd", unix.O_PATH|unix.O_CLOEXEC)
	if err != nil {
		return defaultHome, err
	}
	defer handle.Close()
	var st unix.Stat_t
	if err := unix.Fstat(int(handle.Fd()), &st); err != nil {
		return defaultHome, &os.PathError{Op: "fstat", Path: handle.Name(), Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return defaultHome, errors.New("/etc/passwd is not a regular file")
	}
	passwd, err := pathrs.Reopen(handle, unix.O_RDONLY|unix.O_CLOEXEC)
	if err != nil {
		return defaultHome, err
	}
	defer passwd.Close()

	users, err := user.ParsePasswdFilter(passwd, func(u user.User) bool {
		return u.Uid == uid
	})
	if err != nil || len(users) == 0 {
		// No entries is kinda expected as any UID can be specified.
		return defaultHome, err
	}
	return users[0].Home, nil
}
