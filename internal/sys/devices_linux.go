package sys

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// IsDevNull tells whether st describes the /dev/null device.
func IsDevNull(st *unix.Stat_t) bool {
	//nolint:unconvert // Rdev is uint32 on MIPS.
	return st.Mode&unix.S_IFMT == unix.S_IFCHR && uint64(st.Rdev) == unix.Mkdev(1, 3)
}

// CheckPtmxHandle checks that the given file handle points to a real
// /dev/pts/ptmx device inode on a real devpts mount. We cannot (trivially)
// check that it is *the* /dev/pts for the container itself, but this is good
// enough.
func CheckPtmxHandle(ptmx *os.File) error {
	//nolint:revive,staticcheck,nolintlint // ignore "don't use ALL_CAPS" warning // nolintlint is needed to work around the different lint configs
	const (
		PTMX_MAJOR = 5 // from TTYAUX_MAJOR in <linux/major.h>
		PTMX_MINOR = 2 // from mknod_ptmx in fs/devpts/inode.c
		PTMX_INO   = 2 // from mknod_ptmx in fs/devpts/inode.c
	)
	return VerifyInode(ptmx, func(stat *unix.Stat_t, statfs *unix.Statfs_t) error {
		if statfs.Type != unix.DEVPTS_SUPER_MAGIC {
			return fmt.Errorf("ptmx handle is not on a real devpts mount: super magic is %#x", statfs.Type)
		}
		if stat.Ino != PTMX_INO {
			return fmt.Errorf("ptmx handle has wrong inode number: %v", stat.Ino)
		}
		rdev := uint64(stat.Rdev) //nolint:unconvert // Rdev is uint32 on MIPS.
		if stat.Mode&unix.S_IFMT != unix.S_IFCHR || rdev != unix.Mkdev(PTMX_MAJOR, PTMX_MINOR) {
			return fmt.Errorf("ptmx handle is not a real char ptmx device: ftype %#x %d:%d",
				stat.Mode&unix.S_IFMT, unix.Major(rdev), unix.Minor(rdev))
		}
		return nil
	})
}
