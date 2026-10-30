package rawexec

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/libcontainer/internal/rawfork"
)

// ProcRoot opens a procfs root for the child to set its own LSM attributes
// (see writeProcAttr). As the child joins the container's mount namespace,
// it can't use the container's /proc, which may have overmounts.
//
// If possible, a new private procfs instance (with subset=pid) is created.
// Otherwise (for example, if runc is rootless), the host's /proc is used.
func ProcRoot() (*os.File, error) {
	if f, err := newPrivateProc(); err == nil {
		return f, nil
	}
	f, err := os.OpenFile("/proc", unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if err := verifyProcRoot(f); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func newPrivateProc() (*os.File, error) {
	ctx, err := unix.Fsopen("proc", unix.FSOPEN_CLOEXEC)
	if err != nil {
		return nil, os.NewSyscallError("fsopen proc", err)
	}
	defer unix.Close(ctx)
	// Ignore errors, as this requires Linux 5.8.
	_ = unix.FsconfigSetString(ctx, "subset", "pid")
	if err := unix.FsconfigCreate(ctx); err != nil {
		return nil, os.NewSyscallError("fsconfig create proc", err)
	}
	fd, err := unix.Fsmount(ctx, unix.FSMOUNT_CLOEXEC, unix.MOUNT_ATTR_NODEV|unix.MOUNT_ATTR_NOEXEC|unix.MOUNT_ATTR_NOSUID)
	if err != nil {
		return nil, os.NewSyscallError("fsmount proc", err)
	}
	return os.NewFile(uintptr(fd), "procfs"), nil
}

func verifyProcRoot(f *os.File) error {
	const procRootIno = 1 // PROC_ROOT_INO.
	var fs unix.Statfs_t
	if err := unix.Fstatfs(int(f.Fd()), &fs); err != nil {
		return &os.PathError{Op: "fstatfs", Path: f.Name(), Err: err}
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return &os.PathError{Op: "fstat", Path: f.Name(), Err: err}
	}
	if fs.Type != unix.PROC_SUPER_MAGIC || st.Ino != procRootIno {
		return fmt.Errorf("%s is not procfs root", f.Name())
	}
	return nil
}

// writeProcAttr appends ops to write val to the child's own
// /proc/thread-self/<attr>, using procFd (the child's descriptor of
// procfs root, see ProcRoot). The name is used to name the ops.
func writeProcAttr(p *rawfork.Program, procFd int, attr, val, name string) error {
	path, err := p.String("thread-self/" + attr)
	if err != nil {
		return err
	}
	// In case procfs is the host's /proc, make sure the path is resolved
	// without crossing mounts.
	how := &unix.OpenHow{
		Flags:   unix.O_WRONLY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_XDEV | unix.RESOLVE_NO_MAGICLINKS,
	}
	buf := []byte(val)
	p.Ops = append(p.Ops,
		rawfork.Op{
			Name: name + ": open " + attr,
			Trap: unix.SYS_OPENAT2,
			Args: [6]uintptr{uintptr(procFd), path, p.Pin(unsafe.Pointer(how)), unsafe.Sizeof(*how)},
			Ret:  scratchReg,
		},
		rawfork.Op{
			Name:    name,
			Trap:    unix.SYS_WRITE,
			Args:    [6]uintptr{0, p.Bytes(buf), uintptr(len(buf))},
			ArgRegs: [6]rawfork.Reg{scratchReg},
		},
		rawfork.Op{
			Name:    name + ": close " + attr,
			Trap:    unix.SYS_CLOSE,
			ArgRegs: [6]rawfork.Reg{scratchReg},
		},
	)
	return nil
}

// selinuxExecLabel is like selinux.SetExecLabel.
func selinuxExecLabel(p *rawfork.Program, procFd int, label string) error {
	return writeProcAttr(p, procFd, "attr/exec", label, "set selinux exec label")
}

// apparmorProfile is like apparmor.ApplyProfile. Note that ENOENT from
// writing the attribute means the profile is not loaded.
func apparmorProfile(p *rawfork.Program, procFd int, name string) error {
	attr := "attr/apparmor/exec"
	if _, err := os.Stat("/proc/self/" + attr); errors.Is(err, os.ErrNotExist) {
		// Fall back to the old convention.
		attr = "attr/exec"
	}
	return writeProcAttr(p, procFd, attr, "exec "+name, "apply apparmor profile "+strconv.Quote(name))
}

// selinuxKeyLabel is like selinux.SetKeyLabel. Note that the child is
// single-threaded, so its thread-self is the thread group leader.
func selinuxKeyLabel(p *rawfork.Program, procFd int, label string) error {
	// Same as SetKeyLabel, which ignores ENOENT.
	if _, err := os.Stat("/proc/self/attr/keycreate"); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return writeProcAttr(p, procFd, "attr/keycreate", label, "set selinux key label")
}
