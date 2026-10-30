package rawexec

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/libcontainer/internal/rawfork"
)

// lookupSupported returns [ErrUnsupported] if the binary name is to be
// looked up in path which has relative entries (as for such candidates
// exec.LookPath returns an error rather than continuing).
func lookupSupported(name, path string) error {
	if strings.Contains(name, "/") {
		return nil
	}
	for _, dir := range filepath.SplitList(path) {
		if !filepath.IsAbs(dir) {
			return fmt.Errorf("relative PATH entry %q: %w", dir, ErrUnsupported)
		}
	}
	return nil
}

// execBinary is like [exec.LookPath] followed by linux.Exec, as done by
// linuxSetnsInit.Init. The path is the value of PATH (from env).
//
// The lookup is performed by the child (by trying to execve each candidate),
// as it has to be done with the child's credentials, and in the container's
// mount namespace. If a candidate does not exist or is not executable, the
// next one is tried. Relative PATH entries are not supported (see
// lookupSupported).
func execBinary(p *rawfork.Program, name string, args, env []string, path string) error {
	if err := lookupSupported(name, path); err != nil {
		return err
	}
	lookup := !strings.Contains(name, "/")
	dirs := filepath.SplitList(path)
	argv, err := syscall.SlicePtrFromStrings(args)
	if err != nil {
		return err
	}
	envv, err := syscall.SlicePtrFromStrings(env)
	if err != nil {
		return err
	}
	argp, envp := p.Pin(unsafe.Pointer(&argv[0])), p.Pin(unsafe.Pointer(&envv[0]))
	execOp := func(opName, file string) (rawfork.Op, error) {
		ptr, err := p.String(file)
		return rawfork.Op{
			Name: opName,
			Trap: unix.SYS_EXECVE,
			Args: [6]uintptr{ptr, argp, envp},
		}, err
	}

	if !lookup {
		op, err := execOp("exec "+strconv.Quote(name), name)
		if err != nil {
			return err
		}
		p.Ops = append(p.Ops, op)
		return nil
	}
	for _, dir := range dirs {
		file := filepath.Join(dir, name)
		op, err := execOp("exec "+strconv.Quote(file), file)
		if err != nil {
			return err
		}
		op.Ignore = [4]unix.Errno{unix.ENOENT, unix.EACCES, unix.ENOTDIR, unix.ELOOP}
		p.Ops = append(p.Ops, op)
	}
	// No executable found. Report the error (execve of an empty path
	// fails with ENOENT).
	op, err := execOp(fmt.Sprintf("exec: %q: executable file not found in $PATH", name), "")
	if err != nil {
		return err
	}
	p.Ops = append(p.Ops, op)
	return nil
}
