package rawexec

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/internal/rawfork"
)

// startUsernsUts starts a process in new user and UTS (and those in flags)
// namespaces, with a temporary working directory, returning its pid. If we are
// root, the namespace's root is mapped to 100000 (so that the current user is
// not mapped), otherwise to the current user.
func startUsernsUts(t *testing.T, flags uintptr) int {
	t.Helper()
	uidMap := []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Geteuid(), Size: 1}}
	gidMap := []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getegid(), Size: 1}}
	if os.Geteuid() == 0 {
		uidMap = []syscall.SysProcIDMap{{ContainerID: 0, HostID: 100000, Size: 65536}}
		gidMap = uidMap
	}
	cmd := exec.Command("sleep", "infinity")
	cmd.Dir = t.TempDir()
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWUTS | flags,
		UidMappings: uidMap,
		GidMappings: gidMap,
	}
	if err := cmd.Start(); err != nil {
		t.Skipf("can't create user namespace: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return cmd.Process.Pid
}

// setnsResult is what the child started by runSetns reports.
type setnsResult struct {
	links map[configs.NamespaceType]string
	uid   uint32
	cwd   string
}

// runSetns runs a program which joins the namespaces of the process pid
// (using joinNamespacesPidfd if pidfd is true, or joinNamespaces otherwise), and returns
// what the child reports.
func runSetns(t *testing.T, pid int, types []configs.NamespaceType, pidfd bool) (*setnsResult, error) {
	t.Helper()
	rd, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	defer wr.Close()
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()

	// The child's descriptors are: stdio, the pipe (3), and either the
	// pidfd (4) or namespaces (4+). Like a passed file, the pipe has no
	// O_CLOEXEC.
	nfd := int(null.Fd())
	fds := []int{nfd, nfd, nfd, int(wr.Fd())}
	if pidfd {
		fd, err := unix.PidfdOpen(pid, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		fds = append(fds, fd)
	}
	var nss []Namespace
	for _, typ := range types {
		if pidfd {
			break
		}
		path := "/proc/" + strconv.Itoa(pid) + "/ns/" + configs.NsName(typ)
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		nss = append(nss, Namespace{Type: typ, Fd: len(fds), Path: path})
		fds = append(fds, int(f.Fd()))
	}
	p, err := newProgram(fds, 4)
	if err != nil {
		t.Fatal(err)
	}
	if pidfd {
		joinNamespacesPidfd(p, 4, types)
	} else if err := joinNamespaces(p, nss); err != nil {
		t.Fatal(err)
	}

	// Report the uid, the working directory, and the namespace links
	// (all separated by NUL).
	uid := new(uint32)
	nul := []byte{0}
	cwd := make([]byte, 4096)
	p.Ops = append(p.Ops,
		rawfork.Op{Name: "getuid", Trap: unix.SYS_GETUID, Store: uid},
		rawfork.Op{Name: "write uid", Trap: unix.SYS_WRITE, Args: [6]uintptr{3, p.Pin(unsafe.Pointer(uid)), 4}},
		// The result includes the terminating NUL.
		rawfork.Op{Name: "getcwd", Trap: unix.SYS_GETCWD, Args: [6]uintptr{p.Bytes(cwd), uintptr(len(cwd))}, Ret: rawfork.R1},
		rawfork.Op{Name: "write cwd", Trap: unix.SYS_WRITE, Args: [6]uintptr{3, p.Bytes(cwd)}, ArgRegs: [6]rawfork.Reg{2: rawfork.R1}},
	)
	for _, typ := range types {
		path, err := p.String("/proc/self/ns/" + configs.NsName(typ))
		if err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 128)
		dirFd := unix.AT_FDCWD
		p.Ops = append(p.Ops,
			rawfork.Op{Name: "readlink", Trap: unix.SYS_READLINKAT, Args: [6]uintptr{uintptr(dirFd), path, p.Bytes(buf), uintptr(len(buf))}, Ret: rawfork.R1},
			rawfork.Op{Name: "write", Trap: unix.SYS_WRITE, Args: [6]uintptr{3, p.Bytes(buf)}, ArgRegs: [6]rawfork.Reg{2: rawfork.R1}},
			rawfork.Op{Name: "write", Trap: unix.SYS_WRITE, Args: [6]uintptr{3, p.Bytes(nul), 1}},
		)
	}
	proc, err := p.Start()
	if err != nil {
		t.Fatal(err)
	}
	wr.Close()
	out, readErr := io.ReadAll(rd)
	if err := proc.Wait(); err != nil {
		return nil, err
	}
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(out) < 4 {
		t.Fatalf("unexpected output %q", out)
	}
	fields := bytes.Split(bytes.TrimSuffix(out[4:], []byte{0}), []byte{0})
	if len(fields) != 1+len(types) {
		t.Fatalf("unexpected output %q", out)
	}
	res := &setnsResult{
		links: map[configs.NamespaceType]string{},
		uid:   binary.NativeEndian.Uint32(out),
		cwd:   string(fields[0]),
	}
	for i, typ := range types {
		res.links[typ] = string(fields[1+i])
	}
	return res, nil
}

func checkSetns(t *testing.T, pid int, types []configs.NamespaceType, res *setnsResult) {
	t.Helper()
	for _, typ := range types {
		want, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/ns/" + configs.NsName(typ))
		if err != nil {
			t.Fatal(err)
		}
		if res.links[typ] != want {
			t.Errorf("want %s, got %s", want, res.links[typ])
		}
	}
	// As root, this checks that the child became root in the user
	// namespace (otherwise its uid would be the overflow one).
	if res.uid != 0 {
		t.Errorf("want uid 0, got %d", res.uid)
	}
}

func TestJoinNamespaces(t *testing.T) {
	pid := startUsernsUts(t, syscall.CLONE_NEWNS)
	// UTS first, so that the first attempt to join it fails with EPERM
	// (unless we are root), and the retry after joining userns succeeds.
	types := []configs.NamespaceType{configs.NEWUTS, configs.NEWNS, configs.NEWUSER}
	res, err := runSetns(t, pid, types, false)
	if err != nil {
		t.Fatal(err)
	}
	checkSetns(t, pid, types, res)
	// Joining the mount namespace changes cwd to its root.
	if res.cwd != "/" {
		t.Errorf("want cwd /, got %q", res.cwd)
	}
}

func TestJoinNamespacesPidfd(t *testing.T) {
	pid := startUsernsUts(t, syscall.CLONE_NEWNS)
	types := []configs.NamespaceType{configs.NEWUTS, configs.NEWNS, configs.NEWUSER}
	res, err := runSetns(t, pid, types, true)
	if err != nil {
		t.Fatal(err)
	}
	checkSetns(t, pid, types, res)
	// Same as above (even though the target process cwd is not /).
	if res.cwd != "/" {
		t.Errorf("want cwd /, got %q", res.cwd)
	}
}

func TestJoinNamespacesEPERM(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires non-root")
	}
	pid := startUsernsUts(t, 0)
	// Without joining the user namespace, both attempts fail.
	_, err := runSetns(t, pid, []configs.NamespaceType{configs.NEWUTS}, false)
	want := "setns into uts namespace (/proc/" + strconv.Itoa(pid) + "/ns/uts)"
	var serr *os.SyscallError
	if !errors.As(err, &serr) || serr.Syscall != want || !errors.Is(err, unix.EPERM) {
		t.Fatalf("want %s EPERM error, got %v", want, err)
	}
}
