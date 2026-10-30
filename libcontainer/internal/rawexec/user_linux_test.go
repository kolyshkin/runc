package rawexec

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/libcontainer/internal/rawfork"
)

// userResult is what the child started by runUser reports.
type userResult struct {
	// KeepCaps is PR_GET_KEEPCAPS value after setUser, and after
	// clearing it.
	KeepCaps [2]uint32
	// Status is the child's /proc/self/status, with whitespace in
	// values normalized.
	Status map[string]string
}

// runUser runs a program which creates a new user namespace with the
// given ID mappings, and uses setKeepCaps and setUser to change the user
// in it. It returns what the child reports, or the error from [rawfork.Process.Wait].
func runUser(t *testing.T, uidMap, gidMap string, uid, gid int, groups []int, setGroups bool) (*userResult, error) {
	t.Helper()
	rd, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	defer wr.Close()
	// After unshare, the child tells the parent to write the ID mappings
	// (by writing a byte to wr), and waits on syncRd until it's done.
	syncRd, syncWr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer syncRd.Close()
	defer syncWr.Close()

	var p rawfork.Program
	b := make([]byte, 1)
	p.Ops = append(p.Ops,
		rawfork.Op{Name: "unshare", Trap: unix.SYS_UNSHARE, Args: [6]uintptr{unix.CLONE_NEWUSER}},
		rawfork.Op{Name: "request maps", Trap: unix.SYS_WRITE, Args: [6]uintptr{wr.Fd(), p.Bytes(b), 1}},
		rawfork.Op{Name: "wait for maps", Trap: unix.SYS_READ, Args: [6]uintptr{syncRd.Fd(), p.Bytes(b), 1}},
	)

	keep := new([2]uint32)
	setKeepCaps(&p, true)
	setUser(&p, uid, gid, groups, setGroups)
	p.Ops = append(p.Ops, rawfork.Op{Name: "get keep caps", Trap: unix.SYS_PRCTL, Args: [6]uintptr{unix.PR_GET_KEEPCAPS}, Store: &keep[0]})
	setKeepCaps(&p, false)
	p.Ops = append(p.Ops, rawfork.Op{Name: "get keep caps", Trap: unix.SYS_PRCTL, Args: [6]uintptr{unix.PR_GET_KEEPCAPS}, Store: &keep[1]})

	// Report the results. The child reads its own /proc/self/status
	// so the IDs are shown as seen in its user namespace.
	path, err := p.String("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	cwd := unix.AT_FDCWD
	buf := make([]byte, 8192)
	p.Ops = append(p.Ops,
		rawfork.Op{Name: "open status", Trap: unix.SYS_OPENAT, Args: [6]uintptr{uintptr(cwd), path, unix.O_RDONLY | unix.O_CLOEXEC}, Ret: rawfork.R1},
		rawfork.Op{Name: "read status", Trap: unix.SYS_READ, Args: [6]uintptr{0, p.Bytes(buf), uintptr(len(buf))}, ArgRegs: [6]rawfork.Reg{rawfork.R1}, Ret: rawfork.R2},
		rawfork.Op{Name: "write keep caps", Trap: unix.SYS_WRITE, Args: [6]uintptr{wr.Fd(), p.Pin(unsafe.Pointer(keep)), unsafe.Sizeof(*keep)}},
		rawfork.Op{Name: "write status", Trap: unix.SYS_WRITE, Args: [6]uintptr{wr.Fd(), p.Bytes(buf)}, ArgRegs: [6]rawfork.Reg{2: rawfork.R2}},
	)

	proc, err := p.Start()
	if err != nil {
		t.Fatal(err)
	}
	wr.Close()
	var mapErr, syncErr error
	// No byte means the child has failed (most probably, unshare).
	if _, err := io.ReadFull(rd, b); err == nil {
		mapErr = writeIDMaps(proc.Pid, uidMap, gidMap)
		// Let the child continue even if writing maps failed.
		_, syncErr = syncWr.Write(b)
	}
	out, readErr := io.ReadAll(rd)
	err = proc.Wait()
	if serr := (*os.SyscallError)(nil); errors.As(err, &serr) && serr.Syscall == "unshare" &&
		(errors.Is(err, unix.EPERM) || errors.Is(err, unix.ENOSPC)) {
		t.Skipf("can't create user namespace: %v", err)
	}
	if mapErr != nil {
		t.Fatal(mapErr)
	}
	if syncErr != nil {
		t.Fatal(syncErr)
	}
	if err != nil {
		return nil, err
	}
	if readErr != nil {
		t.Fatal(readErr)
	}

	res := &userResult{Status: map[string]string{}}
	if len(out) < len(res.KeepCaps)*4 {
		t.Fatalf("unexpected output length %d", len(out))
	}
	for i := range res.KeepCaps {
		res.KeepCaps[i] = binary.NativeEndian.Uint32(out[i*4:])
	}
	sc := bufio.NewScanner(bytes.NewReader(out[len(res.KeepCaps)*4:]))
	for sc.Scan() {
		k, v, _ := strings.Cut(sc.Text(), ":")
		res.Status[k] = strings.Join(strings.Fields(v), " ")
	}
	return res, nil
}

func writeIDMaps(pid int, uidMap, gidMap string) error {
	dir := "/proc/" + strconv.Itoa(pid) + "/"
	// An unprivileged process can't write gid_map unless setgroups
	// is denied.
	if os.Geteuid() != 0 {
		if err := os.WriteFile(dir+"setgroups", []byte("deny"), 0); err != nil {
			return err
		}
	}
	if err := os.WriteFile(dir+"uid_map", []byte(uidMap), 0); err != nil {
		return err
	}
	return os.WriteFile(dir+"gid_map", []byte(gidMap), 0)
}

func TestSetUser(t *testing.T) {
	uidMap := "0 " + strconv.Itoa(os.Geteuid()) + " 1"
	gidMap := "0 " + strconv.Itoa(os.Getegid()) + " 1"
	res, err := runUser(t, uidMap, gidMap, 0, 0, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Status["Uid"]; got != "0 0 0 0" {
		t.Errorf("want uids 0, got %q", got)
	}
	if got := res.Status["Gid"]; got != "0 0 0 0" {
		t.Errorf("want gids 0, got %q", got)
	}
	if res.KeepCaps != [2]uint32{1, 0} {
		t.Errorf("want keep caps [1 0], got %v", res.KeepCaps)
	}
}

func TestSetUserUnmapped(t *testing.T) {
	uidMap := "0 " + strconv.Itoa(os.Geteuid()) + " 1"
	gidMap := "0 " + strconv.Itoa(os.Getegid()) + " 1"
	for _, tc := range []struct {
		uid, gid int
		op       string
	}{
		{uid: 1, gid: 0, op: "setuid 1"},
		{uid: 0, gid: 2, op: "setgid 2"},
	} {
		t.Run(tc.op, func(t *testing.T) {
			_, err := runUser(t, uidMap, gidMap, tc.uid, tc.gid, nil, false)
			var serr *os.SyscallError
			if !errors.As(err, &serr) || serr.Syscall != tc.op || !errors.Is(err, unix.EINVAL) {
				t.Fatalf("want %s EINVAL error, got %v", tc.op, err)
			}
		})
	}
}

func TestSetUserGroups(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	// Use IDs which do not fit in 16 bits, to check that 32-bit
	// system calls are used (see rawexec_user_linux_32.go).
	const idMap = "0 100000 100000"
	for _, tc := range []struct {
		name   string
		groups []int
		want   string
	}{
		{name: "groups", groups: []int{10, 70002}, want: "10 70002"},
		{name: "no groups", groups: nil, want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := runUser(t, idMap, idMap, 70000, 70001, tc.groups, true)
			if err != nil {
				t.Fatal(err)
			}
			if got := res.Status["Uid"]; got != "70000 70000 70000 70000" {
				t.Errorf("want uids 70000, got %q", got)
			}
			if got := res.Status["Gid"]; got != "70001 70001 70001 70001" {
				t.Errorf("want gids 70001, got %q", got)
			}
			if got := res.Status["Groups"]; got != tc.want {
				t.Errorf("want groups %q, got %q", tc.want, got)
			}
			if res.KeepCaps != [2]uint32{1, 0} {
				t.Errorf("want keep caps [1 0], got %v", res.KeepCaps)
			}
		})
	}
}

func TestFixStdio(t *testing.T) {
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	// Both files are owned by the current euid.
	dir := t.TempDir()
	var files [2]*os.File
	for i := range files {
		files[i], err = os.CreateTemp(dir, "")
		if err != nil {
			t.Fatal(err)
		}
		defer files[i].Close()
	}
	fds := [3]int{int(null.Fd()), int(files[0].Fd()), int(files[1].Fd())}
	euid := os.Geteuid()

	// Nothing to do if the uid is the same.
	var p rawfork.Program
	if err := fixStdio(&p, euid, euid, fds); err != nil {
		t.Fatal(err)
	}
	if len(p.Ops) != 0 {
		t.Fatalf("want no ops, got %+v", p.Ops)
	}

	// For a different uid, /dev/null is skipped. Unless we are root,
	// fchown fails with EPERM, which is ignored.
	uid := euid + 1000
	np, err := newProgram(fds[:], 3)
	if err != nil {
		t.Fatal(err)
	}
	n := len(np.Ops)
	if err := fixStdio(np, uid, uid, fds); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, op := range np.Ops[n:] {
		names = append(names, op.Name)
	}
	if want := "fchown stdio fd 1,fchown stdio fd 2"; strings.Join(names, ",") != want {
		t.Fatalf("want ops %q, got %q", want, names)
	}
	proc, err := np.Start()
	if err != nil {
		t.Fatal(err)
	}
	if err := proc.Wait(); err != nil {
		t.Fatal(err)
	}
	want := euid
	if euid == 0 {
		want = uid
	}
	for _, f := range files {
		var s unix.Stat_t
		if err := unix.Fstat(int(f.Fd()), &s); err != nil {
			t.Fatal(err)
		}
		if int(s.Uid) != want {
			t.Errorf("%s: want uid %d, got %d", f.Name(), want, s.Uid)
		}
	}
}
