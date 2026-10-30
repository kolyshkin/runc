package rawexec

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/containerd/console"
	"github.com/opencontainers/selinux/go-selinux"
	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/internal/linux"
	"github.com/opencontainers/runc/libcontainer/capabilities"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/seccomp"
)

// startContainerLike starts a process in new user, UTS, mount, PID, and time
// namespaces (with the given ID mapping), returning its pid.
func startContainerLike(t *testing.T, idMap configs.IDMap) int {
	t.Helper()
	m := []syscall.SysProcIDMap{{ContainerID: int(idMap.ContainerID), HostID: int(idMap.HostID), Size: int(idMap.Size)}}
	cmd := exec.Command("sleep", "infinity")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWUTS | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID,
		UidMappings: m,
		GidMappings: m,
		// The time namespace can't be created by clone(2), but
		// unshare(2) followed by execve(2) works (Linux 5.11+).
		Unshareflags: unix.CLONE_NEWTIME,
		// Only root can allow setgroups.
		GidMappingsEnableSetgroups: os.Geteuid() == 0,
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

// TestNew runs a process in a container-like set of namespaces
// using a program from New, and checks the process properties.
func TestNew(t *testing.T) {
	for _, pidfd := range []bool{false, true} {
		t.Run("pidfd="+strconv.FormatBool(pidfd), func(t *testing.T) {
			testNew(t, pidfd)
		})
	}
}

func testNew(t *testing.T, pidfd bool) {
	// As root, use a non-root user with supplementary groups.
	root := os.Geteuid() == 0
	idMap := configs.IDMap{ContainerID: 0, HostID: int64(os.Geteuid()), Size: 1}
	uid, groups := 0, []int(nil)
	if root {
		idMap = configs.IDMap{ContainerID: 0, HostID: 100000, Size: 65536}
		uid, groups = 1000, []int{10}
	}
	pid := startContainerLike(t, idMap)

	// The working directory must be accessible by the user.
	cwd := t.TempDir()
	for _, d := range []string{filepath.Dir(cwd), cwd} {
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	rd, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	defer wr.Close()

	umask := uint32(0o027)
	oomScoreAdj := 500
	script := `echo "uid=$(id -u) groups=$(id -G) cwd=$(pwd) foo=$FOO home=$HOME umask=$(umask) nofile=$(ulimit -n)"
echo "fds=$(ls /proc/self/fd | tr '\n' ' ')"
echo "ns=$(readlink /proc/self/ns/user /proc/self/ns/uts /proc/self/ns/mnt /proc/self/ns/pid /proc/self/ns/time | tr '\n' ' ')"
grep -E '^(NoNewPrivs|CapEff|CapBnd|Seccomp):' /proc/self/status
echo "oom=$(cat /proc/self/oom_score_adj)"
echo "label=$(tr -d '\0' < /proc/self/attr/current)"
read -r stat < /proc/self/stat; set -- $stat; echo "statpid=$1 sid=$6"`
	// The PID and time namespaces are joined by the child, which forks.
	forkRd, forkWr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer forkRd.Close()
	defer forkWr.Close()
	params := &Params{
		Args:             []string{"sh", "-c", script},
		Env:              []string{"PATH=/usr/bin:/bin", "FOO=bar", "HOME=/home/test"},
		Cwd:              cwd,
		UID:              uid,
		GID:              uid,
		AdditionalGroups: groups,
		HostUID:          int(idMap.HostID) + uid,
		SetGroups:        root,
		Capabilities: &configs.Capabilities{
			Bounding:    []string{"CAP_KILL", "CAP_CHOWN"},
			Effective:   []string{"CAP_KILL"},
			Permitted:   []string{"CAP_KILL"},
			Inheritable: []string{"CAP_KILL"},
			Ambient:     []string{"CAP_KILL"},
		},
		NoNewPrivileges: true,
		SessionKeyring:  "_ses.rawtest",
		Umask:           &umask,
		Rlimits:         []configs.Rlimit{{Type: unix.RLIMIT_NOFILE, Soft: 100, Hard: 200}},
		Fds:             []int{int(null.Fd()), int(wr.Fd()), int(wr.Fd())},
		PidFd:           -1,
		ForkPipe:        int(forkWr.Fd()),
		ProcRootFd:      -1,
		SeccompSync:     -1,
	}
	// See New.
	if root {
		params.OomScoreAdj = &oomScoreAdj
	}
	if selinux.GetEnabled() {
		label, err := selinux.CurrentLabel()
		if err != nil {
			t.Fatal(err)
		}
		params.ProcessLabel = label
		proc, err := ProcRoot()
		if err != nil {
			t.Fatal(err)
		}
		defer proc.Close()
		params.ProcRootFd = int(proc.Fd())
	}
	// With seccomp, use a filter for a syscall which is not used. As root,
	// use a listener to check the whole flow (pidfd_getfd requires
	// CAP_SYS_PTRACE for a non-dumpable child).
	var parentSock *os.File
	if seccomp.Enabled {
		action := configs.Errno
		if root {
			action = configs.Notify
		}
		params.Seccomp, err = seccomp.Compile(&configs.Seccomp{
			DefaultAction: configs.Allow,
			Syscalls:      []*configs.Syscall{{Name: "acct", Action: action}},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if params.Seccomp != nil && params.Seccomp.Listener {
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		parentSock = os.NewFile(uintptr(fds[0]), "parent")
		defer parentSock.Close()
		childSock := os.NewFile(uintptr(fds[1]), "child")
		defer childSock.Close()
		params.SeccompSync = int(childSock.Fd())
	}
	if pidfd {
		fd, err := unix.PidfdOpen(pid, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		params.PidFd = fd
	}
	wantNs := make([]string, 0, 5)
	for _, typ := range []configs.NamespaceType{configs.NEWUSER, configs.NEWUTS, configs.NEWNS, configs.NEWPID, configs.NEWTIME} {
		path := "/proc/" + strconv.Itoa(pid) + "/ns/" + configs.NsName(typ)
		if pidfd {
			params.NamespaceTypes = append(params.NamespaceTypes, typ)
		} else {
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			params.Namespaces = append(params.Namespaces, Namespace{Type: typ, Fd: int(f.Fd()), Path: path})
		}
		link, err := os.Readlink(path)
		if err != nil {
			t.Fatal(err)
		}
		wantNs = append(wantNs, link)
	}

	p, err := New(params)
	if err != nil {
		t.Fatal(err)
	}
	proc, err := p.Start()
	if err != nil {
		t.Fatal(err)
	}
	wr.Close()
	forkWr.Close()
	if err := WaitFork(proc, forkRd); err != nil {
		_ = proc.Wait()
		t.Fatal(err)
	}
	if parentSock != nil {
		_ = os.NewFile(uintptr(params.SeccompSync), "child").Close()
		listener, err := SeccompListener(proc.Pid, parentSock)
		if err != nil {
			t.Fatal(err)
		}
		listener.Close()
	}
	execErr := proc.WaitExec()
	out, readErr := io.ReadAll(rd)
	if err := proc.Wait(); err != nil {
		t.Fatalf("exec error: %v, wait error: %v, output: %s", execErr, err, out)
	}
	if readErr != nil {
		t.Fatal(readErr)
	}

	got := map[string]string{}
	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok && !strings.Contains(k, "=") {
			got[k] = strings.TrimSpace(v)
			continue
		}
		for _, kv := range strings.SplitAfter(line, " ") {
			if k, v, ok := strings.Cut(strings.TrimSpace(kv), "="); ok {
				got[k] = v
			}
		}
	}
	t.Logf("output: %s", out)

	wantGroups := strconv.Itoa(uid)
	for _, g := range groups {
		wantGroups += " " + strconv.Itoa(g)
	}
	for k, want := range map[string]string{
		"uid":        strconv.Itoa(uid),
		"cwd":        cwd,
		"foo":        "bar",
		"home":       "/home/test",
		"umask":      "0027",
		"nofile":     "100",
		"NoNewPrivs": "1",
		"Seccomp":    map[bool]string{false: "0", true: "2"}[seccomp.Enabled],
	} {
		if got[k] != want {
			t.Errorf("want %s=%s, got %q", k, want, got[k])
		}
	}
	// Unless we are root, setgroups is denied, and the supplementary
	// groups are inherited.
	if root && !strings.Contains(string(out), " groups="+wantGroups+" cwd=") {
		t.Errorf("want groups %q", wantGroups)
	}
	// The process only has stdio, plus the directory opened by ls.
	if !strings.Contains(string(out), "fds=0 1 2 3 \n") {
		t.Errorf("want fds 0 1 2 3")
	}
	if !strings.Contains(string(out), "ns="+strings.Join(wantNs, " ")+" \n") {
		t.Errorf("want ns %v", wantNs)
	}
	caps, err := capabilities.New(params.Capabilities)
	if err != nil {
		t.Fatal(err)
	}
	masks, _ := caps.Masks()
	bnd, err := strconv.ParseUint(got["CapBnd"], 16, 64)
	if err != nil || bnd != masks.Bounding {
		t.Errorf("want CapBnd %x, got %q", masks.Bounding, got["CapBnd"])
	}
	// Whatever the effective set is after execve, it must have the ambient
	// capabilities, and be within the bounding set.
	eff, err := strconv.ParseUint(got["CapEff"], 16, 64)
	if err != nil || eff&masks.Ambient != masks.Ambient || eff&^masks.Bounding != 0 {
		t.Errorf("want CapEff with %x within %x, got %q", masks.Ambient, masks.Bounding, got["CapEff"])
	}
	// The process is a session leader.
	if got["sid"] == "" || got["sid"] != got["statpid"] {
		t.Errorf("want sid equal to pid %q, got %q", got["statpid"], got["sid"])
	}
	if root && got["oom"] != "500" {
		t.Errorf("want oom=500, got %q", got["oom"])
	}
	if params.ProcessLabel != "" && !strings.Contains(string(out), "label="+params.ProcessLabel) {
		t.Errorf("want label %q", params.ProcessLabel)
	}
}

func TestNewUnsupported(t *testing.T) {
	for _, params := range []*Params{
		{Args: []string{"true"}, Env: []string{"PATH=bin"}},
		{Args: []string{"true"}, Env: []string{"PATH=/bin", "PATH=bin"}},
		{Args: []string{"true"}, Scheduler: &configs.Scheduler{Policy: "SCHED_DEADLINE"}},
	} {
		params.Fds = []int{0, 1, 2}
		params.PidFd, params.ForkPipe, params.ProcRootFd, params.SeccompSync = -1, -1, -1, -1
		if err := Check(params); !errors.Is(err, ErrUnsupported) {
			t.Errorf("%+v: Check: want unsupported error, got %v", params, err)
		}
		_, err := New(params)
		if !errors.Is(err, ErrUnsupported) {
			t.Errorf("%+v: want unsupported error, got %v", params, err)
		}
	}
}

// TestNewConsole checks that the process started by a program from
// New has the pty as its stdio and controlling terminal.
func TestNewConsole(t *testing.T) {
	pty, peerPath, err := console.NewPty()
	if err != nil {
		t.Skipf("can't allocate pty: %v", err)
	}
	defer pty.Close()
	peer, err := linux.GetPtyPeer(pty.Fd(), peerPath, unix.O_RDWR)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	var st unix.Stat_t
	if err := unix.Fstat(int(peer.Fd()), &st); err != nil {
		t.Fatal(err)
	}

	pfd := int(peer.Fd())
	p, err := New(&Params{
		// Not a shell, as it may set the controlling terminal itself
		// (bash opens the terminal without O_NOCTTY).
		Args:        []string{"cat", "/proc/self/stat"},
		Env:         []string{"PATH=/usr/bin:/bin"},
		UID:         os.Geteuid(),
		GID:         os.Getegid(),
		HostUID:     os.Geteuid(),
		Console:     true,
		Fds:         []int{pfd, pfd, pfd},
		PidFd:       -1,
		ForkPipe:    -1,
		ProcRootFd:  -1,
		SeccompSync: -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	proc, err := p.Start()
	if err != nil {
		t.Fatal(err)
	}
	peer.Close()
	execErr := proc.WaitExec()
	// Once the child exits, reading the pty fails with EIO.
	out, _ := io.ReadAll(pty)
	if err := proc.Wait(); err != nil {
		t.Fatalf("exec error: %v, wait error: %v, output: %s", execErr, err, out)
	}
	t.Logf("output: %s", out)
	// The output comes from the pty, and the pty is the controlling
	// terminal (tty_nr uses the same encoding as st_rdev).
	fields := strings.Fields(string(out))
	want := strconv.FormatUint(uint64(st.Rdev), 10) //nolint:unconvert // Rdev is uint32 on MIPS.
	if len(fields) < 7 || fields[6] != want {
		t.Errorf("want tty_nr %s", want)
	}
}
