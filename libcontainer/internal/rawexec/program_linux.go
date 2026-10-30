package rawexec

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/libcontainer/capabilities"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/internal/rawfork"
	"github.com/opencontainers/runc/libcontainer/seccomp"
)

// Params are the parameters of [New], prepared by the parent. All
// descriptors are the parent's ones.
type Params struct {
	// Args is the process arguments, and Env is its environment (which
	// must have no duplicate variables). PATH from Env is used to find
	// the binary.
	Args, Env []string
	// Cwd is the working directory (or "" to not change it).
	Cwd string
	// UID, GID, and AdditionalGroups are the process user and groups.
	UID, GID         int
	AdditionalGroups []int
	// HostUID is UID as seen in the parent's user namespace, or -1 if
	// unknown (see fixStdio).
	HostUID int
	// SetGroups tells whether to set supplementary groups (see setUser).
	SetGroups bool

	Capabilities    *configs.Capabilities
	NoNewPrivileges bool
	// SessionKeyring is the name of the session keyring to join, or ""
	// to not join any.
	SessionKeyring  string
	ProcessLabel    string
	AppArmorProfile string
	Umask           *uint32
	Personality     *configs.LinuxPersonality
	MemoryPolicy    *configs.LinuxMemoryPolicy
	CPUAffinity     *configs.CPUAffinity
	Rlimits         []configs.Rlimit
	OomScoreAdj     *int
	// Scheduler is only checked by New, as it is set by the parent.
	Scheduler *configs.Scheduler
	// Console tells that the stdio is a pty peer (see AllocPty), to be
	// set as the controlling terminal.
	Console bool

	// Fds become the child's stdio and passed files.
	Fds []int
	// Namespaces to join. Their Fd fields are the parent's descriptors.
	// If the PID or time namespace is among these (or NamespaceTypes),
	// the child forks after joining it (see forkChild), using ForkPipe.
	Namespaces []Namespace
	// PidFd, if not -1, is a pidfd of the process which namespaces of
	// NamespaceTypes are to be joined instead (see joinNamespacesPidfd).
	PidFd          int
	NamespaceTypes []configs.NamespaceType
	// ForkPipe is the write end of a pipe for the grandchild's pid (see
	// fork and WaitFork), or -1.
	ForkPipe int
	// ProcRootFd is procfs root (see ProcRoot), needed if LSM labels are
	// set, or -1.
	ProcRootFd int
	// Seccomp is the compiled seccomp filter, or nil.
	Seccomp *seccomp.Filter
	// SeccompSync is the child's end of a socket pair used for getting
	// the seccomp listener (see SeccompListener), or -1.
	SeccompSync int
}

// NeedsFork tells whether the child joins a namespace which only applies
// to its children (PID or time), so it has to fork (see forkChild).
func (params *Params) NeedsFork() bool {
	forChildren := func(typ configs.NamespaceType) bool {
		return typ == configs.NEWPID || typ == configs.NEWTIME
	}
	return slices.ContainsFunc(params.NamespaceTypes, forChildren) ||
		slices.ContainsFunc(params.Namespaces, func(ns Namespace) bool { return forChildren(ns.Type) })
}

// envPath returns the value of PATH from env (the last one, if there are
// duplicates).
func envPath(env []string) string {
	for _, kv := range slices.Backward(env) {
		if v, ok := strings.CutPrefix(kv, "PATH="); ok {
			return v
		}
	}
	return ""
}

// Check returns [ErrUnsupported] if the process can't be run by raw exec.
// It only uses Args, Env (which may have duplicates), Scheduler, and
// OomScoreAdj, so it can be called before preparing the rest of params,
// to avoid doing it in vain. It is also called by [New].
func Check(params *Params) error {
	if err := schedSupported(params.Scheduler); err != nil {
		return err
	}
	// Unlike nsexec, the child sets oom_score_adj after becoming
	// non-dumpable, which makes /proc/self/oom_score_adj owned by
	// root, so it can't be opened unless the child is root.
	if params.OomScoreAdj != nil && os.Geteuid() != 0 {
		return fmt.Errorf("oom_score_adj for non-root: %w", ErrUnsupported)
	}
	if len(params.Args) > 0 {
		return lookupSupported(params.Args[0], envPath(params.Env))
	}
	return nil
}

// New returns a rawfork program to run a process in the container, which
// does the same as nsexec and runc init (linuxSetnsInit.Init) do, in the
// same order, except for the things done by the parent (such as setting
// the scheduler, see schedSupported). It returns [ErrUnsupported] if the
// configuration is not supported.
func New(params *Params) (*rawfork.Program, error) {
	if len(params.Args) == 0 {
		return nil, errors.New("no args")
	}
	if len(params.Fds) < 3 {
		return nil, errors.New("no stdio")
	}
	if err := Check(params); err != nil {
		return nil, err
	}
	needProc := params.ProcessLabel != "" || params.AppArmorProfile != ""
	if needProc && params.ProcRootFd == -1 {
		return nil, errors.New("procfs root is required")
	}
	fork := params.NeedsFork()
	if fork && params.ForkPipe == -1 {
		return nil, errors.New("fork pipe is required")
	}
	listener := params.Seccomp != nil && params.Seccomp.Listener
	if listener && params.SeccompSync == -1 {
		return nil, errors.New("seccomp sync socket is required")
	}

	// The child's descriptors are: the stdio and passed files, then the
	// ones used internally (followed by the error reporting one).
	fds := slices.Clone(params.Fds)
	internal := func(fd int) int {
		fds = append(fds, fd)
		return len(fds) - 1
	}
	nss := make([]Namespace, len(params.Namespaces))
	for i, ns := range params.Namespaces {
		nss[i] = ns
		nss[i].Fd = internal(ns.Fd)
	}
	pidFd, forkFd, procFd, syncFd := -1, -1, -1, -1
	if params.PidFd != -1 {
		pidFd = internal(params.PidFd)
	}
	if fork {
		forkFd = internal(params.ForkPipe)
	}
	if needProc {
		procFd = internal(params.ProcRootFd)
	}
	if listener {
		syncFd = internal(params.SeccompSync)
	}
	p, err := newProgram(fds, len(params.Fds))
	if err != nil {
		return nil, err
	}

	// These are set before joining the user namespace, as the child can't
	// lower oom_score_adj or raise rlimits after (see setnsProcess.start
	// in libcontainer).
	if params.OomScoreAdj != nil {
		if err := setOomScoreAdj(p, *params.OomScoreAdj); err != nil {
			return nil, err
		}
	}
	setRlimits(p, params.Rlimits)
	if pidFd != -1 {
		joinNamespacesPidfd(p, pidFd, params.NamespaceTypes)
	} else if err := joinNamespaces(p, nss); err != nil {
		return nil, err
	}
	if fork {
		forkChild(p, forkFd)
	}
	// Same as nsexec does (in stage-2).
	p.Ops = append(p.Ops, rawfork.Op{Name: "setsid", Trap: unix.SYS_SETSID})

	// The rest is in the order of linuxSetnsInit.Init.
	if params.SessionKeyring != "" {
		if params.ProcessLabel != "" {
			if err := selinuxKeyLabel(p, procFd, params.ProcessLabel); err != nil {
				return nil, err
			}
		}
		if err := joinSessionKeyring(p, params.SessionKeyring); err != nil {
			return nil, err
		}
	}
	if params.Console {
		p.Ops = append(p.Ops, rawfork.Op{
			Name: "set controlling terminal",
			Trap: unix.SYS_IOCTL,
			Args: [6]uintptr{0, unix.TIOCSCTTY, 0},
		})
	}
	if params.NoNewPrivileges {
		noNewPrivs(p)
	}
	if params.Umask != nil {
		setUmask(p, *params.Umask)
	}
	// The scheduler and I/O priority are set by the parent.
	if params.Personality != nil {
		setPersonality(p, params.Personality.Domain)
	}
	setMemoryPolicy(p, params.MemoryPolicy)
	// This is done by the parent after the child is moved into the
	// container's cgroup, which now happens upon clone.
	setCPUAffinity(p, params.CPUAffinity)

	if params.ProcessLabel != "" {
		if err := selinuxExecLabel(p, procFd, params.ProcessLabel); err != nil {
			return nil, err
		}
	}
	if params.Seccomp != nil && !params.NoNewPrivileges {
		loadSeccomp(p, params.Seccomp, syncFd)
	}
	if err := finalizeNamespace(p, params); err != nil {
		return nil, err
	}
	if params.AppArmorProfile != "" {
		if err := apparmorProfile(p, procFd, params.AppArmorProfile); err != nil {
			return nil, err
		}
	}
	if needProc {
		closeFd(p, procFd, "procfs")
	}
	if params.Seccomp != nil && params.NoNewPrivileges {
		loadSeccomp(p, params.Seccomp, syncFd)
	}
	if err := execBinary(p, params.Args[0], params.Args, params.Env, envPath(params.Env)); err != nil {
		return nil, err
	}
	return p, nil
}

// finalizeNamespace is like finalizeNamespace in libcontainer, except for
// the things done elsewhere (closing descriptors and preparing the
// environment).
func finalizeNamespace(p *rawfork.Program, params *Params) error {
	var retryChdir func()
	if params.Cwd != "" {
		var err error
		if retryChdir, err = chdir(p, params.Cwd); err != nil {
			return err
		}
	}
	caps, err := capabilities.New(params.Capabilities)
	if err != nil {
		return err
	}
	masks, setCaps := caps.Masks()
	last, err := capabilities.LastCap()
	if err != nil {
		return err
	}
	if setCaps {
		capsBoundingSet(p, masks, last)
	}
	setKeepCaps(p, true)
	// Like setupUser.
	if err := fixStdio(p, params.UID, params.HostUID, [3]int(params.Fds[:3])); err != nil {
		return err
	}
	setUser(p, params.UID, params.GID, params.AdditionalGroups, params.SetGroups)
	if retryChdir != nil {
		retryChdir()
	}
	setKeepCaps(p, false)
	if setCaps {
		applyCaps(p, masks, last)
	}
	return nil
}
