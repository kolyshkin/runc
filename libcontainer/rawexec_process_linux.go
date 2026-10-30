package libcontainer

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"

	"github.com/containerd/console"
	"github.com/opencontainers/cgroups"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/internal/cmsg"
	"github.com/opencontainers/runc/internal/pathrs"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/internal/rawexec"
	"github.com/opencontainers/runc/libcontainer/internal/rawfork"
	"github.com/opencontainers/runc/libcontainer/seccomp"
	"github.com/opencontainers/runc/libcontainer/system"
)

// setnsRawProcess is a [setnsProcess] which is started using rawfork (see
// [rawexec.New]) rather than runc init.
type setnsRawProcess struct {
	setnsProcess
	program *rawfork.Program
	// pidns is the PID namespace (or a pidfd of a process in it) to be
	// joined by the parent, or nil. It is closed along with the files.
	pidns *os.File
	// forkPipe is the read end of the pipe for the grandchild's pid
	// (see [rawexec.WaitFork]), or nil.
	forkPipe *os.File
	// seccompSock is the parent's end of the seccomp sync socket, or nil.
	seccompSock *os.File
	// pty is the pty master to be sent to the console socket, or nil.
	pty console.Console
	// files are the files to be closed once the child is started.
	files []*os.File
}

// rawStdio returns the file descriptor of a stdio stream, which must be either
// nil (meaning /dev/null) or *os.File (see checkRawExec).
func (p *setnsRawProcess) rawStdio(s any) (int, error) {
	if s == nil {
		f, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
		if err != nil {
			return -1, err
		}
		p.files = append(p.files, f)
		return int(f.Fd()), nil
	}
	return int(s.(*os.File).Fd()), nil
}

// checkRawExec returns [rawexec.ErrUnsupported] if p can't be run using raw
// exec. It is called before preparing anything, to avoid doing it in vain.
func (c *Container) checkRawExec(p *Process) error {
	switch {
	case !rawexec.KernelSupported():
		return fmt.Errorf("kernel: %w", rawexec.ErrUnsupported)
	case p.PidfdSocket != nil:
		return fmt.Errorf("pidfd socket: %w", rawexec.ErrUnsupported)
	case c.intelRdtManager != nil && c.intelRdtManager.GetPath() != "":
		return fmt.Errorf("intel rdt: %w", rawexec.ErrUnsupported)
	case !cgroups.IsCgroup2UnifiedMode() && c.cgroupManager.Path("") != "":
		// The cgroup is joined upon clone. Without cgroup v2, this
		// would require joining it after the child is started.
		return fmt.Errorf("cgroup v1: %w", rawexec.ErrUnsupported)
	}
	if p.ConsoleSocket == nil {
		for _, s := range []any{p.Stdin, p.Stdout, p.Stderr} {
			if f, ok := s.(*os.File); s != nil && (!ok || f == nil) {
				return fmt.Errorf("stdio of type %T: %w", s, rawexec.ErrUnsupported)
			}
		}
	}
	scheduler := c.config.Scheduler
	if p.Scheduler != nil {
		scheduler = p.Scheduler
	}
	return rawexec.Check(&rawexec.Params{
		Args:        p.Args,
		Env:         p.Env,
		Scheduler:   scheduler,
		OomScoreAdj: c.config.OomScoreAdj,
	})
}

// newSetnsRawProcess is like [Container.newSetnsProcess], but returns a
// process to be started using rawfork. If the configuration is not supported,
// it returns [rawexec.ErrUnsupported].
func (c *Container) newSetnsRawProcess(p *Process) (_ *setnsRawProcess, retErr error) {
	if err := c.checkRawExec(p); err != nil {
		return nil, err
	}
	state := c.currentState()

	proc := &setnsRawProcess{
		setnsProcess: setnsProcess{
			containerProcess: containerProcess{
				cmd:       &exec.Cmd{},
				manager:   c.cgroupManager,
				config:    c.newInitConfig(p),
				process:   p,
				container: c,
			},
			rootlessCgroups: c.config.RootlessCgroups,
			intelRdtPath:    state.IntelRdtPath,
			initProcessPid:  state.InitProcessPid,
		},
	}
	defer func() {
		if retErr != nil {
			proc.closeFiles()
			proc.closeParentEnds()
		}
	}()
	config := proc.config
	params := &rawexec.Params{
		Args:             config.Args,
		Cwd:              config.Cwd,
		UID:              config.UID,
		GID:              config.GID,
		AdditionalGroups: config.AdditionalGroups,
		HostUID:          -1,
		SetGroups:        !c.config.RootlessEUID,
		Capabilities:     config.Capabilities,
		NoNewPrivileges:  config.NoNewPrivileges,
		ProcessLabel:     config.ProcessLabel,
		AppArmorProfile:  config.AppArmorProfile,
		Umask:            c.config.Umask,
		Personality:      c.config.Personality,
		MemoryPolicy:     c.config.MemoryPolicy,
		CPUAffinity:      config.CPUAffinity,
		Rlimits:          config.Rlimits,
		OomScoreAdj:      c.config.OomScoreAdj,
		Scheduler:        config.Scheduler,
		Console:          config.CreateConsole,
		PidFd:            -1,
		ForkPipe:         -1,
		ProcRootFd:       -1,
		SeccompSync:      -1,
	}
	if uid, err := c.config.HostUID(config.UID); err == nil {
		params.HostUID = uid
	}
	if !c.config.NoNewKeyring {
		params.SessionKeyring = "_ses." + config.ContainerID
	}

	if p.ConsoleSocket != nil {
		fd, err := proc.allocPty()
		if err != nil {
			return nil, err
		}
		params.Fds = []int{fd, fd, fd}
	} else {
		for _, s := range []any{p.Stdin, p.Stdout, p.Stderr} {
			fd, err := proc.rawStdio(s)
			if err != nil {
				return nil, err
			}
			params.Fds = append(params.Fds, fd)
		}
	}
	for _, f := range p.ExtraFiles {
		params.Fds = append(params.Fds, int(f.Fd()))
	}

	if err := proc.prepareNamespaces(params, state); err != nil {
		return nil, err
	}
	if params.NeedsFork() {
		rd, wr, err := os.Pipe()
		if err != nil {
			return nil, err
		}
		proc.forkPipe = rd
		proc.files = append(proc.files, wr)
		params.ForkPipe = int(wr.Fd())
	}

	// Same as setupUser, except that it is checked by the parent.
	if params.SetGroups {
		if f, err := pathrs.ProcPidOpen(state.InitProcessPid, "setgroups", unix.O_RDONLY); err == nil {
			setgroups, err := io.ReadAll(f)
			f.Close()
			if err != nil {
				return nil, err
			}
			params.SetGroups = string(bytes.TrimSpace(setgroups)) != "deny"
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}

	// Same as prepareEnv, except /etc/passwd is read by the parent.
	env, homeIsSet, err := dedupEnv(config.Env)
	if err != nil {
		return nil, err
	}
	if !homeIsSet {
		home, err := proc.userHome()
		if err != nil {
			// For backward compatibility, don't return an error, but merely log it.
			logrus.WithError(err).Debugf("HOME not set in process.env, and getting UID %d homedir failed", config.UID)
		}
		env = append(env, "HOME="+home)
	}
	params.Env = env

	if config.ProcessLabel != "" || config.AppArmorProfile != "" {
		f, err := rawexec.ProcRoot()
		if err != nil {
			return nil, err
		}
		proc.files = append(proc.files, f)
		params.ProcRootFd = int(f.Fd())
	}

	if c.config.Seccomp != nil {
		filter, err := seccomp.Compile(c.config.Seccomp)
		if err != nil {
			return nil, err
		}
		params.Seccomp = filter
		if filter.Listener {
			if c.config.Seccomp.ListenerPath == "" {
				return nil, errors.New("seccomp listenerPath is not set")
			}
			fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				return nil, os.NewSyscallError("socketpair", err)
			}
			proc.seccompSock = os.NewFile(uintptr(fds[0]), "seccomp sync")
			child := os.NewFile(uintptr(fds[1]), "seccomp sync child")
			proc.files = append(proc.files, child)
			params.SeccompSync = int(child.Fd())
		}
	}

	cgroupFd, err := proc.prepareCgroupFD()
	if err != nil {
		return nil, err
	}

	if cgroupFd != nil {
		// Keep it open until the child is started.
		proc.files = append(proc.files, cgroupFd)
	}

	program, err := rawexec.New(params)
	if err != nil {
		return nil, err
	}
	if cgroupFd != nil {
		program.UseCgroupFD = true
		program.CgroupFD = int(cgroupFd.Fd())
	}
	proc.program = program
	return proc, nil
}

// prepareNamespaces opens the namespaces to join (same as orderNamespacePaths
// does).
//
// The PID namespace is joined by the thread the child is forked from, unless
// the child has to fork anyway (to join the time namespace), or it is not
// root (as joining the PID namespace requires CAP_SYS_ADMIN, which it only
// gets in the container's user namespace). In such case, it is joined by the
// child, which then forks (see [rawexec.Params]). It can't be joined by the
// parent if the child forks, as then the child is in the container's PID
// namespace, and the grandchild's pid it gets is not valid in the parent's.
//
// If all the namespaces were created by the container, a pidfd of the
// container's init is used to join them all at once. Otherwise, the
// namespaces are joined one by one.
func (p *setnsRawProcess) prepareNamespaces(params *rawexec.Params, state *State) error {
	config := p.container.config
	usePidfd := true
	for _, ns := range config.Namespaces {
		if ns.Path != "" {
			usePidfd = false
			break
		}
	}
	if usePidfd {
		fd, err := unix.PidfdOpen(state.InitProcessPid, 0)
		if err != nil {
			return os.NewSyscallError("pidfd_open", err)
		}
		pidfd := os.NewFile(uintptr(fd), "pidfd")
		p.files = append(p.files, pidfd)
		// Make sure the pid was not reused.
		stat, err := system.Stat(state.InitProcessPid)
		if err != nil || stat.StartTime != state.InitProcessStartTime {
			return fmt.Errorf("container init process (pid %d) is gone", state.InitProcessPid)
		}
		params.PidFd = fd
	}

	for _, typ := range configs.NamespaceTypes() {
		path := state.NamespacePaths[typ]
		if !config.Namespaces.Contains(typ) || path == "" {
			continue
		}
		if !configs.IsNamespaceSupported(typ) {
			return fmt.Errorf("namespace %s is not supported", typ)
		}
		byParent := typ == configs.NEWPID && !config.RootlessEUID &&
			(!config.Namespaces.Contains(configs.NEWTIME) || state.NamespacePaths[configs.NEWTIME] == "")
		if usePidfd {
			if byParent {
				p.pidns = p.files[len(p.files)-1]
			} else {
				params.NamespaceTypes = append(params.NamespaceTypes, typ)
			}
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("namespace path: %w", err)
		}
		p.files = append(p.files, f)
		if byParent {
			p.pidns = f
			continue
		}
		params.Namespaces = append(params.Namespaces, rawexec.Namespace{Type: typ, Fd: int(f.Fd()), Path: path})
	}
	return nil
}

// containerRoot opens the container's root directory.
func (p *setnsRawProcess) containerRoot() (*os.File, error) {
	return os.OpenFile("/proc/"+strconv.Itoa(p.initProcessPid)+"/root", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
}

// userHome returns the home directory of the process user, as found in
// /etc/passwd of the container (see [rawexec.UserHome]).
func (p *setnsRawProcess) userHome() (string, error) {
	root, err := p.containerRoot()
	if err != nil {
		return "/", err
	}
	defer root.Close()
	return rawexec.UserHome(root, p.config.UID)
}

// allocPty allocates a pty in the container (see [rawexec.AllocPty]), and returns
// the descriptor of its peer, to be used as the child's stdio.
func (p *setnsRawProcess) allocPty() (int, error) {
	root, err := p.containerRoot()
	if err != nil {
		return -1, err
	}
	defer root.Close()
	pty, peer, err := rawexec.AllocPty(root, p.config.ConsoleWidth, p.config.ConsoleHeight)
	if err != nil {
		return -1, err
	}
	p.pty = pty
	p.files = append(p.files, peer)
	// The peer is owned by the parent's fsuid, which may not be mapped
	// in the container (unlike when it is allocated by runc init), so
	// the child may be unable to change its owner.
	// Change it here, if possible (if not, the child will try).
	if uid, err := p.container.config.HostUID(p.config.UID); err == nil {
		if err := unix.Fchown(int(peer.Fd()), uid, -1); err != nil && !errors.Is(err, unix.EPERM) {
			return -1, &os.PathError{Op: "fchown", Path: peer.Name(), Err: err}
		}
	}
	return int(peer.Fd()), nil
}

// startWithCgroupFallback starts the child after it failed to start in the
// configured cgroup (with startErr), doing the same as addIntoCgroupV2 does:
// unless a sub-cgroup is explicitly requested, fall back to container init's
// cgroup, and ignore the errors for rootless.
func (p *setnsRawProcess) startWithCgroupFallback(startErr error) (*rawfork.Process, error) {
	err := startErr
	if path := p.initProcessCgroupPath(); path != "" && p.process.SubCgroupPaths[""] == "" {
		logrus.Debugf("starting in configured cgroup failed (%v), will start in container init cgroup %q", err, path)
		// NOTE: path is not guaranteed to exist because we didn't pause the container.
		var fd *os.File
		fd, err = cgroups.OpenFile(path, "", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC)
		if err == nil {
			defer fd.Close()
			p.program.CgroupFD = int(fd.Fd())
			var proc *rawfork.Process
			if proc, err = p.program.Start(); err == nil {
				return proc, nil
			}
		}
	}
	if p.rootlessCgroups {
		// Ignore cgroup join errors when rootless.
		p.program.UseCgroupFD = false
		return p.program.Start()
	}
	return nil, fmt.Errorf("error adding pid of new process to cgroups: %w", err)
}

func (p *setnsRawProcess) closeFiles() {
	for _, f := range p.files {
		f.Close()
	}
	p.files = nil
}

// closeParentEnds closes the parent's ends of the pipes, sockets and pty.
func (p *setnsRawProcess) closeParentEnds() {
	if p.pty != nil {
		p.pty.Close()
	}
	if p.forkPipe != nil {
		p.forkPipe.Close()
	}
	if p.seccompSock != nil {
		p.seccompSock.Close()
	}
}

func (p *setnsRawProcess) forwardChildLogs() chan error {
	// There is no runc init, so no logs to forward.
	return nil
}

func (p *setnsRawProcess) start() (retErr error) {
	defer func() {
		p.closeFiles()
		p.closeParentEnds()
	}()

	// Same as setupConsole does.
	if p.pty != nil {
		if err := cmsg.SendRawFd(p.process.ConsoleSocket, p.pty.Name(), p.pty.Fd()); err != nil {
			return err
		}
	}

	// Get the "before" value of oom kill count.
	oom, _ := p.manager.OOMKillCount()

	type result struct {
		proc *rawfork.Process
		err  error
	}
	resCh := make(chan result)
	// Use a goroutine to dedicate an OS thread, which attributes are
	// inherited by the child. If these are changed, the thread is not
	// unlocked, so it is terminated once the goroutine exits.
	go func() {
		runtime.LockOSThread()
		if p.pidns == nil && p.config.Scheduler == nil && p.config.IOPriority == nil {
			// The thread is left intact, so it can be reused.
			defer runtime.UnlockOSThread()
		}
		if p.pidns != nil {
			if err := unix.Setns(int(p.pidns.Fd()), unix.CLONE_NEWPID); err != nil {
				resCh <- result{err: os.NewSyscallError("setns into pid namespace", err)}
				return
			}
		}
		if err := rawSetupThread(p.config); err != nil {
			resCh <- result{err: err}
			return
		}
		proc, err := p.program.Start()
		if err != nil && p.program.UseCgroupFD {
			proc, err = p.startWithCgroupFallback(err)
		}
		resCh <- result{proc: proc, err: err}
	}()
	res := <-resCh
	if res.err != nil {
		return fmt.Errorf("error starting setns process: %w", res.err)
	}
	proc := res.proc
	// The child has its own copies now.
	p.closeFiles()
	// On error, the child is reaped by proc.Wait, otherwise by p.wait.
	defer func() {
		if retErr != nil {
			if newOom, err := p.manager.OOMKillCount(); err == nil && newOom != oom {
				// Someone in this cgroup was killed, this _might_ be us.
				retErr = fmt.Errorf("%w (possibly OOM-killed)", retErr)
			}
			_ = unix.Kill(proc.Pid, unix.SIGKILL)
			_ = proc.Wait()
		}
	}()

	if p.forkPipe != nil {
		if err := rawexec.WaitFork(proc, p.forkPipe); err != nil {
			return err
		}
	}
	logrus.Debugf("raw exec: started pid %d", proc.Pid)
	process, err := os.FindProcess(proc.Pid)
	if err != nil {
		return err
	}
	p.cmd.Process = process

	if p.seccompSock != nil {
		seccompFd, err := rawexec.SeccompListener(proc.Pid, p.seccompSock)
		if err != nil {
			if werr := proc.WaitExec(); werr != nil {
				err = werr
			}
			return err
		}
		defer seccompFd.Close()
		// The listener can be sent after the child is let go, as
		// it will wait for the listener if it hits SCMP_ACT_NOTIFY.
		if err := p.sendSeccompListener(seccompFd); err != nil {
			return err
		}
	}
	if err := proc.WaitExec(); err != nil {
		return err
	}
	p.process.ops = p
	return nil
}
