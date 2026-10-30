package rawexec

import (
	"fmt"
	"os"

	"github.com/containerd/console"
	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/internal/linux"
	"github.com/opencontainers/runc/internal/pathrs"
	"github.com/opencontainers/runc/internal/sys"
)

// AllocPty is like safeAllocPty, but it is used by the parent,
// allocating a pty using /dev/pts/ptmx inside root (the container's root
// directory). If width and height are set, the pty is resized accordingly
// (like setupConsole does).
//
// Unlike safeAllocPty, there is no fallback for kernels without TIOCGPTPEER
// (Linux < 4.13), as the peer path is only valid inside the container (and
// raw exec requires a newer kernel anyway).
func AllocPty(root *os.File, width, height uint16) (_ console.Console, _ *os.File, retErr error) {
	ptmxHandle, err := pathrs.OpenInRoot(root, "/dev/pts/ptmx", unix.O_PATH|unix.O_CLOEXEC)
	if err != nil {
		return nil, nil, err
	}
	defer ptmxHandle.Close()
	if err := sys.CheckPtmxHandle(ptmxHandle); err != nil {
		return nil, nil, fmt.Errorf("verify ptmx handle: %w", err)
	}

	ptyFile, err := pathrs.Reopen(ptmxHandle, unix.O_RDWR|unix.O_NOCTTY)
	if err != nil {
		return nil, nil, fmt.Errorf("reopen ptmx to get new pty pair: %w", err)
	}
	// On success, the ownership is transferred to pty.
	pty, peerPath, err := console.NewPtyFromFile(ptyFile)
	if err != nil {
		_ = ptyFile.Close()
		return nil, nil, err
	}
	defer func() {
		if retErr != nil {
			_ = pty.Close()
		}
	}()
	peer, err := linux.GetPtyPeer(pty.Fd(), peerPath, unix.O_RDWR)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get peer end of newly-allocated console: %w", err)
	}
	if width != 0 && height != 0 {
		if err := pty.Resize(console.WinSize{Width: width, Height: height}); err != nil {
			_ = peer.Close()
			return nil, nil, err
		}
	}
	return pty, peer, nil
}
