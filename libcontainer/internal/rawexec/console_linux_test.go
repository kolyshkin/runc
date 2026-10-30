package rawexec

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestAllocPty(t *testing.T) {
	root, err := os.OpenFile("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	pty, peer, err := AllocPty(root, 123, 45)
	if errors.Is(err, os.ErrPermission) {
		// Host's /dev/pts/ptmx is usually mode 000.
		t.Skipf("requires root: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer pty.Close()
	defer peer.Close()

	ws, err := unix.IoctlGetWinsize(int(peer.Fd()), unix.TIOCGWINSZ)
	if err != nil {
		t.Fatal(err)
	}
	if ws.Col != 123 || ws.Row != 45 {
		t.Errorf("want size 123x45, got %dx%d", ws.Col, ws.Row)
	}
	// The peer is the other end of the pty.
	const msg = "hello"
	if _, err := peer.WriteString(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := pty.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], []byte(msg)) {
		t.Errorf("want %q, got %q", msg, buf[:n])
	}
}
