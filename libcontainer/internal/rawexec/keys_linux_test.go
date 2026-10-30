package rawexec

import (
	"bytes"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/libcontainer/internal/rawfork"
)

func TestJoinSessionKeyring(t *testing.T) {
	rd, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	defer wr.Close()

	name := "_ses.rawexec-test-" + strconv.Itoa(os.Getpid())
	var p rawfork.Program
	if err := joinSessionKeyring(&p, name); err != nil {
		t.Fatal(err)
	}
	// Report the description of the session keyring.
	buf := make([]byte, 4096)
	session := unix.KEY_SPEC_SESSION_KEYRING
	p.Ops = append(p.Ops,
		rawfork.Op{Name: "get session keyring", Trap: unix.SYS_KEYCTL, Args: [6]uintptr{unix.KEYCTL_GET_KEYRING_ID, uintptr(session)}, Ret: rawfork.R1},
		rawfork.Op{Name: "describe", Trap: unix.SYS_KEYCTL, Args: [6]uintptr{unix.KEYCTL_DESCRIBE, 0, p.Bytes(buf), uintptr(len(buf))}, ArgRegs: [6]rawfork.Reg{1: rawfork.R1}, Ret: rawfork.R2},
		rawfork.Op{Name: "write", Trap: unix.SYS_WRITE, Args: [6]uintptr{wr.Fd(), p.Bytes(buf)}, ArgRegs: [6]rawfork.Reg{2: rawfork.R2}},
	)
	proc, err := p.Start()
	if err != nil {
		t.Fatal(err)
	}
	wr.Close()
	out, readErr := io.ReadAll(rd)
	if err := proc.Wait(); err != nil {
		t.Fatal(err)
	}
	if readErr != nil {
		t.Fatal(readErr)
	}
	// The description is "type;uid;gid;perm;name".
	if got := string(bytes.TrimRight(out, "\x00")); !strings.HasPrefix(got, "keyring;") || !strings.HasSuffix(got, ";"+name) {
		t.Fatalf("want session keyring %q, got %q", name, got)
	}
}
