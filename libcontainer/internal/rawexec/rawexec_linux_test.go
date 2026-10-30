package rawexec

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/libcontainer/internal/rawfork"
)

func TestNewProgram(t *testing.T) {
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	fd := int(null.Fd())

	p, err := newProgram([]int{fd, fd, fd}, 3)
	if err != nil {
		t.Fatal(err)
	}
	// Use the dumpable flag as the exit status.
	p.Ops = append(p.Ops,
		rawfork.Op{Name: "get dumpable", Trap: unix.SYS_PRCTL, Args: [6]uintptr{unix.PR_GET_DUMPABLE}, Ret: rawfork.R1},
		rawfork.Op{Name: "exit", Trap: unix.SYS_EXIT_GROUP, ArgRegs: [6]rawfork.Reg{rawfork.R1}},
	)
	proc, err := p.Start()
	if err != nil {
		t.Fatal(err)
	}
	if err := proc.Wait(); err != nil {
		t.Fatalf("want non-dumpable child, got %v", err)
	}
}
