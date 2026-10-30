package libcontainer

import (
	"encoding/binary"
	"io"
	"os"
	"runtime"
	"testing"
	"unsafe"

	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/internal/rawfork"
	"github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

func TestRawSetupThread(t *testing.T) {
	config := &initConfig{
		// Both are allowed for an unprivileged user.
		Scheduler:  &configs.Scheduler{Policy: specs.SchedBatch, Nice: 5},
		IOPriority: &configs.IOPriority{Class: specs.IOPRIO_CLASS_BE, Priority: 6},
	}

	rd, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	defer wr.Close()

	// Report the child's scheduler and I/O priority to the parent.
	var p rawfork.Program
	attr := &unix.SchedAttr{}
	ioprio := new(uint32)
	p.Ops = append(p.Ops,
		rawfork.Op{Name: "sched_getattr", Trap: unix.SYS_SCHED_GETATTR, Args: [6]uintptr{0, p.Pin(unsafe.Pointer(attr)), unsafe.Sizeof(*attr)}},
		rawfork.Op{Name: "ioprio_get", Trap: unix.SYS_IOPRIO_GET, Args: [6]uintptr{1, 0}, Store: ioprio}, // IOPRIO_WHO_PROCESS.
		rawfork.Op{Name: "write attr", Trap: unix.SYS_WRITE, Args: [6]uintptr{wr.Fd(), p.Pin(unsafe.Pointer(attr)), unsafe.Sizeof(*attr)}},
		rawfork.Op{Name: "write ioprio", Trap: unix.SYS_WRITE, Args: [6]uintptr{wr.Fd(), p.Pin(unsafe.Pointer(ioprio)), 4}},
	)

	errCh := make(chan error)
	var proc *rawfork.Process
	go func() {
		// Never unlocked, so the thread is terminated on return.
		runtime.LockOSThread()
		if err := rawSetupThread(config); err != nil {
			errCh <- err
			return
		}
		var startErr error
		proc, startErr = p.Start()
		errCh <- startErr
	}()
	if err := <-errCh; err != nil {
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
	sz := int(unsafe.Sizeof(*attr))
	if len(out) != sz+4 {
		t.Fatalf("unexpected output length %d", len(out))
	}
	got := *(*unix.SchedAttr)(unsafe.Pointer(&out[0]))
	if got.Policy != unix.SCHED_BATCH || got.Nice != 5 {
		t.Errorf("want SCHED_BATCH with nice 5, got policy %d nice %d", got.Policy, got.Nice)
	}
	if v, want := binary.NativeEndian.Uint32(out[sz:]), uint32(2<<13|6); v != want { // IOPRIO_CLASS_BE.
		t.Errorf("want ioprio %#x, got %#x", want, v)
	}
}
