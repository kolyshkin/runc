package rawexec

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/libcontainer/capabilities"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/internal/rawfork"
)

// capsState is the capability state of a process, as reported by
// capget(2) and prctl(2).
type capsState struct {
	Data     [2]unix.CapUserData
	Bounding uint64
	Ambient  uint64
}

func TestCaps(t *testing.T) {
	last, err := capabilities.LastCap()
	if err != nil {
		t.Fatal(err)
	}
	caps, err := capabilities.New(&configs.Capabilities{
		Bounding:    []string{"CAP_CHOWN", "CAP_KILL", "CAP_NET_RAW"},
		Effective:   []string{"CAP_KILL"},
		Permitted:   []string{"CAP_KILL", "CAP_NET_RAW"},
		Inheritable: []string{"CAP_NET_RAW"},
		Ambient:     []string{"CAP_NET_RAW"},
	})
	if err != nil {
		t.Fatal(err)
	}
	m, ok := caps.Masks()
	if !ok {
		t.Fatal("no masks")
	}

	rd, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	defer wr.Close()

	var p rawfork.Program
	// Create a new user namespace to have all capabilities in it
	// without being root.
	p.Ops = append(p.Ops, rawfork.Op{
		Name: "unshare", Trap: unix.SYS_UNSHARE, Args: [6]uintptr{unix.CLONE_NEWUSER},
	})
	applyCaps(&p, m, last)

	// Report the resulting state to the parent. Capability sets are
	// read using capget, bounding and ambient ones using prctl (which
	// return 1 if a capability is set).
	hdr := &unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	state := &capsState{}
	p.Ops = append(p.Ops, rawfork.Op{
		Name: "capget", Trap: unix.SYS_CAPGET,
		Args: [6]uintptr{p.Pin(unsafe.Pointer(hdr)), p.Pin(unsafe.Pointer(&state.Data))},
	})
	bits := make([]uint32, 2*(last+1))
	for c := range last + 1 {
		p.Ops = append(p.Ops,
			rawfork.Op{Name: "read bounding", Trap: unix.SYS_PRCTL, Args: [6]uintptr{unix.PR_CAPBSET_READ, uintptr(c)}, Store: &bits[2*c]},
			rawfork.Op{Name: "read ambient", Trap: unix.SYS_PRCTL, Args: [6]uintptr{unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_IS_SET, uintptr(c)}, Store: &bits[2*c+1]},
		)
	}
	p.Ops = append(p.Ops,
		rawfork.Op{Name: "write state", Trap: unix.SYS_WRITE, Args: [6]uintptr{wr.Fd(), p.Pin(unsafe.Pointer(&state.Data)), unsafe.Sizeof(state.Data)}},
		rawfork.Op{Name: "write bits", Trap: unix.SYS_WRITE, Args: [6]uintptr{wr.Fd(), p.Pin(unsafe.Pointer(&bits[0])), uintptr(4 * len(bits))}},
	)

	proc, err := p.Start()
	if err != nil {
		t.Fatal(err)
	}
	wr.Close()
	out, readErr := io.ReadAll(rd)
	if err := proc.Wait(); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.ENOSPC) {
			t.Skipf("can't create user namespace: %v", err)
		}
		t.Fatal(err)
	}
	if readErr != nil {
		t.Fatal(readErr)
	}
	var got capsState
	sz := int(unsafe.Sizeof(got.Data))
	if len(out) != sz+4*len(bits) {
		t.Fatalf("unexpected output length %d", len(out))
	}
	for i := range got.Data {
		d := out[i*12:]
		got.Data[i] = unix.CapUserData{
			Effective:   binary.NativeEndian.Uint32(d[0:]),
			Permitted:   binary.NativeEndian.Uint32(d[4:]),
			Inheritable: binary.NativeEndian.Uint32(d[8:]),
		}
	}
	for c := range last + 1 {
		if binary.NativeEndian.Uint32(out[sz+8*c:]) == 1 {
			got.Bounding |= 1 << c
		}
		if binary.NativeEndian.Uint32(out[sz+8*c+4:]) == 1 {
			got.Ambient |= 1 << c
		}
	}

	want := capsState{
		Data: [2]unix.CapUserData{{
			Effective:   uint32(m.Effective),
			Permitted:   uint32(m.Permitted),
			Inheritable: uint32(m.Inheritable),
		}},
		Bounding: m.Bounding,
		Ambient:  m.Ambient,
	}
	if got != want {
		t.Fatalf("want %+v, got %+v", want, got)
	}
}
