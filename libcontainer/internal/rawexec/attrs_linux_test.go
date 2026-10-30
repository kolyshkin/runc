package rawexec

import (
	"encoding/binary"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/internal/rawfork"
)

func TestAttrs(t *testing.T) {
	rd, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	defer wr.Close()

	const mask = 0o027
	var p rawfork.Program
	noNewPrivs(&p)
	setUmask(&p, mask)
	setPersonality(&p, configs.PerLinux32)

	// Report the resulting attributes to the parent. Both umask(2) and
	// personality(2) return the previous value.
	got := new([3]uint32)
	p.Ops = append(p.Ops,
		rawfork.Op{Name: "get no new privs", Trap: unix.SYS_PRCTL, Args: [6]uintptr{unix.PR_GET_NO_NEW_PRIVS}, Store: &got[0]},
		rawfork.Op{Name: "get umask", Trap: unix.SYS_UMASK, Store: &got[1]},
		rawfork.Op{Name: "get personality", Trap: unix.SYS_PERSONALITY, Args: [6]uintptr{0xffffffff}, Store: &got[2]},
		rawfork.Op{Name: "write", Trap: unix.SYS_WRITE, Args: [6]uintptr{wr.Fd(), p.Pin(unsafe.Pointer(got)), unsafe.Sizeof(*got)}},
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
	if len(out) != int(unsafe.Sizeof(*got)) {
		t.Fatalf("unexpected output length %d", len(out))
	}
	if v := binary.NativeEndian.Uint32(out[0:]); v != 1 {
		t.Errorf("want no new privs 1, got %d", v)
	}
	if v := binary.NativeEndian.Uint32(out[4:]); v != mask {
		t.Errorf("want umask %#o, got %#o", mask, v)
	}
	if v := binary.NativeEndian.Uint32(out[8:]); v != configs.PerLinux32 {
		t.Errorf("want personality %#x, got %#x", configs.PerLinux32, v)
	}
}

// runAffinity runs a program which sets the CPU affinity as setCPUAffinity
// does, and returns the resulting affinity. If threadCPU is not -1, the
// program is started from a thread with the affinity of that CPU only.
func runAffinity(t *testing.T, aff *configs.CPUAffinity, threadCPU int) unix.CPUSetDynamic {
	t.Helper()
	rd, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	defer wr.Close()

	var p rawfork.Program
	setCPUAffinity(&p, aff)
	got := unix.NewCPUSet(configs.MaxCPU)
	size := uintptr(len(got)) * unsafe.Sizeof(got[0])
	p.Ops = append(p.Ops,
		rawfork.Op{Name: "sched_getaffinity", Trap: unix.SYS_SCHED_GETAFFINITY, Args: [6]uintptr{0, size, p.Pin(unsafe.Pointer(&got[0]))}},
		rawfork.Op{Name: "write", Trap: unix.SYS_WRITE, Args: [6]uintptr{wr.Fd(), p.Pin(unsafe.Pointer(&got[0])), size}},
	)
	errCh := make(chan error)
	var proc *rawfork.Process
	go func() {
		// Never unlocked, so the thread is terminated on return.
		runtime.LockOSThread()
		if threadCPU != -1 {
			mask := unix.NewCPUSet(threadCPU + 1)
			mask.Set(threadCPU)
			if err := unix.SchedSetaffinityDynamic(0, mask); err != nil {
				errCh <- err
				return
			}
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
	if len(out) != int(size) {
		t.Fatalf("unexpected output length %d", len(out))
	}
	return decodeMask(out)
}

// decodeMask decodes a CPU or NUMA node mask (an array of unsigned longs)
// sent by the child (which has its own copy of memory).
func decodeMask(b []byte) unix.CPUSetDynamic {
	const bits = 8 * unsafe.Sizeof(uintptr(0))
	res := unix.NewCPUSet(len(b) * 8)
	for i := range uintptr(len(b) * 8) {
		var word uint64
		w := b[i/bits*(bits/8):]
		if bits == 64 {
			word = binary.NativeEndian.Uint64(w)
		} else {
			word = uint64(binary.NativeEndian.Uint32(w))
		}
		if word&(1<<(i%bits)) != 0 {
			res.Set(int(i))
		}
	}
	return res
}

func TestCPUAffinity(t *testing.T) {
	all := unix.NewCPUSet(configs.MaxCPU)
	if err := unix.SchedGetaffinityDynamic(0, all); err != nil {
		t.Fatal(err)
	}
	if all.Count() < 2 {
		t.Skip("need at least 2 CPUs")
	}
	// Find the first and the last available CPUs.
	first, last := -1, -1
	for i := range configs.MaxCPU {
		if all.IsSet(i) {
			if first == -1 {
				first = i
			}
			last = i
		}
	}
	one := unix.NewCPUSet(last + 1)
	one.Set(last)

	for _, tc := range []struct {
		name string
		aff  *configs.CPUAffinity
		want unix.CPUSetDynamic
	}{
		{name: "final", aff: &configs.CPUAffinity{Initial: all, Final: one}, want: one},
		{name: "initial", aff: &configs.CPUAffinity{Initial: one}, want: one},
		// The affinity of the thread the child is forked from is reset.
		{name: "reset", aff: nil, want: all},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := runAffinity(t, tc.aff, first)
			for i := range configs.MaxCPU {
				if got.IsSet(i) != tc.want.IsSet(i) {
					t.Fatalf("want %d CPUs, got %d (CPU %d differs)", tc.want.Count(), got.Count(), i)
				}
			}
		})
	}
}

func TestMemoryPolicy(t *testing.T) {
	rd, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	defer wr.Close()

	// With MPOL_F_STATIC_NODES, get_mempolicy(2) returns the nodes as
	// specified (even those not available, as long as they fit into the
	// first word), which allows to check that all of them are passed to
	// the kernel, including the last bit of the mask.
	last := int(8*unsafe.Sizeof(uintptr(0))) - 1
	nodes, err := configs.ToCPUSet("0," + strconv.Itoa(last))
	if err != nil {
		t.Fatal(err)
	}
	var p rawfork.Program
	setMemoryPolicy(&p, &configs.LinuxMemoryPolicy{
		Mode:  unix.MPOL_BIND,
		Flags: unix.MPOL_F_STATIC_NODES,
		Nodes: nodes,
	})
	got := new(struct {
		Mode  uint32
		_     uint32
		Nodes [1024 / 8]byte
	})
	p.Ops = append(p.Ops,
		rawfork.Op{Name: "get_mempolicy", Trap: unix.SYS_GET_MEMPOLICY, Args: [6]uintptr{p.Pin(unsafe.Pointer(&got.Mode)), p.Pin(unsafe.Pointer(&got.Nodes)), 1024 + 1}},
		rawfork.Op{Name: "write", Trap: unix.SYS_WRITE, Args: [6]uintptr{wr.Fd(), p.Pin(unsafe.Pointer(got)), unsafe.Sizeof(*got)}},
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
	if len(out) != int(unsafe.Sizeof(*got)) {
		t.Fatalf("unexpected output length %d", len(out))
	}
	if v, want := binary.NativeEndian.Uint32(out), uint32(unix.MPOL_BIND|unix.MPOL_F_STATIC_NODES); v != want {
		t.Errorf("want mode %#x, got %#x", want, v)
	}
	if n := decodeMask(out[8:]); n.Count() != 2 || !n.IsSet(0) || !n.IsSet(last) {
		t.Errorf("want nodes 0 and %d, got %d nodes", last, n.Count())
	}
}

func TestRlimits(t *testing.T) {
	var cur unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &cur); err != nil {
		t.Fatal(err)
	}
	// Lowering the limits is always allowed.
	limits := []configs.Rlimit{
		{Type: unix.RLIMIT_NOFILE, Soft: 100, Hard: 200},
		{Type: unix.RLIMIT_CORE, Soft: 0, Hard: 0},
	}
	if cur.Max < 200 {
		t.Skipf("hard RLIMIT_NOFILE is too low (%d)", cur.Max)
	}
	rd, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	defer wr.Close()

	var p rawfork.Program
	setRlimits(&p, limits)
	got := new([2][2]uint64)
	for i, l := range limits {
		p.Ops = append(p.Ops, rawfork.Op{Name: "get rlimit", Trap: unix.SYS_PRLIMIT64, Args: [6]uintptr{0, uintptr(l.Type), 0, p.Pin(unsafe.Pointer(&got[i]))}})
	}
	p.Ops = append(p.Ops, rawfork.Op{Name: "write", Trap: unix.SYS_WRITE, Args: [6]uintptr{wr.Fd(), p.Pin(unsafe.Pointer(got)), unsafe.Sizeof(*got)}})
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
	if len(out) != int(unsafe.Sizeof(*got)) {
		t.Fatalf("unexpected output length %d", len(out))
	}
	for i, l := range limits {
		soft, hard := binary.NativeEndian.Uint64(out[16*i:]), binary.NativeEndian.Uint64(out[16*i+8:])
		if soft != l.Soft || hard != l.Hard {
			t.Errorf("rlimit %d: want %d/%d, got %d/%d", l.Type, l.Soft, l.Hard, soft, hard)
		}
	}
}

func TestOomScoreAdj(t *testing.T) {
	cur, err := os.ReadFile("/proc/self/oom_score_adj")
	if err != nil {
		t.Fatal(err)
	}
	score, err := strconv.Atoi(strings.TrimSpace(string(cur)))
	if err != nil {
		t.Fatal(err)
	}
	// Raising the value is always allowed.
	want := min(score+100, 1000)
	rd, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	defer wr.Close()

	var p rawfork.Program
	if err := setOomScoreAdj(&p, want); err != nil {
		t.Fatal(err)
	}
	path, err := p.String("/proc/self/oom_score_adj")
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	dirFd := unix.AT_FDCWD
	p.Ops = append(p.Ops,
		rawfork.Op{Name: "open", Trap: unix.SYS_OPENAT, Args: [6]uintptr{uintptr(dirFd), path, unix.O_RDONLY | unix.O_CLOEXEC}, Ret: rawfork.R1},
		rawfork.Op{Name: "read", Trap: unix.SYS_READ, Args: [6]uintptr{0, p.Bytes(buf), uintptr(len(buf))}, ArgRegs: [6]rawfork.Reg{rawfork.R1}, Ret: rawfork.R2},
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
	if got := strings.TrimSpace(string(out)); got != strconv.Itoa(want) {
		t.Fatalf("want oom_score_adj %d, got %q", want, got)
	}
}
