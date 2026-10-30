package rawexec

import (
	"errors"
	"testing"

	"github.com/opencontainers/runtime-spec/specs-go"

	"github.com/opencontainers/runc/libcontainer/configs"
)

func TestSchedSupported(t *testing.T) {
	for _, tc := range []struct {
		s           *configs.Scheduler
		ok          bool
		unsupported bool // Otherwise, invalid.
	}{
		{s: nil, ok: true},
		{s: &configs.Scheduler{Policy: specs.SchedBatch, Nice: 5}, ok: true},
		{s: &configs.Scheduler{Policy: specs.SchedFIFO, Priority: 1, Flags: []specs.LinuxSchedulerFlag{specs.SchedFlagUtilClampMin}}, ok: true},
		{s: &configs.Scheduler{Policy: specs.SchedDeadline}, unsupported: true},
		{s: &configs.Scheduler{Policy: specs.SchedFIFO, Flags: []specs.LinuxSchedulerFlag{specs.SchedFlagResetOnFork}}, unsupported: true},
		{s: &configs.Scheduler{Policy: "SCHED_NONE"}},
	} {
		err := schedSupported(tc.s)
		if (err == nil) != tc.ok || errors.Is(err, ErrUnsupported) != tc.unsupported {
			t.Errorf("%+v: want ok %v (unsupported %v), got error %v", tc.s, tc.ok, tc.unsupported, err)
		}
	}
}
