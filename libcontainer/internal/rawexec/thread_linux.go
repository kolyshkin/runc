package rawexec

import (
	"fmt"

	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/libcontainer/configs"
)

// The scheduler and I/O priority are per-thread attributes inherited by a
// child, so instead of the child setting them, they are set on the thread
// the child is forked from (see [rawfork.Program.Start]).

// schedSupported returns an error if the scheduler s can't be set on the
// thread the child is forked from. In such case (the error is
// [ErrUnsupported]), runc init should be used instead.
func schedSupported(s *configs.Scheduler) error {
	if s == nil {
		return nil
	}
	attr, err := configs.ToSchedAttr(s)
	if err != nil {
		return err
	}
	// A SCHED_DEADLINE thread can't fork, and SCHED_FLAG_RESET_ON_FORK
	// makes the child not inherit the scheduler.
	if attr.Policy == unix.SCHED_DEADLINE {
		return fmt.Errorf("SCHED_DEADLINE policy: %w", ErrUnsupported)
	}
	if attr.Flags&unix.SCHED_FLAG_RESET_ON_FORK != 0 {
		return fmt.Errorf("SCHED_FLAG_RESET_ON_FORK flag: %w", ErrUnsupported)
	}
	return nil
}
