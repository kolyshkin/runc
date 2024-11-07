package fs

import (
	"github.com/opencontainers/cgroups"
	"github.com/opencontainers/cgroups/configs"
)

type PerfEventGroup struct{}

func (s *PerfEventGroup) Name() string {
	return "perf_event"
}

func (s *PerfEventGroup) Apply(path string, _ *configs.Resources, pid int) error {
	return apply(path, pid)
}

func (s *PerfEventGroup) Set(_ string, _ *configs.Resources) error {
	return nil
}

func (s *PerfEventGroup) GetStats(path string, stats *cgroups.Stats) error {
	return nil
}
