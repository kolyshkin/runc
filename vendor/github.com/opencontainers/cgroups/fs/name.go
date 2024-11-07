package fs

import (
	"github.com/opencontainers/cgroups"
	"github.com/opencontainers/cgroups/configs"
)

type NameGroup struct {
	GroupName string
	Join      bool
}

func (s *NameGroup) Name() string {
	return s.GroupName
}

func (s *NameGroup) Apply(path string, _ *configs.Resources, pid int) error {
	if s.Join {
		// Ignore errors if the named cgroup does not exist.
		_ = apply(path, pid)
	}
	return nil
}

func (s *NameGroup) Set(_ string, _ *configs.Resources) error {
	return nil
}

func (s *NameGroup) GetStats(path string, stats *cgroups.Stats) error {
	return nil
}
