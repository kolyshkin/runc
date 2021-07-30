// +build linux

/*
Utility for testing cgroup operations.

Creates a mock of the cgroup filesystem for the duration of the test.
*/
package fs

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/configs"
)

func init() {
	cgroups.TestMode = true
}

type cgroupTestUtil struct {
	res *configs.Resources

	// Path to the mock cgroup directory.
	CgroupPath string

	t *testing.T
}

// Creates a new test util for the specified subsystem
func NewCgroupTestUtil(subsystem string, t *testing.T) *cgroupTestUtil {
	root := t.TempDir()
	testCgroupPath := filepath.Join(root, subsystem)
	// Ensure the full mock cgroup path exists.
	if err := os.MkdirAll(testCgroupPath, 0o755); err != nil {
		t.Fatal(err)
	}
	return &cgroupTestUtil{res: &configs.Resources{}, CgroupPath: testCgroupPath, t: t}
}

// Write the specified contents on the mock of the specified cgroup files.
func (c *cgroupTestUtil) writeFileContents(fileContents map[string]string) {
	for file, contents := range fileContents {
		err := cgroups.WriteFile(c.CgroupPath, file, contents)
		if err != nil {
			c.t.Fatal(err)
		}
	}
}
