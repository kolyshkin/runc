// +build linux

package fs

import (
	"testing"

	"github.com/opencontainers/runc/libcontainer/cgroups/fscommon"
	"github.com/opencontainers/runc/libcontainer/configs"
)

func TestFreezerSetState(t *testing.T) {
	helper := NewCgroupTestUtil("freezer", t)

	helper.writeFileContents(map[string]string{
		"freezer.state": string(configs.Frozen),
	})

	helper.res.Freezer = configs.Thawed
	freezer := &FreezerGroup{}
	if err := freezer.Set(helper.CgroupPath, helper.res); err != nil {
		t.Fatal(err)
	}

	value, err := fscommon.GetCgroupParamString(helper.CgroupPath, "freezer.state")
	if err != nil {
		t.Fatal(err)
	}
	if value != string(configs.Thawed) {
		t.Fatal("Got the wrong value, set freezer.state failed.")
	}
}

func TestFreezerSetInvalidState(t *testing.T) {
	helper := NewCgroupTestUtil("freezer", t)

	const (
		invalidArg configs.FreezerState = "Invalid"
	)

	helper.res.Freezer = invalidArg
	freezer := &FreezerGroup{}
	if err := freezer.Set(helper.CgroupPath, helper.res); err == nil {
		t.Fatal("Failed to return invalid argument error")
	}
}
