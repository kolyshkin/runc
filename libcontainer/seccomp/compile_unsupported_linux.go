//go:build !cgo || !seccomp

package seccomp

import "github.com/opencontainers/runc/libcontainer/configs"

// Compile returns an error because seccomp is not supported.
func Compile(_ *configs.Seccomp) (*Filter, error) {
	return nil, ErrSeccompNotEnabled
}
