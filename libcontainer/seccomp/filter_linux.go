package seccomp

import "golang.org/x/sys/unix"

// Filter is a seccomp filter compiled by [Compile], to be loaded by a
// different process using seccomp(2), or prctl(PR_SET_SECCOMP) if Flags
// is 0.
type Filter struct {
	Program []unix.SockFilter
	// Flags are flags for seccomp(2).
	Flags uint
	// NoNewPrivs is set if the filter requires no_new_privs bit to be set
	// before loading it.
	NoNewPrivs bool
	// Listener is set if seccomp(2) returns a listener file descriptor
	// (i.e. Flags contain SECCOMP_FILTER_FLAG_NEW_LISTENER).
	Listener bool
}
