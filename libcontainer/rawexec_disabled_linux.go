//go:build !rawexec

package libcontainer

// rawExecEnabled tells whether runc exec uses rawfork (see
// [Container.newSetnsRawProcess]) rather than runc init, if possible.
const rawExecEnabled = false
