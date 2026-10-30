// Package rawexec builds [rawfork] programs to run a process in an existing
// container (as runc exec does), doing in the child the same as nsexec and
// runc init do, except for what can be done by the parent.
//
// Unexported functions mentioned in the comments (such as setupUser) are
// those of package libcontainer, unless they are in this package.
package rawexec
