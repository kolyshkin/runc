package libcontainer

// rawSetupThread sets the scheduler (which must be checked by [rawexec.New]
// beforehand) and I/O priority of the current thread. These are per-thread
// attributes inherited by a child, so instead of the child setting them,
// they are set on the thread the child is forked from.
//
// The caller must lock the goroutine to the OS thread, and must not unlock
// it if any of these are set, as the thread attributes can't be restored.
func rawSetupThread(config *initConfig) error {
	// Both setupScheduler and setupIOPriority work on the current thread.
	if err := setupScheduler(config); err != nil {
		return err
	}
	return setupIOPriority(config)
}
