#!/usr/bin/env bats

load helpers

function setup() {
	# runc ps requires cgroups
	[[ "$ROOTLESS" -ne 0 ]] && requires rootless_cgroup

	setup_busybox

	set_cgroups_path

	runc run -d --console-socket "$CONSOLE_SOCKET" test_busybox
	[ "$status" -eq 0 ]

	# check state
	testcontainer test_busybox running
}

function teardown() {
	teardown_bundle
}

@test "ps" {
	runc ps test_busybox
	[ "$status" -eq 0 ]
	[[ ${lines[0]} =~ UID\ +PID\ +PPID\ +C\ +STIME\ +TTY\ +TIME\ +CMD+ ]]
	[[ "${lines[1]}" == *"$(id -un 2>/dev/null)"*[0-9]* ]]
}

@test "ps -f json" {
	runc ps -f json test_busybox
	[ "$status" -eq 0 ]
	[[ ${lines[0]} =~ [0-9]+ ]]
}

@test "ps -e -x" {
	runc ps test_busybox -e -x
	[ "$status" -eq 0 ]
	[[ ${lines[0]} =~ \ +PID\ +TTY\ +STAT\ +TIME\ +COMMAND+ ]]
	[[ "${lines[1]}" =~ [0-9]+ ]]
}

@test "ps after the container stopped" {
	runc ps test_busybox
	[ "$status" -eq 0 ]

	runc kill test_busybox KILL
	[ "$status" -eq 0 ]
	wait_for_container 10 1 test_busybox stopped

	runc ps test_busybox
	[ "$status" -eq 0 ]
}
