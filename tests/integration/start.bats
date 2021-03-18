#!/usr/bin/env bats

load helpers

function setup() {
	setup_busybox
}

function teardown() {
	teardown_bundle
}

@test "runc start" {
    IMAX=4000
    for ((I = 0; I < IMAX; I++)); do
	echo "=== $I/$IMAX ===" >&3

	runc create --console-socket "$CONSOLE_SOCKET" test_busybox
	[ "$status" -eq 0 ]

	testcontainer test_busybox created

	# start container test_busybox
	runc start test_busybox
	[ "$status" -eq 0 ]

	testcontainer test_busybox running

	# delete test_busybox
	runc delete --force test_busybox
	[ "$status" -eq 0 ]

	runc state test_busybox
	[ "$status" -ne 0 ]
    done
}
