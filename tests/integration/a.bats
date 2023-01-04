#!/usr/bin/env bats

load helpers

function teardown() {
        teardown_bundle
}

function setup() {
        setup_debian
}

@test "show /sys" {
	update_config '.process.args = ["/bin/sh", "-c", "find /sys -type f | wc -l"]'
        runc run showsys
        [ "$status" -eq 0 ]
	echo "$output" >&3
}
