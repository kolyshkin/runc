#!/bin/bash
#
# Build every commit in BASE..HEAD and check that the (stripped) runc binary
# does not grow by more than MAX_GROWTH bytes compared to the merge base.
# As a side effect, this also checks that every commit compiles.
#
# Usage: check-binary-size.sh BASE [HEAD]
#
# Environment:
#   MAX_GROWTH    maximum allowed growth, in bytes (default: 51200).
#   ALLOW_GROWTH  if set to 1, report excessive growth but do not fail.
#
# NOTE this script checks out other commits, so the git tree must be clean.
# The original HEAD is restored on exit.

set -Eeuo pipefail

# Everything is in a function so that bash has parsed the whole script
# before "git checkout" has a chance to modify (or remove) this file.
main() {
	local max=${MAX_GROWTH:-51200}
	local base head orig tmp
	local -a commits

	if [ $# -lt 1 ] || [ $# -gt 2 ]; then
		echo "Usage: $0 BASE [HEAD]" >&2
		exit 1
	fi
	head=$(git rev-parse --verify "${2:-HEAD}^{commit}")
	base=$(git merge-base "$1" "$head")
	mapfile -t commits < <(git rev-list --reverse "$base..$head")
	if [ ${#commits[@]} -eq 0 ]; then
		echo "No commits in $base..$head, nothing to check."
		exit 0
	fi

	if ! git diff --quiet HEAD; then
		echo "Git tree is not clean, refusing to check out other commits." >&2
		exit 1
	fi
	orig=$(git symbolic-ref -q --short HEAD || git rev-parse HEAD)
	tmp=$(mktemp -d)
	# shellcheck disable=SC2064 # Expand now, not on exit.
	trap "git checkout -q '$orig'; rm -rf '$tmp'" EXIT

	local base_size size delta c d failed=0
	base_size=$(build_and_size "$base" "$tmp")
	d=$(desc "$base")
	echo "Base: $d: $base_size bytes"
	summary "| Commit | Size | Growth |"
	summary "|---|---:|---:|"
	summary "| base: ${d//|/\\|} | $base_size | |"

	for c in "${commits[@]}"; do
		size=$(build_and_size "$c" "$tmp")
		delta=$((size - base_size))
		d=$(desc "$c")
		echo "Commit: $d: $size bytes ($(signed "$delta"))"
		summary "| ${d//|/\\|} | $size | $(signed "$delta") |"
		if [ "$delta" -gt "$max" ]; then
			failed=1
			error "runc binary grew by $delta bytes at commit $d (max allowed is $max)"
		fi
	done

	if [ "$failed" -eq 0 ]; then
		echo "OK: runc binary growth is within $max bytes."
		return
	fi
	if [ "${ALLOW_GROWTH:-0}" = 1 ]; then
		echo "Binary growth is above the limit, but it is explicitly allowed."
		return
	fi
	echo "Binary growth is above the limit. Please investigate, and fix if possible."
	exit 1
}

# Check out a commit, build runc, and print the size of the stripped binary.
build_and_size() {
	local commit=$1 tmp=$2

	git checkout -q "$commit"
	echo "Building $(desc "$commit")" >&2
	make runc >&2
	strip -o "$tmp/runc" runc
	stat -c %s "$tmp/runc"
}

desc() {
	git log -1 --no-show-signature --format='%h %s' "$1"
}

signed() {
	printf "%+d" "$1"
}

summary() {
	if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
		echo "$*" >>"$GITHUB_STEP_SUMMARY"
	fi
}

error() {
	if [ -n "${GITHUB_ACTIONS:-}" ]; then
		echo "::error::$*"
	else
		echo "ERROR: $*" >&2
	fi
}

main "$@"
exit
