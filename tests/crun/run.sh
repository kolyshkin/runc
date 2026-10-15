#!/bin/bash
# Run the crun integration tests (tests/test_*.py in the crun repository)
# against runc.
#
# Usage: tests/crun/run.sh CRUN_DIR
#
# The tests listed in tests/crun/skip.txt are not run. An entry that does
# not match any test is an error, so that the list does not keep the tests
# which are gone or renamed.
#
# Environment variables:
#   RUNC            runc binary to test (default: runc in the repository root);
#   CGROUP_MANAGER  cgroupfs (default) or systemd;
#   TEST_TIMEOUT    timeout for a single test, in seconds (default: 120).

set -u -o pipefail

die() {
	echo "$0: $*" >&2
	exit 1
}

[ $# -eq 1 ] || die "usage: $0 CRUN_DIR"

dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
crun="$(cd "$1" && pwd)" || die "no crun directory: $1"
RUNC="$(realpath "${RUNC:-$dir/../../runc}")" || exit
export RUNC
export OCI_RUNTIME="$dir/runc"
export CGROUP_MANAGER="${CGROUP_MANAGER:-cgroupfs}"
TEST_TIMEOUT="${TEST_TIMEOUT:-120}"

tmp="$(mktemp -d)" || exit
trap 'rm -rf "$tmp"' EXIT

# Build the container init used by the tests. It includes config.h,
# but does not need anything from it.
touch "$tmp/config.h"
export INIT="$tmp/init"
gcc -O2 -static -I"$tmp" -o "$INIT" "$crun/tests/init.c" || die "failed to build init"

cd "$crun" || exit

# Print the names of all the tests in the given test file. Some test files
# print "1..0" and exit when imported if they lack a dependency (e.g.
# test_mounts.py needs libmount Python bindings); return 77 for those.
list_tests() {
	python3 -I -c '
import contextlib, sys
sys.path.insert(0, "tests")
try:
    with contextlib.redirect_stdout(sys.stderr):
        m = __import__(sys.argv[1])
except SystemExit:
    sys.exit(77)
print("\n".join(m.all_tests))
' "${1%.py}"
}

# Run a single test, given the test file and the test name. Not using
# RUN_TESTS, as it does not work for test names with spaces.
run_test='
import sys
sys.path.insert(0, "tests")
from tests_utils import tests_main
t = __import__(sys.argv[1].removesuffix(".py")).all_tests
tests_main({sys.argv[2]: t[sys.argv[2]]})
'

# Read the skip list into skip_file (whole files to skip) and skip_test
# (individual tests, as "file: test"), checking that every entry exists.
declare -A skip_file skip_test
while IFS= read -r line; do
	[[ $line =~ ^[[:space:]]*(#|$) ]] && continue
	file="${line%%: *}"
	[ -f "tests/$file" ] || die "skip.txt: no such file: $file"
	if [[ $line != *": "* ]]; then
		skip_file[$file]=1
		continue
	fi
	name="${line#*: }"
	names="$(list_tests "$file")"
	case $? in
	0) ;;
	77) continue ;; # Can't check, see below.
	*) exit 1 ;;
	esac
	grep -qxF "$name" <<<"$names" || die "skip.txt: no such test: $line"
	skip_test[$line]=1
done <"$dir/skip.txt"

# Run each test separately, so that a hung test can be killed by timeout
# without losing the results of the others.
failed=()
for f in tests/test_*.py; do
	file="${f#tests/}"
	if [ -v "skip_file[$file]" ]; then
		echo "# $file: skipped"
		continue
	fi
	names="$(list_tests "$file")"
	case $? in
	0) ;;
	77)
		echo "# $file: skipped (failed to import, missing dependency?)"
		continue
		;;
	*) exit 1 ;;
	esac
	echo "# $file"
	while IFS= read -r -u 3 name; do
		if [ -v "skip_test[$file: $name]" ]; then
			echo "# $name: skipped"
			continue
		fi
		# Not using a pipe here, as processes left after a timeout may
		# keep it open.
		timeout -k 10 "$TEST_TIMEOUT" python3 -u -c "$run_test" "$file" "$name" &>"$tmp/out"
		rc=$?
		cat "$tmp/out"
		if [ $rc -eq 124 ] || [ $rc -eq 137 ]; then
			echo "# $name: timed out after ${TEST_TIMEOUT}s"
			failed+=("$file: $name (timed out)")
		elif [ $rc -ne 0 ] || ! grep -q "^ok " "$tmp/out"; then
			failed+=("$file: $name")
		fi
	done 3<<<"$names"
done

if [ ${#failed[@]} -gt 0 ]; then
	echo "# ${#failed[@]} test(s) failed:"
	printf '#\t%s\n' "${failed[@]}"
	exit 1
fi
