#!/bin/bash
# Run podman e2e tests using runc as the OCI runtime.
#
# Usage: run-tests.sh <podman-source-dir>
#
# Podman binaries are expected to be already built (make binaries)
# in <podman-source-dir>. The runc binary to be tested is the one podman
# finds first (most probably /usr/bin/runc). Must be run as root.

set -Eeuo pipefail

if [ $# -ne 1 ]; then
	echo "Usage: $0 <podman-source-dir>" >&2
	exit 1
fi

if [ "$(id -u)" != 0 ]; then
	echo "$0: must be run as root" >&2
	exit 1
fi

PODMAN_SRC="$1"
# Some tests check for the exact runtime name, so it can't be a path.
export OCI_RUNTIME=runc

export CGROUP_MANAGER=systemd
export STORAGE_FS=overlay
export TMPDIR=/var/tmp

# Tests to skip (each entry is a part of the test name, regexp).
SKIP_TESTS=(
	# Flaky, or not using the runtime.
	'generate'
	'image list filter'
	'import'
	'inspect'
	'logs'
	'podman images filter'
	'prune unused images'
	'pull from docker'
	'search'
	'trust'
	'--tls-details'
	# Uses the default runtime (crun) rather than the one from --runtime.
	'podman build with sbom flags'

	# Not working on GitHub Actions.
	'selinux'
	'network'
	'--add-host'
	'Podman kube play'
	'play kube'
	'artifact'
	'authenticated push'
	'local registry with authorization'
	'login and logout'
	'push test'
	'push with --add-compression'
	'push with authorization'
	'attempt push w/o dest'
	'using journald for container'
)
SKIP_REGEX=$(
	IFS='|'
	echo "${SKIP_TESTS[*]}"
)

ulimit -u unlimited

set -x
"$PODMAN_SRC"/bin/podman --runtime "$OCI_RUNTIME" info \
	--format '{{.Host.OCIRuntime.Path}}: {{.Host.OCIRuntime.Version}}'
make -C "$PODMAN_SRC" localintegration \
	GINKGOTIMEOUT=--timeout=50m \
	GINKGO_FLAKE_ATTEMPTS=3 \
	TESTFLAGS="--skip='$SKIP_REGEX'"
